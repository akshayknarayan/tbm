//! A message-oriented TCP Chunnel.
//!
//! Unlike [`bertha::udp`], TCP chunnels are always connection-oriented, so there is no equivalent
//! of [`bertha::udp::UdpSkChunnel`].

#![feature(iter_array_chunks)]

use bertha::{ChunnelConnection, ChunnelConnector, ChunnelListener};
use color_eyre::eyre::{bail, ensure, eyre, Report, WrapErr};
use futures_util::{
    future::{ready, Ready},
    stream::{Stream, StreamExt, TryStreamExt},
};
use std::cmp::Ordering;
use std::net::SocketAddr;
use std::{future::Future, pin::Pin};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;

/// TCP Chunnel connector.
///
/// Wraps [`tokio::net::TcpSocket`]. Carries no state.
///
/// If `WITHADDR` == true, wrap the returned connection in an [`IgnoreAddr`].
#[derive(Default, Clone, Debug)]
pub struct TcpChunnel<const WITHADDR: bool = false>;

fn make_tcp_listener(a: SocketAddr) -> Result<TcpListener, Report> {
    let sk = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sk.set_reuse_port(true)?;
    sk.set_nonblocking(true)?;
    sk.bind(&a.into())?;
    sk.listen(16)?;
    TcpListener::from_std(sk.into()).wrap_err_with(|| eyre!("socket bind failed on {:?}", a))
}

impl ChunnelListener for TcpChunnel<false> {
    type Addr = SocketAddr;
    type Connection = TcpCn;
    type Future = Ready<Result<Self::Stream, Self::Error>>;
    type Stream =
        Pin<Box<dyn Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn listen(&mut self, a: Self::Addr) -> Self::Future {
        ready((|| {
            let sk = make_tcp_listener(a)?;
            Ok(Box::pin(
                TcpListenerStream::new(sk)
                    .map_ok(TcpCn::new)
                    .map_err(Into::into),
            ) as _)
        })())
    }
}

impl ChunnelListener for TcpChunnel<true> {
    type Addr = SocketAddr;
    type Connection = IgnoreAddr<SocketAddr, TcpCn>;
    type Future = Ready<Result<Self::Stream, Self::Error>>;
    type Stream =
        Pin<Box<dyn Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn listen(&mut self, a: Self::Addr) -> Self::Future {
        ready((|| {
            let sk = make_tcp_listener(a)?;
            Ok(Box::pin(TcpListenerStream::new(sk).map(|cn| {
                let cn = cn?;
                let addr = cn.peer_addr()?;
                Ok(IgnoreAddr(addr, TcpCn::new(cn)))
            })) as _)
        })())
    }
}

impl ChunnelConnector for TcpChunnel<false> {
    type Addr = SocketAddr;
    type Connection = TcpCn;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn connect(&mut self, a: Self::Addr) -> Self::Future {
        Box::pin(async move {
            let sk = TcpStream::connect(a).await?;
            Ok(TcpCn::new(sk))
        })
    }
}

impl ChunnelConnector for TcpChunnel<true> {
    type Addr = SocketAddr;
    type Connection = IgnoreAddr<SocketAddr, TcpCn>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn connect(&mut self, a: Self::Addr) -> Self::Future {
        Box::pin(async move {
            let sk = TcpStream::connect(a).await?;
            Ok(IgnoreAddr(a, TcpCn::new(sk)))
        })
    }
}

#[derive(Debug, Clone)]
pub struct IgnoreAddr<A, C>(pub A, pub C);

impl<A, C, D> ChunnelConnection for IgnoreAddr<A, C>
where
    C: ChunnelConnection<Data = D> + Send + Sync + 'static,
    A: Clone + PartialEq + std::fmt::Debug + Send + Sync + 'static,
    D: Send,
{
    type Data = (A, D);

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        self.1.send(burst.into_iter().map(|(_, d)| d))
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>> + Send + 'cn>>
    where
        'buf: 'cn,
    {
        Box::pin(async move {
            let mut with_addr_slots: Vec<_> = (0..msgs_buf.len()).map(|_| None).collect();
            let ms = self.1.recv(&mut with_addr_slots[..]).await?;
            let mut ret_len = 0;
            for (msg, slot) in ms
                .iter_mut()
                .map_while(Option::take)
                .zip(msgs_buf.iter_mut())
            {
                *slot = Some((self.0.clone(), msg));
                ret_len += 1;
            }

            Ok(&mut msgs_buf[..ret_len])
        })
    }
}

pub struct TcpCn {
    inner: TcpStream,
}

impl TcpCn {
    pub fn new(inner: TcpStream) -> Self {
        TcpCn { inner }
    }
}

impl ChunnelConnection for TcpCn {
    type Data = Vec<u8>;

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        Box::pin(async move {
            let mut batches = burst
                .into_iter()
                .map(|msg| (msg.len() as u32, msg))
                .array_chunks::<8>();

            use std::io::IoSlice;
            // we need the while let ... because a for loop takes ownership of `batches`, but we
            // need to call `::into_remainder` afterward.
            #[allow(clippy::while_let_on_iterator)]
            while let Some(
                [(h0, m0), (h1, m1), (h2, m2), (h3, m3), (h4, m4), (h5, m5), (h6, m6), (h7, m7)],
            ) = batches.next()
            {
                ensure!(
                    h0 != 0
                        && h1 != 0
                        && h2 != 0
                        && h3 != 0
                        && h4 != 0
                        && h5 != 0
                        && h6 != 0
                        && h7 != 0,
                    "tried to send 0-length message"
                );
                let h0_buf = h0.to_be_bytes();
                let h1_buf = h1.to_be_bytes();
                let h2_buf = h2.to_be_bytes();
                let h3_buf = h3.to_be_bytes();
                let h4_buf = h4.to_be_bytes();
                let h5_buf = h5.to_be_bytes();
                let h6_buf = h6.to_be_bytes();
                let h7_buf = h7.to_be_bytes();
                let batch = [
                    IoSlice::new(&h0_buf[..]),
                    IoSlice::new(&m0[..]),
                    IoSlice::new(&h1_buf[..]),
                    IoSlice::new(&m1[..]),
                    IoSlice::new(&h2_buf[..]),
                    IoSlice::new(&m2[..]),
                    IoSlice::new(&h3_buf[..]),
                    IoSlice::new(&m3[..]),
                    IoSlice::new(&h4_buf[..]),
                    IoSlice::new(&m4[..]),
                    IoSlice::new(&h5_buf[..]),
                    IoSlice::new(&m5[..]),
                    IoSlice::new(&h6_buf[..]),
                    IoSlice::new(&m6[..]),
                    IoSlice::new(&h7_buf[..]),
                    IoSlice::new(&m7[..]),
                ];

                loop {
                    self.inner.writable().await?;
                    match self.inner.try_write_vectored(&batch) {
                        Ok(_) => {
                            tracing::debug!(lengths = ?(h0,h1,h2,h3,h4,h5,h6,h7), "wrote full burst");
                            break;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(e) => {
                            bail!(eyre!(e).wrap_err("try_write_vectored error"));
                        }
                    }
                }
            }

            if let Some(rem) = batches.into_remainder() {
                // rem is an iterator with at least 0 and at most 7 elements.
                let rem_buf = rem.as_slice();
                if rem_buf.is_empty() {
                    // the Some(rem) was a false positive (seems weird)
                    return Ok(());
                }

                // rem_buf is now a slice with at least 1 and at most 7 elements.
                const NULL: [u8; 0] = [];
                let mut final_batch_nums = [
                    [0u8; 4], [0u8; 4], [0u8; 4], [0u8; 4], [0u8; 4], [0u8; 4], [0u8; 4],
                ];
                let mut final_batch = [
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                    IoSlice::new(&NULL[..]),
                ];

                // `final_batch_nums` is a place to store our message length header buffers. It's
                // not needed in the previous loop since that one contains an exact number of
                // messages, so it can use variables. Since that's not the case here - we could
                // have between 1 and 7 elements - we need an array instead.
                //
                // We need two loops because we are assigning to `final_batch_nums[i]` and also
                // borrowing it to make the IoSlice. We could move the contents of the first loop
                // into the second like this:
                // ```rust
                // let x: *mut [u8; 4] = (&final_batch_nums[i]) as *const _ as *mut _;
                // unsafe { *x = data[i].0.to_be_bytes(); }
                // ```
                // but after checking the resulting assembly the compiler mostly does this for us
                // anyway, so we will keep it like this.
                for i in 0..rem_buf.len() {
                    ensure!(rem_buf[i].0 != 0, "tried to send 0-length message");
                    final_batch_nums[i] = rem_buf[i].0.to_be_bytes();
                }
                for i in 0..rem_buf.len() {
                    final_batch[i * 2] = IoSlice::new(&final_batch_nums[i][..]);
                    final_batch[(i * 2) + 1] = IoSlice::new(&(rem_buf[i].1)[..]);
                }

                loop {
                    self.inner.writable().await?;
                    match self
                        .inner
                        .try_write_vectored(&final_batch[..rem_buf.len() * 2])
                    {
                        Ok(_) => {
                            tracing::debug!(lengths = ?final_batch_nums[..rem_buf.len()], "wrote remainder burst");
                            break;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(e) => {
                            bail!(eyre!(e).wrap_err(eyre!(
                                "try_write_vectored remainder error: {:?}",
                                rem_buf.len() * 2
                            )));
                        }
                    }
                }
            }

            Ok(())
        })
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>> + Send + 'cn>>
    where
        'buf: 'cn,
    {
        Box::pin(async move {
            let mut partial_header_len = 0;
            let mut curr_expected_len: Option<(usize, &mut [u8])> = None;
            let mut tot_msgs = 0;
            let msgs_capacity = msgs_buf.len();
            let mut len_buf = [0; 4];
            'readable: loop {
                self.inner.readable().await?;
                // TODO would be more efficient to do bigger reads into buf, and do message
                // assembly from a buffer here.
                'msg: loop {
                    if let Some((mut so_far, dst_buf)) = curr_expected_len.take() {
                        ensure!(
                            so_far < dst_buf.len(),
                            "invalid state: {:?} !< {:?}",
                            so_far,
                            dst_buf.len()
                        );
                        match self.inner.try_read(&mut dst_buf[so_far..]) {
                            Ok(0) => {
                                unreachable!(
                                    "curr state: so_far {:?}, tot_expect {:?}",
                                    so_far,
                                    dst_buf.len()
                                );
                            }
                            Ok(n) => {
                                so_far += n;
                                match so_far.cmp(&dst_buf.len()) {
                                    Ordering::Equal => {
                                        tot_msgs += 1;
                                        tracing::debug!(?tot_msgs, tot_expect=?dst_buf.len(), "read message");
                                        if tot_msgs == msgs_capacity {
                                            return Ok(&mut msgs_buf[..]);
                                        }

                                        continue 'msg;
                                    }
                                    Ordering::Less => {
                                        curr_expected_len = Some((so_far, dst_buf));
                                        continue 'readable;
                                    }
                                    Ordering::Greater => unreachable!(),
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // put this back and try again. we cannot return here, having
                                // received a header but not its message.
                                //
                                // if we end up in a situation where we receive a full message and
                                // then the header of a second message, the first message will be
                                // delayed while we wait to get the body of the second message.
                                curr_expected_len = Some((so_far, dst_buf));
                                continue 'readable;
                            }
                            Err(e) => {
                                bail!(eyre!(e).wrap_err(eyre!(
                                    "Error reading message body of length {:?}",
                                    dst_buf.len()
                                )));
                            }
                        }
                    } else {
                        ensure!(
                            partial_header_len < len_buf.len(),
                            "partial_header_len is wrong"
                        );
                        match self.inner.try_read(&mut len_buf[partial_header_len..]) {
                            Ok(0) => {
                                unreachable!()
                            }
                            Ok(n) => {
                                partial_header_len += n;
                                match partial_header_len.cmp(&len_buf.len()) {
                                    Ordering::Less => continue 'readable,
                                    Ordering::Greater => unreachable!(),
                                    Ordering::Equal => (),
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock && tot_msgs > 0 =>
                            {
                                return Ok(&mut msgs_buf[..tot_msgs]);
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                continue 'readable;
                            }
                            Err(e) => {
                                bail!(eyre!(e).wrap_err(eyre!("Error reading message header")));
                            }
                        };

                        let tot_expect = u32::from_be_bytes(len_buf) as usize;
                        ensure!(
                            tot_expect > 0 && tot_expect <= 8192,
                            "invalid message length {:?}",
                            tot_expect
                        );
                        let dst_buf = msgs_buf[tot_msgs]
                            .get_or_insert_with(|| Vec::with_capacity(tot_expect));
                        if dst_buf.capacity() < tot_expect {
                            dst_buf.reserve(tot_expect - dst_buf.capacity());
                        }

                        // SAFETY: we ensured that there is at least tot_expect amount of capacity
                        // above. also, we promise not to read dst_buf until writing into it, so we
                        // won't read any uninitialized memory.
                        unsafe { dst_buf.set_len(tot_expect) };

                        curr_expected_len = Some((0, &mut dst_buf[..]));
                        //if curr_expected_len.as_ref().undst_bufp().1 == 0 {
                        //    tracing::warn!(?len_buf, "invalid message length");
                        //    curr_expected_len = None;
                        //}

                        partial_header_len = 0;
                        len_buf = [0, 0, 0, 0];
                        continue 'msg;
                    }
                }
            }
        })
    }
}

pub trait Connected {
    fn local_addr(&self) -> SocketAddr;
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

impl Connected for TcpCn {
    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr().unwrap()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr().ok()
    }
}

impl Connected for bertha::udp::UdpSk<SocketAddr> {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr().unwrap()
    }
}

impl Connected for bertha::udp::UdpConn {
    fn local_addr(&self) -> SocketAddr {
        self.inner().local_addr().unwrap()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.peer())
    }
}

impl<C: Connected> Connected for bertha::util::ProjectLeft<SocketAddr, C> {
    fn local_addr(&self) -> SocketAddr {
        self.conn().local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(*self.addr())
    }
}

impl<C: Connected, D> Connected for bertha::negotiate::InjectWithChannel<C, D> {
    fn local_addr(&self) -> SocketAddr {
        self.conn().local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.conn().peer_addr()
    }
}

pub struct Connect<C>(SocketAddr, C);

impl<C> Connect<C> {
    pub fn new(addr: SocketAddr, inner: C) -> Self {
        Self(addr, inner)
    }
}

impl<C, D> ChunnelConnection for Connect<C>
where
    C: ChunnelConnection<Data = (SocketAddr, D)> + Send + Sync + 'static,
    D: Send + 'static,
{
    type Data = (SocketAddr, D);

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        Box::pin(
            self.1
                .send(burst.into_iter().map(|(_, data)| (self.0, data))),
        ) as _
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>> + Send + 'cn>>
    where
        'buf: 'cn,
    {
        Box::pin(async move {
            let msgs = self.1.recv(&mut msgs_buf[..]).await?;
            for (a, _) in msgs.iter_mut().map_while(Option::as_mut) {
                *a = self.0;
            }

            Ok(&mut msgs[..])
        })
    }
}

impl<C> Connected for Connect<C>
where
    C: Connected,
{
    fn local_addr(&self) -> SocketAddr {
        self.1.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.0)
    }
}

#[cfg(test)]
mod t {
    use super::TcpChunnel;
    use bertha::{ChunnelConnection, ChunnelConnector, ChunnelListener};
    use color_eyre::eyre::{bail, ensure, Report, WrapErr};
    use futures_util::TryStreamExt;
    use std::sync::Arc;
    use std::sync::Once;
    use tokio::sync::Barrier;
    use tracing::{debug, info};
    use tracing_error::ErrorLayer;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    pub static COLOR_EYRE: Once = Once::new();

    #[test]
    fn tcp_chunnel() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();

        async fn server(start: Arc<Barrier>) -> Result<(), Report> {
            let mut ch: TcpChunnel = TcpChunnel;
            let st = ch.listen("127.0.0.1:58281".parse().unwrap()).await?;
            start.wait().await;
            st.try_for_each_concurrent(None, |cn| async move {
                info!("starting connection");
                let mut msgs: Vec<_> = (0..8).map(|_| Some(Vec::with_capacity(2048))).collect();
                loop {
                    let ms = cn.recv(&mut msgs[..]).await?;
                    debug!(?ms, "received from client");
                    cn.send(ms.iter_mut().map_while(Option::take)).await?;
                }
            })
            .await?;
            Ok(())
        }

        //client
        rt.block_on(async move {
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let srv_start = start.clone();
            let jh = tokio::spawn(async move {
                if let Err(err) = server(srv_start).await {
                    tracing::error!(?err, "server errored");
                    return Err(err);
                }

                unreachable!()
            });

            let mut ch: TcpChunnel = TcpChunnel;
            start.wait().await;
            let cn = ch
                .connect("127.0.0.1:58281".parse().unwrap())
                .await
                .wrap_err("could not connect")?;

            let mut msgs: Vec<_> = (0..8).map(|_| Some(Vec::with_capacity(8))).collect();
            for i in 0..10 {
                debug!(?i, "send");
                cn.send((0..4).map(|i| u64::to_le_bytes(i).to_vec()))
                    .await?;

                let ms = cn.recv(&mut msgs[..]).await?;
                debug!(?i, ?ms, "got echo");
                for (i, m) in ms.iter_mut().map_while(Option::take).enumerate() {
                    ensure!(
                        i == u64::from_le_bytes(m[0..8].try_into().unwrap()) as usize,
                        "wrong message"
                    );
                }
            }

            if jh.is_finished() {
                return jh.await.unwrap();
            }

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn big_write() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();

        const TARGET_BYTES: usize = 10000;
        const PKT_SIZE: usize = 282;

        #[tracing::instrument(skip(start), err)]
        async fn server(start: Arc<Barrier>) -> Result<(), Report> {
            info!("starting server");
            let mut ch: TcpChunnel = TcpChunnel;
            let st = ch.listen("127.0.0.1:28281".parse().unwrap()).await?;
            start.wait().await;
            st.try_for_each_concurrent(None, |cn| async move {
                info!("starting connection");
                let mut msgs: Vec<_> = (0..8).map(|_| Some(Vec::with_capacity(2048))).collect();
                let mut tot_recv = 0;
                loop {
                    let ms = cn.recv(&mut msgs[..]).await?;
                    for msg in ms.iter().map_while(Option::as_ref) {
                        tot_recv += msg.len();
                    }

                    debug!(?tot_recv, "received from client");

                    if tot_recv >= TARGET_BYTES {
                        cn.send(std::iter::once(vec![1u8; 1])).await?;
                        info!(?tot_recv, "wrote ack to client");
                    }
                }
            })
            .await?;
            Ok(())
        }

        //client
        rt.block_on(async move {
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let srv_start = start.clone();
            let jh = tokio::spawn(async move {
                if let Err(err) = server(srv_start).await {
                    tracing::error!(?err, "server errored");
                    return Err(err);
                }

                unreachable!()
            });

            let mut ch: TcpChunnel = TcpChunnel;
            start.wait().await;
            let cn = ch
                .connect("127.0.0.1:28281".parse().unwrap())
                .await
                .wrap_err("could not connect")?;

            let sp = tracing::info_span!("client");
            let _spg = sp.entered();

            let mut slot = [None];
            let mut remaining = TARGET_BYTES;
            let mut recv_fut = cn.recv(&mut slot);
            info!("starting");
            let rem_recv = loop {
                let recv_fut_rem = {
                    let res = futures_util::future::select(
                        cn.send((0..16).map_while(|_| {
                            if remaining > 0 {
                                let this_send_size = std::cmp::min(PKT_SIZE, remaining);
                                remaining -= this_send_size;
                                Some(vec![0u8; this_send_size as usize])
                            } else {
                                None
                            }
                        })),
                        recv_fut,
                    )
                    .await;
                    match res {
                        futures_util::future::Either::Left((send_res, recv_fut_rem)) => {
                            send_res?;
                            recv_fut_rem
                        }
                        futures_util::future::Either::Right((recv_res, _)) => {
                            info!("received from server");
                            if let [Some(ref v)] = recv_res?[..] {
                                if v[0] == 1 {
                                    break None;
                                } else {
                                    panic!("wrong recv")
                                }
                            } else {
                                bail!("recv failed");
                            }
                        }
                    }
                };

                tokio::task::yield_now().await;
                if remaining == 0 {
                    break Some(recv_fut_rem);
                } else {
                    recv_fut = recv_fut_rem;
                }
            };

            if let Some(recv_fut) = rem_recv {
                let recv_res = recv_fut.await;
                info!("received from server");
                if let [Some(ref v)] = recv_res?[..] {
                    if v[0] == 1 {
                        ()
                    } else {
                        bail!("wrong recv")
                    }
                } else {
                    bail!("recv failed");
                }
            }

            if jh.is_finished() {
                return jh.await.unwrap();
            }

            Ok(())
        })
        .unwrap();
    }
}
