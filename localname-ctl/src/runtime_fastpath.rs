use super::GetSockAddr;
use crate::client;
use bertha::{
    either::Either, Chunnel, ChunnelConnection, ChunnelConnector, ChunnelListener, Negotiate,
};
use color_eyre::eyre::{Report, WrapErr};
use futures_util::future::Ready;
use futures_util::stream::{Once, StreamExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tcp::Connected;
use tokio::sync::Mutex;
use tracing::{debug, instrument, trace};

/// LocalNameChunnel fast-paths data bound to local destinations.
///
/// `local_chunnel` is the fast-path chunnel.
#[derive(Clone)]
pub struct LocalNameChunnel<Lch, Lr, Side = ()> {
    cl: Option<Arc<Mutex<client::LocalNameClient>>>,
    side: Side,
    local_raw: Lr,
    local_chunnel: Lch,
}

impl<Lch, Lr, S> Debug for LocalNameChunnel<Lch, Lr, S>
where
    Lch: Debug,
    Lr: Debug,
    S: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalNameChunnel")
            .field("side", &self.side)
            .field("local_raw", &self.local_raw)
            .field("local_chunnel", &self.local_chunnel)
            .field("has_client", &self.cl.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SrvState {
    listen_addr: SocketAddr,
    local_addr: Option<PathBuf>,
}

impl<Lch, Lr, S> Negotiate for LocalNameChunnel<Lch, Lr, S> {
    type Capability = ();

    fn guid() -> u64 {
        0xb3fa08967e518987
    }
}

impl<Lch, Lr> LocalNameChunnel<Lch, Lr, ()> {
    async fn new<S>(
        root: impl AsRef<Path>,
        side: S,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<LocalNameChunnel<Lch, Lr, S>, Report> {
        let cl = client::LocalNameClient::new(root.as_ref()).await;
        if let Err(ref e) = &cl {
            debug!(err = %format!("{:#}", e), "LocalNameClient did not connect");
        }

        Ok(LocalNameChunnel {
            cl: cl.map(Mutex::new).map(Arc::new).ok(),
            side,
            local_raw,
            local_chunnel,
        })
    }

    pub async fn server(
        root: impl AsRef<Path>,
        listen_addr: SocketAddr,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<LocalNameChunnel<Lch, Lr, SrvState>, Report> {
        let mut s = Self::new(root, listen_addr, local_raw, local_chunnel).await?;
        if let Some(c) = &mut s.cl {
            let cm = Arc::get_mut(c)
                .expect("get_mut on just-created Arc")
                .get_mut();
            match cm.register(s.side).await {
                Ok(laddr) => {
                    debug!(?laddr, "LocalNameClient registered");
                    return Ok(LocalNameChunnel {
                        cl: s.cl,
                        side: SrvState {
                            listen_addr: s.side,
                            local_addr: Some(laddr),
                        },
                        local_raw: s.local_raw,
                        local_chunnel: s.local_chunnel,
                    });
                }
                Err(e) => {
                    debug!(err = %format!("{:#}", e), "LocalNameClient register failed");
                }
            }
        }

        Ok(LocalNameChunnel {
            cl: s.cl,
            side: SrvState {
                listen_addr: s.side,
                local_addr: None,
            },
            local_raw: s.local_raw,
            local_chunnel: s.local_chunnel,
        })
    }

    pub async fn client(
        root: impl AsRef<Path>,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<LocalNameChunnel<Lch, Lr, ()>, Report> {
        Self::new(root, (), local_raw, local_chunnel).await
    }
}

pub struct AddrWrap<C>(C);
impl<C, D> ChunnelConnection for AddrWrap<C>
where
    C: ChunnelConnection<Data = (SocketAddr, D)> + Send + Sync,
    D: Send,
{
    type Data = (Either<SocketAddr, PathBuf>, D);
    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        self.0.send(burst.into_iter().filter_map(|(a, d)| match a {
            Either::Left(sk) => Some((sk, d)),
            _ => None,
        }))
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>> + Send + 'cn>>
    where
        'buf: 'cn,
    {
        Box::pin(async move {
            let mut slots: Vec<_> = (0..msgs_buf.len()).map(|_| None).collect();
            let ms = self.0.recv(&mut slots).await?;
            let mut slot_idx = 0;
            for (r, slot) in ms
                .iter_mut()
                .map_while(Option::take)
                .map(|(gaddr, data)| (Either::Left(gaddr), data))
                .zip(msgs_buf.iter_mut())
            {
                *slot = Some(r);
                slot_idx += 1;
            }

            Ok(&mut msgs_buf[..slot_idx])
        })
    }
}

impl<C> Connected for AddrWrap<C>
where
    C: Connected,
{
    fn local_addr(&self) -> SocketAddr {
        self.0.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.0.peer_addr()
    }
}

impl<Gc, Lr, LrCn, LrErr, Lrd, Lch, Lcn, LchErr, D> Chunnel<Gc> for LocalNameChunnel<Lch, Lr, ()>
where
    Gc: ChunnelConnection<Data = (SocketAddr, D)> + Send + Sync + 'static,
    D: Send + Sync + 'static,
    // Raw local connections. Lrd, local raw data, is probably Vec<u8> (e.g. for Lctr = UDS), but
    // don't assume this.
    Lr: ChunnelConnector<Connection = LrCn, Addr = (), Error = LrErr> + Clone + Send + 'static,
    LrCn: ChunnelConnection<Data = (PathBuf, Lrd)> + Send,
    LrErr: Into<Report> + Send + Sync + 'static,
    // Local connections
    Lch: Chunnel<LrCn, Connection = Lcn, Error = LchErr> + Clone + Send + 'static,
    Lcn: ChunnelConnection<Data = (PathBuf, D)> + Send + Sync + 'static,
    LchErr: Into<Report> + Send + Sync + 'static,
{
    type Connection = Either<LocalNameCn<Gc, Lcn>, AddrWrap<Gc>>;
    type Error = Report;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect_wrap(&mut self, inner: Gc) -> Self::Future {
        let mut local_raw = self.local_raw.clone();
        let mut local_chunnel = self.local_chunnel.clone();
        let cl = self.cl.clone();
        Box::pin(async move {
            let local_raw_cn = if cl.is_some() {
                local_raw.connect(()).await.map_err(Into::into)?
            } else {
                return Ok(Either::Right(AddrWrap(inner)));
            };

            let local_cn = local_chunnel
                .connect_wrap(local_raw_cn)
                .await
                .map_err(Into::into)?;
            Ok(Either::Left(LocalNameCn::new(cl, inner, local_cn)))
        })
    }
}

impl<Gc, Lr, LrCn, LrErr, Lrd, Lch, Lcn, LchErr, D> Chunnel<Gc>
    for LocalNameChunnel<Lch, Lr, SrvState>
where
    Gc: ChunnelConnection<Data = (SocketAddr, D)> + Send + Sync + 'static,
    D: Send + Sync + 'static,
    // Raw local connections. Lrd, local raw data, is probably Vec<u8> (e.g. for Lctr = UDS), but
    // don't assume this.
    Lr: ChunnelListener<
            Connection = LrCn,
            Addr = PathBuf,
            Error = LrErr,
            Stream = Once<Ready<Result<LrCn, Report>>>,
        > + Clone
        + Send
        + 'static,
    LrCn: ChunnelConnection<Data = (PathBuf, Lrd)> + Send,
    LrErr: Into<Report> + Send + Sync + 'static,
    // Local connections
    Lch: Chunnel<LrCn, Connection = Lcn, Error = LchErr> + Clone + Send + 'static,
    Lcn: ChunnelConnection<Data = (PathBuf, D)> + Send + Sync + 'static,
    LchErr: Into<Report> + Send + Sync + 'static,
{
    type Connection = Either<LocalNameCn<Gc, Lcn>, AddrWrap<Gc>>;
    type Error = Report;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect_wrap(&mut self, inner: Gc) -> Self::Future {
        let mut local_raw = self.local_raw.clone();
        let mut local_chunnel = self.local_chunnel.clone();
        let cl = self.cl.clone();
        let laddr_opt = self.side.local_addr.clone();
        let listen_addr = self.side.listen_addr;
        Box::pin(async move {
            let local_raw_cn = if let Some(laddr) = laddr_opt {
                // a Once stream is ok because we only need a single connection, not a stream: one
                // to the peer of inner.
                local_raw
                    .listen(laddr)
                    .await
                    .map_err(Into::into)?
                    .next()
                    .await
                    .unwrap()?
            } else {
                debug!(?listen_addr, "returning global-only connection");
                return Ok(Either::Right(AddrWrap(inner)));
            };

            let local_cn = local_chunnel
                .connect_wrap(local_raw_cn)
                .await
                .map_err(Into::into)?;
            debug!(?listen_addr, "returning local/global connection");
            Ok(Either::Left(LocalNameCn::new(cl, inner, local_cn)))
        })
    }
}

#[derive(Clone)]
enum LocalAddrCacheEntry<A> {
    Hit {
        laddr: A,
        expiry: std::time::Instant,
    },
    AntiHit {
        expiry: Option<std::time::Instant>,
    },
}

pub struct LocalNameCn<Gc, Lc> {
    cl: Option<Arc<Mutex<client::LocalNameClient>>>,
    global_cn: Gc,
    local_cn: Lc,
    addr_cache: Arc<StdMutex<HashMap<SocketAddr, LocalAddrCacheEntry<PathBuf>>>>,
    rev_addr_map: Arc<StdMutex<HashMap<PathBuf, SocketAddr>>>,
}

impl<Gc, Lc> LocalNameCn<Gc, Lc> {
    fn new(cl: Option<Arc<Mutex<client::LocalNameClient>>>, global_cn: Gc, local_cn: Lc) -> Self {
        Self {
            cl,
            global_cn,
            local_cn,
            addr_cache: Default::default(),
            rev_addr_map: Default::default(),
        }
    }
}

impl<Gc, Lc> tcp::Connected for LocalNameCn<Gc, Lc>
where
    Gc: tcp::Connected,
{
    fn local_addr(&self) -> SocketAddr {
        self.global_cn.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.global_cn.peer_addr()
    }
}

impl<Gc, Lc, D> ChunnelConnection for LocalNameCn<Gc, Lc>
where
    Gc: ChunnelConnection<Data = (SocketAddr, D)> + Send + Sync + 'static,
    Lc: ChunnelConnection<Data = (PathBuf, D)> + Send + Sync + 'static,
    D: Send + Sync + 'static,
{
    type Data = (Either<SocketAddr, PathBuf>, D);

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        Box::pin(async move {
            let (global, local_addr): (
                Vec<(Either<SocketAddr, PathBuf>, D)>,
                Vec<(Either<SocketAddr, PathBuf>, D)>,
            ) = burst
                .into_iter()
                .partition(|(either_addr, _)| either_addr.is_left());

            let mut misses = Vec::new();
            let (global_rem, local_lookup): (Vec<(Either<SocketAddr, PathBuf>, D)>, Vec<_>) = {
                let ac_g = self.addr_cache.lock().unwrap();
                global
                    .into_iter()
                    .map(|(skaddr, d)| {
                        let skaddr = match skaddr {
                            Either::Left(a) => a,
                            _ => unreachable!(),
                        };
                        // 1. check local cache
                        let entry = ac_g.get(&skaddr).map(Clone::clone);
                        // 2. if match, send on correct connection.
                        match entry {
                            // Miss cases. We want to avoid blocking, so just send on the global for
                            // now.
                            None => {
                                misses.push(skaddr);
                                (Either::Left(skaddr), d)
                            }
                            Some(LocalAddrCacheEntry::Hit { expiry, .. })
                            | Some(LocalAddrCacheEntry::AntiHit {
                                expiry: Some(expiry),
                                ..
                            }) if expiry < std::time::Instant::now() => {
                                misses.push(skaddr);
                                (Either::Left(skaddr), d)
                            }
                            // Hit cases.
                            Some(LocalAddrCacheEntry::Hit { laddr, .. }) => {
                                trace!(?laddr, kind = "local", "determined send hit");
                                (Either::Right(laddr.clone()), d)
                            }
                            Some(LocalAddrCacheEntry::AntiHit { .. }) => {
                                trace!(?skaddr, kind = "global", "determined send hit");
                                (Either::Left(skaddr), d)
                            }
                        }
                    })
                    .partition(|(e, _)| e.is_left())
            };

            if !local_addr.is_empty() || !local_lookup.is_empty() {
                self.local_cn
                    .send(
                        local_addr
                            .into_iter()
                            .chain(local_lookup.into_iter())
                            .map(|x| match x {
                                (Either::Right(l), d) => (l, d),
                                _ => unreachable!(),
                            }),
                    )
                    .await?;
            }

            if !global_rem.is_empty() {
                self.global_cn
                    .send(global_rem.into_iter().map(|x| match x {
                        (Either::Left(a), d) => (a, d),
                        _ => unreachable!(),
                    }))
                    .await?;
            }

            // 3. Spawn off lookup.
            if let Some(cl) = &self.cl {
                misses.dedup();
                if !misses.is_empty() {
                    tokio::spawn(query_ctl(
                        misses,
                        Arc::clone(&cl),
                        Arc::clone(&self.addr_cache),
                        Arc::clone(&self.rev_addr_map),
                    ));
                }
            } else {
                let mut c = self.addr_cache.lock().unwrap();
                for a in misses {
                    c.insert(
                        a.as_sk_addr(),
                        LocalAddrCacheEntry::AntiHit { expiry: None },
                    );
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
        use futures_util::future::{self, Either as FEither};
        let mut left_slots: Vec<_> = (0..msgs_buf.len()).map(|_| None).collect();
        let mut right_slots: Vec<_> = (0..msgs_buf.len()).map(|_| None).collect();
        Box::pin(async move {
            let mut slot_idx = 0;
            match future::select(
                self.global_cn.recv(&mut left_slots[..]),
                self.local_cn.recv(&mut right_slots[..]),
            )
            .await
            {
                FEither::Left((Ok(ms), _)) => {
                    for (r, slot) in ms
                        .iter_mut()
                        .map_while(Option::take)
                        .map(|(gaddr, data)| (Either::Left(gaddr), data))
                        .zip(msgs_buf.iter_mut())
                    {
                        *slot = Some(r);
                        slot_idx += 1;
                    }
                }
                FEither::Right((Ok(ms), _)) => {
                    let c = self.rev_addr_map.lock().unwrap();
                    for (r, slot) in ms
                        .iter_mut()
                        .map_while(Option::take)
                        .map(|(laddr, data)| match c.get(&laddr) {
                            Some(addr) => (Either::Left(*addr), data),
                            None => (Either::Right(laddr), data),
                        })
                        .zip(msgs_buf.iter_mut())
                    {
                        *slot = Some(r);
                        slot_idx += 1;
                    }
                }
                FEither::Left((Err(e), _)) => {
                    return Err(e).wrap_err("localname-ctl global_cn recv erred")
                }
                FEither::Right((Err(e), _)) => {
                    return Err(e).wrap_err("localname-ctl local_cn recv erred")
                }
            }

            Ok(&mut msgs_buf[..slot_idx])
        })
    }
}

#[instrument(level = "trace", skip(cl, addr_cache, rev_addr_map))]
async fn query_ctl(
    addrs: Vec<SocketAddr>,
    cl: Arc<Mutex<client::LocalNameClient>>,
    addr_cache: Arc<StdMutex<HashMap<SocketAddr, LocalAddrCacheEntry<PathBuf>>>>,
    rev_addr_map: Arc<StdMutex<HashMap<PathBuf, SocketAddr>>>,
) {
    let a = addrs.clone();
    let mut cl_g = cl.lock().await;
    let res = cl_g.query(addrs).await;
    std::mem::drop(cl_g);
    debug!(?res, "queried localname-ctl");

    fn insert_antihit(
        skaddr: SocketAddr,
        addr_cache: &mut HashMap<SocketAddr, LocalAddrCacheEntry<PathBuf>>,
    ) {
        addr_cache.insert(
            skaddr,
            LocalAddrCacheEntry::AntiHit {
                expiry: Some(std::time::Instant::now() + std::time::Duration::from_millis(100)),
            },
        );
    }

    let mut c = addr_cache.lock().unwrap();
    match res {
        Ok(entries) => {
            let mut r = rev_addr_map.lock().unwrap();
            for (skaddr, laddr_opt) in entries {
                if let Some(laddr) = laddr_opt {
                    let e = c.entry(skaddr).or_insert_with(|| LocalAddrCacheEntry::Hit {
                        laddr: laddr.clone(),
                        expiry: std::time::Instant::now() + Duration::from_millis(100),
                    });
                    match e {
                        LocalAddrCacheEntry::Hit {
                            laddr: ref existing_laddr,
                            expiry: ref mut existing_expiry,
                        } if laddr == *existing_laddr
                            && existing_expiry.elapsed() > Duration::from_millis(100) =>
                        {
                            *existing_expiry = Instant::now()
                                + std::cmp::max(
                                    existing_expiry.elapsed() * 2,
                                    Duration::from_secs(10),
                                );
                        }
                        _ => {
                            *e = LocalAddrCacheEntry::Hit {
                                laddr: laddr.clone(),
                                expiry: std::time::Instant::now()
                                    + std::time::Duration::from_millis(100),
                            };
                        }
                    }

                    r.insert(laddr, skaddr);
                } else {
                    insert_antihit(skaddr, &mut *c);
                }
            }
        }
        Err(e) => {
            debug!(err = %format!("{:#}", e), ?a, "LocalNameClient query failed");
            for skaddr in a {
                insert_antihit(skaddr, &mut *c);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::LocalNameChunnel;
    use bertha::{
        either::Either, negotiate_client, negotiate_server, udp::UdpSkChunnel, uds::UnixSkChunnel,
        util::Nothing, ChunnelConnection, ChunnelConnector, ChunnelListener,
    };
    use futures_util::stream::TryStreamExt;
    use tracing::info;
    use tracing_error::ErrorLayer;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    #[test]
    fn no_ctl() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        crate::t::COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let addr = "127.0.0.1:19052".parse().unwrap();

        rt.block_on(async move {
            tokio::spawn(async move {
                let lch_s = LocalNameChunnel::server(
                    "./nonexistent",
                    addr,
                    UnixSkChunnel::default(),
                    Nothing::<()>::default(),
                )
                .await
                .unwrap();
                let st = negotiate_server(lch_s, UdpSkChunnel.listen(addr).await.unwrap())
                    .await
                    .unwrap();
                st.try_for_each_concurrent(None, |cn| async move {
                    let mut slots = [None, None, None, None];
                    loop {
                        let ms = cn.recv(&mut slots).await.unwrap();
                        cn.send(ms.iter_mut().map_while(Option::take).inspect(|m| {
                            info!(?m, "got msg");
                        }))
                        .await
                        .unwrap();
                    }
                })
                .await
                .unwrap();
            });

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let lch = LocalNameChunnel::client(
                "./nonexistent",
                UnixSkChunnel::default(),
                Nothing::<()>::default(),
            )
            .await
            .unwrap();
            let cn = negotiate_client(lch, UdpSkChunnel.connect(addr).await.unwrap(), addr)
                .await
                .unwrap();

            cn.send(std::iter::once((Either::Left(addr), vec![0u8; 10])))
                .await
                .unwrap();
            let mut slot = [None];
            let m = cn.recv(&mut slot).await.unwrap();
            assert!(!m.is_empty());
            assert_eq!(m[0].take().unwrap(), (Either::Left(addr), vec![0u8; 10]));
        });
    }
}
