//! Bertha logic adapted to work inside a shenango runtime
// we will only use the things needed for the kvstore application.

pub use base_traits::Chunnel;
pub use base_traits::ChunnelConnection;
mod base_traits {
    use bertha::{CxList, CxNil};
    use color_eyre::eyre::{Report, WrapErr};

    pub trait Chunnel<I> {
        type Connection: ChunnelConnection;
        type Error: Send + Sync + 'static;

        fn connect_wrap(&mut self, inner: I) -> Result<Self::Connection, Self::Error>;
    }

    impl<C> Chunnel<C> for CxNil
    where
        C: ChunnelConnection,
    {
        type Connection = C;
        type Error = Report;

        fn connect_wrap(&mut self, inner: C) -> Result<Self::Connection, Self::Error> {
            Ok(inner)
        }
    }

    impl<H, T, I> Chunnel<I> for CxList<H, T>
    where
        H: Chunnel<I>,
        T: Chunnel<<H as Chunnel<I>>::Connection>,
        <T as Chunnel<<H as Chunnel<I>>::Connection>>::Error: From<<H as Chunnel<I>>::Error>,
    {
        type Connection = T::Connection;
        type Error = T::Error;

        fn connect_wrap(&mut self, inner: I) -> Result<Self::Connection, Self::Error> {
            let cn = self.head.connect_wrap(inner)?;
            self.tail.connect_wrap(cn)
        }
    }

    pub trait ChunnelConnection {
        type Data;
        /// Send a message
        fn send(&self, data: Self::Data) -> Result<(), Report>;
        /// Retrieve next incoming message.
        fn recv(&self) -> Result<Self::Data, Report>;
    }

    use bertha::either::Either;
    impl<A, B, D> ChunnelConnection for Either<A, B>
    where
        A: ChunnelConnection<Data = D>,
        B: ChunnelConnection<Data = D>,
    {
        type Data = D;

        fn send(&self, data: Self::Data) -> Result<(), Report> {
            match self {
                Either::Left(a) => a.send(data),
                Either::Right(b) => b.send(data),
            }
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            match self {
                Either::Left(a) => a.recv(),
                Either::Right(b) => b.recv(),
            }
        }
    }

    use std::net::SocketAddrV4;
    pub struct Project<C>(pub SocketAddrV4, pub C);
    impl<C, D> ChunnelConnection for Project<C>
    where
        C: ChunnelConnection<Data = (SocketAddrV4, D)>,
    {
        type Data = D;

        fn send(&self, data: Self::Data) -> Result<(), Report> {
            self.1.send((self.0, data)).wrap_err("Project send")
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            Ok(self.1.recv()?.1)
        }
    }
}

pub mod udp {
    use crate::base_traits::ChunnelConnection;
    use color_eyre::eyre::{Report, WrapErr};
    use shenango::sync::Mutex;
    pub use shenango::udp::udp_accept;
    pub use shenango::udp::UdpConnection;
    use std::net::SocketAddrV4;
    use std::sync::{atomic::AtomicBool, Arc};

    #[derive(Clone)]
    pub struct UdpChunnelConnection(pub Arc<UdpConnection>);

    impl UdpChunnelConnection {
        pub fn new(cn: UdpConnection) -> Self {
            Self(Arc::new(cn))
        }
    }

    impl ChunnelConnection for UdpChunnelConnection {
        type Data = (SocketAddrV4, Vec<u8>);
        /// Send a message
        fn send(&self, (addr, buf): Self::Data) -> Result<(), Report> {
            self.0.write_to(&buf, addr).wrap_err("udp send")?;
            Ok(())
        }
        /// Retrieve next incoming message.
        fn recv(&self) -> Result<Self::Data, Report> {
            let from = self.0.remote_addr();
            let mut buf = [0u8; 2048];
            let len = self.0.recv(&mut buf)?;
            Ok((from, buf[..len].to_vec()))
        }
    }

    pub struct InjectOne<C, D>(C, AtomicBool, Mutex<Option<D>>);

    impl<C, D> InjectOne<C, D> {
        pub fn new(inner: C) -> (Self, Mutex<Option<D>>) {
            let mtx: Mutex<Option<D>> = Mutex::new(None);
            (Self(inner, Default::default(), mtx.clone()), mtx)
        }
    }

    impl<C: ChunnelConnection<Data = D>, D> ChunnelConnection for InjectOne<C, D> {
        type Data = D;

        fn send(&self, d: Self::Data) -> Result<(), Report> {
            self.0.send(d)
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            if self.1.load(std::sync::atomic::Ordering::SeqCst) {
                self.0.recv()
            } else {
                self.1.store(true, std::sync::atomic::Ordering::SeqCst);
                let d = self.2.lock().take().unwrap();
                Ok(d)
            }
        }
    }
}

pub use negotiate::{negotiate_client, ClientNegotiator};
pub use negotiate::{negotiate_server, Negotiate};
pub mod negotiate {
    use crate::base_traits::{Chunnel, ChunnelConnection};
    use crate::udp::{self, InjectOne, UdpChunnelConnection};
    use bertha::CapabilitySet;
    use bertha::{
        negotiate::{monomorphize, Apply, ApplyResult, GetOffers, Pick},
        CxList, DataEither, Either,
    };
    use color_eyre::eyre::{bail, eyre, Report, WrapErr};
    use shenango::sync::Mutex;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::net::SocketAddrV4;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tracing::{debug, trace, warn};

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct StackNonce(HashMap<u64, bertha::Offer>, HashMap<u64, Option<Vec<u8>>>);

    impl StackNonce {
        fn set_ext_info(&mut self, h: HashMap<u64, Option<Vec<u8>>>) {
            self.1 = h
        }
    }

    impl Into<bertha::StackNonce> for StackNonce {
        fn into(self) -> bertha::StackNonce {
            bertha::StackNonce::__from_inner(self.0)
        }
    }
    impl From<bertha::StackNonce> for StackNonce {
        fn from(s: bertha::StackNonce) -> Self {
            Self(s.__into_inner(), Default::default())
        }
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum NegotiateMsg {
        /// A list of stacks the client supports. Response from the server is a `ServerReply`.
        ClientOffer(Vec<StackNonce>),
        /// Can mean one of two things.
        /// 1. In response to a `ClientOffer`, a list of *client* stacks (a subset of those passed in
        ///    the `ClientOffer`) the server supports, given the one the server has chosen.
        /// 2. In response to a `ClientNonce`, a list of *server* stacks the server supports. In this
        ///    case the client can monomorphize to a working stack and try zero-rtt with `ClientNonce`
        ///    again, so the worst case is still one-rtt (the one that returned this `ServerReply`)
        ServerReply(Result<Vec<StackNonce>, String>),
        /// A specific stack the server should use on the given address.
        ServerNonce {
            addr: Vec<u8>,
            picked: StackNonce,
        },
        /// A nonce representing the stack the client wants to use.
        /// If it works, server sends a `ServerNonceAck`. Otherwise, a `ServerReply`
        ClientNonce(StackNonce),
        ServerNonceAck,
    }

    impl From<bertha::NegotiateMsg> for NegotiateMsg {
        fn from(f: bertha::NegotiateMsg) -> Self {
            match f {
                bertha::NegotiateMsg::ServerNonceAck => NegotiateMsg::ServerNonceAck,
                bertha::NegotiateMsg::ClientOffer(v) => {
                    NegotiateMsg::ClientOffer(v.into_iter().map(Into::into).collect())
                }
                bertha::NegotiateMsg::ClientNonce(s) => NegotiateMsg::ClientNonce(s.into()),
                bertha::NegotiateMsg::ServerNonce { addr, picked } => NegotiateMsg::ServerNonce {
                    addr,
                    picked: picked.into(),
                },
                bertha::NegotiateMsg::ServerReply(r) => {
                    NegotiateMsg::ServerReply(r.map(|r| r.into_iter().map(Into::into).collect()))
                }
            }
        }
    }

    pub trait Negotiate: bertha::Negotiate {
        fn picked_blocking(&mut self, _nonce: &[u8]) {}
        fn ext_info(&self) -> Option<Vec<u8>> {
            None
        }

        fn ext_info_callback(&mut self, _info: Vec<u8>) {}
    }

    pub trait NegotiatePicked {
        fn call_negotiate_picked(&mut self, nonce: &[u8]);
        fn collect_ext_info(&self) -> HashMap<u64, Option<Vec<u8>>>;
        fn distribute_ext_info(&mut self, info: &mut HashMap<u64, Option<Vec<u8>>>);
    }

    impl Negotiate for bertha::CxNil {}

    impl<N, C> NegotiatePicked for N
    where
        N: Negotiate<Capability = C>,
        C: CapabilitySet,
    {
        fn call_negotiate_picked(&mut self, nonce: &[u8]) {
            self.picked_blocking(nonce)
        }

        fn collect_ext_info(&self) -> HashMap<u64, Option<Vec<u8>>> {
            std::iter::once((C::guid(), self.ext_info())).collect()
        }

        fn distribute_ext_info(&mut self, info: &mut HashMap<u64, Option<Vec<u8>>>) {
            if let Some(Some(i)) = info.remove(&C::guid()) {
                self.ext_info_callback(i);
            }
        }
    }

    impl<H, T> NegotiatePicked for CxList<H, T>
    where
        H: NegotiatePicked,
        T: NegotiatePicked,
    {
        fn call_negotiate_picked(&mut self, nonce: &[u8]) {
            self.head.call_negotiate_picked(nonce);
            self.tail.call_negotiate_picked(nonce);
        }

        fn collect_ext_info(&self) -> HashMap<u64, Option<Vec<u8>>> {
            self.head
                .collect_ext_info()
                .into_iter()
                .chain(self.tail.collect_ext_info().into_iter())
                .collect()
        }

        fn distribute_ext_info(&mut self, info: &mut HashMap<u64, Option<Vec<u8>>>) {
            self.head.distribute_ext_info(info);
            self.tail.distribute_ext_info(info);
        }
    }

    impl<L, R> NegotiatePicked for DataEither<L, R>
    where
        L: NegotiatePicked,
        R: NegotiatePicked,
    {
        fn call_negotiate_picked(&mut self, nonce: &[u8]) {
            match self {
                DataEither::Left(l) => l.call_negotiate_picked(nonce),
                DataEither::Right(r) => r.call_negotiate_picked(nonce),
            }
        }

        fn collect_ext_info(&self) -> HashMap<u64, Option<Vec<u8>>> {
            match self {
                DataEither::Left(l) => l.collect_ext_info(),
                DataEither::Right(r) => r.collect_ext_info(),
            }
        }

        fn distribute_ext_info(&mut self, info: &mut HashMap<u64, Option<Vec<u8>>>) {
            match self {
                DataEither::Left(l) => l.distribute_ext_info(info),
                DataEither::Right(r) => r.distribute_ext_info(info),
            }
        }
    }

    impl<L, R> NegotiatePicked for Either<L, R>
    where
        L: NegotiatePicked,
        R: NegotiatePicked,
    {
        fn call_negotiate_picked(&mut self, nonce: &[u8]) {
            match self {
                Either::Left(l) => l.call_negotiate_picked(nonce),
                Either::Right(r) => r.call_negotiate_picked(nonce),
            }
        }

        fn collect_ext_info(&self) -> HashMap<u64, Option<Vec<u8>>> {
            match self {
                Either::Left(l) => l.collect_ext_info(),
                Either::Right(r) => r.collect_ext_info(),
            }
        }

        fn distribute_ext_info(&mut self, info: &mut HashMap<u64, Option<Vec<u8>>>) {
            match self {
                Either::Left(l) => l.distribute_ext_info(info),
                Either::Right(r) => r.distribute_ext_info(info),
            }
        }
    }

    pub fn negotiate_server<Srv, F>(
        stack: Srv,
        listen_addr: SocketAddrV4,
        per_conn: F,
    ) -> Result<(), Report>
    where
        Srv: Pick + Apply + GetOffers + Clone + Debug + Send + Sync + 'static,
        // main-line branch: Pick on incoming negotiation handshake.
        <Srv as Pick>::Picked:
            NegotiatePicked + Chunnel<UdpChunnelConnection> + Clone + Debug + Send + 'static,
        <<Srv as Pick>::Picked as Chunnel<UdpChunnelConnection>>::Connection: Send + Sync + 'static,
        <<Srv as Pick>::Picked as Chunnel<UdpChunnelConnection>>::Error:
            Into<Report> + Send + Sync + 'static,
        // nonce branch: Apply stack from nonce on indicated connections.
        <Srv as Apply>::Applied: Chunnel<ApplyInput> + Clone + Debug + Send + 'static,
        <<Srv as Apply>::Applied as Chunnel<ApplyInput>>::Connection: Send + Sync + 'static,
        <<Srv as Apply>::Applied as Chunnel<ApplyInput>>::Error:
            Into<Report> + Send + Sync + 'static,
        F: Fn(
                Either<
                    <<Srv as Pick>::Picked as Chunnel<UdpChunnelConnection>>::Connection,
                    <<Srv as Apply>::Applied as Chunnel<ApplyInput>>::Connection,
                >,
            ) + Clone
            + Send
            + Sync
            + 'static,
    {
        let pending_negotiated_connections: Mutex<HashMap<SocketAddrV4, StackNonce>> =
            Default::default();
        udp::udp_accept(listen_addr, move |cn| {
            let stack = stack.clone();
            let pending_negotiated_connections = pending_negotiated_connections.clone();
            match negotiate_server_connection(cn, stack, pending_negotiated_connections) {
                Ok(Some(cn)) => per_conn(cn),
                _ => (),
            }
        })?;
        Ok(())
    }

    type ApplyInput = InjectOne<UdpChunnelConnection, (SocketAddrV4, Vec<u8>)>;

    fn negotiate_server_connection<Srv>(
        cn: udp::UdpConnection,
        stack: Srv,
        pending_negotiated_connections: Mutex<HashMap<SocketAddrV4, StackNonce>>,
    ) -> Result<
        Option<
            Either<
                <<Srv as Pick>::Picked as Chunnel<UdpChunnelConnection>>::Connection,
                <<Srv as Apply>::Applied as Chunnel<ApplyInput>>::Connection,
            >,
        >,
        Report,
    >
    where
        Srv: Pick + Apply + GetOffers + Clone + Debug + Send + Sync + 'static,
        // main-line branch: Pick on incoming negotiation handshake.
        <Srv as Pick>::Picked:
            NegotiatePicked + Chunnel<UdpChunnelConnection> + Clone + Debug + Send + 'static,
        <<Srv as Pick>::Picked as Chunnel<UdpChunnelConnection>>::Connection: Send + Sync + 'static,
        <<Srv as Pick>::Picked as Chunnel<UdpChunnelConnection>>::Error:
            Into<Report> + Send + Sync + 'static,
        // nonce branch: Apply stack from nonce on indicated connections.
        <Srv as Apply>::Applied: Chunnel<ApplyInput> + Clone + Debug + Send + 'static,
        <<Srv as Apply>::Applied as Chunnel<ApplyInput>>::Connection: Send + Sync + 'static,
        <<Srv as Apply>::Applied as Chunnel<ApplyInput>>::Error:
            Into<Report> + Send + Sync + 'static,
    {
        debug!(local = ?cn.local_addr(), remote = ?cn.remote_addr(), "new connection");
        let a = cn.remote_addr();
        let cn = UdpChunnelConnection::new(cn);
        loop {
            trace!("listening for potential negotiation pkt");
            let (_, buf) = cn.recv()?;
            trace!("got potential negotiation pkt");

            // if `a` is in pending_negotiated_connections, this is a post-negotiation message and we
            // should return the applied connection.
            let opt_picked = {
                let guard = pending_negotiated_connections.lock();
                guard.get(&a).map(Clone::clone)
            };

            if let Some(picked) = opt_picked {
                let (cn, recirculate_mtx) = InjectOne::new(cn);
                let ApplyResult {
                    applied: mut stack, ..
                } = stack
                    .apply(picked.into()) // use check_apply or no?
                    .wrap_err("failed to apply semantics to client connection")?;
                let new_cn = stack.connect_wrap(cn).map_err(Into::into)?;

                debug!(addr = ?&a, stack = ?&stack, "returning pre-negotiated connection");
                *recirculate_mtx.lock() = Some((a, buf));
                return Ok(Some(Either::Right(new_cn)));
            }

            debug!(client_addr = ?&a, "address not already negotiated, doing negotiation");

            // else, do negotiation
            let negotiate_msg: NegotiateMsg =
                match bincode::deserialize(&buf).wrap_err("offer deserialize failed") {
                    Ok(m) => m,
                    Err(e) => {
                        debug!(err = %format!("{:#?}", e), ?buf, "Discarding message");
                        continue;
                    }
                };

            use NegotiateMsg::*;
            match negotiate_msg {
                ServerNonce { addr, picked } => {
                    let addr = bincode::deserialize(&addr).wrap_err("mismatched addr types")?;
                    trace!(client_addr = ?&addr, nonce = ?&picked, "got nonce");
                    pending_negotiated_connections
                        .lock()
                        .insert(addr, picked.clone());

                    // send ack
                    let ack = bincode::serialize(&NegotiateMsg::ServerNonceAck).unwrap();
                    cn.send((a, ack))?;
                    debug!("sent nonce ack");

                    // need to loop on this connection, processing nonces
                    if let Err(e) =
                        process_nonces_connection(cn, pending_negotiated_connections.clone())
                            .wrap_err("process_nonces_connection")
                    {
                        debug!(err = %format!("{:#}", e), "process_nonces_connection exited");
                        return Ok(None);
                    }

                    unreachable!();
                }
                // one-rtt case
                ClientOffer(client_offers) => {
                    let s = stack.clone();
                    let (new_stack, client_resp) = match monomorphize(
                        s,
                        client_offers.into_iter().map(Into::into).collect(),
                        &a,
                    ) {
                        Ok((mut new_stack, nonce, picked_offers)) => {
                            // bertha::NegotiateMsg to crate::NegotiateMsg (with extinfo)
                            let nonce: NegotiateMsg = nonce.into();
                            let nonce_buf = bincode::serialize(&nonce)
                                .wrap_err("Failed to serialize (addr, chosen_stack) nonce")?;

                            new_stack.call_negotiate_picked(&nonce_buf);
                            let ext_info = new_stack.collect_ext_info();
                            let picked_offers = picked_offers
                                .into_iter()
                                .map(|o| {
                                    let mut o: StackNonce = o.into();
                                    o.set_ext_info(ext_info.clone());
                                    o
                                })
                                .collect();

                            (
                                Some(new_stack),
                                NegotiateMsg::ServerReply(Ok(picked_offers)),
                            )
                        }
                        Err(e) => {
                            debug!(err = %format!("{:#}", &e), "negotiation handshake failed");
                            (None, NegotiateMsg::ServerReply(Err(e.to_string())))
                        }
                    };

                    let buf = bincode::serialize(&client_resp)?;
                    assert!(buf.len() < 1500); // response has to fit in a packet
                    cn.send((a, buf))?;
                    debug!("sent client response");
                    if let Some(mut new_stack) = new_stack {
                        debug!(stack = ?&new_stack, "handshake done, picked stack");
                        let new_cn = new_stack.connect_wrap(cn).map_err(Into::into)?;
                        debug!("returning connection");
                        return Ok(Some(Either::Left(new_cn)));
                    } else {
                        continue;
                    }
                }
                // zero-rtt case
                ClientNonce(client_offer) => {
                    let s = stack.clone();
                    let (new_stack, client_resp) =
                        match bertha::negotiate::monomorphize(s, vec![client_offer.into()], &a) {
                            Ok((mut new_stack, nonce, _)) => {
                                let nonce_buf = bincode::serialize(&nonce)
                                    .wrap_err("Failed to serialize (addr, chosen_stack) nonce")?;

                                new_stack.call_negotiate_picked(&nonce_buf);
                                (Some(new_stack), NegotiateMsg::ServerNonceAck)
                            }
                            Err(e) => {
                                debug!(err = %format!("{:#}", &e), "negotiation handshake failed");
                                (
                                    None,
                                    NegotiateMsg::ServerReply(Ok(stack
                                        .offers()
                                        .map(Into::into)
                                        .collect())),
                                )
                            }
                        };

                    let client_resp_buf = bincode::serialize(&client_resp).unwrap();
                    assert!(client_resp_buf.len() < 1500);
                    cn.send((a, client_resp_buf))?;
                    debug!("sent client response");
                    if let Some(mut new_stack) = new_stack {
                        debug!(stack = ?&new_stack, "zero-rtt handshake done, picked stack");
                        let new_cn = new_stack.connect_wrap(cn).map_err(Into::into)?;
                        debug!("returning connection");
                        return Ok(Some(Either::Left(new_cn)));
                    } else {
                        continue;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    fn process_nonces_connection(
        cn: UdpChunnelConnection,
        pending_negotiated_connections: Mutex<HashMap<SocketAddrV4, StackNonce>>,
    ) -> Result<(), Report> {
        loop {
            trace!(local = ?cn.0.local_addr(), remote = ?cn.0.remote_addr(), "call recv()");
            let (a, buf): (_, Vec<u8>) = cn.recv().wrap_err("conn recv")?;
            let negotiate_msg: NegotiateMsg =
                bincode::deserialize(&buf).wrap_err("offer deserialize failed")?;

            use NegotiateMsg::*;
            match negotiate_msg {
                ServerNonce { addr, picked } => {
                    let addr = bincode::deserialize(&addr).wrap_err("mismatched addr types")?;
                    trace!(client_addr = ?&addr, nonce = ?&picked, "got nonce");
                    pending_negotiated_connections
                        .lock()
                        .insert(addr, picked.clone());

                    // send ack
                    let ack = bincode::serialize(&NegotiateMsg::ServerNonceAck).unwrap();
                    cn.send((a, ack))?;
                    debug!("sent nonce ack");
                }
                x => warn!(msg = ?x, "expected server nonce, got different message"),
            }
        }
    }

    pub type NegotiatedConn<S> =
        <<S as Apply>::Applied as Chunnel<UdpChunnelConnection>>::Connection;

    pub struct ClientNegotiator {
        nonces: HashMap<SocketAddrV4, StackNonce>,
    }

    impl Default for ClientNegotiator {
        fn default() -> Self {
            Self {
                nonces: HashMap::new(),
            }
        }
    }

    impl ClientNegotiator {
        pub fn negotiate_fetch_nonce<S>(
            &mut self,
            stack: S,
            cn: UdpChunnelConnection,
            addr: SocketAddrV4,
        ) -> Result<NegotiatedConn<S>, Report>
        where
            S: Apply + GetOffers + Clone + Send + 'static,
            <S as Apply>::Applied:
                Chunnel<UdpChunnelConnection> + NegotiatePicked + Clone + Debug + Send + 'static,
            <<S as Apply>::Applied as Chunnel<UdpChunnelConnection>>::Error:
                Into<Report> + Send + Sync + 'static,
        {
            let (cn, nonce) = negotiate_client_fetch_nonce(stack, cn, addr)?;
            // the insert could be replacing something here.
            self.nonces.insert(addr, nonce);
            Ok(cn)
        }

        pub fn negotiate_zero_rtt<S>(
            &mut self,
            stack: S,
            cn: UdpChunnelConnection,
            addr: SocketAddrV4,
        ) -> Result<
            <<S as Apply>::Applied as Chunnel<
                CheckZeroRttNegotiationReply<UdpChunnelConnection>,
            >>::Connection,
            Report,
        >
        where
            S: Apply + Clone + Send + 'static,
            <S as Apply>::Applied: Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>
                + GetOffers
                + NegotiatePicked
                + Clone
                + Debug
                + Send
                + 'static,
            <<S as Apply>::Applied as Chunnel<
                CheckZeroRttNegotiationReply<UdpChunnelConnection>,
            >>::Connection: Send,
            <<S as Apply>::Applied as Chunnel<
                CheckZeroRttNegotiationReply<UdpChunnelConnection>,
            >>::Error: Into<Report> + Send + Sync + 'static,
        {
            let nonce = self
                .nonces
                .get(&addr)
                .ok_or_else(|| eyre!("No nonce found for addr"))?;
            negotiate_client_nonce(stack, cn, nonce.clone(), addr)
        }

        pub fn re_negotiate<S>(
            &mut self,
            stack: S,
            cn: UdpChunnelConnection,
            addr: SocketAddrV4,
            returned_error: Report,
        ) -> Result<
            <<S as Apply>::Applied as Chunnel<
                CheckZeroRttNegotiationReply<UdpChunnelConnection>,
            >>::Connection,
            Report,
        >
        where
            S: Apply + Pick + GetOffers + Clone + Debug + Send + 'static,
            <S as Apply>::Applied: Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>
                + GetOffers
                + NegotiatePicked
                + Clone
                + Debug
                + Send
                + 'static,
            <<S as Apply>::Applied as Chunnel<
                CheckZeroRttNegotiationReply<UdpChunnelConnection>,
            >>::Connection: Send,
            <<S as Apply>::Applied as Chunnel<
                CheckZeroRttNegotiationReply<UdpChunnelConnection>,
            >>::Error: Into<Report> + Send + Sync + 'static,
            <S as Pick>::Picked: Debug,
        {
            let returned_error: ZeroRttNegotiationError = returned_error.downcast().wrap_err(eyre!("Renegotation only works with an error returned from a connection returned by negotiate_zero_rtt"))?;
            let nonces = match returned_error {
                ZeroRttNegotiationError::NotAccepted(nonces) => nonces,
                e => bail!("Non-negotiation error: {}", e),
            };

            let picked = client_monomorphize(&stack, nonces)?;
            self.nonces.insert(addr.clone(), picked.clone());
            negotiate_client_nonce(stack, cn, picked, addr)
        }
    }

    /// Return a connection with `stack`'s semantics, connecting to `a`.
    ///
    /// This is the traditional "one-rtt" version. It will block until the remote end completes the
    /// negotiation handshake.
    #[allow(clippy::manual_async_fn)] // we need the + 'static which async fn does not do.
    pub fn negotiate_client<S>(
        stack: S,
        cn: UdpChunnelConnection,
        addr: SocketAddrV4,
    ) -> Result<NegotiatedConn<S>, Report>
    where
        S: Apply + GetOffers + Clone + Send + 'static,
        <S as Apply>::Applied:
            Chunnel<UdpChunnelConnection> + NegotiatePicked + Clone + Debug + Send + 'static,
        <<S as Apply>::Applied as Chunnel<UdpChunnelConnection>>::Error:
            Into<Report> + Send + Sync + 'static,
    {
        let (cn, _) = negotiate_client_fetch_nonce(stack, cn, addr)?;
        Ok(cn)
    }

    /// Same as [`negotiate_client`], but also return the [`StackNonce`].
    pub fn negotiate_client_fetch_nonce<S>(
        stack: S,
        cn: UdpChunnelConnection,
        addr: SocketAddrV4,
    ) -> Result<(NegotiatedConn<S>, StackNonce), Report>
    where
        S: Apply + GetOffers + Clone + Send + 'static,
        <S as Apply>::Applied:
            Chunnel<UdpChunnelConnection> + NegotiatePicked + Clone + Debug + Send + 'static,
        <<S as Apply>::Applied as Chunnel<UdpChunnelConnection>>::Error:
            Into<Report> + Send + Sync + 'static,
    {
        debug!(?addr, "client negotiation starting");
        let offers = NegotiateMsg::ClientOffer(stack.offers().map(Into::into).collect());
        let resp = try_negotiate_offer_loop(cn.clone(), addr.clone(), offers)?;
        match resp {
            NegotiateMsg::ServerReply(Ok(picked)) => {
                // 4. monomorphize `stack`, picking received choices
                trace!(?picked, "received server pairs, applying");
                let mut sc = 0;
                let mut applied = None;
                let mut apply_err = eyre!("Apply error");
                for p in picked {
                    let p2 = p.clone();
                    match bertha::negotiate::check_apply(stack.clone(), p.into())
                        .wrap_err(eyre!("Could not apply received impls to stack"))
                    {
                        Ok(ApplyResult {
                            applied: ns,
                            score: p_sc,
                            ..
                        }) => {
                            // TODO what if two options are tied? This will arbitrarily pick the first.
                            if p_sc > sc || applied.is_none() {
                                sc = p_sc;
                                applied = Some((ns, p2));
                            }
                        }
                        Err(e) => {
                            debug!(err = %format!("{:#}", e), "Apply attempt failed");
                            apply_err = apply_err.wrap_err(e);
                            continue;
                        }
                    }
                }

                let (mut applied, nonce) = applied.ok_or_else(|| {
                    apply_err.wrap_err(eyre!("All received options failed to apply"))
                })?;
                debug!(?applied, "applied to stack");
                let inform_picked_nonce_buf = bincode::serialize(&NegotiateMsg::ServerNonce {
                    addr: bincode::serialize(&addr)?,
                    picked: nonce.clone(),
                })?;
                applied.call_negotiate_picked(&inform_picked_nonce_buf);

                let mut inform_extinfo = nonce.1.clone();
                applied.distribute_ext_info(&mut inform_extinfo);

                // 5. return applied.connect_wrap(vec_u8_conn)
                Ok((applied.connect_wrap(cn).map_err(Into::into)?, nonce))
            }
            NegotiateMsg::ServerReply(Err(errmsg)) => Err(eyre!("{:?}", errmsg)),
            _ => Err(eyre!("Received unknown message type")),
        }
    }

    /// Similar to `negotiate_client_nonce`, but the nonce is implicit.
    ///
    /// The nonce in this case is determined by inspecting the provided `stack`. The stack must be
    /// fully-determined, i.e., it cannot have any [`Select`]s. If it does, this will error.
    pub fn negotiate_client_fixed_stack<S>(
        mut stack: S,
        cn: UdpChunnelConnection,
        addr: SocketAddrV4,
    ) -> Result<
        <S as Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>>::Connection,
        Report,
    >
    where
        S: Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>
            + GetOffers
            + NegotiatePicked
            + Clone
            + Debug
            + Send
            + 'static,
        <S as Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>>::Error:
            Into<Report> + Send + Sync + 'static,
    {
        let nonce = {
            let mut offers = stack.offers();
            let nonce: StackNonce = offers
                .next()
                .ok_or_else(|| eyre!("No StackNonce available for {:?}", stack))
                .map(Into::into)?;
            if offers.next().is_some() {
                bail!("Stack should not have Selects: {:?}", stack);
            }

            nonce
        };

        let msg = NegotiateMsg::ClientNonce(nonce.clone());
        let buf = bincode::serialize(&msg)?;
        cn.send((addr, buf))?;

        let picked = NegotiateMsg::ServerNonce {
            addr: bincode::serialize(&addr)?,
            picked: nonce,
        };
        let inform_picked_nonce_buf = bincode::serialize(&picked)?;
        stack.call_negotiate_picked(&inform_picked_nonce_buf);

        stack
            .connect_wrap(CheckZeroRttNegotiationReply::from(cn))
            .map_err(Into::into)
    }

    /// Pass an existing `nonce` to get a "zero-rtt" negotiated connection that be be used immediately.
    ///
    /// The connection might return an error later if `nonce` was incompatible with the other side.
    /// This error will be `.downcast`-able to a [`ZeroRttNegotiationError`], which will contain the
    /// list of valid remote nonces.
    /// From this, callers can monomorphize a new nonce and try again with this function.
    pub fn negotiate_client_nonce<S>(
        stack: S,
        cn: UdpChunnelConnection,
        nonce: StackNonce,
        addr: SocketAddrV4,
    ) -> Result<
        <<S as Apply>::Applied as Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>>::Connection,
        Report,
    >
    where
        S: Apply + Clone + Send + 'static,
        <S as Apply>::Applied: Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>
            + GetOffers
            + NegotiatePicked
            + Clone
            + Debug
            + Send
            + 'static,
        <<S as Apply>::Applied as Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>>::Connection: Send,
        <<S as Apply>::Applied as Chunnel<CheckZeroRttNegotiationReply<UdpChunnelConnection>>>::Error:
            Into<Report> + Send + Sync + 'static,
    {
        let ApplyResult { applied, .. } = stack.apply(nonce.into())?;
        negotiate_client_fixed_stack(applied, cn, addr)
    }

    /// Pick a nonce from a stack and `server_offers` which is returned in [`ZeroRttNegotiationError`].
    pub fn client_monomorphize<S>(
        stack: &S,
        server_offers: Vec<StackNonce>,
    ) -> Result<StackNonce, Report>
    where
        S: Pick + GetOffers + Clone + Debug + Send + 'static,
        <S as Pick>::Picked: Debug,
    {
        match monomorphize(
            stack.clone(),
            server_offers.into_iter().map(Into::into).collect(),
            &String::new(),
        )? {
            (_, bertha::NegotiateMsg::ServerNonce { picked, .. }, _) => Ok(picked.into()),
            _ => unreachable!(),
        }
    }

    fn try_negotiate_offer_loop(
        cn: UdpChunnelConnection,
        addr: SocketAddrV4,
        offer: NegotiateMsg,
    ) -> Result<NegotiateMsg, Report> {
        use shenango::poll::PollWaiter;
        let buf = bincode::serialize(&offer)?;
        loop {
            let mut poll = PollWaiter::new();
            let send_trigger = poll.trigger(0);
            let sleep_trigger = poll.trigger(1);

            shenango::thread::spawn_detached(move || {
                let _sleep_trigger = sleep_trigger;
                shenango::sleep(std::time::Duration::from_millis(2_000));
                // drop sleep_trigger
            });

            let cn_try = cn.clone();
            let b = buf.clone();
            let work = shenango::thread::spawn(move || {
                let _send_trigger = send_trigger;
                let x = try_once(cn_try, addr, b);
                x // drop send_trigger
            });

            match poll.wait() {
                0 => {
                    return work.join().unwrap();
                }
                1 => {
                    debug!("negotiate offer timed out");
                    continue;
                }
                x => {
                    warn!(?x, "invalid return value from wait");
                }
            }
        }

        fn try_once(
            cn: UdpChunnelConnection,
            addr: SocketAddrV4,
            buf: Vec<u8>,
        ) -> Result<NegotiateMsg, Report> {
            // 2. send offers
            cn.send((addr, buf))?;

            // 3. receive picked
            let (_, rbuf) = cn.recv()?;
            bincode::deserialize(&rbuf).wrap_err(eyre!(
                "Could not deserialize negotiate_server response: {:?}",
                rbuf
            ))
        }
    }

    /// Ensures safety for zero-rtt negotiation.
    ///
    /// On recv, errors if the received message (a response to something that was sent) is a
    /// negotiation response. This only would happen in the error case, so we just return the error
    /// [`ZeroRttNegotiationError`] - can downcast the [`Report`] to get it.
    pub struct CheckZeroRttNegotiationReply<C> {
        inner: C,
        success: Arc<AtomicBool>,
    }

    impl<C> From<C> for CheckZeroRttNegotiationReply<C> {
        fn from(inner: C) -> Self {
            Self {
                inner,
                success: Default::default(),
            }
        }
    }

    impl<C> ChunnelConnection for CheckZeroRttNegotiationReply<C>
    where
        C: ChunnelConnection<Data = (SocketAddrV4, Vec<u8>)>,
    {
        type Data = (SocketAddrV4, Vec<u8>);

        fn send(&self, data: Self::Data) -> Result<(), Report> {
            self.inner.send(data)
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            if !self.success.load(Ordering::SeqCst) {
                let (addr, data) = self.inner.recv()?;
                // try parsing a NegotiateMsg::ServerReply
                let m: Result<NegotiateMsg, _> = bincode::deserialize(&data);
                match m {
                    Ok(NegotiateMsg::ServerNonceAck) => {
                        trace!("zero-rtt negotiation succeeded");
                        self.success.as_ref().store(true, Ordering::SeqCst);
                        // the next recv will get application data.
                        // this is safe because we set success to true, so a subsequent call
                        // to this function would skip negotiaton logic anyway
                        return self.inner.recv();
                    }
                    Err(e) => {
                        // do NOT set success because we still need to listen for the
                        // ServerNonceAck, but getting a non-`NegotiateMsg` means that negotiaton
                        // succeeded but there was some reordering.
                        //
                        // This is because the negotiaton server will only return a connection to
                        // the application if negotiaton succeeded, and if it did that then it will
                        // have sent the ServerNonceAck.
                        //
                        // This assumes that:
                        // 1. client and server both implement the negotiaton protocol correctly.
                        // 2. the error `e` is actually a deserialization error and not some other
                        //    error from the base connection.
                        //    TODO check the error type
                        trace!(err = %format!("{:#}", e), ?data, "return reordered message");
                        Ok((addr, data))
                    }
                    Ok(NegotiateMsg::ServerReply(Ok(options))) => {
                        bail!(ZeroRttNegotiationError::NotAccepted(options))
                    }
                    Ok(NegotiateMsg::ServerReply(Err(s))) => {
                        bail!(ZeroRttNegotiationError::UnexpectedError(s))
                    }
                    Ok(m) => bail!(ZeroRttNegotiationError::UnexpectedResponse(m)),
                }
            } else {
                self.inner.recv()
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum ZeroRttNegotiationError {
        NotAccepted(Vec<StackNonce>),
        UnexpectedResponse(NegotiateMsg),
        UnexpectedError(String),
    }

    impl std::fmt::Display for ZeroRttNegotiationError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            use ZeroRttNegotiationError::*;
            match self {
                NotAccepted(_) => f.write_str("Negotiation nonce was not accepted"),
                UnexpectedError(m) => {
                    let e = format!("Unexpected negotiation response: {:?}", m);
                    f.write_str(&e)
                }
                UnexpectedResponse(m) => {
                    let e = format!("Unexpected negotiation response: {:?}", m);
                    f.write_str(&e)
                }
            }
        }
    }
}

pub use chunnels::{
    ClientShardChunnelClient, ClientShardClientConnection, ShardCanonicalServer,
    ShardCanonicalServerConnection,
};
pub use chunnels::{KvReliability, KvReliabilityChunnel, KvReliabilityServerChunnel};
pub use chunnels::{SerializeChunnelProject, SerializeProject};
pub mod chunnels {
    use super::base_traits::{Chunnel, ChunnelConnection};
    use color_eyre::eyre::{eyre, Report, WrapErr};
    use shenango::poll::PollWaiter;
    use shenango::sync::Mutex;
    use shenango::WaitGroup;
    use std::fmt::Debug;
    use std::net::SocketAddrV4;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{debug, trace, warn};

    #[derive(Debug, Clone, Default, Copy)]
    pub struct Nothing<N>(std::marker::PhantomData<N>);

    impl<N: bertha::CapabilitySet> bertha::Negotiate for Nothing<N> {
        type Capability = N;

        fn guid() -> u64 {
            0xa0c77d6bd6bef98c
        }
    }
    impl<N: bertha::CapabilitySet> super::negotiate::Negotiate for Nothing<N> {}
    impl<InC: super::ChunnelConnection, N> Chunnel<InC> for Nothing<N> {
        type Connection = InC;
        type Error = std::convert::Infallible;

        fn connect_wrap(&mut self, cn: InC) -> Result<Self::Connection, Self::Error> {
            Ok(cn)
        }
    }

    #[derive(Debug, Clone)]
    pub struct SerializeChunnelProject<D> {
        _data: std::marker::PhantomData<D>,
    }

    impl<D> bertha::Negotiate for SerializeChunnelProject<D> {
        type Capability = ();

        fn guid() -> u64 {
            0xd5263bf239e761c3
        }
    }

    impl<D> super::negotiate::Negotiate for SerializeChunnelProject<D> {}

    impl<D> Default for SerializeChunnelProject<D> {
        fn default() -> Self {
            SerializeChunnelProject {
                _data: Default::default(),
            }
        }
    }

    impl<A, D, InC> Chunnel<InC> for SerializeChunnelProject<D>
    where
        InC: ChunnelConnection<Data = (A, Vec<u8>)>,
        D: serde::Serialize + serde::de::DeserializeOwned,
    {
        type Connection = SerializeProject<A, D, InC>;
        type Error = std::convert::Infallible;

        fn connect_wrap(&mut self, cn: InC) -> Result<Self::Connection, Self::Error> {
            Ok(SerializeProject::from(cn))
        }
    }

    #[derive(Default, Debug, Clone)]
    pub struct SerializeProject<A, D, C> {
        inner: C,
        _data: std::marker::PhantomData<(A, D)>,
    }

    impl<Cx, A, D> From<Cx> for SerializeProject<A, D, Cx> {
        fn from(inner: Cx) -> SerializeProject<A, D, Cx> {
            debug!(data = ?std::any::type_name::<D>(), "make serialize chunnel");
            SerializeProject {
                inner,
                _data: Default::default(),
            }
        }
    }

    impl<A, C, D> ChunnelConnection for SerializeProject<A, D, C>
    where
        C: ChunnelConnection<Data = (A, Vec<u8>)>,
        D: serde::Serialize + serde::de::DeserializeOwned,
    {
        type Data = (A, D);

        fn send(&self, data: Self::Data) -> Result<(), Report> {
            let buf = bincode::serialize(&data.1).wrap_err("serialize failed")?;
            self.inner.send((data.0, buf))
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            let (a, buf) = self.inner.recv()?;
            let data = bincode::deserialize(&buf[..]).wrap_err(eyre!(
                "deserialize failed: {:?} -> {:?}",
                buf,
                std::any::type_name::<D>()
            ))?;
            Ok((a, data))
        }
    }

    use bertha::reliable::ReliabilityNeg;

    #[derive(Debug, Clone)]
    pub struct KvReliabilityChunnel {
        timeout: Duration,
    }

    impl bertha::Negotiate for KvReliabilityChunnel {
        type Capability = ReliabilityNeg;

        fn guid() -> u64 {
            0xa84943c6f0ce1b78
        }

        fn capabilities() -> Vec<Self::Capability> {
            vec![ReliabilityNeg::Reliability, ReliabilityNeg::Ordering]
        }
    }

    impl super::Negotiate for KvReliabilityChunnel {}

    impl Default for KvReliabilityChunnel {
        fn default() -> Self {
            KvReliabilityChunnel {
                timeout: Duration::from_millis(500),
            }
        }
    }

    impl KvReliabilityChunnel {
        pub fn set_timeout(&mut self, to: Duration) -> &mut Self {
            self.timeout = to;
            self
        }
    }

    impl<A, InC, D> Chunnel<InC> for KvReliabilityChunnel
    where
        InC: ChunnelConnection<Data = (A, D)> + Send + Sync + 'static,
        A: Clone + Eq + std::hash::Hash + std::fmt::Debug + 'static,
        D: MsgId + Clone + 'static,
    {
        type Connection = KvReliability<InC, A, D>;
        type Error = std::convert::Infallible;

        fn connect_wrap(&mut self, cn: InC) -> Result<Self::Connection, Self::Error> {
            Ok(KvReliability::new(cn, self.timeout))
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct KvReliabilityServerChunnel;

    impl bertha::Negotiate for KvReliabilityServerChunnel {
        type Capability = ReliabilityNeg;

        fn guid() -> u64 {
            0xa84943c6f0ce1b78
        }

        fn capabilities() -> Vec<Self::Capability> {
            vec![ReliabilityNeg::Reliability, ReliabilityNeg::Ordering]
        }
    }

    impl super::Negotiate for KvReliabilityServerChunnel {}

    impl<D, InC> Chunnel<InC> for KvReliabilityServerChunnel
    where
        InC: ChunnelConnection<Data = D>,
    {
        type Connection = InC;
        type Error = std::convert::Infallible;

        fn connect_wrap(&mut self, cn: InC) -> Result<Self::Connection, Self::Error> {
            Ok(cn)
        }
    }

    use shenango::sync::Condvar;
    use std::collections::HashMap;

    #[derive(Clone)]
    pub struct KvReliability<C, A, D> {
        inner: Arc<C>,
        timeout: Duration,
        sends: Mutex<HashMap<usize, WaitGroup>>,
        recv_cv: Condvar,
        recvs: Mutex<Vec<(A, D)>>,
    }

    impl<C, A, D> KvReliability<C, A, D> {
        fn new(inner: C, timeout: Duration) -> Self {
            KvReliability {
                inner: Arc::new(inner),
                timeout,
                sends: Default::default(),
                recv_cv: Condvar::new(),
                recvs: Default::default(),
            }
        }
    }

    use bertha::util::MsgId;
    use shenango::time::Timer;
    impl<A, D, C> ChunnelConnection for KvReliability<C, A, D>
    where
        C: ChunnelConnection<Data = (A, D)> + Send + Sync + 'static,
        A: Clone + 'static,
        D: MsgId + Clone + 'static,
    {
        type Data = (A, D);

        fn send(&self, data: Self::Data) -> Result<(), Report> {
            const SND: u32 = 0;
            const RCV: u32 = 1;
            const TIMEOUT: u32 = 2;

            let msg_id = data.1.id();
            let send_waiter = WaitGroup::new();
            // .done() this when the send finishes.
            send_waiter.add(1);
            {
                let mut g = self.sends.lock();
                g.insert(msg_id, send_waiter.clone());
            }

            // blocks, but will finish fast.
            self.inner.send(data.clone())?;

            // there are 3 tasks. when this function returns, all 3 of them *must* exit (or have
            // already exited) shortly after we return.
            let mut poll = PollWaiter::new();
            // 1. wait for the send to finish. this is what lets us return
            let sendcomplete_trigger = poll.trigger(SND);
            // 2. if a timeout happens, retransmit.
            let timeout_trigger = poll.trigger(TIMEOUT);
            // 3. handle receives and notify the corresponding senders.
            let recv_trigger = poll.trigger(RCV);

            shenango::thread::spawn(move || {
                let _send = sendcomplete_trigger;
                send_waiter.wait();
            });

            let recv_cn = Arc::clone(&self.inner);
            let recvs = self.recvs.clone();
            let recv_cv = self.recv_cv.clone();
            let sends = self.sends.clone();
            let recv_jh = shenango::thread::spawn(move || {
                let _recv = recv_trigger;
                loop {
                    let recv_msg_id = {
                        let resp = recv_cn.recv().wrap_err("kvreliability recv acks")?;
                        let recv_msg_id = resp.1.id();

                        // signal recv
                        let mut rg = recvs.lock();
                        rg.push(resp);
                        recv_cv.signal();
                        recv_msg_id
                    };

                    let (sw, done_already) = {
                        let mut g = sends.lock();
                        let sw = g.remove(&recv_msg_id);
                        if sw.is_none() {
                            return Ok(());
                        }

                        (sw.unwrap(), !g.contains_key(&msg_id))
                    };

                    sw.done();
                    if recv_msg_id == msg_id || done_already {
                        return Ok(());
                    }
                }
            });

            let to = self.timeout;
            let mut sleeper = Timer::new();
            let sl = sleeper.clone();
            shenango::thread::spawn_detached(move || {
                let _to = timeout_trigger;
                sl.sleep(to);
                // drop sleep_trigger
            });

            loop {
                let v = poll.wait();
                match v {
                    TIMEOUT => {
                        trace!("kvreliability timeout");
                        self.inner.send(data.clone())?;
                        sleeper = Timer::new();
                        let sl = sleeper.clone();
                        let timeout_trigger = poll.trigger(TIMEOUT);
                        shenango::thread::spawn_detached(move || {
                            let _to = timeout_trigger;
                            sl.sleep(to);
                            // drop sleep_trigger
                        });
                    }
                    RCV => {
                        sleeper.cancel();
                        return recv_jh.join().unwrap();
                    }
                    SND => {
                        sleeper.cancel();
                        return Ok(());
                    }
                    x => {
                        sleeper.cancel();
                        warn!(?x, "invalid poll value");
                        return Err(eyre!("invalid poll value {:?}", x));
                    }
                }
            }
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            let res = {
                let mut g = self.recvs.lock();
                g.pop()
            };
            if let Some(d) = res {
                return Ok(d);
            } else {
                loop {
                    let mut e = self.recv_cv.wait(&self.recvs);
                    if let Some(d) = e.pop() {
                        return Ok(d);
                    } else {
                        shenango::thread::thread_yield();
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct ShardInfo {
        pub canonical_addr: SocketAddrV4,
        pub shard_addrs: Vec<SocketAddrV4>,
    }

    #[derive(Clone)]
    pub struct ShardCanonicalServer {
        addr: ShardInfo,
    }

    impl std::fmt::Debug for ShardCanonicalServer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ShardCanonicalServer")
                .field("addr", &self.addr)
                .finish()
        }
    }

    impl ShardCanonicalServer {
        /// Inner is a chunnel for the external connection.
        pub fn new(addr: ShardInfo) -> Result<Self, Report> {
            Ok(ShardCanonicalServer { addr })
        }
    }

    impl bertha::Negotiate for ShardCanonicalServer {
        type Capability = ShardFns;

        fn guid() -> u64 {
            0xe91d00534cb2b98f
        }

        fn capabilities() -> Vec<ShardFns> {
            vec![ShardFns::Sharding]
        }
    }

    use super::negotiate::NegotiateMsg;
    use super::udp::UdpChunnelConnection;
    use shenango::udp::UdpConnection;
    impl super::Negotiate for ShardCanonicalServer {
        fn picked_blocking(&mut self, nonce: &[u8]) {
            let msg: NegotiateMsg = match bincode::deserialize(nonce) {
                Err(e) => {
                    warn!(err = ?e, "deserialize failed");
                    return;
                }
                Ok(x @ NegotiateMsg::ServerNonce { .. }) => x,
                Ok(_) => {
                    warn!("malformed nonce");
                    return;
                }
            };

            //let offer = self.shards_extern_nonce.clone();
            //let msg = match msg {
            //    NegotiateMsg::ServerNonce { addr, .. } => NegotiateMsg::ServerNonce {
            //        addr,
            //        picked: offer,
            //    },
            //    _ => {
            //        warn!("malformed nonce");
            //        return;
            //    }
            //};

            let buf = match bincode::serialize(&msg) {
                Err(e) => {
                    warn!(err = ?e, "serialize failed");
                    return;
                }
                Ok(m) => m,
            };

            let wg = shenango::sync::WaitGroup::new();
            for shard in &self.addr.shard_addrs {
                let buf = buf.clone();
                wg.add(1);
                let wg = wg.clone();
                let shard = *shard;
                shenango::thread::spawn(move || {
                    let cn = match UdpConnection::dial(
                        SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                        shard,
                    ) {
                        Ok(cn) => cn,
                        Err(err) => {
                            warn!(?err, ?shard, "could not connect to shard");
                            return;
                        }
                    };

                    let cn = UdpChunnelConnection::new(cn);
                    if let Err(e) = cn.send((shard.clone(), buf.clone())) {
                        warn!(err = ?e, "failed sending negotiation nonce to shard");
                        wg.done();
                        return;
                    }

                    trace!(remote = ?shard, "wait for nonce ack");
                    match cn.recv() {
                        Ok((a, buf)) => match bincode::deserialize(&buf) {
                            Ok(NegotiateMsg::ServerNonceAck) => {
                                if a != shard.clone() {
                                    warn!(addr = ?a, expected = ?shard.clone(), "received from unexpected address");
                                }

                                trace!("got nonce ack");
                            }
                            Ok(m) => {
                                warn!(msg = ?m, shard = ?shard.clone(), "got unexpected response to nonce");
                            }
                            Err(e) => {
                                warn!(err = ?e, shard = ?shard.clone(), "failed deserializing nonce ack");
                            }
                        },
                        Err(e) => {
                            warn!(err = ?e, shard = ?shard.clone(), "failed waiting for nonce ack");
                        }
                    }

                    wg.done();
                });
            }

            wg.wait();
        }

        fn ext_info(&self) -> Option<Vec<u8>> {
            let shard_info_bytes = bincode::serialize(&self.addr).unwrap();
            Some(shard_info_bytes)
        }
    }

    use shard_ctl::Kv;
    const FNV1_64_INIT: u64 = 0xcbf29ce484222325u64;
    const FNV_64_PRIME: u64 = 0x100000001b3u64;

    impl<I, D> Chunnel<I> for ShardCanonicalServer
    where
        I: ChunnelConnection<Data = D> + Send + Sync + 'static,
        D: Kv + Send + Sync + 'static,
        <D as Kv>::Key: AsRef<str>,
    {
        type Connection = ShardCanonicalServerConnection<I>;
        type Error = Report;

        fn connect_wrap(&mut self, conn: I) -> Result<Self::Connection, Self::Error> {
            // this fake version does not forward, so don't bother with shard connections etc.
            Ok(ShardCanonicalServerConnection {
                inner: Arc::new(conn),
            })
        }
    }

    pub struct ShardCanonicalServerConnection<C> {
        inner: Arc<C>,
    }

    impl<C> ChunnelConnection for ShardCanonicalServerConnection<C>
    where
        C: ChunnelConnection + Send + Sync + 'static,
    {
        type Data = ();

        fn recv(&self) -> Result<Self::Data, Report> {
            let _d = self.inner.recv()?;
            trace!("got request");
            Ok(())
        }

        fn send(&self, _data: Self::Data) -> Result<(), Report> {
            warn!("Called ShardCanonicalServerConnection.send(), a useless function");
            Ok(())
        }
    }

    /// Client-side sharding chunnel implementation.
    ///
    /// Contacts shard-ctl for sharding information, and does client-side sharding.
    #[derive(Clone)]
    pub struct ClientShardChunnelClient {
        addr: SocketAddrV4,
        shard_info: Option<Vec<SocketAddrV4>>,
    }

    impl std::fmt::Debug for ClientShardChunnelClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ClientShardChunnelClient")
                .field("addr", &self.addr)
                .finish()
        }
    }

    impl ClientShardChunnelClient {
        pub fn new(addr: SocketAddrV4) -> Result<Self, Report> {
            Ok(ClientShardChunnelClient {
                addr,
                shard_info: None,
            })
        }

        pub fn new_static(addr: SocketAddrV4, shard_info: Vec<SocketAddrV4>) -> Self {
            ClientShardChunnelClient {
                addr,
                shard_info: Some(shard_info),
            }
        }
    }

    use shard_ctl::ShardFns;

    impl bertha::Negotiate for ClientShardChunnelClient {
        type Capability = ShardFns;

        fn guid() -> u64 {
            0xafb32251f0697831
        }

        fn capabilities() -> Vec<ShardFns> {
            vec![ShardFns::Sharding]
        }
    }

    impl super::Negotiate for ClientShardChunnelClient {
        fn ext_info_callback(&mut self, info: Vec<u8>) {
            let si: ShardInfo = match bincode::deserialize(&info) {
                Ok(si) => si,
                Err(e) => {
                    warn!(err = ?e, "Could not deserialize extinfo");
                    return;
                }
            };

            let mut addrs = vec![si.canonical_addr.into()];
            addrs.extend(si.shard_addrs.into_iter());

            debug!(addrs = ?&addrs, "Decided sharding plan");
            self.shard_info = Some(addrs);
        }
    }

    impl<I, D> Chunnel<I> for ClientShardChunnelClient
    where
        I: ChunnelConnection<Data = (SocketAddrV4, D)> + Send + Sync + 'static,
        D: Kv + Send + Sync + 'static,
        <D as Kv>::Key: AsRef<str>,
    {
        type Connection = ClientShardClientConnection<D, I>;
        type Error = Report;

        fn connect_wrap(&mut self, inner: I) -> Result<Self::Connection, Self::Error> {
            let addrs = self
                .shard_info
                .clone()
                .ok_or_else(|| eyre!("Shard info was not set"))?;
            let num_shards = addrs.len() - 1;
            Ok(ClientShardClientConnection::new(inner, addrs, move |d| {
                if num_shards == 0 {
                    return 0;
                }

                let mut hash = FNV1_64_INIT;
                for b in d.key().as_ref().as_bytes()[0..4].iter() {
                    hash ^= *b as u64;
                    hash = u64::wrapping_mul(hash, FNV_64_PRIME);
                }

                (hash as usize % num_shards) + 1
            }))
        }
    }

    /// `ChunnelConnection` type for ClientShardChunnelClient.
    pub struct ClientShardClientConnection<D, C>
    where
        C: ChunnelConnection<Data = (SocketAddrV4, D)>,
    {
        inner: Arc<C>,
        shard_addrs: Vec<SocketAddrV4>,
        shard_fn: Arc<dyn Fn(&D) -> usize + Send + Sync + 'static>,
    }

    impl<C, D> ClientShardClientConnection<D, C>
    where
        C: ChunnelConnection<Data = (SocketAddrV4, D)>,
    {
        pub fn new(
            inner: C,
            shard_addrs: Vec<SocketAddrV4>, // canonical_addr is the first
            shard_fn: impl Fn(&D) -> usize + Send + Sync + 'static,
        ) -> Self {
            ClientShardClientConnection {
                inner: Arc::new(inner),
                shard_addrs,
                shard_fn: Arc::new(shard_fn),
            }
        }
    }

    impl<C, D> ChunnelConnection for ClientShardClientConnection<D, C>
    where
        C: ChunnelConnection<Data = (SocketAddrV4, D)> + Send + Sync + 'static,
        D: Kv + Send + Sync + 'static,
    {
        type Data = (SocketAddrV4, D);

        fn send(&self, data: Self::Data) -> Result<(), Report> {
            // figure out which shard to send to.
            let shard_idx = (self.shard_fn)(&data.1);
            let a = self.shard_addrs[shard_idx];
            let _ = &data;
            self.inner.send((a, data.1))
        }

        fn recv(&self) -> Result<Self::Data, Report> {
            self.inner.recv()
        }
    }
}

pub use crate::kvstore::{serve, single_shard};
pub use crate::kvstore::{KvClient, KvClientBuilder};
mod kvstore {
    use super::ChunnelConnection;
    use super::{KvReliabilityChunnel, KvReliabilityServerChunnel, SerializeChunnelProject};
    use bertha::CxList;
    use color_eyre::eyre::{eyre, Report, WrapErr};
    use std::net::SocketAddrV4;
    use std::sync::{atomic::AtomicUsize, Arc};
    use tracing::{debug, info, trace, warn};

    use kvstore::kv::Store;
    //use kvstore::Op;
    //use std::collections::HashMap;

    pub fn single_shard(addr: SocketAddrV4, skip_negotiation: bool) {
        info!(?addr, "listening");

        let external = CxList::from(KvReliabilityServerChunnel::default())
            .wrap(SerializeChunnelProject::default());

        // initialize the kv store.
        let store = Store::default();
        //let store: Mutex<HashMap<String, String>> = Default::default();
        //fn get(this: &Mutex<HashMap<String, String>>, k: &str) -> Option<String> {
        //    let g = this.lock();
        //    g.get(k).map(Clone::clone)
        //}

        //fn put(
        //    this: &Mutex<HashMap<String, String>>,
        //    k: &str,
        //    v: Option<String>,
        //) -> Option<String> {
        //    let mut g = this.lock();
        //    if let Some(v) = v {
        //        g.insert(k.to_string(), v)
        //    } else {
        //        g.remove(k)
        //    }
        //}

        //fn call(this: &Mutex<HashMap<String, String>>, req: Msg) -> Msg {
        //    match req.op() {
        //        Op::Get => {
        //            let val = get(this, req.key());
        //            req.resp(val)
        //        }
        //        Op::Put => {
        //            let old = put(this, req.key(), req.val());
        //            req.resp(old)
        //        }
        //    }
        //}
        use crate::base_traits::Chunnel;
        use crate::udp;
        fn skip_neg<Srv, F>(
            stack: Srv,
            listen_addr: SocketAddrV4,
            per_conn: F,
        ) -> Result<(), Report>
        where
            Srv: Chunnel<UdpChunnelConnection> + Clone + Send + Sync + 'static,
            <Srv as Chunnel<UdpChunnelConnection>>::Connection: Send + Sync + 'static,
            <Srv as Chunnel<UdpChunnelConnection>>::Error: Into<Report> + Send + Sync + 'static,
            F: Fn(<Srv as Chunnel<UdpChunnelConnection>>::Connection)
                + Clone
                + Send
                + Sync
                + 'static,
        {
            udp::udp_accept(listen_addr, move |cn| {
                let mut stack = stack.clone();
                per_conn(
                    stack
                        .connect_wrap(UdpChunnelConnection::new(cn))
                        .map_err(Into::into)
                        .unwrap(),
                )
            })?;
            Ok(())
        }

        fn perconn(
            cn: impl ChunnelConnection<Data = (SocketAddrV4, Msg)>,
            store: Store,
            idx: usize,
        ) {
            debug!(?idx, "new");
            loop {
                let (a, msg) = match cn.recv() {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(?e, "recv failed");
                        break;
                    }
                };

                //trace!(msg = ?&msg, from=?&a, "got msg");
                let rsp = store.call(msg);
                //let rsp = call(&store, msg);

                if let Err(e) = cn.send((a, rsp)) {
                    warn!(?e, "send failed");
                    break;
                }
            }
        }

        let idx = Arc::new(AtomicUsize::new(0));
        if skip_negotiation {
            skip_neg(external, addr, move |cn| {
                let idx = idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let store = store.clone();
                perconn(cn, store, idx)
            })
            .unwrap();
        } else {
            super::negotiate_server(external, addr, move |cn| {
                let idx = idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let store = store.clone();
                perconn(cn, store, idx)
            })
            .unwrap();
        }
    }

    /// Start and serve a `ShardCanonicalServer` and shards.
    ///
    /// `srv_addr`: Local addr to serve on.
    /// `num_shards`: Number of shards to start. Shard addresses are selected sequentially after
    /// `srv_port`, but this could change.
    pub fn serve(
        srv_addr: SocketAddrV4,
        num_shards: u16,
        skip_negotiation: bool,
    ) -> Result<(), Report> {
        // 1. Define addr.
        let si = make_shardinfo(srv_addr, num_shards);

        // 2. start shard serv
        for a in si.clone().shard_addrs {
            info!(addr = ?&a, "start shard");
            shenango::thread::spawn(move || single_shard(a, skip_negotiation));
        }

        if skip_negotiation {
            Ok(())
        } else {
            serve_canonical(si)
        }
    }

    use super::chunnels::ShardInfo;
    fn serve_canonical(si: ShardInfo) -> Result<(), Report> {
        let cnsrv = super::chunnels::ShardCanonicalServer::new(si.clone())
            .wrap_err("Create ShardCanonicalServer")?;
        let external = CxList::from(cnsrv)
            .wrap(KvReliabilityServerChunnel::default())
            .wrap(SerializeChunnelProject::<kvstore::Msg>::default());
        info!(shard_info = ?&si, "start canonical server");

        super::negotiate_server(external, si.canonical_addr, move |cn| {
            loop {
                match cn
                    .recv() // ShardCanonicalServerConnection is recv-only
                    .wrap_err("kvstore/server: Error while processing requests")
                {
                    Ok(()) => {
                        warn!("got request at canonical server");
                    }
                    Err(e) => {
                        warn!(err = ?e, "exiting");
                        break;
                    }
                }
            }
        })
        .unwrap();
        unreachable!() // negotiate_server never returns None
    }

    fn make_shardinfo(srv_addr: SocketAddrV4, num_shards: u16) -> ShardInfo {
        let shard_addrs = (1..=num_shards)
            .map(|i| SocketAddrV4::new(*srv_addr.ip(), srv_addr.port() + i))
            .collect();
        ShardInfo {
            canonical_addr: srv_addr,
            shard_addrs,
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct KvClientBuilder {
        canonical_addr: SocketAddrV4,
    }

    impl KvClientBuilder {
        pub fn new(canonical_addr: SocketAddrV4) -> Self {
            KvClientBuilder { canonical_addr }
        }
    }

    use super::ClientShardChunnelClient;
    use crate::udp::{UdpChunnelConnection, UdpConnection};

    impl KvClientBuilder {
        pub fn new_shardclient(
            self,
        ) -> Result<KvClient<impl ChunnelConnection<Data = Msg> + Send + Sync + 'static>, Report>
        {
            let cl = ClientShardChunnelClient::new(self.canonical_addr)?;
            let stack = CxList::from(cl)
                .wrap(KvReliabilityChunnel::default())
                .wrap(SerializeChunnelProject::default());
            let raw = UdpChunnelConnection::new(UdpConnection::listen(SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            ))?);
            debug!("negotiation");
            let cn = super::negotiate::negotiate_client(stack, raw, self.canonical_addr)?;
            let cn = super::base_traits::Project(self.canonical_addr, cn);
            Ok(KvClient::new_from_cn(cn))
        }

        pub fn new_fiat_client(
            self,
            shards: Vec<SocketAddrV4>,
        ) -> Result<KvClient<impl ChunnelConnection<Data = Msg> + Send + Sync + 'static>, Report>
        {
            let cl = ClientShardChunnelClient::new_static(self.canonical_addr, shards);
            let mut stack = CxList::from(cl)
                .wrap(KvReliabilityChunnel::default())
                .wrap(SerializeChunnelProject::default());
            let raw = UdpChunnelConnection::new(UdpConnection::listen(SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            ))?);
            use crate::base_traits::Chunnel;
            let cn = stack.connect_wrap(raw)?;
            let cn = super::base_traits::Project(self.canonical_addr, cn);
            Ok(KvClient::new_from_cn(cn))
        }
    }

    pub struct KvClient<C>(MsgIdMatcher<C, Msg>);

    impl<C> Clone for KvClient<C> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }

    impl KvClient<()> {
        fn new_from_cn<C: ChunnelConnection<Data = Msg> + Send + Sync + 'static>(
            inner: C,
        ) -> KvClient<C> {
            KvClient(MsgIdMatcher::new(inner))
        }
    }

    use kvstore::Msg;

    impl<C> KvClient<C>
    where
        C: ChunnelConnection<Data = Msg> + Send + Sync + 'static,
    {
        fn do_req(&self, req: Msg) -> Result<Option<String>, Report> {
            let cn = &self.0;
            let id = req.id();
            trace!(?id, "sending");
            cn.send_msg(req).wrap_err("Error sending request")?;
            trace!(?id, "sent");
            let rsp = cn.recv_msg(id).wrap_err("Error awaiting response")?;
            trace!(?id, "received");
            if rsp.id() != id {
                return Err(eyre!(
                    "Msg id mismatch, check for reordering: {} != {}",
                    rsp.id(),
                    id
                ));
            }

            Ok(rsp.into_kv().1)
        }
    }

    impl<C> KvClient<C>
    where
        C: ChunnelConnection<Data = Msg> + Send + Sync + 'static,
    {
        pub fn update(&self, key: String, val: String) -> Result<Option<String>, Report> {
            let req = Msg::put_req(key, val);
            self.do_req(req)
        }

        pub fn get(&self, key: String) -> Result<Option<String>, Report> {
            let req = Msg::get_req(key);
            self.do_req(req)
        }
    }

    pub struct MsgIdMatcher<C, D> {
        inner: Arc<C>,
        //inflight: Mutex<HashMap<usize, (WaitGroup, Option<D>)>>,
        inflight: Arc<DashMap<usize, (WaitGroup, Option<D>)>>,
    }

    impl<C, D> Clone for MsgIdMatcher<C, D> {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
                //inflight: self.inflight.clone(),
                inflight: Arc::clone(&self.inflight),
            }
        }
    }

    use dashmap::DashMap;
    //use shenango::sync::{Mutex, WaitGroup};
    use shenango::sync::WaitGroup;
    use std::sync::atomic::{AtomicBool, Ordering};

    impl<C, D> MsgIdMatcher<C, D>
    where
        C: ChunnelConnection<Data = D> + Send + Sync + 'static,
        D: bertha::util::MsgId + Send + Sync + 'static,
    {
        pub fn new(inner: C) -> Self {
            Self {
                inner: Arc::new(inner),
                //inflight: Mutex::new(Default::default()),
                inflight: Default::default(),
            }
        }

        pub fn send_msg(&self, data: D) -> Result<(), Report> {
            let recv_waiter = WaitGroup::new();
            recv_waiter.add(1);
            //let old = self
            //    .inflight
            //    .lock()
            //    .insert(data.id(), (recv_waiter.clone(), None));
            let old = self.inflight.insert(data.id(), (recv_waiter.clone(), None));
            assert!(old.is_none(), "double send");
            self.inner.send(data)
        }

        pub fn recv_msg(&self, msg_id: usize) -> Result<D, Report> {
            let done: Arc<AtomicBool> = Default::default();
            let recv_waiter: WaitGroup = {
                let val = self
                    .inflight
                    .get(&msg_id)
                    .ok_or_else(|| eyre!("msg id not found"))?;
                val.value().0.clone()
            };

            let inner = Arc::clone(&self.inner);
            //let infl = self.inflight.clone();
            let infl = Arc::clone(&self.inflight);
            let d = Arc::clone(&done);
            shenango::thread::spawn(move || {
                while !d.load(Ordering::SeqCst) {
                    let r = inner.recv();
                    match r {
                        Ok(r) => match infl.get_mut(&r.id()) {
                            Some(ref mut e) => {
                                let id = r.id();
                                let (m, ref mut d) = e.value_mut();
                                if let Some(old_d) = d {
                                    assert!(old_d.id() == id, "double recv mismatched");
                                } else {
                                    *d = Some(r);
                                    m.done(); // wake up the other thread
                                }

                                if msg_id == id {
                                    break;
                                }
                            }
                            None => {
                                // probably a spurious retx.
                                trace!(id = ?r.id(), local_id = ?msg_id, "got unexpected message");
                            }
                        },
                        Err(e) => {
                            warn!(?e, "recv errored");
                            return;
                        }
                    }
                }
            });

            recv_waiter.wait();
            done.store(true, Ordering::SeqCst);
            Ok(self.inflight.remove(&msg_id).unwrap().1 .1.unwrap())
        }
    }
}

pub use no_chunnels::RawKvClient;
/// KV client and server with not just no negotiation, but no chunnels
pub use no_chunnels::{single_shard_conns, single_shard_no_conns};
mod no_chunnels {
    use super::udp;
    use color_eyre::eyre::{eyre, Report};
    use kvstore::kv::Store;
    use kvstore::Msg;
    use shenango::udp::UdpConnection;
    use shenango::{
        poll::PollWaiter,
        sync::{Mutex, WaitGroup},
        time::Timer,
    };
    use std::collections::HashMap;
    use std::net::SocketAddrV4;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tracing::{debug, info, trace, warn};

    /// still process 5-tuples in separate threads.
    /// the main savings here is no need for allocating Vecs for the messages.
    pub fn single_shard_conns(addr: SocketAddrV4) {
        info!(?addr, "listening");

        // initialize the kv store.
        let store = Store::default();

        fn perconn(cn: UdpConnection, store: Store, idx: usize) -> Result<(), Report> {
            let from = cn.remote_addr();
            debug!(?idx, ?from, "new");
            let mut buf = [0u8; 2048];
            loop {
                let len = cn.recv(&mut buf)?;
                let msg: Msg = bincode::deserialize(&buf[..len])?;
                let rsp = store.call(msg);

                let sz = bincode::serialized_size(&rsp)? as usize;
                bincode::serialize_into(&mut buf[..], &rsp)?;
                if let Err(e) = cn.send(&buf[..sz]) {
                    warn!(?e, "send failed");
                    break Err(e.into());
                }
            }
        }

        let idx = Arc::new(AtomicUsize::new(0));
        udp::udp_accept(addr, move |cn| {
            let idx = idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let store = store.clone();
            perconn(cn, store, idx).unwrap()
        })
        .unwrap()
    }

    /// additionally strip out connections (which bertha needs)
    pub fn single_shard_no_conns(addr: SocketAddrV4) -> Result<(), Report> {
        info!(?addr, "listening");

        // initialize the kv store.
        let store = Store::default();

        let sk = UdpConnection::listen(addr)?;
        let mut buf = [0u8; 2048];
        loop {
            let (len, from) = sk.read_from(&mut buf)?;
            let msg: Msg = bincode::deserialize(&buf[..len])?;
            let rsp = store.call(msg);

            let sz = bincode::serialized_size(&rsp)? as usize;
            bincode::serialize_into(&mut buf[..], &rsp)?;
            if let Err(e) = sk.write_to(&buf[..sz], from) {
                warn!(?e, "send failed");
                break Err(e.into());
            }
        }
    }

    enum RecvState {
        Inflight(WaitGroup),
        Recvd(Msg),
    }

    impl RecvState {
        fn take_put(&mut self, m: Msg) -> Option<WaitGroup> {
            match self {
                RecvState::Inflight(_) => {
                    let wg = std::mem::replace(self, RecvState::Recvd(m));
                    match wg {
                        RecvState::Inflight(wg) => Some(wg),
                        _ => unreachable!(),
                    }
                }
                _ => None,
            }
        }

        fn done(self) -> Msg {
            match self {
                RecvState::Recvd(m) => m,
                _ => panic!("called done on still-inflight msg"),
            }
        }
    }

    #[derive(Clone)]
    pub struct RawKvClient {
        inner: Vec<Arc<UdpConnection>>,
        inflight: Arc<Mutex<HashMap<usize, RecvState>>>,
    }

    impl RawKvClient {
        pub fn new(shard_addrs: Vec<SocketAddrV4>) -> Self {
            RawKvClient {
                inner: shard_addrs
                    .into_iter()
                    .map(|sa| {
                        UdpConnection::dial(
                            SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                            sa,
                        )
                        .unwrap()
                    })
                    .map(Arc::new)
                    .collect(),
                inflight: Default::default(),
            }
        }

        pub fn update(&self, key: String, val: String) -> Result<Option<String>, Report> {
            let req = Msg::put_req(key, val);
            self.do_req(req)
        }

        pub fn get(&self, key: String) -> Result<Option<String>, Report> {
            let req = Msg::get_req(key);
            self.do_req(req)
        }

        fn do_req(&self, req: Msg) -> Result<Option<String>, Report> {
            let shard = shardfn(&req, self.inner.len());
            let cn = &self.inner[shard];
            let msg_id = req.id();
            let mut send_buf = [0u8; 2048];
            let sz = bincode::serialized_size(&req)? as usize;
            bincode::serialize_into(&mut send_buf[..sz], &req)?;

            const SND: u32 = 0;
            const RCV: u32 = 1;
            const TIMEOUT: u32 = 2;

            let send_waiter = WaitGroup::new();
            // .done() this when the send finishes.
            send_waiter.add(1);
            {
                let mut g = self.inflight.lock();
                g.insert(msg_id, RecvState::Inflight(send_waiter.clone()));
            }

            let mut poll = PollWaiter::new();
            let sendcomplete_trigger = poll.trigger(SND);
            let recv_trigger = poll.trigger(RCV);

            shenango::thread::spawn(move || {
                let _send = sendcomplete_trigger;
                send_waiter.wait();
            });

            let done: Arc<AtomicBool> = Default::default();
            let recv_cn = Arc::clone(&cn);
            let infl = self.inflight.clone();
            let d = done.clone();
            let recv_jh = shenango::thread::spawn(move || {
                let _recv = recv_trigger;
                let done = d;
                let mut buf = [0u8; 2048];
                while !done.load(Ordering::SeqCst) {
                    let len = recv_cn.recv(&mut buf)?;
                    let msg: Msg = bincode::deserialize(&buf[..len])?;
                    let recv_msg_id = msg.id();
                    trace!(?recv_msg_id, "received");

                    let mut g = infl.lock();
                    match g.get_mut(&recv_msg_id) {
                        None => {
                            return Err(eyre!("unknown message"));
                        }
                        Some(ref mut r) => match r.take_put(msg) {
                            Some(wg) => wg.done(),
                            None => {
                                warn!(?recv_msg_id, "duplicate msg");
                            }
                        },
                    }
                }

                Ok(())
            });

            loop {
                trace!(?msg_id, "sending");
                cn.send(&send_buf[..sz])?;
                let timeout_trigger = poll.trigger(TIMEOUT);
                let sleeper = Timer::new();
                let sl = sleeper.clone();
                shenango::thread::spawn_detached(move || {
                    let _to = timeout_trigger;
                    sl.sleep(Duration::from_millis(50));
                    // drop sleep_trigger
                });

                let v = poll.wait();
                match v {
                    TIMEOUT => continue,
                    RCV => {
                        sleeper.cancel();
                        // an error happened
                        return Err(recv_jh.join().unwrap().unwrap_err());
                    }
                    SND => {
                        sleeper.cancel();
                        let m = self.inflight.lock().remove(&msg_id).unwrap().done();
                        if m.id() != msg_id {
                            return Err(eyre!(
                                "Msg id mismatch, check for reordering: {} != {}",
                                m.id(),
                                msg_id
                            ));
                        }
                        return Ok(m.into_kv().1);
                    }
                    x => {
                        sleeper.cancel();
                        warn!(?x, "invalid poll value");
                        return Err(eyre!("invalid poll value {:?}", x));
                    }
                }
            }
        }
    }

    fn shardfn(m: &Msg, num_shards: usize) -> usize {
        const FNV1_64_INIT: u64 = 0xcbf29ce484222325u64;
        const FNV_64_PRIME: u64 = 0x100000001b3u64;
        if num_shards == 0 {
            return 0;
        }

        let mut hash = FNV1_64_INIT;
        for b in m.key().as_bytes()[0..4].iter() {
            hash ^= *b as u64;
            hash = u64::wrapping_mul(hash, FNV_64_PRIME);
        }

        hash as usize % num_shards
    }
}
