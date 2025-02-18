//! Sharding chunnel.

// Pin<Box<...>> is necessary and not worth breaking up
#![allow(clippy::type_complexity)]

use bertha::{
    enumerate_enum,
    negotiate::{Apply, GetOffers},
    Chunnel, ChunnelConnection, ChunnelConnector, IpPort, Negotiate,
};
use color_eyre::eyre;
use eyre::{eyre, Error, WrapErr};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, debug_span};
use tracing_futures::Instrument;

pub const CONTROLLER_ADDRESS: &str = "shard-ctl";

mod redis_util;

/// Request type for servers registering.
///
/// The Addr type is to parameterize by the inner chunnel's addr type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo<Addr> {
    pub canonical_addr: Addr,
    pub shard_addrs: Vec<Addr>,
}

impl<A> IpPort for ShardInfo<A>
where
    A: IpPort,
{
    fn ip(&self) -> std::net::IpAddr {
        self.canonical_addr.ip()
    }

    fn port(&self) -> u16 {
        self.canonical_addr.port()
    }
}

/// Allow the shard chunnel to look into messages.
pub trait Kv {
    type Key;
    fn key(&self) -> Self::Key;

    type Val;
    fn val(&self) -> Self::Val;
}

impl<T> Kv for Option<T>
where
    T: Kv,
{
    type Key = Option<T::Key>;
    fn key(&self) -> Self::Key {
        self.as_ref().map(|t| t.key())
    }

    type Val = Option<T::Val>;
    fn val(&self) -> Self::Val {
        self.as_ref().map(|t| t.val())
    }
}

impl<T, U> Kv for (U, T)
where
    T: Kv,
{
    type Key = T::Key;
    fn key(&self) -> Self::Key {
        self.1.key()
    }

    type Val = T::Val;
    fn val(&self) -> Self::Val {
        self.1.val()
    }
}

const FNV1_64_INIT: u64 = 0xcbf29ce484222325u64;
const FNV_64_PRIME: u64 = 0x100000001b3u64;

enumerate_enum!(pub ShardFns, 0xe898734df758d0c0, Sharding);

mod server;
pub use server::{ShardCanonicalServer, ShardCanonicalServerConnection};

mod client;
pub use client::{ClientShardChunnelClient, ClientShardClientConnection};

mod shard_raw;
pub use shard_raw::ShardCanonicalServerRaw;

pub mod static_client;

#[cfg(feature = "ebpf")]
mod ebpf;
#[cfg(feature = "ebpf")]
pub use ebpf::ShardCanonicalServerEbpf;

#[cfg(test)]
mod test {
    use super::{ClientShardChunnelClient, Kv, ShardCanonicalServer, ShardInfo};
    use bertha::{
        bincode::SerializeChunnel,
        chan_transport::RendezvousChannel,
        negotiate::StackNonce,
        select::SelectListener,
        udp::{UdpReqChunnel, UdpSkChunnel},
        util::{Nothing, ProjectLeft},
        ChunnelConnection, ChunnelConnector, ChunnelListener, CxList,
    };
    use color_eyre::eyre;
    use eyre::{eyre, WrapErr};
    use futures_util::TryStreamExt;
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;
    use std::sync::Once;
    use tracing::{debug, debug_span, info, trace, warn};
    use tracing_error::ErrorLayer;
    use tracing_futures::Instrument;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    pub static COLOR_EYRE: Once = Once::new();

    #[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct Msg {
        pub(crate) k: String,
        pub(crate) v: String,
    }

    impl super::Kv for Msg {
        type Key = String;
        fn key(&self) -> Self::Key {
            self.k.clone()
        }
        type Val = String;
        fn val(&self) -> Self::Val {
            self.v.clone()
        }
    }

    pub(crate) async fn start_shard(
        addr: SocketAddr,
        internal_srv: RendezvousChannel<SocketAddr, Vec<u8>, bertha::chan_transport::Srv>,
        s: tokio::sync::oneshot::Sender<Vec<StackNonce>>,
    ) {
        let external = SerializeChunnel::default();
        let stack = external.clone();
        info!(addr = ?&addr, "listening");
        let st = SelectListener::new(UdpReqChunnel::default(), internal_srv)
            .listen(addr)
            .await
            .unwrap();
        trace!("got raw connection");
        let st = bertha::negotiate::negotiate_server(external, st)
            .await
            .unwrap();
        use bertha::GetOffers;
        s.send(stack.offers().collect()).unwrap();

        if let Err(e) = st
            .try_for_each_concurrent(None, |cn| {
                async move {
                    debug!("new");
                    let mut slots = [None, None, None, None];
                    loop {
                        let ms: &mut [Option<(_, Msg)>] = cn
                            .recv(&mut slots)
                            .await
                            .wrap_err("receive message error")?;
                        debug!("got msg batch");
                        // just echo.
                        cn.send(ms.iter_mut().map_while(Option::take))
                            .await
                            .wrap_err("send response err")?;
                        debug!("sent echo");
                    }
                }
                .instrument(debug_span!("shard_connection"))
            })
            .instrument(debug_span!("negotiate_server"))
            .await
        {
            warn!(shard_addr = ?addr, err = ?e, "Shard errorred");
            panic!("{}", e);
        }
    }

    #[test]
    fn single_shard() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));

        // 0. Make rt.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(
            async move {
                let addr: SocketAddr = "127.0.0.1:21422".parse().unwrap();
                let (s, r) = tokio::sync::oneshot::channel();

                let (internal_srv, mut internal_cli) =
                    RendezvousChannel::<SocketAddr, _, _>::new(100).split();

                info!(addr = ?&addr, "start shard");

                tokio::spawn(
                    start_shard(addr, internal_srv, s).instrument(debug_span!("shard thread")),
                );

                let _ = r.await.wrap_err("shard thread crashed").unwrap();
                let stack = SerializeChunnel::default();

                async fn do_msg(cn: impl ChunnelConnection<Data = Msg>) {
                    debug!("send request");
                    cn.send(std::iter::once(Msg {
                        k: "c".to_owned(),
                        v: "d".to_owned(),
                    }))
                    .await
                    .unwrap();

                    debug!("await response");
                    let mut slot = [None];
                    let ms = cn.recv(&mut slot).await.unwrap();
                    let m = ms[0].take().unwrap();
                    debug!(msg = ?m, "got response");
                    assert_eq!(m.key(), "c");
                    assert_eq!(m.val(), "d");
                }

                // udp connection
                async {
                    debug!("connect to shard");
                    let cn = UdpSkChunnel::default()
                        .connect(addr)
                        .await
                        .wrap_err("client connect")
                        .unwrap();
                    let cn = bertha::negotiate::negotiate_client(stack.clone(), cn, addr)
                        .await
                        .unwrap();
                    let cn = ProjectLeft::new(addr, cn);
                    do_msg(cn).await;
                }
                .instrument(tracing::info_span!("udp client"))
                .await;

                // channel connection
                async {
                    debug!("connect to shard");
                    let cn = internal_cli
                        .connect(addr)
                        .await
                        .wrap_err("client connect")
                        .unwrap();
                    let cn = bertha::negotiate::negotiate_client(stack.clone(), cn, addr)
                        .await
                        .unwrap();
                    let cn = ProjectLeft::new(addr, cn);
                    do_msg(cn).await;
                }
                .instrument(tracing::info_span!("chan client"))
                .await;
            }
            .instrument(debug_span!("single_shard")),
        );
    }

    async fn shard_setup(redis_port: u16, srv_port: u16) -> (test_util::Redis, SocketAddr) {
        // 1. start redis.
        let redis_addr = format!("redis://127.0.0.1:{}", redis_port);
        info!(port = ?redis_port, "start redis");
        let redis_guard = test_util::start_redis(redis_port);

        let shard1_port = srv_port + 1;
        let shard2_port = srv_port + 2;
        // 2. Define addr.
        let si: ShardInfo<SocketAddr> = ShardInfo {
            canonical_addr: format!("127.0.0.1:{}", srv_port).parse().unwrap(),
            shard_addrs: vec![
                format!("127.0.0.1:{}", shard1_port).parse().unwrap(),
                format!("127.0.0.1:{}", shard2_port).parse().unwrap(),
            ],
        };

        // 3. start shard serv
        let (internal_srv, internal_cli) =
            RendezvousChannel::<SocketAddr, Vec<u8>, _>::new(100).split();
        let rdy = futures_util::stream::FuturesUnordered::new();
        for a in si.clone().shard_addrs {
            info!(addr = ?&a, "start shard");
            let (s, r) = tokio::sync::oneshot::channel();
            let int_srv = internal_srv.clone();
            tokio::spawn(
                start_shard(a, int_srv, s).instrument(debug_span!("shardsrv", addr = ?&a)),
            );
            rdy.push(r);
        }

        let mut offers: Vec<Vec<StackNonce>> = rdy.try_collect().await.unwrap();

        // 4. start canonical server
        let cnsrv = ShardCanonicalServer::<_, _, _, (_, Msg)>::new(
            si.clone(),
            None,
            internal_cli,
            SerializeChunnel::default(),
            offers.pop().unwrap().pop().unwrap(),
            &redis_addr,
        )
        .await
        .unwrap();
        // UdpConn: (SocketAddr, Vec<u8>)
        // SerializeChunnelProject: (A, Vec<u8>) -> _
        // ReliabilityChunnel: (A, _) -> (A, (u32, Msg))
        // TaggerChunnel: (A, (u32, Msg)) -> (A, Msg)
        // ShardCanonicalServer: (A, Msg) -> ()
        let external = CxList::from(cnsrv).wrap(SerializeChunnel::default());
        info!(shard_info = ?&si, "start canonical server");
        let st = UdpReqChunnel::default()
            .listen(si.canonical_addr)
            .await
            .unwrap();
        let st = bertha::negotiate::negotiate_server(external, st)
            .instrument(tracing::info_span!("negotiate_server"))
            .await
            .unwrap();

        tokio::spawn(
            async move {
                if let Err(e) = st
                    .try_for_each_concurrent(None, |r| {
                        async move {
                            let mut slot = [None];
                            loop {
                                r.recv(&mut slot).await?; // ShardCanonicalServerConnection is recv-only
                            }
                        }
                    })
                    .instrument(tracing::info_span!("negotiate_server"))
                    .await
                {
                    warn!(err = ?e, "canonical server crashed");
                    panic!("{}", e);
                }
            }
            .instrument(tracing::info_span!("canonicalsrv", addr = ?&si.canonical_addr)),
        );

        (redis_guard, si.canonical_addr)
    }

    #[test]
    fn shard_negotiate_basicclient() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));

        // 0. Make rt.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(
            async move {
                // 0-4. make shard servers and shard canonical server
                let (_redis_h, canonical_addr) = shard_setup(35215, 31421).await;

                // 5. make client
                info!("make client");

                let neg_stack = SerializeChunnel::default();

                let raw_cn = UdpSkChunnel::default()
                    .connect(canonical_addr)
                    .await
                    .unwrap();
                let cn = bertha::negotiate::negotiate_client(neg_stack, raw_cn, canonical_addr)
                    .await
                    .unwrap();
                let cn = ProjectLeft::new(canonical_addr, cn);

                // 6. issue a request
                info!("send request");
                cn.send(std::iter::once(Msg {
                    k: "aaaaaaaa".to_owned(),
                    v: "bbbbbbbb".to_owned(),
                }))
                .await
                .unwrap();

                info!("await response");
                let mut slot = [None];
                let ms = cn.recv(&mut slot).await.unwrap();
                let m = ms[0].take().unwrap();
                use super::Kv;
                assert_eq!(m.key(), "aaaaaaaa");
                assert_eq!(m.val(), "bbbbbbbb");
            }
            .instrument(tracing::info_span!("negotiate_basicclient")),
        );
    }

    #[test]
    fn shard_negotiate_clientonly() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));

        // 0. Make rt.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(
            async move {
                // 0-4. make shard servers and shard canonical server
                let (redis_h, canonical_addr) = shard_setup(25215, 21421).await;

                // 5. make client
                info!("make client");
                let redis_addr = redis_h.get_addr();

                let cl = ClientShardChunnelClient::new(canonical_addr, &redis_addr)
                    .await
                    .unwrap();

                use bertha::negotiate::Select;
                let neg_stack = CxList::from(Select::from((cl, Nothing::<()>::default())))
                    .wrap(SerializeChunnel::default());

                let raw_cn = UdpSkChunnel::default()
                    .connect(canonical_addr)
                    .await
                    .unwrap();
                let cn = bertha::negotiate::negotiate_client(neg_stack, raw_cn, canonical_addr)
                    .await
                    .unwrap();
                let cn = ProjectLeft::new(canonical_addr, cn);

                // 6. issue a request
                info!("send request");
                cn.send(std::iter::once(Msg {
                    k: "aaaaaaaa".to_owned(),
                    v: "bbbbbbbb".to_owned(),
                }))
                .await
                .unwrap();

                info!("await response");
                let mut slot = [None];
                let ms = cn.recv(&mut slot).await.unwrap();
                let m = ms[0].take().unwrap();
                use super::Kv;
                assert_eq!(m.key(), "aaaaaaaa");
                assert_eq!(m.val(), "bbbbbbbb");
            }
            .instrument(tracing::info_span!("negotiate_clientonly")),
        );
    }
}
