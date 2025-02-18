use super::eyre::{eyre, Report, WrapErr};
use super::ShardCanonicalServer;
use crate::ShardInfo;
use bertha::{negotiate::StackNonce, Chunnel, ChunnelConnection, IpPort, Negotiate};
use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};
use tracing_futures::Instrument;

/// A chunnel managing a sharded service.
///
/// Forwards incoming messages to one of the internal connections specified by `ShardInfo` after
/// evaluating the sharding function. Also registers with shard-ctl, which will perform other setup
/// (loading XDP program, answering client queries, etc).
#[derive(Clone)]
pub struct ShardCanonicalServerEbpf<A, S, Ss, D> {
    inner: ShardCanonicalServer<A, S, Ss, D>,
    handles: Arc<Mutex<HashMap<String, xdp_shard::BpfHandles<xdp_shard::Ingress>>>>,
}

impl<A: std::fmt::Debug, S, Ss, D> std::fmt::Debug for ShardCanonicalServerEbpf<A, S, Ss, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardCanonicalServerEbpf")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<A, S, Ss, D> ShardCanonicalServerEbpf<A, S, Ss, D>
where
    A: Clone + std::fmt::Debug,
{
    /// Inner is a chunnel for the external connection.
    /// Shards is a chunnel for an internal connection to the shards.
    pub async fn new(
        addr: ShardInfo<A>,
        internal_addr: Option<Vec<A>>,
        shards_inner: S,
        shards_inner_stack: Ss,
        shards_extern_nonce: StackNonce,
        redis_addr: &str,
    ) -> Result<Self, Report> {
        let inner = ShardCanonicalServer::new(
            addr,
            internal_addr,
            shards_inner,
            shards_inner_stack,
            shards_extern_nonce,
            redis_addr,
        )
        .await?;

        Ok(ShardCanonicalServerEbpf {
            inner,
            handles: Default::default(),
        })
    }

    /// Future which will poll stats from the ebpf program.
    ///
    /// If file is Some, the stats will be dumped to the file in addition to being logged via
    /// the tracing crate.
    pub async fn log_shard_stats(&self, file: Option<std::fs::File>) {
        read_shard_stats(Arc::clone(&self.handles), file)
            .instrument(tracing::info_span!("read-shard-stats"))
            .await
            .expect("read_shard_stats")
    }
}

fn get_addr_from_nonce(nonce: &[u8]) -> Result<SocketAddrV4, Report> {
    use bertha::negotiate::NegotiateMsg;
    let msg: NegotiateMsg = bincode::deserialize(nonce).wrap_err("Deserialize nonce")?;
    match msg {
        NegotiateMsg::ServerNonce { addr, .. } => {
            match bincode::deserialize(&addr).wrap_err("Deserialize socket addr") {
                Ok(SocketAddr::V4(addr)) => Ok(addr),
                Ok(a) => Err(eyre!("ipv6 addrs not supported: {}", a)),
                _ => Err(eyre!("Deserialize addr from nonce")),
            }
        }
        _ => Err(eyre!("malformed nonce")),
    }
}

impl<A, S, Ss, D, Cap> Negotiate for ShardCanonicalServerEbpf<A, S, Ss, D>
where
    Cap: bertha::negotiate::CapabilitySet,
    ShardCanonicalServer<A, S, Ss, D>: Negotiate<Capability = Cap>,
{
    type Capability = Cap;

    fn guid() -> u64 {
        0xe91d00534cb2b99f
    }

    fn capabilities() -> Vec<Cap> {
        ShardCanonicalServer::<A, S, Ss, D>::capabilities()
    }

    fn picked<'s>(&mut self, nonce: &'s [u8]) -> Pin<Box<dyn Future<Output = ()> + Send + 's>> {
        let addr = get_addr_from_nonce(nonce);

        let inner_fut = self.inner.picked(nonce);
        let handles = Arc::clone(&self.handles);
        Box::pin(async move {
            match addr {
                Ok(addr) => {
                    let client_addr = addr.ip();
                    let client_port = addr.port();
                    let mut h = handles.lock().await;
                    for (_, iface_handle) in h.iter_mut() {
                        if let Err(e) = iface_handle.register_client(*client_addr, client_port) {
                            debug!(err = %format!("{:#}", e), ?client_addr, ?client_port, "client not registered");
                        }
                    }
                }
                Err(e) => {
                    debug!(err = %format!("{:#}", e), "client not registered");
                }
            }

            inner_fut.await
        })
    }
}

impl<I, A, S, Ss, D, Ic, Ie> Chunnel<I> for ShardCanonicalServerEbpf<A, S, Ss, D>
where
    A: Clone + IpPort + Sync + Send + 'static,
    ShardCanonicalServer<A, S, Ss, D>: Chunnel<I, Connection = Ic, Error = Ie>,
    Ic: ChunnelConnection + Send + 'static,
    Ie: Send + Sync + 'static,
{
    type Connection = Ic;
    type Error = Ie;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect_wrap(&mut self, inner: I) -> Self::Future {
        let fut = self.inner.connect_wrap(inner);
        let addr = self.inner.addr.clone();
        let handles = Arc::clone(&self.handles);
        Box::pin(async move {
            register_shardinfo(handles, addr.clone())
                .instrument(tracing::debug_span!("register-shardinfo-ebpf"))
                .await;
            fut.await
        })
    }
}

async fn clear_port<T>(handles: Arc<Mutex<HashMap<String, xdp_shard::BpfHandles<T>>>>, port: u16) {
    let mut map = handles.lock().await;
    for h in map.values_mut() {
        if let Err(e) = h.clear_port(port) {
            debug!(err = ?e, port = ?port, "Failed to clear port map");
        }
    }
}

pub(crate) async fn register_shardinfo<A: IpPort + Clone>(
    handles: Arc<Mutex<HashMap<String, xdp_shard::BpfHandles<xdp_shard::Ingress>>>>,
    si: ShardInfo<A>,
) {
    let shard_ports: Vec<u16> = si.shard_addrs.iter().map(|a| a.port()).collect();
    let sk = si.canonical_addr.clone();

    clear_port(handles.clone(), sk.port()).await;

    // see if handles are there already
    let ifnames = match xdp_shard::get_interface_name(sk.ip()) {
        Ok(ifnames) => ifnames,
        Err(e) => {
            warn!(err = ?e, ip = ?sk.ip(), port = ?sk.port(), "Error getting interface");
            return;
        }
    };

    let mut map = handles.lock().await;
    for ifn in ifnames {
        if !map.contains_key(&ifn) {
            let l = xdp_shard::BpfHandles::<xdp_shard::Ingress>::load_on_interface_name(&ifn);
            let handle = match l {
                Ok(s) => s,
                Err(e) => {
                    warn!(err = %format!("{:#}", e), ifn = ?&ifn, "Error loading xdp-shard");
                    return;
                }
            };

            info!(service_ip = ?&si.canonical_addr.ip(), service_port = ?&si.canonical_addr.port(), "Loaded XDP program");

            map.insert(ifn.clone(), handle);
        }

        let h = map.get_mut(&ifn).unwrap();
        let ok = h.shard_ports(
            sk.port(),
            &shard_ports[..],
            si.shard_info.packet_data_offset,
            si.shard_info.packet_data_length,
        );
        match ok {
            Ok(_) => (),
            Err(e) => {
                warn!(
                    err = ?e,
                    ifn = ?&ifn,
                    port = ?sk.port(),
                    shard_port = ?&shard_ports[..],
                    "Error writing xdp-shard ports",
                );
                return;
            }
        }

        info!(
            service_ip = ?si.canonical_addr.ip(),
            service_port = ?si.canonical_addr.port(),
            interface = ?&ifn,
            "Registered sharding with XDP program"
        );
    }
}

pub(crate) async fn read_shard_stats(
    handles: Arc<Mutex<HashMap<String, xdp_shard::BpfHandles<xdp_shard::Ingress>>>>,
    mut stats_log: Option<std::fs::File>,
) -> Result<(), Report> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut first = true;
    let start = std::time::Instant::now();
    loop {
        interval.tick().await;
        for (inf, handle) in handles.lock().await.iter_mut() {
            match handle.get_stats() {
                Ok((c, p)) => {
                    let mut c = c.get_rxq_cpu_port_count();
                    xdp_shard::diff_maps(&mut c, &p.get_rxq_cpu_port_count());
                    trace!("logging XDP stats");
                    // c: rxq_id -> cpu_id -> port -> count
                    for (rxq_id, cpu_map) in c.iter().enumerate() {
                        for (cpu_id, port_map) in cpu_map.iter().enumerate() {
                            for (port, count) in port_map.iter() {
                                info!(
                                    interface = ?inf,
                                    rxq = ?rxq_id,
                                    cpu = ?cpu_id,
                                    port = ?port,
                                    count = ?count,
                                    "XDP stats"
                                );

                                if let Some(ref mut f) = stats_log {
                                    use std::io::Write;
                                    if first {
                                        if let Err(e) = write!(f, "Time CPU Rxq Port Count\n") {
                                            debug!(err = ?e, "Failed writing to stats_log");
                                            continue;
                                        }

                                        first = false;
                                    }

                                    if let Err(e) = write!(
                                        f,
                                        "{} {} {} {} {}\n",
                                        start.elapsed().as_secs_f32(),
                                        cpu_id,
                                        rxq_id,
                                        port,
                                        count
                                    ) {
                                        debug!(err = ?e, "Failed writing to stats_log");
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(err = ?e, "Could not get rxq stats");
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::ShardCanonicalServerEbpf;
    use crate::test::{start_shard, Msg};
    use crate::{Kv, ShardInfo};
    use bertha::{
        bincode::SerializeChunnelProject,
        chan_transport::RendezvousChannel,
        negotiate::Offer,
        reliable::ReliabilityProjChunnel,
        tagger::TaggerProjChunnel,
        udp::{UdpReqChunnel, UdpSkChunnel},
        util::ProjectLeft,
        ChunnelConnection, ChunnelConnector, ChunnelListener, CxList,
    };
    use futures_util::TryStreamExt;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tracing::{debug_span, info, warn};
    use tracing_error::ErrorLayer;
    use tracing_futures::Instrument;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    #[test]
    fn shard_negotiate_ebpf() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        color_eyre::install().unwrap_or(());

        // 0. Make rt.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(
            async move {
                let (_redis_h, canonical_addr) = shard_setup_ebpf(45215, 41421).await;
                info!("make client");
                let udp_addr = canonical_addr;
                let neg_stack = CxList::from(TaggerProjChunnel)
                    .wrap(ReliabilityProjChunnel::default())
                    .wrap(SerializeChunnelProject::default());

                let raw_cn = UdpSkChunnel::default().connect(()).await.unwrap();
                let cn = bertha::negotiate::negotiate_client(neg_stack, raw_cn, udp_addr)
                    .await
                    .unwrap();
                let cn = ProjectLeft::new(udp_addr, cn);

                // 6. issue a request
                info!("send request");
                cn.send(Msg {
                    k: "aaaaaaaa".to_owned(),
                    v: "bbbbbbbb".to_owned(),
                })
                .await
                .unwrap();

                info!("await response");
                let m = cn.recv().await.unwrap();
                assert_eq!(m.key(), "aaaaaaaa");
                assert_eq!(m.val(), "bbbbbbbb");
            }
            .instrument(debug_span!("negotiate_ebpf")),
        );
    }

    async fn shard_setup_ebpf(redis_port: u16, srv_port: u16) -> (test_util::Redis, SocketAddr) {
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

        let stack = CxList::from(TaggerProjChunnel)
            .wrap(ReliabilityProjChunnel::default())
            .wrap(SerializeChunnelProject::default());
        let offer = offers.pop().unwrap().pop().unwrap();
        let esrv =
            ShardCanonicalServerEbpf::new(si.clone(), internal_cli, stack, offer, &redis_addr)
                .await
                .unwrap();
        let external = CxList::from(esrv)
            .wrap(TaggerProjChunnel)
            .wrap(ReliabilityProjChunnel::default())
            .wrap(SerializeChunnelProject::default());
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
                            loop {
                                let _: Option<(_, Msg)> = r.recv().await?; // ShardCanonicalServerConnection is recv-only
                            }
                        }
                    })
                    .instrument(tracing::info_span!("negotiate_server"))
                    .await
                {
                    warn!(err = ?e, "canonical server crashed");
                    panic!(e);
                }
            }
            .instrument(tracing::info_span!("canonicalsrv", addr = ?&si.canonical_addr)),
        );

        (redis_guard, si.canonical_addr)
    }
}
