//! Server side.

use crate::msg::Msg;
use crate::reliability::KvReliabilityServerChunnel;
use bertha::{
    bincode::SerializeChunnel, chan_transport::RendezvousChannel, negotiate::StackNonce,
    ChunnelConnection, ChunnelListener, CxList,
};
use color_eyre::eyre::{Report, WrapErr};
use futures_util::stream::{Stream, TryStreamExt};
use shard_ctl::ShardInfo;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tracing::{debug_span, error, info, info_span, trace_span, warn};
use tracing_futures::Instrument;

mod serve_lb;
mod single_shard;
mod udp_to_shard;

pub use serve_lb::serve_lb;
pub use single_shard::single_shard;
pub use udp_to_shard::UdpToShard;

/// Start and serve a `ShardCanonicalServer` and `num_shards` shards.
///
/// Need to avoid use of `tokio::spawn` since this interferes with `Datapath::DpdkMultiThread`
/// configurations.
///
/// `raw_listener`: A ChunnelListener that can return `Data = (SocketAddr, Vec<u8>)`
/// `ChunnelConnection`s.
/// `redis_addr`: Address of a redis instance.
/// `srv_ip`: Local ip to serve on.
/// `srv_port`: Local port to serve on.
/// `num_shards`: Number of shards to start. Shard addresses are selected sequentially after
/// `srv_port`, but this could change.
/// `ready`: An optional notification for after setup and negotiation are done and before we start serving.
/// `batching`: Which [`BatchMode`] to use.
pub fn serve(
    mut raw_listener: impl ChunnelListener<
            Addr = SocketAddr,
            Connection = impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)>
                             + udp_to_shard::Connected
                             + Send
                             + Sync
                             + 'static,
            Error = impl Into<Report> + Send + Sync + 'static,
        > + Clone
        + Send
        + Sync
        + 'static,
    redis_addr: SocketAddr,
    srv_ip: IpAddr,
    srv_port: u16,
    num_shards: u16,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
    no_negotiation: bool,
) -> Result<(), Report> {
    // 1. Define addr.
    let si = make_shardinfo(srv_ip, srv_port, num_shards);

    // 2. start shard serv
    let (internal_srv, internal_cli) = RendezvousChannel::<SocketAddr, _, _>::new(100).split();
    let rdy = futures_util::stream::FuturesUnordered::new();
    for a in si.clone().shard_addrs {
        info!(addr = ?&a, "start shard");
        let (s, r) = tokio::sync::oneshot::channel();
        let int_srv = internal_srv.clone();
        let listener = raw_listener.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(err) => {
                    error!(?err, "Could not start tokio runtime for shard thread");
                    return;
                }
            };
            match rt.block_on(
                single_shard(a, listener, None, Some(int_srv), false, s, no_negotiation)
                    .instrument(debug_span!("shardsrv", addr = ?&a)),
            ) {
                Ok(_) => (),
                Err(err) => {
                    error!(?err, "Shard errored");
                }
            }
        });
        rdy.push(r);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        if no_negotiation {
            info!("no negotiation: no serve_canonical needed");
            futures_util::future::pending().await
        } else {
            let mut offers: Vec<Vec<StackNonce>> = rdy.try_collect().await.unwrap();

            let st = raw_listener
                .listen(si.canonical_addr)
                .await
                .map_err(Into::into)
                .wrap_err("Listen on raw_listener")?;
            serve_canonical(
                si,
                st.map_err(Into::into),
                internal_cli,
                redis_addr,
                offers.pop().unwrap(),
                ready,
            )
            .await
        }
    })
}

#[tracing::instrument(skip(st, internal_cli, redis_addr, offer, ready), level = "debug", err)]
async fn serve_canonical(
    si: ShardInfo<SocketAddr>,
    st: impl Stream<
            Item = Result<
                impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
                Report,
            >,
        > + Send
        + 'static,
    internal_cli: RendezvousChannel<SocketAddr, Vec<u8>, bertha::chan_transport::Cln>,
    redis_addr: SocketAddr,
    mut offer: Vec<StackNonce>,
    ready: impl Into<Option<tokio::sync::oneshot::Sender<()>>>,
) -> Result<(), Report> {
    let redis_addr = format!("redis://{}:{}", redis_addr.ip(), redis_addr.port());

    macro_rules! serve_stack {
        ($negotiator: path, $stack: expr) => {{
            info!(shard_info = ?&si, "start canonical server");
            let st = $negotiator($stack, st) // bertha::negotiate::negotiate_server
                .instrument(info_span!("negotiate_server"))
                .await
                .wrap_err("negotiate_server")?;

            if let Some(ready) = ready.into() {
                ready.send(()).unwrap_or_default();
            }

            let ctr: Arc<AtomicUsize> = Default::default();
            tokio::pin!(st);
            st.try_for_each_concurrent(None, |r| {
                let ctr = Arc::clone(&ctr);
                let mut slot = [None];
                async move {
                    let ctr = ctr.fetch_add(1, Ordering::SeqCst);
                    loop {
                        match tokio::time::timeout(std::time::Duration::from_millis(500), async { r
                            .recv(&mut slot) // ShardCanonicalServerConnection is recv-only
                            .instrument(trace_span!("shard-canonical-server-connection", ?ctr)).await
                            .wrap_err("kvstore/server: Error while processing requests")
                        })
                            .await.wrap_err("kvstore/server: Error in serving canonical connection")
                            {
                                Ok(Err(e)) | Err(e) => {
                                    warn!(err = ?e, ?ctr, "exiting connection loop");
                                    break Ok(());
                                }
                                Ok(_) => {}
                            }
                    }
                }
            }).await?;
        }}
    }

    let shard_stack =
        CxList::from(KvReliabilityServerChunnel::default()).wrap(SerializeChunnel::default());

    #[cfg(not(feature = "ebpf"))]
    let cnsrv = shard_ctl::ShardCanonicalServer::new(
        si.clone(),
        None,
        internal_cli,
        shard_stack,
        Some(offer.pop().unwrap()),
        &redis_addr,
    )
    .await
    .wrap_err("Create ShardCanonicalServer")?;

    #[cfg(feature = "ebpf")]
    let cnsrv = shard_ctl::ShardCanonicalServerEbpf::new(
        si.clone(),
        None,
        internal_cli,
        shard_stack,
        offer.pop().unwrap(),
        &redis_addr,
    )
    .await
    .wrap_err("Create ShardCanonicalServer")?;
    let external = CxList::from(cnsrv)
        .wrap(KvReliabilityServerChunnel::default())
        .wrap(SerializeChunnel::<Msg>::default());
    serve_stack!(bertha::negotiate::negotiate_server, external);

    unreachable!() // negotiate_server never returns None
}

fn make_shardinfo(srv_ip: IpAddr, srv_port: u16, num_shards: u16) -> ShardInfo<SocketAddr> {
    let shard_addrs = (1..=num_shards)
        .map(|i| SocketAddr::new(srv_ip, srv_port + i))
        .collect();
    ShardInfo {
        canonical_addr: SocketAddr::new(srv_ip, srv_port),
        shard_addrs,
    }
}
