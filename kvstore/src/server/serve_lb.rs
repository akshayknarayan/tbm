use crate::msg::Msg;
use crate::reliability::KvReliabilityServerChunnel;
use crate::server::UdpToShard;
use bertha::{
    bincode::SerializeChunnel, ChunnelConnection, ChunnelConnector, ChunnelListener, CxList,
    GetOffers,
};
use color_eyre::eyre::{Report, WrapErr};
use futures_util::stream::TryStreamExt;
use shard_ctl::ShardInfo;
use std::net::SocketAddr;
use std::sync::{atomic::AtomicUsize, Arc};
use tracing::{debug_span, info, info_span, trace_span, warn};
use tracing_futures::Instrument;

macro_rules! serve {
    ($raw_listener: expr, $si: expr, $external: expr, $ready: expr) => {{
    let st = $raw_listener
        .listen($si.canonical_addr)
        .await
        .map_err(Into::into)
        .wrap_err("Listen on raw_listener")?;
    let st = bertha::negotiate::negotiate_server($external, st)
        .instrument(info_span!("negotiate_server"))
        .await
        .wrap_err("negotiate_server")?;

    if let Some(ready) = $ready.into() {
        ready.send(()).unwrap_or_default();
    }

    let ctr: Arc<AtomicUsize> = Default::default();
    tokio::pin!(st);
    st.try_for_each_concurrent(None, |cn| {
        let ctr = Arc::clone(&ctr);
        async move {
            let ctr = ctr.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            info!(?ctr, "established connection");
            let mut slot = [None];
            loop {
                if let Err(e) = cn
                    .recv(&mut slot) // ShardCanonicalServerConnection is recv-only
                    .instrument(trace_span!("shard-canonical-server-connection", ?ctr))
                    .await
                    .wrap_err("kvstore/serve_lb: Error in serving canonical connection")
                {
                    warn!(err = ?e, ?ctr, "exiting connection loop");
                    break Ok(());
                }
            }
        }
        .instrument(debug_span!("serve_lb_conn"))
    })
    .await?;

    unreachable!() // negotiate_server never returns None
    }}
}

/// Start and serve a load balancer, which just forwards connections to existing shards.
///
/// Don't call `spawn`.
pub async fn serve_lb(
    addr: SocketAddr,
    shards: Vec<SocketAddr>,
    mut raw_listener: impl ChunnelListener<
            Addr = SocketAddr,
            Connection = impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
            Error = impl Into<Report> + Send + Sync + 'static,
        > + Clone
        + Send
        + 'static,
    shards_internal: Vec<SocketAddr>,
    shard_connector: impl ChunnelConnector<
            Addr = SocketAddr,
            Connection = impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
            Error = impl Into<Report> + Send + Sync + 'static,
        > + Send
        + Sync
        + 'static,
    redis_addr: SocketAddr,
    ready: impl Into<Option<tokio::sync::oneshot::Sender<()>>>,
    opt: bool,
) -> Result<(), Report> {
    let si = ShardInfo {
        canonical_addr: addr,
        shard_addrs: shards,
    };

    info!(?si, "starting serve_lb");

    let shard_stack =
        CxList::from(KvReliabilityServerChunnel::default()).wrap(SerializeChunnel::default());
    let mut offer: Vec<_> = shard_stack.offers().collect();
    let redis_addr = format!("redis://{}:{}", redis_addr.ip(), redis_addr.port());

    let cnsrv = shard_ctl::ShardCanonicalServer::<_, _, _, (SocketAddr, Msg)>::new(
        si.clone(),
        Some(shards_internal),
        UdpToShard::new(shard_connector),
        shard_stack,
        Some(offer.pop().unwrap()),
        &redis_addr,
    )
    .await
    .wrap_err("Create ShardCanonicalServer")?;

    if opt {
        //use crate::opt::SerdeOpt;
        //let external = external.serde_opt();
        let cnsrv = shard_ctl::ShardCanonicalServerRaw::<_, _, _, _, 18>::from(cnsrv);
        let external = CxList::from(cnsrv).wrap(KvReliabilityServerChunnel::default());
        serve!(raw_listener, si, external, ready)
    } else {
        let external = CxList::from(cnsrv)
            .wrap(KvReliabilityServerChunnel::default())
            .wrap(SerializeChunnel::default());
        serve!(raw_listener, si, external, ready)
    }
}
