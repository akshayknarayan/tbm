use bertha::{
    bincode::SerializeChunnelProject,
    negotiate_server,
    udp::UdpReqChunnel,
    uds::{UnixReqChunnel, UnixSkChunnel},
    ChunnelListener, CxList,
};
use color_eyre::eyre::{bail, eyre, Report, WrapErr};
use localname_ctl::{MicroserviceChunnel, MicroserviceTLSChunnel};
use rpcbench::{EncryptOpt, TlsWrapAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use structopt::StructOpt;
use tls_tunnel::{TLSChunnel, TlsConnAddr};
use tracing::info;
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, StructOpt)]
#[structopt(name = "ping_server")]
struct Opt {
    #[structopt(short, long)]
    unix_addr: Option<PathBuf>,
    #[structopt(short, long)]
    port: Option<u16>,
    #[structopt(long)]
    burrito_root: Option<PathBuf>,

    #[structopt(long, default_value = "/tmp")]
    encr_unix_root: PathBuf,
    #[structopt(long)]
    encr_ghostunnel_root: Option<PathBuf>,

    #[structopt(short, long)]
    out_file: Option<PathBuf>,
}

impl rpcbench::AsEncryptOpt for Opt {
    fn gt_root(&self) -> Option<PathBuf> {
        self.encr_ghostunnel_root.clone()
    }
    fn unix_root(&self) -> PathBuf {
        self.encr_unix_root.clone()
    }
}

#[tracing::instrument(skip(srv))]
async fn unix(srv: rpcbench::Server, addr: PathBuf) -> Result<(), Report> {
    info!(?addr, "Serving unix-only mode");
    let st = negotiate_server(
        SerializeChunnelProject::default(),
        UnixReqChunnel.listen(addr).await?,
    )
    .await?;
    srv.serve(st, true).await
}

#[tracing::instrument(skip(srv))]
async fn udp(srv: rpcbench::Server, port: u16, enc: Option<EncryptOpt>) -> Result<(), Report> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    info!(?port, encrypt = enc.is_some(), "Serving udp mode");
    if let Some(enc) = enc {
        let tls =
            TLSChunnel::<TlsConnAddr>::new(enc.unix_root(), enc.bin_path(), enc.cert_dir_path())
                .listen(addr);
        let st = negotiate_server(
            CxList::from(SerializeChunnelProject::default()).wrap(tls),
            UdpReqChunnel::default().listen(addr).await?,
        )
        .await?;
        srv.serve(st, true).await
    } else {
        let st = negotiate_server(
            CxList::from(SerializeChunnelProject::default()),
            UdpReqChunnel::default().listen(addr).await?,
        )
        .await?;
        srv.serve(st, true).await
    }
}

#[tracing::instrument(skip(srv))]
async fn burrito(
    srv: rpcbench::Server,
    port: u16,
    root: PathBuf,
    enc: Option<EncryptOpt>,
) -> Result<(), Report> {
    use tls_tunnel::TlsConnAddr;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);

    if let Some(enc) = enc {
        let tls =
            TLSChunnel::<TlsWrapAddr>::new(enc.unix_root(), enc.bin_path(), enc.cert_dir_path())
                .listen(addr);
        let lch = MicroserviceTLSChunnel::<_, _, TlsWrapAddr>::server(
            tls,
            root.clone(),
            (addr, TlsConnAddr::Request).into(),
            UnixSkChunnel::with_root(root.clone()),
            bertha::CxNil,
        )
        .await?;
        let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);

        info!(?port, ?root, "Serving localname mode with encryption");
        let st = negotiate_server(stack, UdpReqChunnel.listen(addr).await?).await?;
        srv.serve(st, true).await
    } else {
        let lch = MicroserviceChunnel::<_, _, SocketAddr>::server(
            root.clone(),
            addr,
            UnixSkChunnel::with_root(root.clone()),
            bertha::CxNil,
        )
        .await?;
        let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);

        info!(?port, ?root, "Serving localname mode without encryption");
        let st = negotiate_server(stack, UdpReqChunnel.listen(addr).await?).await?;
        srv.serve(st, true).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    color_eyre::install().unwrap();
    let mut opt = Opt::from_args();
    let subscriber = tracing_subscriber::registry();
    let trigger_trace_rewrite = if let Some(path) = opt.out_file.take() {
        let timing_layer = tracing_timing::Builder::default()
            .no_span_recursion()
            .span_close_events()
            .layer(|| tracing_timing::Histogram::new_with_max(1_000_000, 2).unwrap());
        let timing_downcaster = timing_layer.downcaster();
        let subscriber = subscriber
            .with(timing_layer)
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.clone().init();
        // sends on s trigger rewrites on r.
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while r.recv().await.is_some() {
                rpcbench::write_tracing(&path, timing_downcaster, &d, "")
                    .wrap_err(eyre!("write to {:?}", path))
                    .expect("write tracing");
            }
        });
        Some(s)
    } else {
        let subscriber = subscriber
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.init();
        None
    };

    let mut srv = rpcbench::Server::default();
    srv.set_trace_collection_trigger(trigger_trace_rewrite);

    if let Some(path) = opt.unix_addr {
        return unix(srv, path).await;
    }

    if opt.port.is_none() {
        bail!("Must specify port if not using unix address");
    }

    let encrypt = EncryptOpt::from(&opt);
    let port = opt.port.unwrap();
    if let Some(root) = opt.burrito_root {
        return burrito(srv, port, root, encrypt).await;
    }

    udp(srv, port, encrypt).await
}
