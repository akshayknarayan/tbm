use bertha::{
    bincode::SerializeChunnelProject, either::Either, negotiate_client, udp::UdpSkChunnel,
    uds::UnixSkChunnel, util::ProjectLeft, ChunnelConnector, ClientNegotiator, CxList,
};
use color_eyre::eyre::{bail, Report, WrapErr};
use localname_ctl::{EitherAddr, MicroserviceChunnel, MicroserviceTLSChunnel};
use rpcbench::{EncryptOpt, TlsWrapAddr};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use structopt::StructOpt;
use tls_tunnel::{TLSChunnel, TlsConnAddr};
use tokio::sync::Mutex;
use tracing::{debug, info};
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy)]
enum NegotiationMode {
    OneRtt,
    ZeroRtt,
}

impl std::str::FromStr for NegotiationMode {
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "false" | "off" => bail!("No-negotiation removed"),
            "true" | "one" => NegotiationMode::OneRtt,
            "zero" => NegotiationMode::ZeroRtt,
            s => bail!(
                "Invalid NegotiationMode value {:?} not in [off, one, zero]",
                s
            ),
        })
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "ping_client")]
struct Opt {
    #[structopt(short, long)]
    burrito_root: Option<PathBuf>,
    #[structopt(long)]
    addr: Option<SocketAddr>,
    #[structopt(long)]
    unix_addr: Option<PathBuf>,

    #[structopt(long)]
    negotiation: NegotiationMode,

    #[structopt(short, long)]
    work: rpcbench::Work,
    #[structopt(short, long)]
    size_of_req: Option<usize>,
    #[structopt(short, long)]
    iters: usize,
    #[structopt(long)]
    reqs_per_iter: usize,

    #[structopt(long, default_value = "/tmp")]
    encr_unix_root: PathBuf,
    #[structopt(long)]
    encr_ghostunnel_root: Option<PathBuf>,

    #[structopt(short, long)]
    out_file: Option<std::path::PathBuf>,
}

impl rpcbench::AsEncryptOpt for Opt {
    fn gt_root(&self) -> Option<PathBuf> {
        self.encr_ghostunnel_root.clone()
    }
    fn unix_root(&self) -> PathBuf {
        self.encr_unix_root.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    color_eyre::install().unwrap();
    let opt = Opt::from_args();
    let subscriber = tracing_subscriber::registry();
    let timing_downcaster = if opt.out_file.is_some() {
        let timing_layer = tracing_timing::Builder::default()
            .no_span_recursion()
            .span_close_events()
            .spans(|s: &tracing::span::Attributes| {
                let mut val = s.metadata().name().to_owned();
                let mut f = |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                    if field.name() == "which" {
                        val.push_str(&format!(" which={:?}", value));
                    };
                };
                s.record(&mut f);
                val
            })
            .events(|e: &tracing::Event| {
                let mut val = String::new();
                let mut f = |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                    if field.name() == "message" {
                        val.push_str(&format!(" {:?} ", value));
                    } else if field.name() == "which" {
                        val.push_str(&format!(" which={:?} ", value));
                    };
                };
                e.record(&mut f);
                val
            })
            .layer(|| tracing_timing::Histogram::new_with_max(1_000_000, 2).unwrap());
        let timing_downcaster = timing_layer.downcaster();
        let subscriber = subscriber
            .with(timing_layer)
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.clone().init();
        Some((timing_downcaster, d))
    } else {
        let subscriber = subscriber
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.init();
        None
    };

    let enc = EncryptOpt::from(&opt);

    let pp = rpcbench::PingParams {
        work: opt.work,
        padding: vec![0u8; opt.size_of_req.unwrap_or_default()],
    };

    let per_iter = opt.reqs_per_iter;
    let out_file = opt.out_file.clone();
    let data = match (opt, enc) {
        (
            Opt {
                unix_addr: Some(addr),
                burrito_root,
                iters,
                reqs_per_iter,
                negotiation,
                ..
            },
            _,
        ) => {
            // raw unix mode
            info!(?addr, "uds mode");
            let ctr = |addr: PathBuf| {
                let br = burrito_root.clone();
                async move {
                    let u = if let Some(r) = br {
                        UnixSkChunnel::with_root(r).connect(()).await?
                    } else {
                        UnixSkChunnel::default().connect(()).await?
                    };
                    let cn = negotiate_client(SerializeChunnelProject::default(), u, addr.clone())
                        .await?;
                    Ok(ProjectLeft::new(addr, cn))
                }
            };

            let did_first_round: Arc<AtomicBool> = Default::default();
            let cl_neg = Arc::new(Mutex::new(ClientNegotiator::default()));
            let zerortt_ctr = |addr: PathBuf| {
                let br = burrito_root.clone();
                let did_first_round = Arc::clone(&did_first_round);
                let cl_neg = Arc::clone(&cl_neg);
                async move {
                    let u = if let Some(r) = br {
                        UnixSkChunnel::with_root(r).connect(()).await?
                    } else {
                        UnixSkChunnel::default().connect(()).await?
                    };

                    let mut cl_neg = cl_neg.lock().await;
                    let stack = SerializeChunnelProject::default();
                    if !did_first_round.load(Ordering::SeqCst) {
                        let cn = cl_neg.negotiate_fetch_nonce(stack, u, addr.clone()).await?;
                        did_first_round.store(true, Ordering::SeqCst);
                        Ok(ProjectLeft::new(addr, Either::Left(cn)))
                    } else {
                        let cn = cl_neg.negotiate_zero_rtt(stack, u, addr.clone()).await?;
                        Ok(ProjectLeft::new(addr, Either::Right(cn)))
                    }
                }
            };

            match negotiation {
                NegotiationMode::OneRtt => {
                    rpcbench::client_ping(addr, ctr, pp, iters, reqs_per_iter).await?
                }
                NegotiationMode::ZeroRtt => {
                    rpcbench::client_ping(addr, zerortt_ctr, pp, iters, reqs_per_iter).await?
                }
            }
        }
        (
            Opt {
                burrito_root: Some(root),
                addr: Some(addr),
                iters,
                reqs_per_iter,
                negotiation,
                ..
            },
            None,
        ) => {
            let fncl = |addr| {
                let r = root.clone();
                async move {
                    let sk = UdpSkChunnel.connect(()).await?;
                    let lch = MicroserviceChunnel::<_, _, SocketAddr>::client(
                        r.clone(),
                        addr,
                        sk.local_addr()?,
                        UnixSkChunnel::with_root(r),
                        bertha::CxNil,
                    )
                    .await?;
                    let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);
                    let cn = negotiate_client(stack, sk, addr).await?;
                    Ok(ProjectLeft::new(EitherAddr::Global(addr), cn))
                }
            };

            let did_first_round: Arc<AtomicBool> = Default::default();
            let cl_neg = Arc::new(Mutex::new(ClientNegotiator::default()));
            let zerortt_fncl = |addr| {
                let did_first_round = Arc::clone(&did_first_round);
                let cl_neg = Arc::clone(&cl_neg);
                let r = root.clone();
                async move {
                    let sk = UdpSkChunnel.connect(()).await?;
                    let lch = MicroserviceChunnel::<_, _, SocketAddr>::client(
                        r.clone(),
                        addr,
                        sk.local_addr()?,
                        UnixSkChunnel::with_root(r),
                        bertha::CxNil,
                    )
                    .await?;
                    let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);
                    let mut cl_neg = cl_neg.lock().await;

                    if !did_first_round.load(Ordering::SeqCst) {
                        let cn = cl_neg.negotiate_fetch_nonce(stack, sk, addr).await?;
                        did_first_round.store(true, Ordering::SeqCst);
                        Ok(ProjectLeft::new(EitherAddr::Global(addr), Either::Left(cn)))
                    } else {
                        let cn = cl_neg.negotiate_zero_rtt(stack, sk, addr).await?;
                        Ok(ProjectLeft::new(
                            EitherAddr::Global(addr),
                            Either::Right(cn),
                        ))
                    }
                }
            };
            info!(
                ?root,
                ?addr,
                encryption = "no",
                ?negotiation,
                "Burrito mode"
            );

            match negotiation {
                NegotiationMode::OneRtt => {
                    rpcbench::client_ping(addr, fncl, pp, iters, reqs_per_iter).await?
                }
                NegotiationMode::ZeroRtt => {
                    rpcbench::client_ping(addr, zerortt_fncl, pp, iters, reqs_per_iter).await?
                }
            }
        }
        (
            Opt {
                burrito_root: Some(root),
                addr: Some(addr),
                iters,
                reqs_per_iter,
                negotiation,
                ..
            },
            Some(enc),
        ) => {
            let fncl = |(addr, x)| {
                let enc = enc.clone();
                let r = root.clone();
                async move {
                    let sk = UdpSkChunnel.connect(()).await?;
                    let tls = TLSChunnel::<TlsWrapAddr>::new(
                        enc.unix_root(),
                        enc.bin_path(),
                        enc.cert_dir_path(),
                    )
                    .connect(addr);
                    let lch = MicroserviceTLSChunnel::<_, _, TlsWrapAddr>::client(
                        tls,
                        r.clone(),
                        (addr, TlsConnAddr::Request).into(),
                        (sk.local_addr()?, TlsConnAddr::Request).into(),
                        UnixSkChunnel::with_root(r),
                        bertha::CxNil,
                    )
                    .await?;
                    let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);
                    let cn = negotiate_client(stack, sk, addr)
                        .await
                        .wrap_err("burrito-mode yes-neg connector")?;
                    Ok(ProjectLeft::new(EitherAddr::Global((addr, x).into()), cn))
                }
            };

            let did_first_round: Arc<AtomicBool> = Default::default();
            let cl_neg = Arc::new(Mutex::new(ClientNegotiator::default()));
            let zerortt_fncl = |(addr, x)| {
                let did_first_round = Arc::clone(&did_first_round);
                let cl_neg = Arc::clone(&cl_neg);
                let enc = enc.clone();
                let r = root.clone();
                async move {
                    let sk = UdpSkChunnel.connect(()).await?;
                    let tls = TLSChunnel::<TlsWrapAddr>::new(
                        enc.unix_root(),
                        enc.bin_path(),
                        enc.cert_dir_path(),
                    )
                    .connect(addr);
                    let lch = MicroserviceTLSChunnel::<_, _, TlsWrapAddr>::client(
                        tls,
                        r.clone(),
                        (addr, TlsConnAddr::Request).into(),
                        (sk.local_addr()?, TlsConnAddr::Request).into(),
                        UnixSkChunnel::with_root(r),
                        bertha::CxNil,
                    )
                    .await?;
                    let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);
                    let mut cl_neg = cl_neg.lock().await;

                    if !did_first_round.load(Ordering::SeqCst) {
                        let cn = cl_neg
                            .negotiate_fetch_nonce(stack, sk, addr)
                            .await
                            .wrap_err("burrito-mode first-round yes-neg connector")?;
                        did_first_round.store(true, Ordering::SeqCst);
                        Ok(ProjectLeft::new(
                            EitherAddr::Global((addr, x).into()),
                            Either::Left(cn),
                        ))
                    } else {
                        let cn = cl_neg.negotiate_zero_rtt(stack, sk, addr).await?;
                        Ok(ProjectLeft::new(
                            EitherAddr::Global((addr, x).into()),
                            Either::Right(cn),
                        ))
                    }
                }
            };

            info!(
                ?root,
                ?addr,
                encryption = "yes",
                ?negotiation,
                "Burrito mode"
            );

            match negotiation {
                NegotiationMode::OneRtt => {
                    rpcbench::client_ping(
                        (addr, TlsConnAddr::Request),
                        fncl,
                        pp,
                        iters,
                        reqs_per_iter,
                    )
                    .await?
                }
                NegotiationMode::ZeroRtt => {
                    rpcbench::client_ping(
                        (addr, TlsConnAddr::Request),
                        zerortt_fncl,
                        pp,
                        iters,
                        reqs_per_iter,
                    )
                    .await?
                }
            }
        }
        (
            Opt {
                burrito_root: None,
                addr: Some(addr),
                iters,
                reqs_per_iter,
                negotiation,
                ..
            },
            None,
        ) => {
            // raw udp mode
            info!(?addr, encrypt = "no", "UDP mode");
            let fncl = |addr| async move {
                let cn = negotiate_client(
                    SerializeChunnelProject::default(),
                    UdpSkChunnel.connect(()).await?,
                    addr,
                )
                .await?;
                Ok(ProjectLeft::new(addr, cn))
            };

            let did_first_round: Arc<AtomicBool> = Default::default();
            let cl_neg = Arc::new(Mutex::new(ClientNegotiator::default()));
            let zerortt_fncl = |addr| {
                let did_first_round = Arc::clone(&did_first_round);
                let cl_neg = Arc::clone(&cl_neg);
                async move {
                    let stack = SerializeChunnelProject::default();
                    let mut cl_neg = cl_neg.lock().await;
                    if !did_first_round.load(Ordering::SeqCst) {
                        let cn = cl_neg
                            .negotiate_fetch_nonce(stack, UdpSkChunnel.connect(()).await?, addr)
                            .await?;
                        did_first_round.store(true, Ordering::SeqCst);
                        Ok(ProjectLeft::new(addr, Either::Left(cn)))
                    } else {
                        let cn = cl_neg
                            .negotiate_zero_rtt(stack, UdpSkChunnel.connect(()).await?, addr)
                            .await?;
                        Ok(ProjectLeft::new(addr, Either::Right(cn)))
                    }
                }
            };

            match negotiation {
                NegotiationMode::OneRtt => {
                    rpcbench::client_ping(addr, fncl, pp, iters, reqs_per_iter).await?
                }
                NegotiationMode::ZeroRtt => {
                    rpcbench::client_ping(addr, zerortt_fncl, pp, iters, reqs_per_iter).await?
                }
            }
        }
        (
            Opt {
                burrito_root: None,
                addr: Some(addr),
                iters,
                reqs_per_iter,
                negotiation,
                ..
            },
            Some(enc),
        ) => {
            // raw udp mode
            info!(?addr, encrypt = "yes", "UDP mode");
            let fncl = |addr| {
                let enc = enc.clone();
                async move {
                    let tls = TLSChunnel::<TlsConnAddr>::new(
                        enc.unix_root(),
                        enc.bin_path(),
                        enc.cert_dir_path(),
                    )
                    .connect(addr);
                    let cn = negotiate_client(
                        CxList::from(SerializeChunnelProject::default()).wrap(tls),
                        UdpSkChunnel.connect(()).await?,
                        addr,
                    )
                    .await?;
                    Ok(ProjectLeft::new(TlsConnAddr::Request, cn))
                }
            };

            let did_first_round: Arc<AtomicBool> = Default::default();
            let cl_neg = Arc::new(Mutex::new(ClientNegotiator::default()));
            let zerortt_fncl = |addr| {
                let did_first_round = Arc::clone(&did_first_round);
                let cl_neg = Arc::clone(&cl_neg);
                let enc = enc.clone();
                async move {
                    let tls = TLSChunnel::<TlsConnAddr>::new(
                        enc.unix_root(),
                        enc.bin_path(),
                        enc.cert_dir_path(),
                    )
                    .connect(addr);
                    let stack = CxList::from(SerializeChunnelProject::default()).wrap(tls);
                    let mut cl_neg = cl_neg.lock().await;
                    if !did_first_round.load(Ordering::SeqCst) {
                        let cn = cl_neg
                            .negotiate_fetch_nonce(stack, UdpSkChunnel.connect(()).await?, addr)
                            .await?;
                        did_first_round.store(true, Ordering::SeqCst);
                        Ok(ProjectLeft::new(TlsConnAddr::Request, Either::Left(cn)))
                    } else {
                        let cn = cl_neg
                            .negotiate_zero_rtt(stack, UdpSkChunnel.connect(()).await?, addr)
                            .await?;
                        Ok(ProjectLeft::new(TlsConnAddr::Request, Either::Right(cn)))
                    }
                }
            };

            match negotiation {
                NegotiationMode::OneRtt => {
                    rpcbench::client_ping(addr, fncl, pp, iters, reqs_per_iter).await?
                }
                NegotiationMode::ZeroRtt => {
                    rpcbench::client_ping(addr, zerortt_fncl, pp, iters, reqs_per_iter).await?
                }
            }
        }
        _ => {
            bail!("Bad option set");
        }
    };

    info!("done");
    if let Some(ref path) = out_file {
        rpcbench::write_durs(path, data)?;

        debug!("writing trace file");
        let (downcaster, d) = timing_downcaster.unwrap();
        let path = path.with_extension("trace");
        rpcbench::write_tracing(&path, downcaster, &d, &per_iter.to_string())?;
    }
    Ok(())
}
