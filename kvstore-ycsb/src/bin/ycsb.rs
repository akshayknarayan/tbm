use bertha::{ChunnelConnection, ChunnelConnector};
use color_eyre::eyre::{bail, ensure, eyre, Report, WrapErr};
use futures_util::{
    future::{select, Either},
    stream::{FuturesUnordered, Stream, StreamExt, TryStreamExt},
};
use kvstore::{bin::Datapath, KvClient, KvClientBuilder};
use kvstore_ycsb::{
    const_paced_ops_stream, dump_tracing, group_by_client, ops, poisson_paced_ops_stream,
    write_results, Op,
};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tracing::{debug, info, info_span, instrument, trace, warn};
use tracing_error::ErrorLayer;
use tracing_futures::Instrument;
use tracing_subscriber::prelude::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "kvclient")]
struct Opt {
    #[structopt(long)]
    addr: SocketAddr,

    #[structopt(long)]
    redis_addr: SocketAddr,

    #[structopt(short, long)]
    interarrival_client_micros: usize,

    #[structopt(long)]
    poisson_arrivals: bool,

    #[structopt(long)]
    accesses: PathBuf,

    #[structopt(short, long)]
    datapath: Datapath,

    #[structopt(short, long)]
    cfg: Option<PathBuf>,

    #[structopt(short, long, default_value = "4")]
    num_threads: usize,

    #[structopt(long)]
    use_clientsharding: bool,

    #[structopt(long)]
    skip_negotiation: Option<Vec<u16>>,

    #[structopt(short, long)]
    logging: bool,

    #[structopt(short, long)]
    tracing: bool,

    #[structopt(long)]
    loads_only: bool,

    #[structopt(long)]
    skip_loads: bool,

    #[structopt(short, long)]
    out_file: Option<PathBuf>,
}

fn main() -> Result<(), Report> {
    let opt = Opt::from_args();
    let tracing = if opt.logging && opt.tracing {
        let timing_layer = tracing_timing::Builder::default()
            .no_span_recursion()
            .layer(|| tracing_timing::Histogram::new_with_max(100_000_000, 3).unwrap());
        let timing_downcaster = timing_layer.downcaster();
        let subscriber = tracing_subscriber::registry()
            .with(timing_layer)
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.clone().init();
        color_eyre::install()?;
        Some((timing_downcaster, d))
    } else if opt.tracing {
        let timing_layer = tracing_timing::Builder::default()
            .no_span_recursion()
            .layer(|| tracing_timing::Histogram::new_with_max(100_000_000, 3).unwrap());
        let timing_downcaster = timing_layer.downcaster();
        let subscriber = tracing_subscriber::registry()
            .with(timing_layer)
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.clone().init();
        color_eyre::install()?;
        Some((timing_downcaster, d))
    } else if opt.logging {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.init();
        color_eyre::install()?;
        None
    } else {
        None
    };

    if opt.loads_only && opt.skip_loads {
        warn!("Doing only loads and skipping loads. Done.");
        return Err(eyre!("Cannot both do only loads and also skip them."));
    }

    let of = opt.out_file.clone();
    opt.datapath
        .validate_cfg(opt.cfg.as_ref().map(PathBuf::as_path))?;

    match opt.datapath {
        Datapath::Kernel => {
            let ctr = bertha::udp::UdpSkChunnel::default();
            do_exp(opt, ctr)
        }
        #[cfg(feature = "shenango-chunnel")]
        Datapath::Shenango if cfg!(feature = "shenango-chunnel") => {
            let ctr = shenango_chunnel::ShenangoUdpSkChunnel::new(
                opt.cfg.as_ref().map(PathBuf::as_path).unwrap(),
            );
            do_exp(opt, ctr)
        }
        Datapath::Shenango => {
            bail!("This binary was not compiled with shenango-chunnel support.");
        }
        #[cfg(feature = "dpdk-direct")]
        Datapath::DpdkSingleThread if cfg!(feature = "dpdk-direct") => {
            let ctr = dpdk_direct::DpdkUdpSkChunnel::new(
                opt.cfg.as_ref().map(PathBuf::as_path).unwrap(),
            )?;
            do_exp(opt, ctr)
        }
        #[cfg(feature = "dpdk-direct")]
        Datapath::DpdkMultiThread if cfg!(feature = "dpdk-direct") => {
            let ctr = dpdk_direct::DpdkInlineChunnel::new(
                opt.cfg.clone().expect("Needed config file not found"),
                opt.num_threads,
            )?;
            do_exp(opt, ctr)
        }
        _ => {
            bail!("This binary was not compiled with dpdk-direct support.");
        }
    }?;

    if let Some((td, d)) = tracing {
        if let Some(of) = of {
            let timing = td.downcast(&d).expect("downcast timing layer");
            let fname = of.with_extension("trace");
            let mut f = std::fs::File::create(&fname).unwrap();
            dump_tracing(timing, &mut f)?;
        }
    }

    Ok(())
}

fn do_exp(
    opt: Opt,
    ctr: impl ChunnelConnector<
            Addr = SocketAddr,
            Connection = impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
            Error = impl Into<Report> + Send + Sync + 'static,
        > + Clone
        + Send
        + Sync
        + 'static,
) -> Result<(), Report> {
    let loads_ctr = ctr.clone();
    if !opt.skip_loads {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let accesses = opt.accesses.clone();
        let skip_negotiation = opt.skip_negotiation.clone();
        rt.block_on(async move {
            info!("reading workload loads");
            let loads = ops(accesses.with_extension("load")).wrap_err("Reading loads")?;
            info!(num_ops = ?loads.len(), "done reading workload loads");

            if let Some(ref shards) = skip_negotiation {
                let mut fiat_client = KvClientBuilder::new(opt.addr)
                    .new_fiat_client(
                        loads_ctr
                            .clone()
                            .connect(opt.addr)
                            .await
                            .map_err(Into::into)?,
                        shard_ctl::ShardInfo {
                            canonical_addr: opt.addr,
                            shard_addrs: shards
                                .iter()
                                .map(|p| SocketAddr::new(opt.addr.ip(), *p))
                                .collect(),
                        },
                    )
                    .await?;
                do_loads(&mut fiat_client, loads)
                    .instrument(info_span!("loads"))
                    .await
            } else {
                let mut basic_client = KvClientBuilder::new(opt.addr)
                    .new_nonshardclient(
                        loads_ctr
                            .clone()
                            .connect(opt.addr)
                            .await
                            .map_err(Into::into)?,
                    )
                    .instrument(info_span!("make kvclient", client_id = "loads_client"))
                    .await?;
                do_loads(&mut basic_client, loads)
                    .instrument(info_span!("loads"))
                    .await
            }
        })?;
    } else {
        info!("skipping loads");
    }

    if opt.loads_only {
        info!("doing only loads, done");
        return Ok(());
    }

    info!("reading workload");
    let accesses = ops(opt.accesses).wrap_err("Reading accesses")?;
    info!(num_ops = ?accesses.len(), "done reading workload");

    let ExpResult {
        num_clients,
        durs,
        remaining_inflight,
        tot_time,
    } = if let Some(shard_ports) = opt.skip_negotiation {
        let make_fiat_client = move |_cid| {
            let mut ctr = ctr.clone();
            let shard_ports = shard_ports.clone();
            async move {
                KvClientBuilder::new(opt.addr)
                    .new_fiat_client(
                        ctr.connect(opt.addr).await.map_err(Into::into)?,
                        shard_ctl::ShardInfo {
                            canonical_addr: opt.addr,
                            shard_addrs: shard_ports
                                .clone()
                                .into_iter()
                                .map(|p| SocketAddr::new(opt.addr.ip(), p))
                                .collect(),
                        },
                    )
                    .await
            }
        };

        do_requests(
            accesses,
            opt.num_threads,
            opt.interarrival_client_micros as _,
            opt.poisson_arrivals,
            make_fiat_client,
        )?
    } else if !opt.use_clientsharding {
        info!(mode = "nonshardclient", "make clients");
        let make_client = move |cid| {
            let mut ctr = ctr.clone();
            async move {
                Ok::<_, Report>(
                    KvClientBuilder::new(opt.addr)
                        .new_nonshardclient(ctr.connect(opt.addr).await.map_err(Into::into)?)
                        .instrument(info_span!("make kvclient", client_id = ?cid))
                        .await
                        .wrap_err("make KvClient")?,
                )
            }
        };

        do_requests(
            accesses,
            opt.num_threads,
            opt.interarrival_client_micros as _,
            opt.poisson_arrivals,
            make_client,
        )?
    } else {
        info!(mode = "shardclient", "make clients");
        let make_client = move |cid| {
            let mut ctr = ctr.clone();
            async move {
                Ok::<_, Report>(
                    KvClientBuilder::new(opt.addr)
                        .new_shardclient(
                            ctr.connect(opt.addr).await.map_err(Into::into)?,
                            opt.redis_addr,
                        )
                        .instrument(info_span!("make kvclient", client_id = ?cid))
                        .await
                        .wrap_err("make KvClient")?,
                )
            }
        };

        do_requests(
            accesses,
            opt.num_threads,
            opt.interarrival_client_micros as _,
            opt.poisson_arrivals,
            make_client,
        )?
    };

    // done
    write_results(
        durs,
        remaining_inflight,
        tot_time,
        num_clients,
        opt.interarrival_client_micros,
        opt.out_file,
    );

    Ok(())
}

struct ExpResult {
    durs: Vec<Duration>,
    remaining_inflight: usize,
    tot_time: Duration,
    num_clients: usize,
}

/// Issue a workload of requests, divided by client worker.
///
/// Each client issues its requests open-loop. So we get one future per client, resolving to a
/// Result<Vec<durations, _>>.
/// Terminate once the first client finishes, since the load characteristics would change
/// otherwise.
///
/// Have to measure from the time the request leaves the queue.
fn do_requests<S, MC, Fut>(
    accesses: Vec<Op>, //HashMap<usize, (KvClient<S>, Vec<Op>)>,
    num_threads: usize,
    interarrival_micros: u64,
    poisson_arrivals: bool,
    make_client: MC,
) -> Result<ExpResult, Report>
where
    S: bertha::ChunnelConnection<Data = kvstore::Msg> + Send + Sync + 'static,
    MC: Fn(usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<KvClient<S>, Report>>,
{
    let access_by_client = group_by_client(accesses);
    let num_clients = access_by_client.len();
    let mut access_by_thread = {
        let mut threads = vec![vec![]; num_threads];
        for (client_id, ops) in access_by_client {
            threads[client_id % num_threads].push((client_id, ops));
        }

        threads
    };

    async fn time_req(
        cl: &KvClient<impl bertha::ChunnelConnection<Data = kvstore::Msg> + Send + Sync + 'static>,
        op: Op,
    ) -> Result<Duration, Report> {
        let now = tokio::time::Instant::now();
        let _ycsb_result = op.exec(&cl).await?;
        Ok::<_, Report>(now.elapsed())
    }

    #[instrument(level = "info", skip(cl, ops, done), err)]
    async fn req_loop(
        cl: KvClient<impl bertha::ChunnelConnection<Data = kvstore::Msg> + Send + Sync + 'static>,
        mut ops: impl Stream<Item = (usize, Op)> + Unpin + Send + 'static,
        done: tokio::sync::watch::Receiver<bool>,
        client_id: usize,
    ) -> Result<(Vec<Duration>, usize), Report> {
        let mut durs = vec![];
        let mut inflight = FuturesUnordered::new();
        let mut arrv = std::time::Instant::now();

        info!("starting ycsb client requests");
        loop {
            // first check for a finished request.
            let ops_val = match select(ops.next(), inflight.next()).await {
                Either::Right((Some(Ok(d)), _)) => {
                    trace!(inflight = inflight.len(), "request done");
                    durs.push(d);
                    None
                }
                Either::Right((Some(Err(e)), _)) => return Err(e),
                Either::Right((None, f)) => Some(f.await),
                Either::Left((x, _)) => Some(x),
            };

            // if after the above, something happened in incoming request stream -- either the
            // stream directly yielded, or inflight gave us None and we then waited for a request -- then handle that.
            if let Some(ov) = ops_val {
                match ov {
                    Some((remaining_cnt, o)) if remaining_cnt > 0 => {
                        inflight.push(time_req(&cl, o));
                        let interarrv = arrv.elapsed();
                        arrv = std::time::Instant::now();
                        trace!(
                            remaining_cnt,
                            inflight = inflight.len(),
                            ?interarrv,
                            "new request"
                        );
                    }
                    _ => {
                        info!(completed = durs.len(), "finished requests");
                        break;
                    }
                }
            }

            // This can't be inside the select because then the else clause would never be
            // triggered.
            if *done.borrow() {
                debug!(completed = durs.len(), "stopping");
                break; // the first client finished. stop.
            }
        }

        Ok::<_, Report>((durs, inflight.len()))
    }

    fn run_thread<S, MC, Fut>(
        thread_id: usize,
        done_tx: Arc<tokio::sync::watch::Sender<bool>>,
        done_rx: tokio::sync::watch::Receiver<bool>,
        start: Arc<tokio::sync::Barrier>,
        access_by_client: Vec<(usize, Vec<Op>)>,
        interarrival_micros: u64,
        poisson_arrivals: bool,
        make_client: Arc<MC>,
    ) -> Result<(Vec<Duration>, usize), Report>
    where
        S: bertha::ChunnelConnection<Data = kvstore::Msg> + Send + Sync + 'static,
        MC: Fn(usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<KvClient<S>, Report>>,
    {
        if access_by_client.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let mut reqs: FuturesUnordered<_> = access_by_client
                .into_iter()
                .map(|(client_id, ops)| {
                    assert!(!ops.is_empty());
                    let start = start.clone();
                    let done_rx = done_rx.clone();
                    let make_client = Arc::clone(&make_client);
                    async move {
                        let cl = make_client(client_id)
                            .await
                            .wrap_err("could not make client")?;
                        debug!(?thread_id, ?client_id, "wait for start barrier");
                        start.wait().await;
                        if poisson_arrivals {
                            let ops = poisson_paced_ops_stream(ops, interarrival_micros, client_id);
                            req_loop(cl, ops, done_rx.clone(), client_id).await
                        } else {
                            let ops = const_paced_ops_stream(ops, interarrival_micros, client_id);
                            req_loop(cl, ops, done_rx.clone(), client_id).await
                        }
                    }
                })
                .collect();

            // do the accesses until the first client is done.
            let (mut durs, mut remaining_inflight) = reqs
                .try_next()
                .await
                .wrap_err("error driving request loop")?
                .expect("No clients?");
            ensure!(!durs.is_empty(), "No requests finished");
            if !reqs.is_empty() {
                info!(?thread_id, "broadcasting done");
                done_tx
                    .send(true)
                    .wrap_err("failed to broadcast experiment termination")?;

                // collect all the requests that have completed.
                let rest_durs: Vec<(_, _)> = reqs
                    .try_collect()
                    .await
                    .wrap_err("error driving request loop")?;
                let (rest_durs, rest_left_inflight): (Vec<_>, Vec<_>) =
                    rest_durs.into_iter().unzip();
                assert!(!rest_durs.is_empty());
                info!(?thread_id, "all clients reported");
                durs.extend(rest_durs.into_iter().flat_map(|x| x.into_iter()));
                remaining_inflight += rest_left_inflight.into_iter().sum::<usize>();
            }

            Ok((durs, remaining_inflight))
        })
    }

    let start = Arc::new(tokio::sync::Barrier::new(num_clients));
    info!(?interarrival_micros, ?num_clients, "starting requests");
    let (done_tx, done_rx) = tokio::sync::watch::channel::<bool>(false);
    let done_tx = Arc::new(done_tx);
    let make_client = Arc::new(make_client);
    let mut threads = Vec::with_capacity(num_threads);
    for thread_id in 1..num_threads {
        let done_tx = done_tx.clone();
        let done_rx = done_rx.clone();
        let start = start.clone();
        let access_by_client = std::mem::take(&mut access_by_thread[thread_id]);
        let mc = Arc::clone(&make_client);
        let thread_jh = std::thread::spawn(move || {
            run_thread(
                thread_id,
                done_tx,
                done_rx,
                start,
                access_by_client,
                interarrival_micros,
                poisson_arrivals,
                mc,
            )
        });

        threads.push(thread_jh);
    }

    let access_start = tokio::time::Instant::now();
    // local thread
    let (mut durs, mut remaining_inflight) = run_thread(
        0,
        done_tx,
        done_rx,
        start,
        std::mem::take(&mut access_by_thread[0]),
        interarrival_micros,
        poisson_arrivals,
        make_client,
    )?;

    for t in threads {
        match t.join() {
            Ok(thread_res) => {
                let (thread_durs, thread_remaining) = thread_res?;
                durs.extend(thread_durs);
                remaining_inflight += thread_remaining;
            }
            Err(err) => std::panic::resume_unwind(err),
        }
    }

    let access_end = access_start.elapsed();
    Ok(ExpResult {
        durs,
        remaining_inflight,
        tot_time: access_end,
        num_clients,
    })
}

async fn do_loads<C>(cl: &mut KvClient<C>, loads: Vec<Op>) -> Result<(), Report>
where
    C: bertha::ChunnelConnection<Data = kvstore::Msg> + Send + Sync + 'static,
{
    info!("starting");
    // don't need to time the loads.
    for o in loads {
        trace!("starting load");
        match o {
            Op::Get(_, k) => cl.get(k).await?,
            Op::Update(_, k, v) => cl.update(k, v).await?,
        };

        trace!("finished load");
    }

    info!("done");
    Ok(())
}
