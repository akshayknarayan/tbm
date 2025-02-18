//! RPC pings.

#![warn(clippy::all)]

use bertha::ChunnelConnection;
use color_eyre::eyre::WrapErr;
use color_eyre::eyre::{bail, eyre, Report};
use futures_util::stream::TryStreamExt;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Debug;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{atomic::AtomicUsize, Arc};
use std::time::Duration;
use tls_tunnel::TlsConnAddr;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, debug_span, info, instrument, trace, trace_span};
use tracing_futures::Instrument;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Work {
    Immediate,
    Const(u64),
    Poisson(u64),
    BusyTimeConst(u64),
    BusyWorkConst(u64),
}

impl FromStr for Work {
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<_> = s.split(':').collect();
        match &sp[..] {
            [variant] if *variant == "immediate" || *variant == "imm" => Ok(Work::Immediate),
            [variant, amt] if *variant == "const" => Ok(Work::Const(amt.parse()?)),
            [variant, amt] if *variant == "poisson" => Ok(Work::Poisson(amt.parse()?)),
            [variant, amt] if *variant == "busytime" || *variant == "bt" => {
                Ok(Work::BusyTimeConst(amt.parse()?))
            }
            [variant, amt] if *variant == "busywork" || *variant == "bw" => {
                Ok(Work::BusyWorkConst(amt.parse()?))
            }
            x => {
                bail!("Could not parse work: {:?}", x)
            }
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PingParams {
    pub work: Work,
    pub padding: Vec<u8>,
}

impl std::fmt::Debug for PingParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingParams")
            .field("work", &self.work)
            .field("padding", &self.padding.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Pong {
    pub duration_us: i64,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Msg {
    Ping(usize, PingParams),
    Pong(usize, Pong),
}

impl From<Pong> for Msg {
    fn from(p: Pong) -> Self {
        Msg::Pong(get_id(), p)
    }
}

impl From<PingParams> for Msg {
    fn from(p: PingParams) -> Self {
        Msg::Ping(get_id(), p)
    }
}

impl Msg {
    fn pong_with_id(id: usize, p: Pong) -> Self {
        Msg::Pong(id, p)
    }
}

fn get_id() -> usize {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}

impl bertha::util::MsgId for Msg {
    fn id(&self) -> usize {
        use Msg::*;
        match self {
            Ping(x, _) | Pong(x, _) => *x,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Server {
    req_cnt: Arc<AtomicUsize>,
    collect_traces: Option<UnboundedSender<()>>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            req_cnt: Arc::new(0.into()),
            collect_traces: None,
        }
    }
}

impl Server {
    pub fn set_trace_collection_trigger(&mut self, collect_traces: Option<UnboundedSender<()>>) {
        self.collect_traces = collect_traces;
    }

    pub fn get_counter(&self) -> Arc<AtomicUsize> {
        self.req_cnt.clone()
    }

    pub async fn do_ping(&mut self, ping_req: PingParams) -> Result<Pong, Report> {
        let then = std::time::Instant::now();

        self.req_cnt
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        match ping_req.work {
            Work::Immediate => (),
            Work::Const(amt) => {
                tokio::time::sleep(Duration::from_micros(amt)).await;
            }
            Work::Poisson(amt) => {
                tokio::time::sleep(gen_poisson_duration(amt as f64)?).await;
            }
            Work::BusyTimeConst(amt) => {
                let completion_time = then + Duration::from_micros(amt);
                while std::time::Instant::now() < completion_time {
                    // spin
                }
            }
            Work::BusyWorkConst(amt) => {
                // copy from shenango:
                // https://github.com/shenango/shenango/blob/master/apps/synthetic/src/fakework.rs#L54
                let k = 2350845.545;
                for i in 0..amt {
                    criterion::black_box(f64::sqrt(k * i as f64));
                }
            }
        }

        Ok(Pong {
            duration_us: then
                .elapsed()
                .as_micros()
                .try_into()
                .expect("u128 to i64 cast"),
        })
    }

    #[allow(clippy::unit_arg)] // https://github.com/tokio-rs/tracing/issues/1093
    #[instrument(skip(self, l), err)]
    pub async fn serve<A: std::fmt::Debug>(
        self,
        l: impl futures_util::stream::Stream<
            Item = Result<impl ChunnelConnection<Data = (A, crate::Msg)>, Report>,
        >,
        timeout_conns: bool,
    ) -> Result<(), Report> {
        let mut conn_ctr = 0;
        l.try_for_each_concurrent(None, |cn| {
            let mut srv = self.clone();
            let ctr = conn_ctr;
            conn_ctr += 1;
            async move {
                debug!("New connection");
                loop {
                    let (a, i, p) = match tokio::time::timeout(
                        std::time::Duration::from_millis(1000),
                        cn.recv(),
                    )
                    .instrument(trace_span!("listen_req"))
                    .await
                    {
                        Ok(Ok((a, Msg::Ping(i, p)))) => (a, i, p),
                        Ok(Err(e)) => {
                            debug!(err = %format!("{:#}", e), "Connection recv error, terminating");
                            return Ok(());
                        }
                        Ok(Ok(d)) => bail!("Expected PingParams, got {:?}", d),
                        Err(_to) if timeout_conns => {
                            debug!("Connection timing out");
                            if let Some(ref ch) = srv.collect_traces {
                                ch.send(()).expect("Receiver won't drop");
                            }
                            return Ok(());
                        }
                        Err(_) => {
                            continue;
                        }
                    };
                    trace!("got req");
                    let ans: Pong = srv.do_ping(p).await.unwrap();
                    trace!("sending resp");
                    cn.send((a, Msg::pong_with_id(i, ans)))
                        .instrument(trace_span!("send_resp"))
                        .await?;
                }
            }
            .instrument(debug_span!("connection", ?ctr))
        })
        .await?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ConnData {
    conn_idx: usize,
    conn_time: Duration,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Datapoint {
    conn_idx: usize,
    req_idx: usize,
    exp_time: Duration,
    rtt: i64,
    srv_time: i64,
}

#[derive(Debug, Default, Clone)]
pub struct Data {
    conns: Vec<ConnData>,
    reqs: Vec<Datapoint>,
}

impl Data {
    fn with_capacity(conns: usize, per_iter: usize) -> Self {
        Self {
            conns: Vec::with_capacity(conns),
            reqs: Vec::with_capacity(conns * per_iter),
        }
    }
}

#[instrument(skip(addr, connector, msg), err)]
pub async fn client_ping<A, C, F, S>(
    addr: A,
    connector: C,
    msg: PingParams,
    iters: usize,
    reqs_per_iter: usize,
) -> Result<Data, Report>
where
    A: Clone,
    C: Fn(A) -> F,
    F: Future<Output = Result<S, Report>>,
    S: ChunnelConnection<Data = Msg> + Send + 'static,
{
    let mut data = Data::with_capacity(iters, reqs_per_iter);
    let start = std::time::Instant::now();
    for i in 0..iters {
        trace!(iter = i, "start_loop");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let then = std::time::Instant::now();
        let st = connector(addr.clone())
            .instrument(tracing::trace_span!("connector", iter = i))
            .await
            .wrap_err("could not connect")?;
        let conntime = then.elapsed();
        trace!(iter = i, "connected");
        for j in 0..reqs_per_iter {
            let reqtime = start.elapsed();
            trace!(iter = i, which = j, "ping_start");
            let (tot, srv) = do_one_ping(&st, msg.clone(), i, j).await?;
            trace!(iter = i, which = j, "ping_end");
            data.reqs.push(Datapoint {
                conn_idx: i,
                req_idx: j,
                exp_time: reqtime,
                rtt: tot,
                srv_time: srv,
            });
        }

        let elap = then.elapsed();
        trace!(iter = i, overall_time = ?elap, "end_loop");
        data.conns.push(ConnData {
            conn_idx: i,
            conn_time: conntime,
        });
    }

    dump_durs(&data);
    Ok(data)
}

async fn do_one_ping(
    cn: &impl ChunnelConnection<Data = Msg>,
    msg: PingParams,
    iter: usize,
    which: usize,
) -> Result<(i64, i64), Report> {
    let then = std::time::Instant::now();
    let mut ctr = 0;
    let msg: Msg = msg.into();
    loop {
        match cn
            .send(msg.clone())
            .instrument(tracing::trace_span!("req", ?iter, ?which))
            .await
            .wrap_err(eyre!("ping send #{:?},{:?}", iter, which))
        {
            Ok(_) => break,
            Err(e) => {
                if ctr > 5 {
                    return Err(e).wrap_err(eyre!("attempt #{:?}", ctr));
                }

                trace!(err = %format!("{:#?}", e), "send failed, retry");
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
        ctr += 1;
    }
    trace!(?iter, ?which, "send done");
    let response = match cn
        .recv()
        .instrument(tracing::trace_span!("resp", ?iter, ?which))
        .await
        .wrap_err("pong recv")?
    {
        Msg::Pong(_, p) => p,
        _ => bail!("Didn't receive Pong"),
    };

    let elap = then.elapsed().as_micros().try_into()?;
    let srv_dur = response.duration_us;
    Ok((elap, srv_dur))
}

fn gen_poisson_duration(amt: f64) -> Result<std::time::Duration, Report> {
    let mut rng = rand::thread_rng();
    use rand_distr::{Distribution, Poisson};
    let pois = Poisson::new(amt as f64).map_err(|e| eyre!("Invalid amount {}: {:?}", amt, e))?;
    Ok(std::time::Duration::from_micros(pois.sample(&mut rng)))
}

pub fn write_durs(path: &std::path::Path, data: Data) -> Result<(), Report> {
    debug!("writing latencies file");
    let mut f = std::fs::File::create(path).wrap_err(eyre!("Create file: {:?}", path))?;
    writeln!(
        &mut f,
        "Conn_idx,Conn_time_us,Req_idx,Elapsed_us,Total_us,Server_us"
    )?;

    for ConnData {
        conn_idx: idx,
        conn_time,
        ..
    } in data.conns
    {
        for Datapoint {
            req_idx,
            exp_time,
            rtt,
            srv_time,
            ..
        } in data
            .reqs
            .iter()
            .filter(|Datapoint { conn_idx, .. }| *conn_idx == idx)
        {
            writeln!(
                &mut f,
                "{},{},{},{},{},{}",
                idx,
                conn_time.as_micros(),
                req_idx,
                exp_time.as_micros(),
                rtt,
                srv_time,
            )?;
        }
    }

    Ok(())
}

pub fn write_tracing<S, E>(
    path: &std::path::Path,
    downcaster: tracing_timing::LayerDowncaster<S, E>,
    d: &tracing::Dispatch,
    tag: &str,
) -> Result<(), Report>
where
    S: tracing_timing::SpanGroup + 'static,
    E: tracing_timing::EventGroup + 'static,
    S::Id: Clone + std::hash::Hash + Eq + std::fmt::Display + 'static,
    E::Id: Clone + std::hash::Hash + Eq + std::fmt::Display + 'static,
{
    let mut f = std::fs::File::create(path)?;
    let timing = downcaster
        .downcast(d)
        .ok_or_else(|| eyre!("downcast timing layer"))?;
    timing.force_synchronize();
    // these values are in nanoseconds
    timing.with_histograms(|hs| {
        for (span_group, hs) in hs {
            for (event_group, h) in hs {
                writeln!(
                    &mut f,
                    "{} {}:{} (ns:min,p25,p50,p75,p95): {} {} {} {} {} {} {}",
                    tag,
                    span_group,
                    event_group,
                    h.min(),
                    h.value_at_quantile(0.25),
                    h.value_at_quantile(0.5),
                    h.value_at_quantile(0.75),
                    h.value_at_quantile(0.95),
                    h.max(),
                    h.len(),
                )
                .expect("write to trace file");
            }
        }
    });

    Ok(())
}

pub trait AsEncryptOpt {
    fn gt_root(&self) -> Option<PathBuf>;
    fn unix_root(&self) -> PathBuf;
}

#[derive(Debug, Clone)]
pub struct EncryptOpt {
    unix_root: PathBuf,
    ghostunnel_root: PathBuf,
}

impl EncryptOpt {
    pub fn from(o: &impl AsEncryptOpt) -> Option<Self> {
        o.gt_root().as_ref().map(|gt| EncryptOpt {
            ghostunnel_root: gt.clone(),
            unix_root: o.unix_root(),
        })
    }

    pub fn unix_root(&self) -> PathBuf {
        self.unix_root.clone()
    }

    pub fn bin_path(&self) -> PathBuf {
        self.ghostunnel_root.join("ghostunnel")
    }

    pub fn cert_dir_path(&self) -> PathBuf {
        self.ghostunnel_root.join("test-keys/")
    }
}

fn dump_durs(data: &Data) {
    let mut just_durs: Vec<_> = data.reqs.iter().map(|Datapoint { rtt, .. }| rtt).collect();
    just_durs.sort();
    let len = just_durs.len() as f64;
    let quantile_idxs = [0.25, 0.5, 0.75, 0.95];
    let req_quantiles: Vec<_> = quantile_idxs
        .iter()
        .map(|q| (len * q) as usize)
        .map(|i| just_durs[i])
        .collect();
    let mut conn_durs: Vec<_> = data
        .conns
        .iter()
        .map(|ConnData { conn_time, .. }| conn_time)
        .collect();
    conn_durs.sort();
    let len = conn_durs.len() as f64;
    let conn_quantiles: Vec<_> = quantile_idxs
        .iter()
        .map(|q| (len * q) as usize)
        .map(|i| conn_durs[i])
        .collect();
    info!(?conn_quantiles, ?req_quantiles, "done");
    println!("conn quantiles: {:?}", conn_quantiles);
    println!("req quantiles: {:?}", req_quantiles);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TlsWrapAddr(SocketAddr, TlsConnAddr);

impl From<(SocketAddr, TlsConnAddr)> for TlsWrapAddr {
    fn from((s, t): (SocketAddr, TlsConnAddr)) -> TlsWrapAddr {
        Self(s, t)
    }
}

impl localname_ctl::GetSockAddr for TlsWrapAddr {
    fn as_sk_addr(&self) -> SocketAddr {
        self.0
    }
}

impl tls_tunnel::GetTlsConnAddr for TlsWrapAddr {
    fn as_tlsconn_addr(&self) -> TlsConnAddr {
        self.1
    }
}

impl From<SocketAddr> for TlsWrapAddr {
    fn from(s: SocketAddr) -> Self {
        Self(s, Default::default())
    }
}

#[cfg(test)]
mod test {
    use super::Report;
    use bertha::{
        bincode::SerializeChunnelProject,
        either::Either,
        negotiate_client, negotiate_server,
        udp::{UdpReqChunnel, UdpSkChunnel},
        uds::UnixSkChunnel,
        util::ProjectLeft,
        ChunnelConnector, ChunnelListener, CxList,
    };
    use color_eyre::eyre::WrapErr;
    use localname_ctl::{ctl::serve_ctl, LocalNameChunnel};
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use tracing::{info, info_span, instrument};
    use tracing_error::ErrorLayer;
    use tracing_futures::Instrument;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    #[test]
    fn rpcbench_ping() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        color_eyre::install().unwrap_or(());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let addr = "127.0.0.1:18649".parse().unwrap();
        let root = PathBuf::from("./tmp-test-ping/");
        test_util::reset_root_dir(&root);

        #[instrument]
        async fn server(root: PathBuf, addr: SocketAddr) -> Result<(), Report> {
            let srv = super::Server::default();
            let lch = LocalNameChunnel::new(
                root.clone(),
                Some(addr),
                UnixSkChunnel::with_root(root.clone()),
                SerializeChunnelProject::default(),
            )
            .await?;
            let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);
            info!("Serving localname mode");
            let st = negotiate_server(stack, UdpReqChunnel.listen(addr).await?).await?;
            srv.serve(st, false).await
        }

        rt.block_on(
            async move {
                // start ctl
                tokio::spawn(serve_ctl(Some(root.clone()), true));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                tokio::spawn(server(root.clone(), addr));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                let fncl = |addr| {
                    let r = root.clone();
                    async move {
                        let lch = LocalNameChunnel::new(
                            r.clone(),
                            None,
                            UnixSkChunnel::with_root(r),
                            SerializeChunnelProject::default(),
                        )
                        .await?;
                        let stack = CxList::from(SerializeChunnelProject::default()).wrap(lch);
                        let cn =
                            negotiate_client(stack, UdpSkChunnel.connect(()).await?, addr).await?;
                        let cn = ProjectLeft::new(Either::Left(addr), cn);
                        Ok(cn)
                    }
                };

                super::client_ping(
                    addr,
                    fncl,
                    super::PingParams {
                        work: super::Work::Immediate,
                        padding: vec![],
                    },
                    2, // iters
                    3, // reqs_per_iter
                )
                .await
                .wrap_err("client_ping")
            }
            .instrument(info_span!("rpcbench_ping")),
        )
        .unwrap();
    }
}
