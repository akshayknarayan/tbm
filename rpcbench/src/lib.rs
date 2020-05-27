//! RPC utility library that connects either to a remote machine
//! or to a local pipe depending on what burrito-ctl says

use failure::Error;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use tracing::{span, trace, Level};
use tracing_futures::Instrument;

mod ping {
    tonic::include_proto!("ping");
}

pub use ping::ping_server::{Ping, PingServer};
pub use ping::{ping_params::Work, PingParams, Pong};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SPingParams {
    pub work: i32,
    pub amount: i64,
    pub padding: Vec<u8>,
}

impl From<PingParams> for SPingParams {
    fn from(p: PingParams) -> Self {
        Self {
            work: p.work,
            amount: p.amount,
            padding: p.padding,
        }
    }
}

impl Into<PingParams> for SPingParams {
    fn into(self) -> PingParams {
        PingParams {
            work: self.work,
            amount: self.amount,
            padding: self.padding,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SPong {
    pub duration_us: i64,
}

impl From<Pong> for SPong {
    fn from(p: Pong) -> Self {
        Self {
            duration_us: p.duration_us,
        }
    }
}

impl Into<Pong> for SPong {
    fn into(self) -> Pong {
        Pong {
            duration_us: self.duration_us,
        }
    }
}

use std::sync::{atomic::AtomicUsize, Arc};

#[derive(Clone, Debug)]
pub struct Server {
    req_cnt: Arc<AtomicUsize>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            req_cnt: Arc::new(0.into()),
        }
    }
}

impl Server {
    pub fn get_counter(&self) -> Arc<AtomicUsize> {
        self.req_cnt.clone()
    }

    pub async fn do_ping(
        &self,
        ping_req: PingParams,
    ) -> Result<Pong, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let span = span!(Level::DEBUG, "ping()", req = ?ping_req);
        let _span = span.enter();
        let then = std::time::Instant::now();

        let w: Work = Work::from_i32(ping_req.work).ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Unknown value {} for PingParams.Work", ping_req.work),
            )
        })?;

        self.req_cnt
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let amt = ping_req.amount.try_into().expect("u64 to i64 cast");

        match w {
            Work::Immediate => (),
            Work::Const => {
                let completion_time = then + std::time::Duration::from_micros(amt);
                tokio::time::delay_until(tokio::time::Instant::from_std(completion_time)).await;
            }
            Work::Poisson => {
                let completion_time = then + gen_poisson_duration(amt as f64)?;
                tokio::time::delay_until(tokio::time::Instant::from_std(completion_time)).await;
            }
            Work::BusyTimeConst => {
                let completion_time = then + std::time::Duration::from_micros(amt);
                while std::time::Instant::now() < completion_time {
                    // spin
                }
            }
            Work::BusyWorkConst => {
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
}

#[tonic::async_trait]
impl Ping for Server {
    async fn ping(
        &self,
        req: tonic::Request<PingParams>,
    ) -> Result<tonic::Response<Pong>, tonic::Status> {
        let ping_req = req.into_inner();
        let pong = self
            .do_ping(ping_req)
            .await
            .map_err(|e| tonic::Status::invalid_argument(format!("{:?}", e)))?;
        Ok(tonic::Response::new(pong))
    }
}

/// Issue many requests to a tonic endpoint.
#[tracing::instrument(skip(addr, connector))]
pub async fn client_ping<A, C>(
    addr: A,
    connector: C,
    msg: PingParams,
    iters: usize,
    reqs_per_iter: usize,
) -> Result<Vec<(std::time::Duration, i64, i64)>, Error>
where
    A: std::convert::TryInto<tonic::transport::Endpoint> + Clone,
    A::Error: Send + Sync + std::error::Error + 'static,
    C: tower_make::MakeConnection<hyper::Uri> + Send + 'static + Clone,
    C::Connection: Unpin + Send + 'static,
    C::Future: Send + 'static,
    Box<dyn std::error::Error + Send + Sync>: From<C::Error> + Send + 'static,
{
    let start = std::time::Instant::now();
    let mut durs = vec![];
    for i in 0..iters {
        trace!(iter = i, "start_loop");
        let ctr = connector.clone();
        let endpoint = addr.clone().try_into()?;

        let then = std::time::Instant::now();
        let channel = endpoint
            .tcp_nodelay(true)
            .connect_with_connector(ctr)
            .instrument(span!(Level::DEBUG, "connector"))
            .await?;
        trace!(iter = i, "connected");
        let mut client = ping::ping_client::PingClient::new(channel);

        for j in 0..reqs_per_iter {
            trace!(iter = i, which = j, "ping_start");
            let (tot, srv) = do_one_ping(&mut client, msg.clone()).await?;
            trace!(iter = i, which = j, "ping_end");
            durs.push((start.elapsed(), tot, srv));
        }

        let elap: i64 = then.elapsed().as_micros().try_into()?;
        trace!(iter = i, overall_time = elap, "end_loop");
    }

    Ok(durs)
}

async fn do_one_ping<T>(
    client: &mut ping::ping_client::PingClient<T>,
    msg: PingParams,
) -> Result<(i64, i64), Error>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::ResponseBody: tonic::body::Body + http_body::Body + Send + 'static,
    T::Error: Into<Box<dyn std::error::Error>>,
    <T::ResponseBody as http_body::Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync + 'static>> + Send,
{
    let req = tonic::Request::new(msg.clone());
    let then = std::time::Instant::now();
    let response = client
        .ping(req)
        .instrument(span!(Level::DEBUG, "tonic_ping"))
        .await?;
    let elap = then.elapsed().as_micros().try_into()?;
    let srv_dur = response.into_inner().duration_us;
    Ok((elap, srv_dur))
}

use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

#[tracing::instrument(skip(addr, connector))]
pub async fn bincode_client_ping<A, C, F, E, S>(
    addr: A,
    connector: C,
    msg: SPingParams,
    iters: usize,
    reqs_per_iter: usize,
) -> Result<Vec<(std::time::Duration, i64, i64)>, Error>
where
    A: Clone,
    C: Fn(A) -> F,
    F: Future<Output = Result<S, E>>,
    S: AsyncRead + AsyncWrite + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    let start = std::time::Instant::now();
    let mut durs = vec![];
    let mut buf = [0u8; 64];
    for i in 0..iters {
        trace!(iter = i, "start_loop");

        let then = std::time::Instant::now();
        let mut st = connector(addr.clone()).await?;
        trace!(iter = i, "connected");
        for j in 0..reqs_per_iter {
            trace!(iter = i, which = j, "ping_start");
            let (tot, srv) = do_one_bincode_ping(&mut st, &mut buf, msg.clone()).await?;
            trace!(iter = i, which = j, "ping_end");
            durs.push((start.elapsed(), tot, srv));
        }

        let elap: i64 = then.elapsed().as_micros().try_into()?;
        trace!(iter = i, overall_time = elap, "end_loop");
    }

    Ok(durs)
}

async fn do_one_bincode_ping(
    st: &mut (impl AsyncRead + AsyncWrite + Unpin),
    buf: &mut [u8],
    msg: SPingParams,
) -> Result<(i64, i64), Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let then = std::time::Instant::now();
    let msg = bincode::serialize(&msg)?;
    let msg_len = msg.len() as u32;
    st.write(&msg_len.to_be_bytes()).await?;
    st.write(&msg).await?;
    st.read_exact(&mut buf[0..4]).await?;
    let resp_len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if resp_len == 0 {
        tracing::warn!("msg header says 0 length");
    }
    st.read_exact(&mut buf[0..resp_len as usize]).await?;
    let response: SPong = bincode::deserialize(&buf[..resp_len as usize])?;
    let elap = then.elapsed().as_micros().try_into()?;
    let srv_dur = response.duration_us;
    Ok((elap, srv_dur))
}

fn gen_poisson_duration(amt: f64) -> Result<std::time::Duration, tonic::Status> {
    use rand_distr::{Distribution, Poisson};

    let mut rng = rand::thread_rng();
    let pois = Poisson::new(amt as f64).map_err(|e| {
        tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("Invalid amount {}: {:?}", amt, e),
        )
    })?;
    Ok(std::time::Duration::from_micros(pois.sample(&mut rng)))
}
