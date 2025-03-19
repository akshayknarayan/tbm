//! Measure message latency and ordered-ness for an experiment [`Mode`].
//!
//! This program is both the producer and the consumer (in different threads).
//! The chunnel stacks it benchmarks should support the (addr, data) = (impl SetGroup, String)
//! datatype.

use bertha::{
    bincode::{Base64Chunnel, SerializeChunnelProject},
    Chunnel, CxList,
};
use color_eyre::{
    eyre::{bail, eyre},
    Report,
};
use gcp_pubsub::{PubSubAddr, PubSubChunnel};
use queue_steer::bin_help::{
    do_atmostonce_exp, do_atmostonce_exp_batch, do_best_effort_exp, do_best_effort_exp_batch,
    do_ordered_groups_exp, do_ordered_groups_exp_batch, dump_results, Mode, RecvdMsg,
};
use queue_steer::{
    AtMostOnce, BatchSqsChunnelWrap, GcpPubSubWrap, KafkaChunnelWrap, Ordered,
    OrderedGcpPubSubWrap, OrderedSqsChunnelWrap, SqsChunnelWrap,
};
use sqs::{SqsAddr, SqsChunnel, SqsChunnelBatch};
use std::fmt::Debug;
use std::iter::once;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tracing::{debug, info};
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

#[derive(Debug, Clone, Copy)]
enum BatchMode {
    None,
    Auto,
    AppLevel(usize),
}

impl std::str::FromStr for BatchMode {
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<_> = s.split(":").collect();
        Ok(match &sp[..] {
            &["none"] => BatchMode::None,
            &["auto"] => BatchMode::Auto,
            &["applevel", x] => BatchMode::AppLevel(x.parse()?),
            x => bail!("Unknown batching mode {:?}", x),
        })
    }
}

#[derive(Clone, Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    mode: Mode,
    #[structopt(short = "n", long)]
    num_reqs: usize,
    #[structopt(short, long)]
    queue: Option<String>,
    #[structopt(short, long)]
    inter_request_ms: u64,
    #[structopt(short = "r", long)]
    num_receivers: usize,
    #[structopt(long)]
    batch_mode: BatchMode,
    #[structopt(long)]
    service_mode: bool, // client-side or service-side impl. it is a flag, so if not provided its value is false, which is client mode.
    #[structopt(short, long)]
    out_file: std::path::PathBuf,
    #[structopt(long)]
    iter: usize,

    #[structopt(subcommand)]
    provider: Provider,
}

#[derive(Clone, StructOpt)]
pub enum Provider {
    Aws {
        #[structopt(long)]
        aws_access_key_id: String,
        #[structopt(long)]
        aws_secret_access_key: String,
    },
    Gcp {
        #[structopt(long)]
        gcp_key_file: std::path::PathBuf,
        #[structopt(long)]
        gcp_project_name: String,
    },
    Kafka {
        #[structopt(long)]
        addr: String,
    },
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws { .. } => f.debug_struct("Aws").finish(),
            Self::Gcp { .. } => f.debug_struct("Gcp").finish(),
            Self::Kafka { addr } => f.debug_struct("Kafka").field("addr", addr).finish(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    color_eyre::install()?;
    let subscriber = tracing_subscriber::registry();
    let subscriber = subscriber
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(ErrorLayer::default());
    let d = tracing::Dispatch::new(subscriber);
    d.init();
    let Opt {
        mode,
        num_reqs,
        num_receivers,
        batch_mode,
        inter_request_ms,
        service_mode,
        out_file,
        queue,
        provider,
        iter,
    } = Opt::from_args();
    let prov = provider.provider().to_owned();
    info!(
        ?mode,
        ?num_reqs,
        ?inter_request_ms,
        ?batch_mode,
        ?service_mode,
        ?provider,
        "starting"
    );
    let (msgs, elapsed) = provider
        .run_exp(
            queue,
            mode,
            service_mode,
            batch_mode,
            num_reqs,
            inter_request_ms,
            num_receivers,
            iter,
        )
        .await?;

    if !msgs.is_empty() {
        let mut latencies: Vec<_> = msgs.iter().map(|m| m.elapsed).collect();
        latencies.sort_unstable();
        let len = latencies.len() as f64;
        let quantile_idxs = [0.25, 0.5, 0.75, 0.95];
        let quantiles: Vec<_> = quantile_idxs
            .iter()
            .map(|q| (len * q) as usize)
            .map(|i| latencies[i])
            .collect();

        info!(
            ?elapsed,
            ?num_reqs,
            p25 = ?quantiles[0],
            p50 = ?quantiles[1],
            p75 = ?quantiles[2],
            p95 = ?quantiles[3],
            "done",
        );
    } else {
        info!("skipped",);
    }

    dump_results(out_file, msgs, elapsed, mode, inter_request_ms, &prov)?;
    Ok(())
}

impl Provider {
    pub fn provider(&self) -> &str {
        match self {
            Provider::Aws { .. } => "aws",
            Provider::Gcp { .. } => "gcp",
            Provider::Kafka { .. } => "kafka",
        }
    }

    #[tracing::instrument(skip(queue))]
    async fn run_exp(
        self,
        queue: Option<String>,
        mode: Mode,
        service_mode: bool,
        batch_mode: BatchMode,
        num_reqs: usize,
        inter_request_ms: u64,
        num_receivers: usize,
        iter: usize,
    ) -> Result<(Vec<RecvdMsg>, Duration), Report> {
        debug!(?iter, "start");
        if !service_mode && num_receivers != 1 {
            return Err(eyre!("Cannot have > 1 receiver with client mode"));
        }

        let mut generated = false;
        let queue: String = queue.unwrap_or_else(|| {
            generated = true;
            use rand::Rng;
            let rng = rand::thread_rng();
            "bertha-"
                .chars()
                .chain(
                    rng.sample_iter(&rand::distributions::Alphanumeric)
                        .take(10)
                        .flat_map(char::to_lowercase),
                )
                .collect()
        });

        macro_rules! do_exp_service {
            ($mode: expr, $cn: expr, $addr: expr, $num_reqs: expr, $inter_request_ms: expr, $num_receivers: expr) => {{
                use bertha::util::NeverCn;
                match mode {
                    Mode::BestEffort => {
                        info!("skipping service-side besteffort");
                        (vec![], Duration::from_millis(0))
                    }
                    Mode::Ordered { num_groups: None } => {
                        let mut stack = CxList::from(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_atmostonce_exp(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            $inter_request_ms,
                            $num_receivers,
                        )
                        .await?
                    }
                    Mode::Ordered {
                        num_groups: Some(n),
                    } => {
                        let mut stack = CxList::from(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_ordered_groups_exp(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            n,
                            $inter_request_ms,
                            $num_receivers,
                        )
                        .await?
                    }
                }
            }};
        }

        macro_rules! do_exp {
            ($mode: expr, $cn: expr, $addr: expr, $num_reqs: expr, $inter_request_ms: expr, $num_receivers: expr) => {{
                use bertha::util::NeverCn;
                match mode {
                    Mode::BestEffort => {
                        let mut stack = CxList::from(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_best_effort_exp(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            $inter_request_ms,
                            $num_receivers,
                        )
                        .await?
                    }
                    Mode::Ordered { num_groups: None } => {
                        // at most once.
                        let mut stack = CxList::from(AtMostOnce::default())
                            .wrap(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_atmostonce_exp(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            $inter_request_ms,
                            $num_receivers,
                        )
                        .await?
                    }
                    Mode::Ordered {
                        num_groups: Some(n),
                    } => {
                        // ordered, with potentially many groups
                        let mut stack = CxList::from(Ordered::default())
                            .wrap(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_ordered_groups_exp(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            n,
                            $inter_request_ms,
                            $num_receivers,
                        )
                        .await?
                    }
                }
            }};
        }

        macro_rules! do_exp_batch {
            ($mode: expr, $cn: expr, $addr: expr, $num_reqs: expr, $inter_request_ms: expr, $num_receivers: expr, $batch_size: expr) => {{
                use bertha::util::NeverCn;
                match mode {
                    Mode::BestEffort => {
                        let mut stack = CxList::from(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_best_effort_exp_batch(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            $inter_request_ms,
                            $num_receivers,
                            $batch_size,
                        )
                        .await?
                    }
                    Mode::Ordered { num_groups: None } => {
                        // at most once.
                        let mut stack = CxList::from(AtMostOnce::default())
                            .wrap(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_atmostonce_exp_batch(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            $inter_request_ms,
                            $num_receivers,
                            $batch_size,
                        )
                        .await?
                    }
                    Mode::Ordered {
                        num_groups: Some(n),
                    } => {
                        // ordered, with potentially many groups
                        let mut stack = CxList::from(Ordered::default())
                            .wrap(SerializeChunnelProject::default())
                            .wrap(Base64Chunnel::default())
                            .wrap($cn);
                        let ch = stack.connect_wrap(NeverCn::default()).await?;
                        do_ordered_groups_exp_batch(
                            ch,
                            $addr.clone(),
                            $num_reqs,
                            n,
                            $inter_request_ms,
                            $num_receivers,
                            $batch_size,
                        )
                        .await?
                    }
                }
            }};
        }

        use Provider::*;
        match self {
            Aws {
                aws_access_key_id,
                aws_secret_access_key,
            } => {
                let sqs_client =
                    sqs::sqs_client_from_creds(aws_access_key_id, aws_secret_access_key)?;
                let (queue, generated): (_, Option<ProviderCleanup>) = if generated {
                    if service_mode {
                        let mut q = queue.clone();
                        q.push_str(".fifo");
                        let queue = sqs::make_fifo_queue(&sqs_client, q.clone()).await?;
                        (queue.clone(), Some((queue, sqs_client.clone()).into()))
                    } else {
                        let queue = sqs::make_be_queue(&sqs_client, queue.clone()).await?;
                        (queue.clone(), Some((queue, sqs_client.clone()).into()))
                    }
                } else {
                    (queue, None)
                };

                debug!(?queue, "AWS queue");
                let addr = SqsAddr {
                    queue_id: queue.clone(),
                    group: None,
                };

                let (msgs, elapsed) = match batch_mode {
                    BatchMode::AppLevel(batch_size) => {
                        let cn: BatchSqsChunnelWrap =
                            SqsChunnelBatch::new(SqsChunnel::new(sqs_client, once(queue.as_str())))
                                .into();
                        if service_mode {
                            todo!()
                        } else {
                            do_exp_batch!(
                                mode,
                                cn,
                                addr,
                                num_reqs,
                                inter_request_ms,
                                num_receivers,
                                batch_size
                            )
                        }
                    }
                    BatchMode::Auto => {
                        let cn: BatchSqsChunnelWrap =
                            SqsChunnelBatch::new(SqsChunnel::new(sqs_client, once(queue.as_str())))
                                .into();
                        if service_mode {
                            todo!()
                        } else {
                            use bertha::util::NeverCn;
                            match mode {
                                Mode::BestEffort => {
                                    let mut stack =
                                        CxList::from(SerializeChunnelProject::default())
                                            .wrap(Base64Chunnel::default())
                                            .wrap(cn);
                                    let ch = stack.connect_wrap(NeverCn::default()).await?;
                                    let ch = batcher::Batcher::new(ch);
                                    do_best_effort_exp(
                                        ch,
                                        addr.clone(),
                                        num_reqs,
                                        inter_request_ms,
                                        num_receivers,
                                    )
                                    .await?
                                }
                                Mode::Ordered { num_groups: None } => {
                                    // at most once.
                                    let mut stack = CxList::from(AtMostOnce::default())
                                        .wrap(SerializeChunnelProject::default())
                                        .wrap(Base64Chunnel::default())
                                        .wrap(cn);
                                    let ch = stack.connect_wrap(NeverCn::default()).await?;
                                    let ch = batcher::Batcher::new(ch);
                                    do_atmostonce_exp(
                                        ch,
                                        addr.clone(),
                                        num_reqs,
                                        inter_request_ms,
                                        num_receivers,
                                    )
                                    .await?
                                }
                                Mode::Ordered {
                                    num_groups: Some(n),
                                } => {
                                    // ordered, with potentially many groups
                                    let mut stack = CxList::from(Ordered::default())
                                        .wrap(SerializeChunnelProject::default())
                                        .wrap(Base64Chunnel::default())
                                        .wrap(cn);
                                    let ch = stack.connect_wrap(NeverCn::default()).await?;
                                    let ch = batcher::Batcher::new(ch);
                                    do_ordered_groups_exp(
                                        ch,
                                        addr.clone(),
                                        num_reqs,
                                        n,
                                        inter_request_ms,
                                        num_receivers,
                                    )
                                    .await?
                                }
                            }
                        }
                    }
                    BatchMode::None => {
                        let cn: SqsChunnelWrap =
                            SqsChunnel::new(sqs_client, once(queue.as_str())).into();
                        if service_mode {
                            let cn: OrderedSqsChunnelWrap = cn.into();
                            do_exp_service!(
                                mode,
                                cn,
                                addr,
                                num_reqs,
                                inter_request_ms,
                                num_receivers
                            )
                        } else {
                            do_exp!(mode, cn, addr, num_reqs, inter_request_ms, num_receivers)
                        }
                    }
                };

                if let Some(gen) = generated {
                    gen.cleanup().await?;
                }
                Ok((msgs, elapsed))
            }
            Kafka { addr } => {
                kafka::make_topic(&addr, &queue).await?;
                info!(?queue, ?addr, "Kafka queue");
                let ch = kafka::KafkaChunnel::new(&addr)?;
                ch.listen(&[&queue])?;
                let cn: KafkaChunnelWrap = ch.into();
                let c_addr = kafka::KafkaAddr {
                    topic_id: queue.clone(),
                    group: None,
                };

                let (msgs, elapsed) = if service_mode {
                    do_exp_service!(mode, cn, c_addr, num_reqs, inter_request_ms, num_receivers)
                } else {
                    do_exp!(mode, cn, c_addr, num_reqs, inter_request_ms, num_receivers)
                };

                kafka::delete_topic(&addr, &queue).await?;
                Ok((msgs, elapsed))
            }
            Gcp {
                gcp_key_file,
                gcp_project_name,
            } => {
                let mut gcp_client = gcp_pubsub::GcpCreds::default()
                    .with_creds_path(gcp_key_file)
                    .with_project_name(gcp_project_name)
                    .finish()
                    .await?;

                let (queue, generated): (_, Option<ProviderCleanup>) = if generated {
                    let queue = gcp_pubsub::make_topic(&mut gcp_client, queue.clone()).await?;
                    (queue.clone(), Some((queue, gcp_client.clone()).into()))
                } else {
                    (queue, None)
                };

                debug!(?queue, "GCP queue");
                let addr = PubSubAddr {
                    topic_id: queue.clone(),
                    group: None,
                };

                // todo figure out how to call .cleanup
                let cn: GcpPubSubWrap = PubSubChunnel::new(gcp_client, once(queue.as_str()))
                    .await?
                    .into();
                let (msgs, elapsed) = if service_mode {
                    let cn = OrderedGcpPubSubWrap::convert(cn).await?;
                    do_exp_service!(mode, cn, addr, num_reqs, inter_request_ms, num_receivers)
                } else {
                    do_exp!(mode, cn, addr, num_reqs, inter_request_ms, num_receivers)
                };

                if let Some(gen) = generated {
                    gen.cleanup().await?;
                }
                Ok((msgs, elapsed))
            }
        }
    }
}

struct ProviderCleanup {
    queue: String,
    inner: ProviderCleanupInner,
}

impl ProviderCleanup {
    async fn cleanup(self) -> Result<(), Report> {
        use ProviderCleanupInner::*;
        let queue = self.queue;
        debug!(?queue, provider = ?self.inner.provider(), "deleting queue");
        match self.inner {
            Aws(c) => sqs::delete_queue(&c, queue).await,
            Gcp(mut c) => gcp_pubsub::delete_topic(&mut c, queue).await,
        }
    }
}

impl From<(String, sqs::SqsClient)> for ProviderCleanup {
    fn from((queue, inner): (String, sqs::SqsClient)) -> Self {
        Self {
            queue,
            inner: ProviderCleanupInner::Aws(inner),
        }
    }
}
impl From<(String, gcp_pubsub::GcpClient)> for ProviderCleanup {
    fn from((queue, inner): (String, gcp_pubsub::GcpClient)) -> Self {
        Self {
            queue,
            inner: ProviderCleanupInner::Gcp(inner),
        }
    }
}

enum ProviderCleanupInner {
    Aws(sqs::SqsClient),
    Gcp(gcp_pubsub::GcpClient),
}

impl ProviderCleanupInner {
    fn provider(&self) -> &str {
        match self {
            ProviderCleanupInner::Aws(_) => "aws",
            ProviderCleanupInner::Gcp(_) => "gcp",
        }
    }
}
