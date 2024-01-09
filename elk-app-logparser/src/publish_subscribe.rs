use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize},
        Arc,
    },
    time::Duration,
};

use bertha::{
    bincode::{Base64Chunnel, SerializeChunnel},
    negotiate_rendezvous,
    tagger::OrderedChunnel,
    ChunnelConnection, CxList, Either, Select, StackUpgradeHandle, UpgradeHandle, UpgradeSelect,
};
use color_eyre::{
    eyre::{eyre, WrapErr},
    Report,
};
use gcp_pubsub::{GcpClient, OrderedPubSubChunnel, PubSubChunnel};
use kafka::KafkaChunnel;
use queue_steer::{MessageQueueAddr, Ordered};
use redis_basechunnel::RedisBase;
use tokio::sync::watch;
use tracing::{info, instrument, warn};

use crate::parse_log::ParsedLine;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnState {
    KafkaOrdering,
    GcpClientSideOrdering,
    GcpServiceSideOrdering,
}

impl ConnState {
    pub fn is_kafka(&self) -> bool {
        match self {
            Self::KafkaOrdering => true,
            Self::GcpClientSideOrdering | Self::GcpServiceSideOrdering => false,
        }
    }

    pub fn is_gcp(&self) -> bool {
        !self.is_kafka()
    }
}

pub struct MeasureMessageRate<C> {
    inner: C,
    clk: quanta::Clock,
    epoch_length: Duration,
    epoch_start: Arc<AtomicU64>,
    epoch_num_sent_messages: Arc<AtomicUsize>,
    last_epoch_num_msgs_sender: watch::Sender<u64>,
}

impl MeasureMessageRate<()> {
    pub fn new<C>(
        inner: C,
        epoch_length: Duration,
        last_epoch_num_msgs_sender: watch::Sender<u64>,
    ) -> MeasureMessageRate<C> {
        let clk = quanta::Clock::new();
        let now = clk.raw();
        MeasureMessageRate {
            inner,
            clk,
            epoch_length,
            epoch_start: Arc::new(now.into()),
            epoch_num_sent_messages: Default::default(),
            last_epoch_num_msgs_sender,
        }
    }
}

impl<C> ChunnelConnection for MeasureMessageRate<C>
where
    C: ChunnelConnection + Send + Sync,
    <C as ChunnelConnection>::Data: Send,
{
    type Data = C::Data;

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        Box::pin(async move {
            let b: Vec<_> = burst.into_iter().collect();
            let num_msgs = b.len();
            let now = self.clk.raw();
            if self.clk.delta(
                self.epoch_start.load(std::sync::atomic::Ordering::Relaxed),
                now,
            ) > self.epoch_length
            {
                let last_epoch_num_msgs = self
                    .epoch_num_sent_messages
                    .swap(num_msgs, std::sync::atomic::Ordering::SeqCst)
                    as u64;
                self.last_epoch_num_msgs_sender
                    .send_if_modified(|s: &mut u64| {
                        let diff = (*s).max(last_epoch_num_msgs) - (*s).min(last_epoch_num_msgs);
                        // notify only if value changed by 10%
                        let ret = diff > (last_epoch_num_msgs / 10);
                        *s = last_epoch_num_msgs;
                        ret
                    });
                self.epoch_start
                    .store(now, std::sync::atomic::Ordering::SeqCst);
            } else {
                self.epoch_num_sent_messages
                    .fetch_add(num_msgs, std::sync::atomic::Ordering::SeqCst);
            }

            self.inner.send(b.into_iter()).await
        })
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>> + Send + 'cn>>
    where
        'buf: 'cn,
    {
        self.inner.recv(msgs_buf)
    }
}

macro_rules! gcp_stack {
    ($topic: expr, $gcloud_client: expr) => {{
        // We repeat SerializeChunnel in both sides because the SerializeChunnel is actually different in either case due to the different data types.
        let mut ord = OrderedChunnel::default();
        ord.ordering_threshold(10);
        let ord: Ordered = ord.into();
        let mut sub_name = $topic.to_owned();
        sub_name.push_str("-elk-subscription");
        UpgradeSelect::from_select(Select::from((
            CxList::from(ord)
                .wrap(SerializeChunnel::default())
                .wrap(Base64Chunnel::default())
                .wrap(PubSubChunnel::new($gcloud_client.clone(), [($topic, Some(sub_name.clone()))])),
            CxList::from(SerializeChunnel::default())
                .wrap(Base64Chunnel::default())
                .wrap(OrderedPubSubChunnel::from(PubSubChunnel::new(
                    $gcloud_client.clone(),
                    [($topic, Some(sub_name.clone()))],
                ))),
        )))
    }};
}

pub async fn connect(
    topic: &str,
    redis: RedisBase,
    gcloud_client: GcpClient,
    kafka_addr: &str,
) -> Result<
    (
        watch::Receiver<ConnState>,
        impl ChunnelConnection<Data = (MessageQueueAddr, ParsedLine)> + Send + 'static,
    ),
    Report,
> {
    // the chunnel stack we want:
    // serialize |> base64 |> select(
    //   select(
    //     ordering |> besteffort_gcp,
    //     nothing  |> ordered_gcp,
    //   ),
    //   kafka
    // )

    // 1. gcp-only part (no kafka option)
    let (gcp_st, gcp_switch_ordering_handle) = gcp_stack!(topic, gcloud_client);
    // 2. kafka option.
    // kafka guarantees ordering within a partition, and in the case in which client-side ordering
    // might help - a single consumer - that consumer would pull from one partition at a time
    // only anyway. so, there's no point trying to get lower latency by increasing the number
    // of partitions.
    let (st, kafka_gcp_handle) = UpgradeSelect::from_select(Select::from((
        CxList::from(SerializeChunnel::default())
            .wrap(Base64Chunnel::default())
            .wrap(KafkaChunnel::new(
                kafka_addr,
                [topic],
                Some("elk-logparser"),
            )),
        gcp_st,
    )));

    // 3. initial negotiation and spawn the manager task.
    let (cn, stack_negotiation_manager) =
        negotiate_rendezvous(st, redis, topic.to_owned(), |np, select| {
            if Arc::ptr_eq(select, &gcp_switch_ordering_handle) {
                match np {
                    1 | 2 => Some(Either::Left(())),
                    3.. => Some(Either::Right(())),
                    _ => unreachable!(),
                }
            } else {
                None
            }
        })
        .await?;
    let (s, r) = tokio::sync::watch::channel(0);
    let cn = MeasureMessageRate::new(cn, Duration::from_secs(1), s);

    let cn_state = gcp_switch_ordering_handle
        .current()
        .map(|e| match e {
            Either::Left(()) => ConnState::GcpClientSideOrdering,
            Either::Right(()) => ConnState::GcpServiceSideOrdering,
        })
        .or(Some(ConnState::KafkaOrdering))
        .unwrap();
    info!(?cn_state, "Established connection");
    let (cn_state_watcher_s, cn_state_watcher_r) = watch::channel(cn_state);
    tokio::spawn(conn_negotiation_manager(
        topic.to_owned(),
        cn_state_watcher_s,
        stack_negotiation_manager,
        Some(kafka_gcp_handle),
        gcp_switch_ordering_handle,
        Some(r),
    ));
    Ok((cn_state_watcher_r, cn))
}

pub async fn connect_gcp_only(
    topic: &str,
    redis: RedisBase,
    gcloud_client: GcpClient,
) -> Result<
    (
        watch::Receiver<ConnState>,
        impl ChunnelConnection<Data = (MessageQueueAddr, ParsedLine)> + Send + 'static,
    ),
    Report,
> {
    let (gcp_st, gcp_switch_ordering_handle) = gcp_stack!(topic, gcloud_client);
    let (cn, stack_negotiation_manager) =
        negotiate_rendezvous(gcp_st, redis, topic.to_owned(), |np, select| {
            if Arc::ptr_eq(select, &gcp_switch_ordering_handle) {
                info!(?np, "prefer Right when np >= 3");
                match np {
                    1 | 2 => Some(Either::Left(())),
                    3.. => Some(Either::Right(())),
                    _ => unreachable!(),
                }
            } else {
                None
            }
        })
        .await?;
    let cn_state = gcp_switch_ordering_handle
        .current()
        .map(|e| match e {
            Either::Left(()) => ConnState::GcpClientSideOrdering,
            Either::Right(()) => ConnState::GcpServiceSideOrdering,
        })
        .ok_or_else(|| eyre!("GCP stack should be active"))?;
    info!(?cn_state, "Established connection");
    let (cn_state_watcher_s, cn_state_watcher_r) = watch::channel(cn_state);
    tokio::spawn(conn_negotiation_manager(
        topic.to_owned(),
        cn_state_watcher_s,
        stack_negotiation_manager,
        None,
        gcp_switch_ordering_handle,
        None,
    ));
    Ok((cn_state_watcher_r, cn))
}

#[instrument(
    skip(
        cn_state_watcher,
        stack_negotiation_manager,
        kafka_gcp_handle,
        gcp_switch_ordering_handle,
    ),
    level = "debug"
)]
async fn conn_negotiation_manager(
    topic: String,
    cn_state_watcher: watch::Sender<ConnState>,
    mut stack_negotiation_manager: StackUpgradeHandle<RedisBase>,
    kafka_gcp_handle: Option<Arc<UpgradeHandle>>,
    gcp_switch_ordering_handle: Arc<UpgradeHandle>,
    msg_per_sec_watcher: Option<watch::Receiver<u64>>,
) {
    let mut num_participants_changed_listener = stack_negotiation_manager
        .conn_participants_changed_receiver
        .clone();
    let mut gcp_changed = Box::pin(gcp_switch_ordering_handle.stack_changed());
    let monitor_connection_negotiation_state =
        stack_negotiation_manager.monitor_connection_negotiation_state();
    let mut monitor_connection_negotiation_state =
        std::pin::pin!(monitor_connection_negotiation_state);
    let mut transition_in_progress = Either::Left(futures_util::future::pending());
    let (mut msg_per_sec_watcher, active_rate_watcher) = if let Some(w) = msg_per_sec_watcher {
        (w, true)
    } else {
        let (_, r) = watch::channel(0);
        (r, false)
    };
    loop {
        tokio::select! {
            exit = &mut monitor_connection_negotiation_state => {
                if let Err(e) = exit {
                    warn!(negotiation_manager_exit = ?e, "Exiting negotiation manager");
                }

                return;
            }
            res = &mut transition_in_progress, if transition_in_progress.is_right() => {
                transition_in_progress = Either::Left(futures_util::future::pending());
                if let Err(err) = res {
                    warn!(?err, "stack transition failed");
                } else {
                    info!("did transition");
                }
            }
            // if the kafka stack is available and we are using it, we don't need to switch between
            // ordering implementations based on the number of participants.
            _ = num_participants_changed_listener.changed(), if !matches!(kafka_gcp_handle.as_ref().and_then(|h| h.current()), Some(Either::Left(()))) => {
                let new_num_participants = *num_participants_changed_listener.borrow_and_update();
                let cn_state = gcp_switch_ordering_handle
                    .current()
                    .map(|e| match e {
                        Either::Left(()) => ConnState::GcpClientSideOrdering,
                        Either::Right(()) => ConnState::GcpServiceSideOrdering,
                    })
                    .or(Some(ConnState::KafkaOrdering))
                    .unwrap();
                info!(
                    ?new_num_participants,
                    ?cn_state,
                    "num participants changed"
                );
                let trans_fut: Pin<Box<dyn Future<Output = Result<(), Report>> + Send>> = match new_num_participants {
                    1 | 2 => Box::pin(gcp_switch_ordering_handle.trigger_left()) as Pin<Box<_>>,
                    3.. => Box::pin(gcp_switch_ordering_handle.trigger_right()) as Pin<Box<_>>,
                    _ => unreachable!(),
                };
                transition_in_progress = Either::Right(trans_fut);
            }
            _ = (&mut gcp_changed) => {
                let cn_state = gcp_switch_ordering_handle
                    .current()
                    .map(|e| match e {
                        Either::Left(()) => ConnState::GcpClientSideOrdering,
                        Either::Right(()) => ConnState::GcpServiceSideOrdering,
                    });
                let cn_state = if kafka_gcp_handle.is_some() {
                    cn_state.unwrap_or(ConnState::KafkaOrdering)
                } else {
                    match cn_state {
                        Some(c) => c,
                        None => {
                            warn!("expect gcp to be active if no kafka");
                            return;
                        }
                    }
                };
                cn_state_watcher.send_replace(cn_state);
                // make a new future
                gcp_changed = Box::pin(gcp_switch_ordering_handle.stack_changed());
            }
            _ = msg_per_sec_watcher.changed(), if active_rate_watcher && transition_in_progress.is_left() => {
                let msg_per_sec = {
                    let x = msg_per_sec_watcher.borrow_and_update();
                    *x
                };
                info!(?msg_per_sec, "message rate sample");
                if let Some(ref h) = kafka_gcp_handle {
                    if msg_per_sec < 75 {
                        transition_in_progress = Either::Right(Box::pin(h.trigger_right()) as Pin<Box<_>>);
                    } else if msg_per_sec > 90 {
                        transition_in_progress = Either::Right(Box::pin(h.trigger_left()) as Pin<Box<_>>);
                    }
                }
            }
        }
    }
}

pub async fn make_topic(
    cn: ConnState,
    kafka_addr: &Option<String>,
    gcp_client: &mut GcpClient,
    topic_name: &str,
) -> Result<(), Report> {
    match cn {
        ConnState::KafkaOrdering => {
            info!(?topic_name, "creating kafka topic");
            kafka::make_topics(
                    kafka_addr.clone().expect("if kafka_addr was not provided, we cannot have ended up with ConnState::KafkaOrdering"),
                    vec![topic_name.to_owned()]
                ).await.wrap_err("make kafka topic")?;
        }
        ConnState::GcpClientSideOrdering | ConnState::GcpServiceSideOrdering => {
            info!(?topic_name, "creating GCP Pub/Sub topic");
            gcp_pubsub::make_topic(gcp_client, topic_name.to_owned())
                .await
                .wrap_err("make GCP Pub/Sub topic")?;
        }
    }

    Ok(())
}

pub async fn delete_topic(
    cn: ConnState,
    kafka_addr: &Option<String>,
    gcp_client: &mut GcpClient,
    topic_name: &str,
) -> Result<(), Report> {
    match cn {
        ConnState::KafkaOrdering => {
            info!(?topic_name, "delete kafka topic");
            kafka::delete_topic(
                    kafka_addr.clone().expect("if kafka_addr was not provided, we cannot have ended up with ConnState::KafkaOrdering"),
                    vec![topic_name.to_owned()]
                ).await.wrap_err("delete kafka topic")?;
        }
        ConnState::GcpClientSideOrdering | ConnState::GcpServiceSideOrdering => {
            info!(?topic_name, "delete GCP Pub/Sub topic");
            gcp_pubsub::delete_topic(gcp_client, topic_name.to_owned())
                .await
                .wrap_err("delete GCP Pub/Sub topic")?;
        }
    }

    Ok(())
}
