//! Server-side sharding functionality.

use crate::{redis_util, Kv, ShardFns, ShardInfo, FNV1_64_INIT, FNV_64_PRIME};
use bertha::{
    negotiate::{Apply, GetOffers, StackNonce},
    CapabilitySet, Chunnel, ChunnelConnection, ChunnelConnector, IpPort, Negotiate,
};
use color_eyre::eyre;
use eyre::{eyre, Error, WrapErr};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;
use tracing::{debug, debug_span, trace, trace_span, warn};
use tracing_futures::Instrument;

/// A chunnel managing a sharded service.
///
/// Forwards incoming messages to one of the internal connections specified by `shards_inner` after
/// evaluating the sharding function.
pub struct ShardCanonicalServer<A, S, Ss, D> {
    pub(crate) addr: ShardInfo<A>,
    pub(crate) internal_addr: Vec<A>,
    pub(crate) shards_inner: Arc<StdMutex<S>>,
    pub(crate) shards_inner_stack: Ss,
    pub(crate) shards_extern_nonce: Option<StackNonce>,
    pub(crate) redis_listen_connection: Arc<Mutex<redis::aio::MultiplexedConnection>>,
    _phantom: std::marker::PhantomData<D>,
}

impl<A, S, Ss, D> Clone for ShardCanonicalServer<A, S, Ss, D>
where
    A: Clone,
    Ss: Clone,
{
    fn clone(&self) -> Self {
        Self {
            addr: self.addr.clone(),
            internal_addr: self.internal_addr.clone(),
            shards_inner: Arc::clone(&self.shards_inner),
            shards_inner_stack: self.shards_inner_stack.clone(),
            shards_extern_nonce: self.shards_extern_nonce.clone(),
            redis_listen_connection: Arc::clone(&self.redis_listen_connection),
            _phantom: Default::default(),
        }
    }
}

impl<A: std::fmt::Debug, S, Ss, D> std::fmt::Debug for ShardCanonicalServer<A, S, Ss, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardCanonicalServer")
            .field("addr", &self.addr)
            .finish()
    }
}

impl<A, S, Ss, D> ShardCanonicalServer<A, S, Ss, D>
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
        shards_extern_nonce: Option<StackNonce>,
        redis_addr: &str,
    ) -> Result<Self, Error> {
        let redis_client = redis::Client::open(redis_addr)
            .wrap_err_with(|| eyre!("Opening redis connection: {:?}", redis_addr))?;
        let redis_listen_connection = Arc::new(Mutex::new(
            redis_client
                .get_multiplexed_tokio_connection()
                .await
                .wrap_err("Connecting to redis")?,
        ));

        let internal_addr = internal_addr.unwrap_or_else(|| addr.shard_addrs.clone());
        if internal_addr.len() != addr.shard_addrs.len() {
            return Err(eyre!(
                "Shard addresses mismatched between internal and external: {:?} != {:?}",
                internal_addr,
                addr
            ));
        }

        Ok(ShardCanonicalServer {
            addr,
            internal_addr,
            shards_inner: Arc::new(StdMutex::new(shards_inner)),
            shards_inner_stack,
            shards_extern_nonce,
            redis_listen_connection,
            _phantom: Default::default(),
        })
    }
}

impl<A, S, Ss, D> Negotiate for ShardCanonicalServer<A, S, Ss, D>
where
    A: IpPort
        + Serialize
        + DeserializeOwned
        + Clone
        + PartialEq
        + std::fmt::Debug
        + std::fmt::Display
        + Send
        + Sync
        + 'static,
    S: ChunnelConnector<Addr = A> + Send + Sync + 'static,
    <S as ChunnelConnector>::Error: Into<eyre::Report>,
    S::Connection: ChunnelConnection<Data = (A, Vec<u8>)> + Send + Sync + 'static,
{
    type Capability = ShardFns;

    fn guid() -> u64 {
        0xe91d00534cb2b98f
    }

    fn capabilities() -> Vec<ShardFns> {
        vec![ShardFns::Sharding]
    }

    fn picked<'s>(&mut self, nonce: &'s [u8]) -> Pin<Box<dyn Future<Output = ()> + Send + 's>> {
        let addrs = self.internal_addr.clone();
        let ctr = Arc::clone(&self.shards_inner);
        let offer = self.shards_extern_nonce.clone();
        let msg: bertha::negotiate::NegotiateMsg = match bincode::deserialize(nonce) {
            Err(e) => {
                warn!(err = ?e, "deserialize failed");
                return Box::pin(futures_util::future::ready(()));
            }
            Ok(m) => m,
        };

        let msg = match msg {
            bertha::negotiate::NegotiateMsg::ServerNonce { addr, picked } => {
                if let Some(o) = offer {
                    bertha::negotiate::NegotiateMsg::ServerNonce { addr, picked: o }
                } else {
                    let mut p = picked.__into_inner();
                    p.remove(&ShardFns::guid());
                    bertha::negotiate::NegotiateMsg::ServerNonce {
                        addr,
                        picked: StackNonce::__from_inner(p),
                    }
                }
            }
            _ => {
                warn!("malformed nonce");
                return Box::pin(futures_util::future::ready(()));
            }
        };

        let buf = match bincode::serialize(&msg) {
            Err(e) => {
                warn!(err = ?e, "serialize failed");
                return Box::pin(futures_util::future::ready(()));
            }
            Ok(m) => m,
        };

        let redis_conn = Arc::clone(&self.redis_listen_connection);
        let addr = self.addr.clone();
        Box::pin(async move {
            // redis insert
            if let Err(e) = redis_util::redis_insert(redis_conn, &addr)
                .await
                .wrap_err("Could not register shard info")
            {
                warn!(err = ?e, "failed inserting shard info in redis");
                return;
            }

            futures_util::future::join_all(addrs.into_iter().map(|shard| {
                let buf = buf.clone();
                let shard_addr = shard.clone();
                let ctr = Arc::clone(&ctr);
                async move {
                    let connect_fut = {
                        let mut  ctr_g = ctr.lock().unwrap();
                        ctr_g.connect(shard.clone())
                    };
                    let cn = match connect_fut.await {
                        Ok(c) => c,
                        Err(e) => {
                            let e = e.into();
                            warn!(err = ?e, "failed making connection to shard");
                            return;
                        }
                    };
                    if let Err(e) = cn.send(std::iter::once((shard.clone(), buf.clone()))).await {
                        warn!(err = ?e, "failed sending negotiation nonce to shard");
                        return;
                    }

                    debug!("wait for nonce ack");
                    let mut slot = [None];
                    match cn.recv(&mut slot).await {
                        Ok([Some((a, buf))]) => match bincode::deserialize(buf) {
                            Ok(bertha::negotiate::NegotiateMsg::ServerNonceAck) => {
                                // TODO collect received addresses since we could receive acks from
                                // any shard
                                if *a != shard.clone() {
                                    warn!(addr = ?a, expected = ?shard.clone(), "received from unexpected address");
                                }

                                debug!("got nonce ack");
                            }
                            Ok(m) => {
                                warn!(msg = ?m, shard = ?shard.clone(), "got unexpected response to nonce");
                            }
                            Err(e) => {
                                warn!(err = ?e, shard = ?shard.clone(), "failed deserializing nonce ack");
                            }
                        },
                        Ok(_) => {
                            warn!("got empty response to nonce");
                        }
                        Err(e) => {
                            warn!(err = ?e, shard = ?shard.clone(), "failed waiting for nonce ack");
                        }
                    }
                }
                .instrument(debug_span!("shard-send-nonce", shard = ?&shard_addr))
            }))
            .await;
        })
    }
}

impl<I, A, S, Ss, D, E> Chunnel<I> for ShardCanonicalServer<A, S, Ss, D>
where
    I: ChunnelConnection<Data = D> + Send + Sync + 'static,
    A: IpPort
        + Serialize
        + DeserializeOwned
        + Clone
        + std::fmt::Debug
        + std::fmt::Display
        + Send
        + Sync
        + 'static,
    S: ChunnelConnector<Addr = A, Error = E> + Send + Sync + 'static,
    S::Connection: ChunnelConnection<Data = (A, Vec<u8>)> + Send + Sync + 'static,
    Ss: Apply + GetOffers + Clone + Send + Sync + 'static,
    <Ss as Apply>::Applied:
        Chunnel<S::Connection> + bertha::NegotiatePicked + Clone + Debug + Send + 'static,
    <<Ss as Apply>::Applied as Chunnel<S::Connection>>::Connection:
        ChunnelConnection<Data = D> + Send + Sync + 'static,
    <<Ss as Apply>::Applied as Chunnel<S::Connection>>::Error: Into<Error> + Send + Sync + 'static,
    D: Kv + Send + Sync + 'static,
    <D as Kv>::Key: AsRef<str>,
    E: Into<Error> + Send + Sync + 'static,
{
    type Connection =
        ShardCanonicalServerConnection<I, bertha::negotiate::NegotiatedConn<S::Connection, Ss>, D>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Error;

    fn connect_wrap(&mut self, conn: I) -> Self::Future {
        let addr = self.addr.clone();
        let internal_addr = self.internal_addr.clone();
        let a1 = addr.clone();
        let shards_inner = Arc::clone(&self.shards_inner);
        let shards_inner_stack = self.shards_inner_stack.clone();
        Box::pin(
            async move {
                let _ = &addr;
                let num_shards = addr.shard_addrs.len();

                // connect to shards
                let conns: Vec<_> =
                    futures_util::future::join_all(internal_addr.into_iter().map(|a| async {
                        debug!(?a, "connecting to shard");
                        let a = a;
                        let connect_fut = {
                            let mut ctr_g = shards_inner.lock().unwrap();
                            ctr_g.connect(a.clone())
                        };
                        let cn = connect_fut
                            .await
                            .map_err(Into::into)
                            .wrap_err_with(|| eyre!("Could not connect to {}", a.clone()))?;
                        let cn = bertha::negotiate::negotiate_client(
                            shards_inner_stack.clone(),
                            cn,
                            a.clone(),
                        )
                        .await
                        .wrap_err("negotiate_client failed")?;
                        Ok::<_, Error>(cn)
                    }))
                    .await
                    .into_iter()
                    .collect::<Result<_, Error>>()
                    .wrap_err("Could not connect to at least one shard")?;
                debug!("connected to shards");

                // serve canonical address
                // we are only responsible for the canonical address here.
                Ok(ShardCanonicalServerConnection {
                    inner: conn,
                    shards: conns,
                    shard_fn: Arc::new(move |d: &D| {
                        /* xdp_shard version of FNV: take the first 4 bytes of the key
                        * u64 hash = FNV1_64_INIT;
                        * // ...
                        * // value start
                        * pkt_val = ((u8*) app_data) + offset;

                        * // compute FNV hash
                        * #pragma clang loop unroll(full)
                        * for (i = 0; i < 4; i++) {
                        *     hash = hash ^ ((u64) pkt_val[i]);
                        *     hash *= FNV_64_PRIME;
                        * }

                        * // map to a shard and assign to that port.
                        * idx = hash % shards->num;
                        */
                        let mut hash = FNV1_64_INIT;
                        for b in d.key().as_ref().as_bytes()[0..4].iter() {
                            hash ^= *b as u64;
                            hash = u64::wrapping_mul(hash, FNV_64_PRIME);
                        }

                        hash as usize % num_shards
                    }),
                })
            }
            .instrument(debug_span!("serve", addr = ?&a1)),
        )
    }
}

/// Chunnel connection type for serving the shard canonical address.
///
/// Does not implement `send()`, since the server does not send messages unprompted.  Similarly,
/// the Data type is `()`, since any received message is forwarded to the appropriate shard.
/// Expected usage is to call `recv()` in a loop.
pub struct ShardCanonicalServerConnection<C, S, D> {
    pub(crate) inner: C,
    pub(crate) shards: Vec<S>,
    pub(crate) shard_fn: Arc<dyn Fn(&D) -> usize + Send + Sync + 'static>,
}

impl<C, S, D> ChunnelConnection for ShardCanonicalServerConnection<C, S, D>
where
    C: ChunnelConnection<Data = D> + Send + Sync + 'static,
    S: ChunnelConnection<Data = D> + Send + Sync + 'static,
    D: Send + Sync + 'static,
{
    type Data = ();

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<
        Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], eyre::Report>> + Send + 'cn>,
    >
    where
        'buf: 'cn,
    {
        Box::pin(
            async move {
                // received a packet on the canonical_addr.
                // need to
                // 1. evaluate the hash fn
                // 2. forward to the right shard,
                //    preserving the src addr so the response goes back to the client

                // 0. receive the packet.
                let mut slots: Vec<_> = (0..msgs_buf.len()).map(|_| None).collect();
                let ms = self.inner.recv(&mut slots).await?;
                trace!("got request batch");

                let mut shard_batches: Vec<Vec<D>> =
                    (0..self.shards.len()).map(|_| Vec::new()).collect();
                for data in ms.iter_mut().map_while(Option::take) {
                    // 1. evaluate the hash fn to determine where to forward to.
                    let shard_idx = (self.shard_fn)(&data);
                    trace!(shard_idx, "checked shard");
                    shard_batches[shard_idx].push(data);
                }

                // 2. Forward to the shard.
                // TODO this assumes no reordering.
                let mut shard_completion_slots: Vec<Vec<_>> = shard_batches
                    .iter()
                    .map(|batch| (0..batch.len()).map(|_| None).collect())
                    .collect();
                let shard_completion_futs = self
                    .shards
                    .iter()
                    .zip(shard_batches.into_iter())
                    .zip(&mut shard_completion_slots)
                    .enumerate()
                    .filter_map(|(shard_idx, ((conn, batch), slots))| {
                        if !batch.is_empty() {
                            Some(async move {
                                conn.send(batch).await.wrap_err("Forward to shard")?;
                                // 3. Get response from the shard
                                let resps = conn
                                    .recv(&mut slots[..])
                                    .instrument(trace_span!(
                                        "canonical-server-internal-recv",
                                        ?shard_idx
                                    ))
                                    .await
                                    .wrap_err("receive from shard")?;
                                Ok::<_, eyre::Report>((shard_idx, resps))
                            })
                        } else {
                            None
                        }
                    });
                let resps = futures_util::future::try_join_all(shard_completion_futs).await?;
                trace!("got shard responses");
                for (shard_idx, resp_batch) in resps {
                    // 4. Send back to client.
                    self.inner
                        .send(resp_batch.iter_mut().map_while(Option::take))
                        .await?;
                    trace!(shard_idx, "send response");
                }

                Ok(&mut msgs_buf[0..0])
            }
            .instrument(trace_span!("server-shard-recv")),
        )
    }

    fn send<'cn, B>(
        &self,
        _data: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), eyre::Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        warn!("Called ShardCanonicalServerConnection.send(), a useless function");
        Box::pin(async move { Ok(()) })
    }
}
