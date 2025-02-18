//! Client-side sharding functionality.

use crate::{redis_util, Kv, ShardFns, FNV1_64_INIT, FNV_64_PRIME};
use bertha::{Chunnel, ChunnelConnection, Negotiate};
use color_eyre::eyre;
use eyre::{eyre, Error, WrapErr};
use serde::{de::DeserializeOwned, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::{fmt::Debug, future::Future};
use tokio::sync::Mutex;
use tracing::{debug, debug_span, trace};
use tracing_futures::Instrument;

/// Client-side sharding chunnel implementation.
///
/// Contacts shard-ctl for sharding information, and does client-side sharding.
#[derive(Clone)]
pub struct ClientShardChunnelClient<A, A2> {
    addr: A,
    redis_listen_connection: Arc<Mutex<redis::aio::MultiplexedConnection>>,
    _phantom: std::marker::PhantomData<A2>,
}

impl<A, A2> Debug for ClientShardChunnelClient<A, A2>
where
    A: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientShardChunnelClient")
            .field("addr", &self.addr)
            .finish()
    }
}

impl<A, A2> ClientShardChunnelClient<A, A2> {
    pub async fn new(addr: A, redis_addr: &str) -> Result<Self, Error> {
        let redis_client = redis::Client::open(redis_addr)
            .wrap_err_with(|| eyre!("Opening redis client: {:?}", redis_addr))?;
        let redis_listen_connection = Arc::new(Mutex::new(
            redis_client
                .get_multiplexed_tokio_connection()
                .await
                .wrap_err_with(|| eyre!("Opening redis async connection: {:?}", redis_addr))?,
        ));

        Ok(ClientShardChunnelClient {
            addr,
            redis_listen_connection,
            _phantom: Default::default(),
        })
    }
}

impl<A, A2> Negotiate for ClientShardChunnelClient<A, A2> {
    type Capability = ShardFns;

    fn guid() -> u64 {
        0xafb32251f0697831
    }

    fn capabilities() -> Vec<ShardFns> {
        vec![ShardFns::Sharding]
    }
}

impl<A, A2, I, D> Chunnel<I> for ClientShardChunnelClient<A, A2>
where
    A: Serialize
        + DeserializeOwned
        + Clone
        + std::cmp::PartialEq
        + Debug
        + std::fmt::Display
        + Send
        + Sync
        + 'static,
    A: Into<A2>,
    A2: Clone + Debug + std::fmt::Display + Send + Sync + 'static,
    I: ChunnelConnection<Data = (A2, D)> + Send + Sync + 'static,
    D: Kv + Send + Sync + 'static,
    <D as Kv>::Key: AsRef<str>,
{
    type Connection = ClientShardClientConnection<A2, D, I>;
    type Error = Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    // implementing this is tricky - we have been given one connection with some semantics,
    // but we need n connections, to each shard.
    // 1. ignore the connection (to the canonical_addr) to establish our own, to the shards.
    // 2. force the connection to have (addr, data) semantics, so we can do routing without
    //    establishing our own connections
    //
    //  -> pick #2
    fn connect_wrap(&mut self, inner: I) -> Self::Future {
        let a = self.addr.clone();
        let redis_conn = Arc::clone(&self.redis_listen_connection);
        Box::pin(
            async move {
                trace!("query redis");
                // query redis for si
                let si = redis_util::redis_query(&a, redis_conn.lock().await)
                    .await
                    .wrap_err("redis query failed")?;

                let addrs = match si {
                    None => vec![a.into()],
                    Some(si) => {
                        let mut addrs = vec![si.canonical_addr.into()];
                        addrs.extend(si.shard_addrs.into_iter().map(Into::into));
                        addrs
                    }
                };

                debug!(addrs = ?&addrs, "Decided sharding plan");
                let num_shards = addrs.len() - 1;
                Ok(ClientShardClientConnection::new(inner, addrs, move |d| {
                    if num_shards == 0 {
                        return 0;
                    }
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

                    (hash as usize % num_shards) + 1
                }))
            }
            .instrument(debug_span!("ClientShardChunnelClient::connect")),
        )
    }
}

/// `ChunnelConnection` type for ClientShardChunnelClient.
pub struct ClientShardClientConnection<A, D, C>
where
    C: ChunnelConnection<Data = (A, D)>,
{
    inner: C,
    shard_addrs: Vec<A>,
    shard_fn: Arc<dyn Fn(&D) -> usize + Send + Sync + 'static>,
}

impl<A, C, D> ClientShardClientConnection<A, D, C>
where
    C: ChunnelConnection<Data = (A, D)>,
{
    pub fn new(
        inner: C,
        shard_addrs: Vec<A>, // canonical_addr is the first
        shard_fn: impl Fn(&D) -> usize + Send + Sync + 'static,
    ) -> Self {
        ClientShardClientConnection {
            inner,
            shard_addrs,
            shard_fn: Arc::new(shard_fn),
        }
    }
}

impl<A, C, D> ChunnelConnection for ClientShardClientConnection<A, D, C>
where
    A: Clone + Debug + Send + Sync + 'static,
    C: ChunnelConnection<Data = (A, D)> + Send + Sync + 'static,
    D: Kv + Send + Sync + 'static,
{
    type Data = (A, D);

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), eyre::Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        self.inner.send(burst.into_iter().map(|(_, payload)| {
            let shard_idx = (self.shard_fn)(&payload);
            let a = self.shard_addrs[shard_idx].clone();
            trace!(?a, ?shard_idx, "picked shard");
            (a, payload)
        }))
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<
        Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], eyre::Report>> + Send + 'cn>,
    >
    where
        'buf: 'cn,
    {
        self.inner.recv(msgs_buf)
    }
}
