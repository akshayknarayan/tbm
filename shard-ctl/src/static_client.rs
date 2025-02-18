use crate::{Kv, ShardFns, ShardInfo, FNV1_64_INIT, FNV_64_PRIME};
use bertha::{Chunnel, ChunnelConnection, Negotiate};
use color_eyre::eyre::{self, Error};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, debug_span};
use tracing_futures::Instrument;

#[derive(Clone)]
pub struct ClientShardChunnelClient {
    addr: ShardInfo<SocketAddr>,
}

impl std::fmt::Debug for ClientShardChunnelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientShardChunnelClient")
            .field("addr", &self.addr)
            .finish()
    }
}

impl ClientShardChunnelClient {
    pub fn new(addr: ShardInfo<SocketAddr>) -> Self {
        ClientShardChunnelClient { addr }
    }
}

impl Negotiate for ClientShardChunnelClient {
    type Capability = ShardFns;

    fn guid() -> u64 {
        0xafb32251f0697831
    }

    fn capabilities() -> Vec<ShardFns> {
        vec![super::ShardFns::Sharding]
    }
}

impl<I, D> Chunnel<I> for ClientShardChunnelClient
where
    I: ChunnelConnection<Data = (SocketAddr, D)> + Send + Sync + 'static,
    D: Kv + Send + Sync + 'static,
    <D as Kv>::Key: AsRef<str>,
{
    type Connection = ClientShardClientConnection<SocketAddr, D, I>;
    type Error = Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect_wrap(&mut self, inner: I) -> Self::Future {
        let a = self.addr.clone();
        Box::pin(
            async move {
                let mut addrs = vec![a.canonical_addr];
                addrs.extend(a.shard_addrs.into_iter());

                debug!(addrs = ?&addrs, "Decided sharding plan");
                let num_shards = addrs.len() - 1;
                Ok(ClientShardClientConnection::new(inner, addrs, move |d| {
                    if num_shards == 0 {
                        return 0;
                    }

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
    A: Clone + Send + Sync + 'static,
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
