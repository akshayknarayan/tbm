use crate::*;

/// Skip serde in situations where possible.
///
/// If we know the client's serialization format (and it is constant), then we know `OFFSET`, so we
/// can just hash based on looking at the Vec<u8> instead of deserializing.
///
/// Otherwise just wrap `ShardCanonicalServer`, functionality is identical (even the connection
/// type is identical).
pub struct ShardCanonicalServerRaw<A, S, Ss, D, const OFFSET: usize> {
    inner: ShardCanonicalServer<A, S, Ss, D>,
}

impl<A, S, Ss, D, const OFFSET: usize> Clone for ShardCanonicalServerRaw<A, S, Ss, D, OFFSET>
where
    A: Clone,
    Ss: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<A: std::fmt::Debug, S, Ss, D, const OFFSET: usize> std::fmt::Debug
    for ShardCanonicalServerRaw<A, S, Ss, D, OFFSET>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardCanonicalServerRaw")
            .field("addr", &self.inner.addr)
            .field("offset", &OFFSET)
            .finish()
    }
}

impl<A, S, Ss, D, const OFFSET: usize> From<ShardCanonicalServer<A, S, Ss, D>>
    for ShardCanonicalServerRaw<A, S, Ss, D, OFFSET>
{
    fn from(inner: ShardCanonicalServer<A, S, Ss, D>) -> Self {
        ShardCanonicalServerRaw { inner }
    }
}

impl<A, S, Ss, D, const OFFSET: usize> Negotiate for ShardCanonicalServerRaw<A, S, Ss, D, OFFSET>
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
        ShardCanonicalServer::<A, S, Ss, D>::guid()
    }

    fn capabilities() -> Vec<ShardFns> {
        ShardCanonicalServer::<A, S, Ss, D>::capabilities()
    }

    fn picked<'s>(&mut self, nonce: &'s [u8]) -> Pin<Box<dyn Future<Output = ()> + Send + 's>> {
        self.inner.picked(nonce)
    }
}

impl<I, A, S, Ss, E, D, const OFFSET: usize> Chunnel<I>
    for ShardCanonicalServerRaw<A, S, Ss, D, OFFSET>
where
    I: ChunnelConnection<Data = (A, Vec<u8>)> + Send + Sync + 'static,
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
        Chunnel<Arc<S::Connection>> + bertha::NegotiatePicked + Clone + Debug + Send + 'static,
    <<Ss as Apply>::Applied as Chunnel<Arc<S::Connection>>>::Connection:
        ChunnelConnection<Data = D> + Send + Sync + 'static,
    <<Ss as Apply>::Applied as Chunnel<Arc<S::Connection>>>::Error:
        Into<Error> + Send + Sync + 'static,
    E: Into<Error> + Send + Sync + 'static,
{
    type Connection = ShardCanonicalServerConnection<I, S::Connection, (A, Vec<u8>)>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Error;

    fn connect_wrap(&mut self, conn: I) -> Self::Future {
        let addr = self.inner.addr.clone();
        let internal_addr = self.inner.internal_addr.clone();
        let a1 = addr.clone();
        let shards_inner = Arc::clone(&self.inner.shards_inner);
        let shards_inner_stack = self.inner.shards_inner_stack.clone();
        Box::pin(
            async move {
                let _ = &addr;
                let num_shards = addr.shard_addrs.len();

                // negotiate with shards
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
                        let cn = Arc::new(cn);
                        // What is happening here???
                        //
                        // We have a problem: we want our ShardCanonicalServerConnection to operate
                        // on (A, Vec<u8>) because doing shards_inner_stack is expensive at
                        // runtime. But, we need to make the shard still expect
                        // `shards_inner_stack` semantics, since that's what the packets will be.
                        // So, we do negotiation to make the shard think we are using
                        // `shards_inner_stack`, but then we don't use that connection (with the
                        // semantics) and instead we directly use the raw `cn`.
                        //
                        // TODO is this unsafe?
                        let _ = bertha::negotiate::negotiate_client(
                            shards_inner_stack.clone(),
                            cn.clone(),
                            a.clone(),
                        )
                        .await
                        .wrap_err("negotiate_client failed")?;
                        // we made an Arc, but it was potentially returned to us in the return type of
                        // negotiate_client. Since we assigned the return value to `_`, it was
                        // dropped, so the one clone we made of the Arc was dropped. So, the strong
                        // count of the Arc is now 1, so we can unwrap.
                        let cn = Arc::try_unwrap(cn)
                            .map_err(|_| eyre!("Strong count should be 1"))
                            .expect("Strong count should be 1");
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
                    shard_fn: Arc::new(move |d: &(_, Vec<u8>)| {
                        let mut hash = FNV1_64_INIT;
                        for b in d.1[OFFSET..OFFSET + 4].iter() {
                            hash ^= *b as u64;
                            hash = u64::wrapping_mul(hash, FNV_64_PRIME);
                        }

                        hash as usize % num_shards
                    }),
                })
            }
            .instrument(debug_span!("serve_raw", addr = ?&a1)),
        )
    }
}
