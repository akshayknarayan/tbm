//! Client side.

use crate::msg::Msg;
use crate::reliability::KvReliabilityChunnel;
use bertha::{
    bincode::SerializeChunnel,
    negotiate::Select,
    util::ProjectLeft,
    util::{MsgIdMatcher, NeverCn, Nothing},
    ChunnelConnection, CxList,
};
use color_eyre::eyre::{eyre, Report, WrapErr};
use shard_ctl::ClientShardChunnelClient;
use std::net::SocketAddr;
use std::pin::Pin;
use tracing::{debug, debug_span, instrument, trace};
use tracing_futures::Instrument;

#[derive(Debug, Clone, Copy)]
pub struct KvClientBuilder {
    canonical_addr: SocketAddr,
}

impl KvClientBuilder {
    pub fn new(canonical_addr: SocketAddr) -> Self {
        KvClientBuilder { canonical_addr }
    }
}

macro_rules! nonshard {
    ($raw_cn: expr, $ca: expr) => {{
        let stack = CxList::from(KvReliabilityChunnel::default()).wrap(SerializeChunnel::default());
        debug!("negotiation");
        let cn = bertha::negotiate::negotiate_client(stack, $raw_cn, $ca)
            .instrument(debug_span!("client_negotiate"))
            .await?;
        ProjectLeft::new($ca, cn)
    }};
}

macro_rules! shardcl {
    ($raw_cn: expr, $redis_addr: expr, $ca: expr, $sel: expr) => {{
        let redis_addr = format!("redis://{}:{}", $redis_addr.ip(), $redis_addr.port());
        let cl = ClientShardChunnelClient::new($ca, &redis_addr).await?;
        let stack = CxList::from(Select::from((
            cl,
            Nothing::<shard_ctl::ShardFns>::default(),
        )))
        .wrap($sel);
        debug!("negotiation");
        let cn = bertha::negotiate::negotiate_client(stack, $raw_cn, $ca)
            .instrument(debug_span!("client_negotiate"))
            .await?;
        ProjectLeft::new($ca, cn)
    }};
}

impl KvClientBuilder {
    #[instrument(skip(raw_cn), err)]
    pub async fn new_nonshardclient(
        self,
        raw_cn: impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
    ) -> Result<KvClient<impl ChunnelConnection<Data = Msg> + Send + Sync + 'static>, Report> {
        let cn = nonshard!(raw_cn, self.canonical_addr);
        Ok(KvClient::new_from_cn(cn))
    }

    #[instrument(skip(raw_cn), err)]
    pub async fn new_shardclient(
        self,
        raw_cn: impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
        redis_addr: SocketAddr,
    ) -> Result<KvClient<impl ChunnelConnection<Data = Msg> + Send + Sync + 'static>, Report> {
        let st = CxList::from(KvReliabilityChunnel::default()).wrap(SerializeChunnel::default());
        let cn = shardcl!(raw_cn, redis_addr, self.canonical_addr, st);
        Ok(KvClient::new_from_cn(cn))
    }
}

impl KvClientBuilder {
    #[instrument(skip(raw_cn), err)]
    pub async fn new_fiat_client(
        self,
        raw_cn: impl ChunnelConnection<Data = (SocketAddr, Vec<u8>)> + Send + Sync + 'static,
        si: shard_ctl::ShardInfo<SocketAddr>,
    ) -> Result<KvClient<impl ChunnelConnection<Data = Msg> + Send + Sync + 'static>, Report> {
        use bertha::Chunnel;
        let cl = shard_ctl::static_client::ClientShardChunnelClient::new(si);
        let mut stack = CxList::from(cl)
            .wrap(KvReliabilityChunnel::default())
            .wrap(SerializeChunnel::default());
        let cn = stack.connect_wrap(raw_cn).await?;
        let cn = ProjectLeft::new(self.canonical_addr, cn);
        Ok(KvClient::new_from_cn(cn))
    }
}

/// Connect to a Kv service.
pub struct KvClient<C: ChunnelConnection>(MsgIdMatcher<C, Msg>);

impl<C: ChunnelConnection> Clone for KvClient<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl KvClient<NeverCn> {
    fn new_from_cn<C2: ChunnelConnection<Data = Msg> + Send + Sync + 'static>(
        inner: C2,
    ) -> KvClient<C2> {
        KvClient(MsgIdMatcher::new(inner))
    }
}

impl<C> KvClient<C>
where
    C: ChunnelConnection<Data = Msg> + Send + Sync + 'static,
{
    #[instrument(level = "trace", skip(self))]
    async fn do_req(&self, req: Msg) -> Result<Option<String>, Report> {
        let cn = &self.0;
        let id = req.id;
        trace!("sending");
        cn.send_msg(req).await.wrap_err("Error sending request")?;
        let rsp = cn.recv_msg(id).await.wrap_err("Error awaiting response")?;
        trace!("received");
        if rsp.id != id {
            return Err(eyre!(
                "Msg id mismatch, check for reordering: {} != {}",
                rsp.id,
                id
            ));
        }

        Ok(rsp.into_kv().1)
    }
}

impl<C> KvClient<C>
where
    C: ChunnelConnection<Data = Msg> + Send + Sync + 'static,
{
    fn do_req_fut(
        &self,
        req: Msg,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<String>, Report>>>> {
        let cl = self.clone();
        Box::pin(async move { cl.do_req(req).await })
    }

    pub fn update_fut(
        &self,
        key: String,
        val: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<String>, Report>>>> {
        let req = Msg::put_req(key, val);
        self.do_req_fut(req)
    }

    pub async fn update(&self, key: String, val: String) -> Result<Option<String>, Report> {
        let req = Msg::put_req(key, val);
        self.do_req(req).await
    }

    pub fn get_fut(
        &self,
        key: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<String>, Report>>>> {
        let req = Msg::get_req(key);
        self.do_req_fut(req)
    }

    pub async fn get(&self, key: String) -> Result<Option<String>, Report> {
        let req = Msg::get_req(key);
        self.do_req(req).await
    }
}
