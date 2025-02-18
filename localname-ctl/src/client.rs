use crate::{proto, CONTROLLER_ADDRESS};
use color_eyre::eyre::{bail, eyre, Error};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tokio_tower::pipeline;
use tower_service::Service;

#[derive(Debug)]
pub struct LocalNameClient {
    root: PathBuf,
    cl: pipeline::Client<
        async_bincode::AsyncBincodeStream<
            UnixStream,
            proto::Reply,
            proto::Request,
            async_bincode::AsyncDestination,
        >,
        Error,
        proto::Request,
    >,
}

impl LocalNameClient {
    pub async fn new(burrito_root: &Path) -> Result<Self, Error> {
        let root = burrito_root.to_path_buf();
        let controller_addr = burrito_root.join(CONTROLLER_ADDRESS);
        let uc: async_bincode::AsyncBincodeStream<_, proto::Reply, proto::Request, _> =
            UnixStream::connect(controller_addr).await?.into();
        let uc = uc.for_async();
        let cl = pipeline::Client::new(uc);

        Ok(LocalNameClient { root, cl })
    }

    pub async fn register(&mut self, name: SocketAddr) -> Result<PathBuf, Error> {
        if name.ip().is_unspecified() {
            let addrs = pnet::datalink::interfaces()
                .into_iter()
                .filter(|i| i.is_up() && !i.ips.is_empty())
                .flat_map(|i| {
                    i.ips.into_iter().map(|a| {
                        let mut addr = name;
                        addr.set_ip(a.ip());
                        addr
                    })
                });
            self.do_register_addrs(addrs.collect()).await
        } else {
            self.do_register_addrs(vec![name]).await
        }
    }

    async fn do_register_addrs(&mut self, addrs: Vec<SocketAddr>) -> Result<PathBuf, Error> {
        tracing::trace!(?addrs, "registering");
        futures_util::future::poll_fn(|cx| self.cl.poll_ready(cx)).await?;
        match self
            .cl
            .call(proto::Request::Register(proto::RegisterRequest { addrs }))
            .await
        {
            Ok(proto::Reply::Register(r)) => {
                let r: Result<proto::RegisterReplyOk, String> = r.into();
                r.map_err(|s| eyre!("{}", s))
                    .map(|r| self.root.join(r.local_addr))
            }
            _ => bail!("Reply mismatched request type"),
        }
    }

    pub async fn query(
        &mut self,
        req: Vec<SocketAddr>,
    ) -> Result<Vec<(SocketAddr, Option<PathBuf>)>, Error> {
        futures_util::future::poll_fn(|cx| self.cl.poll_ready(cx)).await?;
        match self.cl.call(proto::Request::Query(req)).await {
            Ok(proto::Reply::Query(r)) => {
                let rp: Result<proto::QueryNameReplyOk, String> = r.into();
                let rp = rp.map_err(|s| eyre!("{}", s))?;
                Ok(rp
                    .0
                    .into_iter()
                    .map(|proto::QueryNameReplyEntry { addr, local_addr }| {
                        (addr, local_addr.map(|a| self.root.join(a)))
                    })
                    .collect())
            }
            _ => bail!("Reply mismatched request type"),
        }
    }
}
