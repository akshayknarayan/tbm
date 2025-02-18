use crate::{client, GetSockAddr};
use bertha::{Chunnel, ChunnelConnection, ChunnelListener, Negotiate};
use color_eyre::eyre::{eyre, Report};
use futures_util::{future::ready, stream::StreamExt};
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Side<A> {
    Server(A),
    Client { local_addr: A, remote_addr: A },
}

impl<A> Side<A> {
    pub(crate) fn register_addr(&self) -> &A {
        match self {
            Side::Server(a) => a,
            Side::Client { local_addr, .. } => local_addr,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MicroserviceChunnel<Lch, Lr, Ag> {
    cl: Option<Arc<Mutex<client::LocalNameClient>>>,
    local_addr: Option<PathBuf>,
    peer_global_addr: Option<SocketAddr>,
    side: Side<Ag>,
    local_raw: Lr,
    local_chunnel: Lch,
}

impl<Lch, Lr, Ag> Negotiate for MicroserviceChunnel<Lch, Lr, Ag> {
    type Capability = ();

    fn guid() -> u64 {
        0xb3fa08967e518987
    }

    fn picked<'s>(&mut self, nonce: &'s [u8]) -> Pin<Box<dyn Future<Output = ()> + Send + 's>> {
        let msg: bertha::negotiate::NegotiateMsg = match bincode::deserialize(nonce) {
            Err(e) => {
                debug!(err = ?e, "nonce deserialize failed");
                return Box::pin(futures_util::future::ready(()));
            }
            Ok(m) => m,
        };

        let addr = match msg {
            bertha::negotiate::NegotiateMsg::ServerNonce { addr, .. } => addr,
            _ => {
                debug!("malformed nonce");
                return Box::pin(futures_util::future::ready(()));
            }
        };

        match bincode::deserialize(&addr) {
            Ok(skaddr) => {
                self.peer_global_addr = Some(skaddr);
            }
            Err(e) => {
                debug!(err = ?e, "socketaddr deserialize failed");
            }
        }

        Box::pin(futures_util::future::ready(()))
    }
}

impl<Lch, Lr, A> MicroserviceChunnel<Lch, Lr, A>
where
    A: GetSockAddr,
{
    /// Server side `MicroserviceChunnel`.
    ///
    /// We will register on the `listen_addr`.
    pub async fn server(
        root: impl AsRef<Path>,
        listen_addr: A,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<Self, Report> {
        Self::new(root, Side::Server(listen_addr), local_raw, local_chunnel).await
    }

    /// Client side `MicroserviceChunnel`.
    ///
    /// `remote_addr`: The address we are connecting to
    /// `local_addr`: The local address we are bound to
    ///
    /// We will register on the `local_addr`.
    pub async fn client(
        root: impl AsRef<Path>,
        remote_addr: A,
        local_addr: A,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<Self, Report> {
        Self::new(
            root,
            Side::Client {
                local_addr,
                remote_addr,
            },
            local_raw,
            local_chunnel,
        )
        .await
    }

    async fn new(
        root: impl AsRef<Path>,
        side: Side<A>,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<Self, Report> {
        let mut cl = client::LocalNameClient::new(root.as_ref()).await;
        let local_addr = match &mut cl {
            Err(ref e) => {
                debug!(err = %format!("{:#}", e), "LocalNameClient did not connect");
                None
            }
            Ok(ref mut c) => c.register(side.register_addr().as_sk_addr()).await.ok(),
        };

        Ok(Self {
            cl: cl.map(Mutex::new).map(Arc::new).ok(),
            local_addr,
            peer_global_addr: None,
            side,
            local_raw,
            local_chunnel,
        })
    }
}

impl<A, Gc, Lr, LrCn, LrErr, Lrd, Lch, Lcn, LchErr, D> Chunnel<Gc>
    for MicroserviceChunnel<Lch, Lr, A>
where
    Gc: ChunnelConnection<Data = (A, D)> + Send + Sync + 'static,
    A: GetSockAddr + From<SocketAddr> + Clone + PartialEq + Debug + Send + Sync + 'static,
    D: Send + Sync + 'static,
    // Raw local connections. Lrd, local raw data, is probably Vec<u8> (e.g. for Lctr = UDS), but
    // don't assume this.
    Lr: ChunnelListener<Connection = LrCn, Addr = PathBuf, Error = LrErr> + Clone + Send + 'static,
    <Lr as ChunnelListener>::Stream: Unpin,
    LrCn: ChunnelConnection<Data = (PathBuf, Lrd)> + Send,
    LrErr: Into<Report> + Send + Sync + 'static,
    // Local connections with semantics.
    Lch: Chunnel<LrCn, Connection = Lcn, Error = LchErr> + Clone + Send + 'static,
    Lcn: ChunnelConnection<Data = (PathBuf, D)> + Send + Sync + 'static,
    LchErr: Into<Report> + Send + Sync + 'static,
{
    type Connection = MicroserviceCn<Gc, Lcn, A>;
    type Error = Report;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect_wrap(&mut self, inner: Gc) -> Self::Future {
        match &self.cl {
            Some(ref c) => {
                let side = self.side.clone();
                let cl = c.clone();
                let local_self_addr = self.local_addr.clone();
                let mut local_raw = self.local_raw.clone();
                let mut local_chunnel = self.local_chunnel.clone();
                let peer_global_addr = self.peer_global_addr;
                Box::pin(async move {
                    let mut cl_g = cl.lock().await;
                    let a: A = match side {
                        Side::Client { remote_addr: a, .. } => a,
                        Side::Server(_) => peer_global_addr
                            .ok_or_else(|| eyre!("no peer client address set"))?
                            .into(),
                    };

                    match cl_g.query(a.as_sk_addr()).await? {
                        None => {
                            trace!(global_addr = ?&a, "using global connection");
                            Ok(MicroserviceCn::Global(inner))
                        }
                        Some(local_peer_addr) => {
                            trace!(?local_peer_addr, global_addr = ?&a, "getting local connection");
                            let local_raw_cn = local_raw
                                .listen(local_self_addr.unwrap())
                                .await
                                .map_err(Into::into)?
                                .next()
                                .await
                                .unwrap()
                                .map_err(Into::into)?;
                            let local_cn = local_chunnel
                                .connect_wrap(local_raw_cn)
                                .await
                                .map_err(Into::into)?;
                            trace!(?local_peer_addr, global_addr = ?&a, "using local connection");
                            Ok(MicroserviceCn::Local {
                                cn: local_cn,
                                local_addr: local_peer_addr,
                                global_addr: a,
                            })
                        }
                    }
                })
            }
            None => {
                // if we couldn't connect to localname-ctl, it's all global anyway.
                trace!("no localname-ctl, using global connection");
                Box::pin(ready(Ok(MicroserviceCn::Global(inner))))
            }
        }
    }
}

pub enum MicroserviceCn<G, L, A> {
    Local {
        cn: L,
        local_addr: PathBuf,
        global_addr: A,
    },
    Global(G),
}

#[derive(Clone, Debug, PartialEq)]
pub enum EitherAddr<A> {
    Global(A),
    Local(PathBuf),
}

impl<A> From<A> for EitherAddr<A> {
    fn from(g: A) -> Self {
        EitherAddr::Global(g)
    }
}

impl<G, L, A, D> ChunnelConnection for MicroserviceCn<G, L, A>
where
    G: ChunnelConnection<Data = (A, D)> + Send + Sync + 'static,
    L: ChunnelConnection<Data = (PathBuf, D)> + Send + Sync + 'static,
    A: Clone + PartialEq + Send + Sync + 'static,
    D: 'static,
{
    type Data = (EitherAddr<A>, D);

    fn send(
        &self,
        (addr, data): Self::Data,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'static>> {
        match (self, addr) {
            (
                Self::Local {
                    cn,
                    local_addr,
                    global_addr,
                },
                EitherAddr::Global(addr),
            ) if addr == *global_addr => {
                trace!(?local_addr, "local send");
                Box::pin(cn.send((local_addr.clone(), data)))
            }
            (Self::Local { cn, .. }, EitherAddr::Local(pbuf)) => {
                trace!(?pbuf, "local send");
                Box::pin(cn.send((pbuf, data)))
            }
            (Self::Local { .. }, _) => Box::pin(ready(Err(eyre!(
                "Address mismatched pre-connected local address"
            )))),
            (Self::Global(cn), EitherAddr::Global(g)) => {
                trace!("global send");
                Box::pin(cn.send((g, data)))
            }
            (Self::Global(_), _) => Box::pin(ready(Err(eyre!(
                "Global connection can't use local address"
            )))),
        }
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Self::Data, Report>> + Send + 'static>> {
        match self {
            Self::Local {
                cn,
                global_addr,
                local_addr,
            } => {
                let f = cn.recv();
                let global_addr = global_addr.clone();
                let local_addr = local_addr.clone();
                Box::pin(async move {
                    let (la, d) = f.await?;
                    trace!(?la, "recvd");
                    if la == local_addr {
                        Ok((EitherAddr::Global(global_addr), d))
                    } else {
                        Ok((EitherAddr::Local(la), d))
                    }
                })
            }
            Self::Global(cn) => {
                use futures_util::TryFutureExt;
                trace!("global recv");
                let f = cn.recv().map_ok(|(a, d)| (EitherAddr::Global(a), d));
                Box::pin(f)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::EitherAddr;
    use super::MicroserviceChunnel;
    use bertha::{
        negotiate_client, negotiate_server, udp::UdpSkChunnel, uds::UnixSkChunnel, util::Nothing,
        ChunnelConnection, ChunnelConnector, ChunnelListener,
    };
    use futures_util::stream::TryStreamExt;
    use std::net::SocketAddr;
    use tracing::info;
    use tracing_error::ErrorLayer;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    #[test]
    fn microservice_no_ctl() {
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

        let addr: SocketAddr = "127.0.0.1:12571".parse().unwrap();

        rt.block_on(async move {
            let lch = MicroserviceChunnel::server(
                "/foo/bar",
                addr,
                UnixSkChunnel::default(),
                Nothing::<()>::default(),
            )
            .await
            .unwrap();
            tokio::spawn(async move {
                let st = negotiate_server(lch, UdpSkChunnel.listen(addr).await.unwrap())
                    .await
                    .unwrap();
                st.try_for_each_concurrent(None, |cn| async move {
                    loop {
                        let m: (_, Vec<u8>) = cn.recv().await.unwrap();
                        info!(?m, "got msg");
                        cn.send(m).await.unwrap();
                    }
                })
                .await
                .unwrap();
            });

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let sk = UdpSkChunnel.connect(()).await.unwrap();
            let lch = MicroserviceChunnel::client(
                "/foo/bar",
                addr,
                sk.local_addr().unwrap(),
                UnixSkChunnel::default(),
                Nothing::<()>::default(),
            )
            .await
            .unwrap();
            let cn = negotiate_client(lch, sk, addr).await.unwrap();

            let addr: EitherAddr<_> = addr.into();
            cn.send((addr.clone(), vec![0u8; 10])).await.unwrap();
            let m = cn.recv().await.unwrap();
            assert_eq!(m, (addr, vec![0u8; 10]));
        });
    }

    #[cfg(feature = "ctl")]
    #[test]
    fn microservice_ctl() {
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

        let addr: SocketAddr = "127.0.0.1:13571".parse().unwrap();
        const ROOT: &'static str = "./tmp-test-burrito-root";

        rt.block_on(
            async move {
                test_util::reset_root_dir(std::path::Path::new(ROOT));
                tokio::spawn(
                    async move {
                        info!("starting");
                        crate::ctl::serve_ctl(Some(std::path::PathBuf::from(ROOT)), true).await?;
                        Ok::<_, Report>(())
                    }
                    .instrument(info_span!("ctl")),
                );

                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                tokio::spawn(
                    async move {
                        info!("starting");
                        let lch = MicroserviceChunnel::server(
                            ROOT,
                            addr,
                            UnixSkChunnel::default(),
                            Nothing::<()>::default(),
                        )
                        .await
                        .unwrap();
                        let st = negotiate_server(lch, UdpSkChunnel.listen(addr).await.unwrap())
                            .await
                            .unwrap();
                        st.try_for_each_concurrent(None, |cn| async move {
                            info!("got conn");
                            loop {
                                let m: (_, Vec<u8>) = cn.recv().await.unwrap();
                                info!(?m, "got msg");
                                cn.send(m).await.unwrap();
                            }
                        })
                        .await
                        .unwrap();
                    }
                    .instrument(info_span!("server")),
                );

                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                info!("making client");

                let sk = UdpSkChunnel.connect(()).await.unwrap();
                let lch = MicroserviceChunnel::client(
                    ROOT,
                    addr,
                    sk.local_addr().unwrap(),
                    UnixSkChunnel::default(),
                    Nothing::<()>::default(),
                )
                .await
                .unwrap();
                let cn = negotiate_client(lch, sk, addr).await.unwrap();

                let addr: EitherAddr<_> = addr.into();

                info!("sending");
                cn.send((addr.clone(), vec![0u8; 10])).await.unwrap();
                let m = cn.recv().await.unwrap();
                assert_eq!(m, (addr, vec![0u8; 10]));
                info!("done");
            }
            .instrument(info_span!("microservice_ctl")),
        );
    }
}
