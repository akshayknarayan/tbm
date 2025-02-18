use crate::{client, GetSockAddr, MicroserviceCn, Side};
use bertha::{Chunnel, ChunnelConnection, ChunnelListener, Negotiate};
use color_eyre::eyre::{Report, WrapErr};
use futures_util::stream::StreamExt;
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use tls_tunnel::{TLSChunnel, TlsConn};
use tokio::sync::Mutex;
use tracing::{debug, trace};

/// Uses Lch.connect_wrap(Lr) if local, and TLSChunnel<Inner> otherwise.
#[derive(Debug, Clone)]
pub struct MicroserviceTLSChunnel<Lch, Lr, Ag> {
    tls: tls_tunnel::TLSChunnel<Ag>,
    cl: Option<Arc<Mutex<client::LocalNameClient>>>,
    local_addr: Option<PathBuf>,
    local_peer_addr: Arc<StdMutex<Option<(PathBuf, Ag)>>>,
    local_raw: Lr,
    local_chunnel: Lch,
}

impl<Lch, Lr, Ag> Negotiate for MicroserviceTLSChunnel<Lch, Lr, Ag>
where
    Ag: From<SocketAddr> + tls_tunnel::GetTlsConnAddr + Send + 'static,
    Lch: Send,
    Lr: Send,
{
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

        let skaddr = match bincode::deserialize(&addr) {
            Ok(skaddr) => skaddr,
            Err(e) => {
                debug!(err = ?e, "socketaddr deserialize failed");
                return Box::pin(futures_util::future::ready(()));
            }
        };

        let cl = self.cl.clone();
        let mut tls = self.tls.clone();
        let res = self.local_peer_addr.clone();
        Box::pin(async move {
            if let Some(ref c) = cl {
                let mut cl_g = c.lock().await;
                if let Some(l) = cl_g.query(skaddr).await.ok().flatten() {
                    let mut r = res.lock().unwrap();
                    *r = Some((l, skaddr.into()));
                    return;
                }
            }

            {
                let mut r = res.lock().unwrap();
                *r = None;
            }
            trace!(global_addr = ?&skaddr, "initializing TLS connection");
            tls.picked(nonce).await;
        })
    }
}

impl<Lch, Lr, A> MicroserviceTLSChunnel<Lch, Lr, A>
where
    A: GetSockAddr,
{
    /// Server side `MicroserviceChunnel`.
    ///
    /// We will register on the `listen_addr`.
    pub async fn server(
        tls: TLSChunnel<A>,
        root: impl AsRef<Path>,
        listen_addr: A,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<Self, Report> {
        Self::new(
            tls,
            root,
            Side::Server(listen_addr),
            local_raw,
            local_chunnel,
        )
        .await
    }

    /// Client side `MicroserviceChunnel`.
    ///
    /// `remote_addr`: The address we are connecting to
    /// `local_addr`: The local address we are bound to
    ///
    /// We will register on the `local_addr`.
    pub async fn client(
        tls: TLSChunnel<A>,
        root: impl AsRef<Path>,
        remote_addr: A,
        local_addr: A,
        local_raw: Lr,
        local_chunnel: Lch,
    ) -> Result<Self, Report> {
        Self::new(
            tls,
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
        tls: TLSChunnel<A>,
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
            Ok(ref mut c) => match c.register(side.register_addr().as_sk_addr()).await {
                Ok(la) => {
                    trace!(?la, "registered address");
                    Some(la)
                }
                Err(err) => {
                    debug!(?err, addr = ?&side.register_addr().as_sk_addr(), "register call failed");
                    None
                }
            },
        };

        Ok(Self {
            tls,
            cl: cl.map(Mutex::new).map(Arc::new).ok(),
            local_addr,
            local_peer_addr: Default::default(),
            local_raw,
            local_chunnel,
        })
    }
}

impl<A, Gc, Lr, LrCn, LrErr, Lrd, Lch, Lcn, LchErr, D> Chunnel<Gc>
    for MicroserviceTLSChunnel<Lch, Lr, A>
where
    A: GetSockAddr
        + tls_tunnel::GetTlsConnAddr
        + Debug
        + From<SocketAddr>
        + Clone
        + PartialEq
        + Send
        + Sync
        + 'static,
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
    MicroserviceCn<TlsConn<A>, Lcn, A>: ChunnelConnection<Data = (crate::EitherAddr<A>, D)>,
{
    type Connection = MicroserviceCn<TlsConn<A>, Lcn, A>;
    type Error = Report;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect_wrap(&mut self, _: Gc) -> Self::Future {
        let local_self_addr = self.local_addr.clone();
        let local_peer_addr = { self.local_peer_addr.clone().lock().unwrap().clone() };
        let mut local_raw = self.local_raw.clone();
        let mut local_chunnel = self.local_chunnel.clone();
        let mut tls = self.tls.clone();
        Box::pin(async move {
            match local_peer_addr {
                None => {
                    let tls_conn = tls.connect_wrap(()).await?;
                    Ok(MicroserviceCn::Global(tls_conn))
                }
                Some((local_peer_addr, a)) => {
                    let local_raw_cn = local_raw
                        .listen(local_self_addr.unwrap())
                        .await
                        .map_err(Into::into)
                        .wrap_err("Local conection listen")?
                        .next()
                        .await
                        .unwrap()
                        .map_err(Into::into)
                        .wrap_err("Local conection listen")?;
                    let local_cn = local_chunnel
                        .connect_wrap(local_raw_cn)
                        .await
                        .map_err(Into::into)?;
                    trace!(?local_peer_addr, global_addr = ?&a, "returning local connection");
                    Ok(MicroserviceCn::Local {
                        cn: local_cn,
                        local_addr: local_peer_addr,
                        global_addr: a,
                    })
                }
            }
        })
    }
}
