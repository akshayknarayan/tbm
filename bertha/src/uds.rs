//! Unix datagram/socket chunnel.

use crate::{ChunnelConnection, ChunnelConnector, ChunnelListener};
use color_eyre::eyre::{eyre, Report};
use futures_util::stream::{Stream, StreamExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::trace;

/// UDP Chunnel connector.
///
/// Carries no state.
#[derive(Default, Clone, Debug)]
pub struct UnixSkChunnel;

impl ChunnelListener for UnixSkChunnel {
    type Addr = PathBuf;
    type Connection = UnixSk;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send + 'static>>;
    type Stream =
        Pin<Box<dyn Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn listen(&mut self, a: Self::Addr) -> Self::Future {
        Box::pin(async move {
            let sk = tokio::net::UnixDatagram::bind(a)?;
            Ok(
                Box::pin(futures_util::stream::once(futures_util::future::ready(Ok(
                    UnixSk::new(sk),
                )))) as _,
            )
        })
    }
}

impl ChunnelConnector for UnixSkChunnel {
    type Addr = ();
    type Connection = UnixSk;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn connect(&mut self, _a: Self::Addr) -> Self::Future {
        Box::pin(async move {
            use rand::Rng;
            let rng = rand::thread_rng();
            let stem: String = rng
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(10)
                .collect();
            let d = std::env::temp_dir();
            let f = d.join(stem);
            let sk = tokio::net::UnixDatagram::bind(f)?;
            Ok(UnixSk::new(sk))
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnixSk {
    sk: Arc<tokio::net::UnixDatagram>,
}

impl UnixSk {
    fn new(sk: tokio::net::UnixDatagram) -> Self {
        Self { sk: Arc::new(sk) }
    }
}

impl ChunnelConnection for UnixSk {
    type Data = (PathBuf, Vec<u8>);

    fn send(
        &self,
        data: Self::Data,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'static>> {
        let sk = Arc::clone(&self.sk);
        Box::pin(async move {
            let (addr, data) = data;
            trace!(to = ?&addr, "send");
            sk.send_to(&data, &addr).await?;
            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Self::Data, Report>> + Send + 'static>> {
        let mut buf = [0u8; 1024];
        let sk = Arc::clone(&self.sk);

        Box::pin(async move {
            let (len, from) = sk.recv_from(&mut buf).await?;
            trace!(from = ?&from, "recv");
            let data = buf[0..len].to_vec();
            Ok((
                from.as_pathname()
                    .ok_or_else(|| eyre!("received from unnamed socket"))?
                    .to_path_buf(),
                data,
            ))
        })
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct UnixReqChunnel;

impl ChunnelListener for UnixReqChunnel {
    type Addr = PathBuf;
    type Connection = UnixConn;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send + 'static>>;
    type Stream =
        Pin<Box<dyn Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Error = Report;

    fn listen(&mut self, a: Self::Addr) -> Self::Future {
        Box::pin(async move {
            let sk = tokio::net::UnixDatagram::bind(a)?;
            let sends = futures_util::stream::FuturesUnordered::new();
            Ok(Box::pin(futures_util::stream::try_unfold(
                (
                    Arc::new(sk),
                    sends,
                    HashMap::<_, mpsc::Sender<(PathBuf, Vec<u8>)>>::new(),
                ),
                |(sk, mut sends, mut map)| async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        // careful: potential deadlocks since .recv on returned connection blocks
                        // on .listen
                        tokio::select!(
                            Some((from, res)) = sends.next() => {
                                #[allow(clippy::redundant_pattern_matching)]
                                if let Err(_) = res {
                                    map.remove(&from);
                                }
                            }
                            Ok((len, from)) = sk.recv_from(&mut buf) => {
                                trace!(from = ?&from, "received pkt");
                                let data = buf[0..len].to_vec();

                                let from = from.as_pathname()
                                    .ok_or_else(|| eyre!("received from unnamed socket"))?
                                    .to_path_buf();

                                let mut done = None;
                                let c = map.entry(from.clone()).or_insert_with(|| {
                                    let (sch, rch) = mpsc::channel(100);
                                    done = Some(UnixConn {
                                        resp_addr: from.clone(),
                                        recv: Arc::new(Mutex::new(rch)),
                                        send: Arc::clone(&sk),
                                    });

                                    sch
                                });

                                let c = c.clone();
                                sends.push(async move {
                                    let res = c.send((from.clone(), data)).await;
                                    (from, res)
                                });

                                if let Some(d) = done {
                                    return Ok(Some((d, (sk, sends,  map))));
                                }
                            }
                        )
                    }
                },
            )) as _)
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnixConn {
    resp_addr: PathBuf,
    recv: Arc<Mutex<mpsc::Receiver<(PathBuf, Vec<u8>)>>>,
    send: Arc<tokio::net::UnixDatagram>,
}

impl ChunnelConnection for UnixConn {
    type Data = (PathBuf, Vec<u8>);

    fn send(
        &self,
        data: Self::Data,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'static>> {
        let sk = Arc::clone(&self.send);
        let addr = self.resp_addr.clone();
        let (_, data) = data;
        Box::pin(async move {
            sk.send_to(&data, &addr).await?;
            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = Result<Self::Data, Report>> + Send + 'static>> {
        let r = Arc::clone(&self.recv);
        Box::pin(async move {
            let d = r.lock().await.recv().await;
            d.ok_or_else(|| eyre!("Nothing more to receive"))
        }) as _
    }
}

#[cfg(test)]
mod test {
    use super::{UnixReqChunnel, UnixSkChunnel};
    use crate::{ChunnelConnection, ChunnelConnector, ChunnelListener};
    use futures_util::{StreamExt, TryStreamExt};
    use std::path::PathBuf;
    use tracing_error::ErrorLayer;
    use tracing_futures::Instrument;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    #[test]
    fn echo() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        color_eyre::install().unwrap_or_else(|_| ());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        std::fs::remove_file("./tmp-unix-echo-addr").unwrap_or_else(|_| ());

        rt.block_on(
            async move {
                let addr = PathBuf::from(r"./tmp-unix-echo-addr");
                let srv = UnixSkChunnel::default()
                    .listen(addr.clone().into())
                    .await
                    .unwrap()
                    .next()
                    .await
                    .unwrap()
                    .unwrap();

                let cli = UnixSkChunnel::default().connect(()).await.unwrap();

                tokio::spawn(async move {
                    loop {
                        let (from, data) = srv.recv().await.unwrap();
                        srv.send((from, data)).await.unwrap();
                    }
                });

                cli.send((addr.clone().into(), vec![1u8; 12]))
                    .await
                    .unwrap();
                let (from, data) = cli.recv().await.unwrap();

                let from: PathBuf = from.into();
                let addr: PathBuf = addr.into();
                assert_eq!(from, addr);
                assert_eq!(data, vec![1u8; 12]);
            }
            .instrument(tracing::info_span!("unix::echo")),
        );
    }

    #[test]
    fn rendezvous() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        color_eyre::install().unwrap_or_else(|_| ());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        let path = r"./tmp-unix-req-echo-addr";
        std::fs::remove_file(path).unwrap_or_else(|_| ());

        rt.block_on(
            async move {
                let addr = PathBuf::from(path);
                let saddr = addr.clone();
                tokio::spawn(async move {
                    let srv = UnixReqChunnel::default().listen(saddr).await.unwrap();
                    srv.try_for_each_concurrent(None, |cn| async move {
                        let data = cn.recv().await?;
                        cn.send(data).await?;
                        Ok(())
                    })
                    .await
                    .unwrap();
                });

                let cli = UnixSkChunnel::default().connect(()).await.unwrap();
                cli.send((addr.clone().into(), vec![1u8; 12]))
                    .await
                    .unwrap();
                let (from, data) = cli.recv().await.unwrap();

                let from: PathBuf = from.into();
                let addr: PathBuf = addr.into();
                assert_eq!(from, addr);
                assert_eq!(data, vec![1u8; 12]);
            }
            .instrument(tracing::info_span!("udp::rendezvous")),
        );
    }
}
