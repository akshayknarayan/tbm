//! Tools for working with Chunnels.

// Pin<Box<...>> is necessary and not worth breaking up
#![allow(clippy::type_complexity)]

use color_eyre::eyre;
use futures_util::stream::Stream;
use std::future::Future;
use std::pin::Pin;

mod and_then_concurrent;
pub mod bincode;
pub mod chan_transport;
pub mod either;
pub mod negotiate;
pub mod reliable;
pub mod select;
pub mod tagger;
pub mod udp;
pub mod uds;
pub mod util;

pub use either::*;
pub use negotiate::*;

/// `Serve`s transform the semantics of the data flowing through them in some way.
pub trait Serve<I> {
    type Future: Future<Output = Result<Self::Stream, Self::Error>> + Send + 'static;
    type Connection: ChunnelConnection + 'static;
    type Error: Send + Sync + 'static;
    type Stream: Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static;

    fn serve(&mut self, inner: I) -> Self::Future;
}

/// `Client`s transform semantics of the data flowing through them in some way.
pub trait Client<I> {
    type Future: Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static;
    type Connection: ChunnelConnection + 'static;
    type Error: Send + Sync + 'static;

    fn connect_wrap(&mut self, inner: I) -> Self::Future;
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct CxNil;

impl<I, C, E> Serve<I> for CxNil
where
    I: Stream<Item = Result<C, E>> + Send + 'static,
    C: ChunnelConnection + 'static,
    E: Send + Sync + 'static,
{
    type Future = futures_util::future::Ready<Result<Self::Stream, Self::Error>>;
    type Connection = C;
    type Error = E;
    type Stream = I;

    fn serve(&mut self, inner: I) -> Self::Future {
        futures_util::future::ready(Ok(inner))
    }
}

impl<C> Client<C> for CxNil
where
    C: ChunnelConnection + Send + 'static,
{
    type Future = futures_util::future::Ready<Result<Self::Connection, Self::Error>>;
    type Connection = C;
    type Error = eyre::Report;

    fn connect_wrap(&mut self, inner: C) -> Self::Future {
        futures_util::future::ready(Ok(inner))
    }
}

/// Chain multiple chunnels together with the `Serve` and `Client` traits.
#[derive(Clone, Debug)]
pub struct CxList<Head, Tail> {
    pub head: Head,
    pub tail: Tail,
}

impl<T> From<T> for CxList<T, CxNil> {
    fn from(t: T) -> Self {
        CxList {
            head: t,
            tail: CxNil,
        }
    }
}

impl<T, L> From<(T, L)> for CxList<T, CxList<L, CxNil>> {
    fn from(t: (T, L)) -> Self {
        CxList::from(t.1).wrap(t.0)
    }
}

impl<H, L> CxList<H, L> {
    pub fn wrap<T>(self, head: T) -> CxList<T, CxList<H, L>> {
        CxList { head, tail: self }
    }
}

impl<H, T, I> Serve<I> for CxList<H, T>
where
    H: Serve<I>,
    T: Serve<<H as Serve<I>>::Stream> + Clone + Send + 'static,
    <T as Serve<<H as Serve<I>>::Stream>>::Error: From<<H as Serve<I>>::Error>,
{
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send + 'static>>;
    type Connection = T::Connection;
    type Error = T::Error;
    type Stream = T::Stream;

    fn serve(&mut self, inner: I) -> Self::Future {
        let st_fut = self.head.serve(inner);
        let mut tail = self.tail.clone();
        Box::pin(async move {
            let st = st_fut.await?;
            let st = tail.serve(st).await?;
            Ok(st)
        })
    }
}

impl<H, T, I> Client<I> for CxList<H, T>
where
    H: Client<I>,
    <H as Client<I>>::Connection: Send + 'static,
    T: Client<<H as Client<I>>::Connection> + Clone + Send + 'static,
    <T as Client<<H as Client<I>>::Connection>>::Error: From<<H as Client<I>>::Error>,
{
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Connection = T::Connection;
    type Error = T::Error;

    fn connect_wrap(&mut self, inner: I) -> Self::Future {
        let cn_fut = self.head.connect_wrap(inner);
        let mut tail = self.tail.clone();
        Box::pin(async move {
            let cn = cn_fut.await?;
            let cn = tail.connect_wrap(cn).await?;
            Ok(cn)
        })
    }
}

pub trait ChunnelListener {
    type Future: Future<Output = Result<Self::Stream, Self::Error>> + Send + 'static;
    type Addr;
    type Connection: ChunnelConnection + 'static;
    type Error: Send + Sync + 'static;
    type Stream: Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static;

    fn listen(&mut self, a: Self::Addr) -> Self::Future;
}

/// `ChunnelConnector`s connect to a single remote Chunnel endpoint and return one connection.
pub trait ChunnelConnector {
    type Future: Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static;
    type Addr;
    type Connection: ChunnelConnection + 'static;
    type Error: Send + Sync + 'static;

    fn connect(&mut self, a: Self::Addr) -> Self::Future;
}

/// A connection with the semantics of the Chunnel type's functionality.
pub trait ChunnelConnection {
    type Data;

    /// Send a message
    fn send(
        &self,
        data: Self::Data,
    ) -> Pin<Box<dyn Future<Output = Result<(), eyre::Report>> + Send + 'static>>;

    /// Retrieve next incoming message.
    fn recv(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Data, eyre::Report>> + Send + 'static>>;
}

/// For address types to expose ip and port information for inner addresses.
pub trait IpPort {
    fn ip(&self) -> std::net::IpAddr;
    fn port(&self) -> u16;
}

impl IpPort for std::net::SocketAddr {
    fn ip(&self) -> std::net::IpAddr {
        self.ip()
    }

    fn port(&self) -> u16 {
        self.port()
    }
}

/// Where the Chunnel implementation allows functionality to be implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Must be inside the application.
    Application,
    /// Anywhere on the same host.
    Host,
    /// Anywhere in the local network.
    Local,
    /// Anywhere.
    Global,
}

/// Semantics of the Chunnel.
pub enum Endedness {
    /// Chunnel uses wrap/unwrap semantics
    Both,
    /// Chunnel doesn't change semantics
    Either,
}

#[cfg(test)]
mod test {
    use crate::chan_transport::Chan;
    use crate::{
        ChunnelConnection, ChunnelConnector, ChunnelListener, Client, CxList, CxNil, Serve,
    };
    use color_eyre::Report;
    use futures_util::StreamExt;
    use tracing_error::ErrorLayer;
    use tracing_futures::Instrument;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    #[test]
    fn cxnil() {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();
        color_eyre::install().unwrap_or_else(|_| ());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();

        rt.block_on(
            async move {
                let (mut srv, mut cln) = Chan::default().split();

                let stack = CxList::from(CxNil);
                let mut stack = stack.wrap(CxNil);

                let rcv_st = srv.listen(()).await?;
                let mut rcv_st = stack.serve(rcv_st).await?;
                let rcv = rcv_st.next().await.unwrap().unwrap();

                let cln = cln.connect(()).await?;
                let snd = stack.connect_wrap(cln).await?;

                snd.send(((), vec![1u8; 1])).await?;
                let (_, buf) = rcv.recv().await?;
                assert_eq!(buf, vec![1u8; 1]);
                Ok::<_, Report>(())
            }
            .instrument(tracing::info_span!("cxnil")),
        )
        .unwrap();
    }
}
