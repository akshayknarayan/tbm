use futures_util::stream::Stream;
use std::future::Future;
use std::pin::Pin;

pub mod bincode;
pub mod chan_transport;
pub mod reliable;
pub mod tagger;

/// A connection with the semantics of the Chunnel type's functionality.
pub trait Chunnel {
    type Data;

    /// Send a message
    fn send(
        &self,
        data: Self::Data,
    ) -> Pin<Box<dyn Future<Output = Result<(), eyre::Report>> + Send + Sync>>;

    /// Retrieve next incoming message.
    fn recv(&self)
        -> Pin<Box<dyn Future<Output = Result<Self::Data, eyre::Report>> + Send + Sync>>;

    fn init(&mut self) {}
    fn teardown(&mut self) {}

    fn scope(&self) -> Scope;
    fn endedness(&self) -> Endedness;
    fn implementation_priority(&self) -> usize;
    // fn resource_requirements(&self) -> ?;
}

/// A way to produce `Chunnel` connections.
pub trait Connector {
    type Addr;
    type Connection;

    fn listen(
        &mut self,
        a: Self::Addr,
    ) -> Pin<Box<dyn Future<Output = Pin<Box<dyn Stream<Item = Self::Connection>>>>>>;
    fn connect(&mut self, a: Self::Addr) -> Pin<Box<dyn Future<Output = Self::Connection>>>;
}

/// Where the Chunnel implementation allows functionality to be implemented.
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

//pub fn register_chunnel<A, C>(name: &str, factory: impl Fn(A) -> C, endpt: Endedness, sc: Scope)
//where
//    C: Chunnel,
//{
//    unimplemented!();
//}
