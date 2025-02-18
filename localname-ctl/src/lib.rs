#![warn(clippy::all)]
#![allow(clippy::type_complexity)]

pub const CONTROLLER_ADDRESS: &str = "localname-ctl";

pub mod client;
pub mod proto;

#[cfg(feature = "ctl")]
pub mod ctl;

use std::net::SocketAddr;

pub trait GetSockAddr {
    fn as_sk_addr(&self) -> SocketAddr;
}

impl GetSockAddr for SocketAddr {
    fn as_sk_addr(&self) -> SocketAddr {
        *self
    }
}

impl<A> GetSockAddr for (SocketAddr, A) {
    fn as_sk_addr(&self) -> SocketAddr {
        self.0
    }
}

#[cfg(feature = "runtime")]
mod runtime_fastpath;
#[cfg(feature = "runtime")]
pub use runtime_fastpath::*;

#[cfg(feature = "conntime")]
mod static_fastpath;
#[cfg(feature = "conntime")]
pub use static_fastpath::*;

#[cfg(feature = "tls-tunnel")]
mod fused_tls_fastpath;
#[cfg(feature = "tls-tunnel")]
pub use fused_tls_fastpath::*;

#[cfg(test)]
mod t {
    pub static COLOR_EYRE: std::sync::Once = std::sync::Once::new();
}
