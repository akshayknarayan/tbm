//! Chunnel wrapper types to negotiate between multiple implementations.

use super::{ChunnelConnection, ChunnelConnector, ChunnelListener, Either, Endedness, Scope};
use eyre::{eyre, Report};
use futures_util::stream::Stream;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use tracing::debug;

// remote negotiation
// goal: need to pass a message describing what functionality goes where.
//
// "one-way handshake"
// client, in connect(), offers a set of functionality known to the chunnel
// server, in listen(), picks the right type out of {T1, T2, ..., Tn} given what the client said.
//   - no need to respond because the client has already sent what it is doing.
//
// problems:
//   - how to deal with arbitrary chunnel data types?
//    - impl Into<C::Connection::Data>? "bring your own serialization"
//
// solutions:
//   - how do we know what this functionality is?
//     - chunnels describe via trait method implementation a type for the functionality set (Vec of
//   enum)?

/// A type that can list out the `universe()` of possible values it can have.
pub trait CapabilitySet: Sized {
    /// All possible values this type can have.
    fn universe() -> Vec<Self>;
}

impl CapabilitySet for () {
    fn universe() -> Vec<Self> {
        vec![()]
    }
}

/// Define an enum that implements the `CapabilitySet` trait.
///
/// Invoke with enum name (with optional `pub`) followed by variant names.
///
/// # Example
/// ```rust
/// # use bertha::enumerate_enum;
/// enumerate_enum!(pub Foo, A, B, C);
/// enumerate_enum!(Bar, A, B, C);
/// fn main() {
///     let f = Foo::B;
///     let b = Bar::C;
///     println!("{:?}, {:?}", f, b);
/// }
/// ```
#[macro_export]
macro_rules! enumerate_enum {
    (pub $name:ident, $($variant:ident),+) => {
        #[derive(Debug, Clone, Copy, PartialEq)]
        pub enum $name {
            $(
                $variant
            ),+
        }

        impl $crate::negotiate::CapabilitySet for $name {
            fn universe() -> Vec<Self> {
                vec![
                    $($name::$variant),+
                ]
            }
        }
    };
    ($(keyw:ident)* $name:ident, $($variant:ident),+) => {
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum $name {
            $(
                $variant
            ),+
        }

        impl $crate::negotiate::CapabilitySet for $name {
            fn universe() -> Vec<Self> {
                vec![
                    $($name::$variant),+
                ]
            }
        }
    };
}

/// Expresses the ability to negotiate chunnel implementations over a set of capabilities enumerated
/// by the `Capability` type.
///
/// Read: `Negotiate` *over* `Capability`.
pub trait Negotiate<Capability: CapabilitySet> {
    fn capabilities() -> Vec<Capability>;
}

impl<T> Negotiate<()> for T {
    fn capabilities() -> Vec<()> {
        vec![()]
    }
}

impl<A, E1, E2, T1, C1, T2, C2, D> ChunnelConnector for (T1, T2)
where
    A: Clone,
    T1: ChunnelConnector<Addr = A, Error = E1, Connection = C1>,
    T2: ChunnelConnector<Addr = A, Error = E2, Connection = C2>,
    C1: ChunnelConnection<Data = D> + Send + 'static,
    C2: ChunnelConnection<Data = D> + Send + 'static,
    E1: Into<eyre::Error> + Send + Sync + 'static,
    E2: Into<eyre::Error> + Send + Sync + 'static,
{
    type Addr = A;
    type Connection = Either<T1::Connection, T2::Connection>;
    type Error = Report;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn connect(&mut self, a: Self::Addr) -> Self::Future {
        let use_t1 = match (T1::scope(), T2::scope()) {
            (Scope::Application, _) => true,
            (_, Scope::Application) => false,
            (Scope::Host, _) => true,
            (_, Scope::Host) => false,
            (Scope::Local, _) => true,
            (_, Scope::Local) => false,
            (Scope::Global, _) => true,
        };

        let left_fut = self.0.connect(a.clone());
        let right_fut = self.1.connect(a);
        if use_t1 {
            Box::pin(async move {
                debug!(chunnel_type = std::any::type_name::<T1>(), "picking");
                match left_fut.await {
                    Ok(c) => Ok(Either::Left(c)),
                    Err(left_e) => {
                        let left_e = left_e
                            .into()
                            .wrap_err(eyre!("First-choice chunnel connect() failed"));
                        debug!(chunnel_type = std::any::type_name::<T2>(), "fallback");
                        match right_fut.await {
                            Ok(c) => Ok(Either::Right(c)),
                            Err(right_e) => Err(right_e
                                .into()
                                .wrap_err(eyre!("Second-choice chunnel connect() failed"))
                                .wrap_err(left_e)),
                        }
                    }
                }
            })
        } else {
            Box::pin(async move {
                debug!(chunnel_type = std::any::type_name::<T2>(), "picking");
                match right_fut.await {
                    Ok(c) => Ok(Either::Right(c)),
                    Err(right_e) => {
                        let right_e = right_e
                            .into()
                            .wrap_err(eyre!("First-choice chunnel connect() failed"));
                        debug!(chunnel_type = std::any::type_name::<T1>(), "fallback");
                        match left_fut.await {
                            Ok(c) => Ok(Either::Left(c)),
                            Err(left_e) => Err(left_e
                                .into()
                                .wrap_err(eyre!("Second-choice chunnel connect() failed"))
                                .wrap_err(right_e)),
                        }
                    }
                }
            })
        }
    }

    fn scope() -> Scope {
        unimplemented!()
    }
    fn endedness() -> Endedness {
        unimplemented!()
    }
    fn implementation_priority() -> usize {
        unimplemented!()
    }
}

impl<A, T1, C1, T2, C2, E1, E2, D> ChunnelListener for (T1, T2)
where
    A: Clone,
    T1: ChunnelListener<Addr = A, Error = E1, Connection = C1>,
    T2: ChunnelListener<Addr = A, Error = E2, Connection = C2>,
    C1: ChunnelConnection<Data = D> + 'static,
    C2: ChunnelConnection<Data = D> + 'static,
    E1: Into<Report> + Send + Sync + 'static,
    E2: Into<Report> + Send + Sync + 'static,
{
    type Addr = A;
    type Connection = Either<T1::Connection, T2::Connection>;
    type Error = Report;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send + 'static>>;
    type Stream =
        Pin<Box<dyn Stream<Item = Result<Self::Connection, Self::Error>> + Send + 'static>>;

    fn listen(&mut self, a: Self::Addr) -> Self::Future {
        let use_t1 = match (T1::scope(), T2::scope()) {
            (Scope::Application, _) => true,
            (_, Scope::Application) => false,
            (Scope::Host, _) => true,
            (_, Scope::Host) => false,
            (Scope::Local, _) => true,
            (_, Scope::Local) => false,
            (Scope::Global, _) => true,
        };

        use futures_util::TryStreamExt;

        let left_fut = self.0.listen(a.clone());
        let right_fut = self.1.listen(a);
        if use_t1 {
            debug!(chunnel_type = std::any::type_name::<T1>(), "picking");
            Box::pin(async move {
                match left_fut.await {
                    Ok(st) => Ok(
                        Box::pin(st.map_ok(|c| Either::Left(c)).map_err(|e| e.into()))
                            as Pin<
                                Box<
                                    dyn Stream<Item = Result<Self::Connection, Self::Error>>
                                        + Send
                                        + 'static,
                                >,
                            >,
                    ),
                    Err(left_e) => {
                        let left_e = left_e
                            .into()
                            .wrap_err(eyre!("First-choice chunnel listen() failed"));
                        match right_fut.await {
                            Ok(st) => Ok(Box::pin(
                                st.map_ok(|c| Either::Right(c)).map_err(|e| e.into()),
                            )
                                as Pin<
                                    Box<
                                        dyn Stream<Item = Result<Self::Connection, Self::Error>>
                                            + Send
                                            + 'static,
                                    >,
                                >),
                            Err(right_e) => Err(right_e
                                .into()
                                .wrap_err(eyre!("Second-choice chunnel listen() failed"))
                                .wrap_err(left_e)),
                        }
                    }
                }
            }) as _
        } else {
            debug!(chunnel_type = std::any::type_name::<T2>(), "picking");
            Box::pin(async move {
                match right_fut.await {
                    Ok(st) => Ok(
                        Box::pin(st.map_ok(|c| Either::Right(c)).map_err(|e| e.into()))
                            as Pin<
                                Box<
                                    dyn Stream<Item = Result<Self::Connection, Self::Error>>
                                        + Send
                                        + 'static,
                                >,
                            >,
                    ),
                    Err(right_e) => {
                        let right_e = right_e
                            .into()
                            .wrap_err(eyre!("First-choice chunnel listen() failed"));
                        match left_fut.await {
                            Ok(st) => Ok(Box::pin(
                                st.map_ok(|c| Either::Left(c)).map_err(|e| e.into()),
                            )
                                as Pin<
                                    Box<
                                        dyn Stream<Item = Result<Self::Connection, Self::Error>>
                                            + Send
                                            + 'static,
                                    >,
                                >),
                            Err(left_e) => Err(left_e
                                .into()
                                .wrap_err(eyre!("Second-choice chunnel listen() failed"))
                                .wrap_err(right_e)),
                        }
                    }
                }
            }) as _
        }
    }

    fn scope() -> Scope {
        unimplemented!()
    }
    fn endedness() -> Endedness {
        unimplemented!()
    }
    fn implementation_priority() -> usize {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use crate::{ChunnelConnector, ChunnelListener, Endedness, Scope};

    macro_rules! test_scope_impl {
        ($name:ident,$scope:expr) => {
            struct $name<C>(C);

            impl<C> ChunnelConnector for $name<C>
            where
                C: ChunnelConnector + Send + Sync + 'static,
            {
                type Addr = C::Addr;
                type Connection = C::Connection;
                type Future = C::Future;
                type Error = C::Error;

                fn connect(&mut self, a: Self::Addr) -> Self::Future {
                    self.0.connect(a)
                }

                fn scope() -> Scope {
                    $scope
                }
                fn endedness() -> Endedness {
                    C::endedness()
                }
                fn implementation_priority() -> usize {
                    C::implementation_priority()
                }
            }

            impl<C> ChunnelListener for $name<C>
            where
                C: ChunnelListener + Send + Sync + 'static,
            {
                type Addr = C::Addr;
                type Connection = C::Connection;
                type Future = C::Future;
                type Stream = C::Stream;
                type Error = C::Error;

                fn listen(&mut self, a: Self::Addr) -> Self::Future {
                    self.0.listen(a)
                }

                fn scope() -> Scope {
                    $scope
                }
                fn endedness() -> Endedness {
                    C::endedness()
                }
                fn implementation_priority() -> usize {
                    C::implementation_priority()
                }
            }
        };
    }

    test_scope_impl!(ImplA, Scope::Host);
    test_scope_impl!(ImplB, Scope::Local);

    use crate::chan_transport::RendezvousChannel;
    use crate::util::{Never, OptionUnwrap};
    use crate::ChunnelConnection;
    use futures_util::TryStreamExt;
    use tracing::info;
    use tracing_futures::Instrument;

    #[test]
    fn negotiate() {
        let _guard = tracing_subscriber::fmt::try_init();
        color_eyre::install().unwrap_or_else(|_| ());

        let mut rt = tokio::runtime::Builder::new()
            .basic_scheduler()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();
        rt.block_on(
            async move {
                let (srv, cln) = RendezvousChannel::new(10).split();
                let mut srv = OptionUnwrap::from(srv);
                let (s, r) = tokio::sync::oneshot::channel();

                tokio::spawn(
                    async move {
                        let st = srv.listen(3u8).await.unwrap();
                        s.send(()).unwrap();
                        st.try_for_each_concurrent(None, |cn| async move {
                            let m = cn.recv().await?;
                            cn.send(m).await?;
                            Ok::<_, eyre::Report>(())
                        })
                        .await
                    }
                    .instrument(tracing::debug_span!("server")),
                );

                let mut cln = (ImplA(cln.clone()), ImplB(Never::from(cln)));
                let _: () = r.await.unwrap();
                info!("connecting client");
                let cn = cln
                    .connect(3u8)
                    .instrument(tracing::debug_span!("connect"))
                    .await
                    .unwrap();

                cn.send(vec![1u8; 8])
                    .instrument(tracing::debug_span!("send"))
                    .await
                    .unwrap();
                let d = cn
                    .recv()
                    .instrument(tracing::debug_span!("recv"))
                    .await
                    .unwrap();
                assert_eq!(d, vec![1u8; 8]);
            }
            .instrument(tracing::debug_span!("negotiate")),
        );
    }
}
