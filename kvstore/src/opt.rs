//! Chunnel stack optimization

//use crate::reliability::KvReliabilityServerChunnel;
//use crate::Msg;
//use bertha::{
//    bincode::SerializeChunnelProject,
//    reliable::{Pkt, ReliabilityProjChunnel},
//    tagger::OrderedChunnelProj,
//    CxList, CxNil, Select,
//};
//use shard_ctl::{ShardCanonicalServer, ShardCanonicalServerRaw};

/// Optimization to inject ShardCanonicalServerRaw
pub trait SerdeOpt {
    type Opt;
    fn serde_opt(self) -> Self::Opt;
}

// optimization case:
//    let cnsrv = shard_ctl::ShardCanonicalServer::new(
//        si.clone(),
//        Some(shards_internal),
//        udp_to_shard::UdpToShard(shard_connector),
//        shard_stack,
//        offer.pop().unwrap(),
//        &redis_addr,
//    )
//    .await
//    .wrap_err("Create ShardCanonicalServer")?;
//    let external = CxList::from(cnsrv)
//        .wrap(
//            Select::from((
//                CxList::from(OrderedChunnelProj::default()).wrap(ReliabilityProjChunnel::default()),
//                KvReliabilityServerChunnel::default(),
//            ))
//            .inner_type::<DataEither<bertha::reliable::Pkt<Msg>, Msg>>()
//            .prefer_right(),
//        )
//        .wrap(SerializeChunnelProject::default());
//
//  bertha::CxList<
//      bertha::bincode::SerializeChunnelProject<
//          bertha::either::DataEither<bertha::reliable::Pkt<kvstore::msg::Msg>, kvstore::msg::Msg>
//      >,
//      bertha::CxList<bertha::negotiate::Select<
//          bertha::CxList<
//              bertha::reliable::ReliabilityProjChunnel, bertha::CxList<bertha::tagger::OrderedChunnelProj, bertha::CxNil>>,
//          kvstore::reliability::KvReliabilityServerChunnel,
//          bertha::either::DataEither<bertha::reliable::Pkt<kvstore::msg::Msg>, kvstore::msg::Msg>
//      >,
//      bertha::CxList<shard_ctl::ShardCanonicalServer<
//          std::net::addr::SocketAddr,
//          ...
//      >,
//      bertha::CxNil>>
//  >
//
//  new version:
//  bertha::CxList<
//      bertha::CxList<bertha::negotiate::Select<
//          bertha::CxList<bertha::bincode::SerializeChunnelProject<kvstore::msg::Msg>,
//              bertha::CxList<bertha::reliable::ReliabilityProjChunnel,
//              bertha::CxList<bertha::tagger::OrderedChunnelProj, bertha::CxNil>>>,
//          bertha::CxList<bertha::bincode::SerializeChunnelProject<kvstore::msg::Msg>,
//              bertha::CxList<kvstore::reliability::KvReliabilityServerChunnel, bertha::CxNil>>
//      >,
//      bertha::CxList<shard_ctl::ShardCanonicalServer<std::net::addr::SocketAddr, ...>,
//      bertha::CxNil>>
//  >
//
//  replace with:
//
//    Select(
//      CxList::from(OrderedChunnelProj::default())
//          .wrap(ReliabilityProjChunnel::default())
//          .wrap(SerializeChunnelProject::default()),
//      CxList::from(KvReliabilityServerChunnel::default())
//          .wrap(ShardCanonicalServerRaw::<_, _, _, OFFSET = 18>::from(cnsrv))
//    )
//    .prefer_right()

//impl<A, S, Ss> SerdeOpt
//    for CxList<
//        SerializeChunnelProject<(A, Msg)>,
//        CxList<KvReliabilityServerChunnel, CxList<ShardCanonicalServer<A, S, Ss>, CxNil>>,
//    >
//{
//    // why 18?: see msg.rs, bincode will put the key starting at byte 18.
//    type Opt = ShardCanonicalServerRaw<A, S, Ss, 18>;
//
//    fn transform(self) -> Self::Opt {
//        let CxList {
//            head: _ser,
//            tail:
//                CxList {
//                    head: _rel,
//                    tail:
//                        CxList {
//                            head: cnsrv,
//                            tail: CxNil,
//                        },
//                },
//        } = self;
//        cnsrv.into()
//    }
//}

// sharding optimization to make this route raw packets.
// If the ordered |> reliable path is picked, we can't do the optimization because the bytes
// have semantics. `KvReliabilityServerChunnel` is basically a no-op though, so we can
// pass-through without the serialization.
//impl<A, S, Ss, D> SerdeOpt
//    for CxList<
//        Select<
//            CxList<
//                SerializeChunnelProject<Pkt<Msg>>,
//                CxList<ReliabilityProjChunnel, CxList<OrderedChunnelProj, CxNil>>,
//            >,
//            CxList<SerializeChunnelProject<Msg>, CxList<KvReliabilityServerChunnel, CxNil>>,
//        >,
//        CxList<ShardCanonicalServer<A, S, Ss, D>, CxNil>,
//    >
//where
//    ShardCanonicalServer<A, S, Ss, D>: Clone,
//{
//    type Opt = Select<
//        CxList<
//            SerializeChunnelProject<Pkt<Msg>>,
//            CxList<
//                ReliabilityProjChunnel,
//                CxList<OrderedChunnelProj, CxList<ShardCanonicalServer<A, S, Ss, D>, CxNil>>,
//            >,
//        >,
//        // why 18?: see msg.rs, bincode will put the key starting at byte 18.
//        CxList<KvReliabilityServerChunnel, CxList<ShardCanonicalServerRaw<A, S, Ss, D, 18>, CxNil>>,
//    >;
//
//    fn serde_opt(self) -> Self::Opt {
//        let CxList {
//            head:
//                Select {
//                    left:
//                        CxList {
//                            head: ser,
//                            tail:
//                                CxList {
//                                    head: rel,
//                                    tail:
//                                        CxList {
//                                            head: ord,
//                                            tail: CxNil,
//                                        },
//                                },
//                        },
//                    right:
//                        CxList {
//                            head: _ser,
//                            tail:
//                                CxList {
//                                    head: kv_server_rel,
//                                    tail: _,
//                                },
//                        },
//                    prefer,
//                    ..
//                },
//            tail: CxList {
//                head: cnsrv,
//                tail: CxNil,
//            },
//        } = self;
//
//        let left = CxList {
//            head: ser,
//            tail: CxList {
//                head: rel,
//                tail: CxList {
//                    head: ord,
//                    tail: CxList {
//                        head: cnsrv.clone(),
//                        tail: CxNil,
//                    },
//                },
//            },
//        };
//        let right = CxList {
//            head: kv_server_rel,
//            tail: CxList {
//                head: cnsrv.into(),
//                tail: CxNil,
//            },
//        };
//
//        let mut sel = Select::from((left, right));
//        sel.prefer = prefer;
//        sel
//    }
//}
