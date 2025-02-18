use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub addrs: Vec<SocketAddr>,
}

/// register_addr: The name that was passed.
/// local_addr: The assigned path to listen on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterReplyOk {
    pub register_addr: Vec<SocketAddr>,
    pub local_addr: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterReply(Result<RegisterReplyOk, String>);

impl From<Result<RegisterReplyOk, String>> for RegisterReply {
    fn from(s: Result<RegisterReplyOk, String>) -> Self {
        RegisterReply(s)
    }
}

impl From<RegisterReply> for Result<RegisterReplyOk, String> {
    fn from(rr: RegisterReply) -> Result<RegisterReplyOk, String> {
        rr.0
    }
}

/// A reply for a name query.
///
/// Returns all service entries matching the query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryNameReplyOk(pub Vec<QueryNameReplyEntry>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryNameReplyEntry {
    pub addr: SocketAddr,
    pub local_addr: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryNameReply(Result<QueryNameReplyOk, String>);

impl From<Result<QueryNameReplyOk, String>> for QueryNameReply {
    fn from(s: Result<QueryNameReplyOk, String>) -> Self {
        QueryNameReply(s)
    }
}

impl From<QueryNameReply> for Result<QueryNameReplyOk, String> {
    fn from(qnr: QueryNameReply) -> Result<QueryNameReplyOk, String> {
        qnr.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Register(RegisterRequest),
    Query(Vec<SocketAddr>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply {
    Register(RegisterReply),
    Query(QueryNameReply),
}
