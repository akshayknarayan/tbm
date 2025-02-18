use super::ShardInfo;
use color_eyre::eyre;
use eyre::{eyre, Error};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

fn redis_key<A>(a: &A) -> String
where
    A: std::fmt::Display,
{
    format!("shard:{}", a)
}

#[tracing::instrument(level = "trace", skip(conn))]
pub async fn redis_insert<A>(
    conn: Arc<Mutex<redis::aio::MultiplexedConnection>>,
    serv: &ShardInfo<A>,
) -> Result<(), Error>
where
    A: std::fmt::Display + std::fmt::Debug + Serialize + DeserializeOwned,
{
    let name = redis_key(&serv.canonical_addr);
    let shard_blob = bincode::serialize(serv)?;
    let mut r = redis::pipe();
    r.atomic()
        .sadd("shard-services", &name)
        .set(&name, shard_blob)
        .ignore();
    trace!("adding");
    r.query_async(&mut *conn.lock().await).await?;
    trace!("done");
    Ok(())
}

#[tracing::instrument(level = "trace", err, skip(con))]
pub async fn redis_query<A>(
    canonical_addr: &A,
    mut con: impl std::ops::DerefMut<Target = redis::aio::MultiplexedConnection>,
) -> Result<Option<ShardInfo<A>>, Error>
where
    A: Serialize
        + DeserializeOwned
        + std::cmp::PartialEq
        + std::fmt::Display
        + std::fmt::Debug
        + Sync
        + 'static,
{
    use redis::AsyncCommands;

    let a = redis_key(canonical_addr);
    // there is a race between the negotiation ack and the redis write.
    // as a result, if this is empty we must retry.
    let start = tokio::time::Instant::now();
    let sh_info_blob = loop {
        trace!(key = ?&a, "sending request");
        let sh_info_blob: Vec<u8> = con.get::<_, Vec<u8>>(&a).await?;
        if sh_info_blob.is_empty() {
            trace!(key = ?&a, "got empty response");
            if start.elapsed() > tokio::time::Duration::from_secs(5) {
                debug!(key = ?&a, "giving up on finding key");
                return Ok(None);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            continue;
        }

        break sh_info_blob;
    };

    trace!(key = ?&a, "got non-empty response");
    let sh_info: ShardInfo<A> = bincode::deserialize(&sh_info_blob)?;
    if canonical_addr != &sh_info.canonical_addr {
        warn!(
            canonical_addr = %canonical_addr,
            shardinfo_addr = %sh_info.canonical_addr,
            "Mismatch error with redis key <-> ShardInfo",
        );

        return Err(eyre!(
            "redis key mismatched: {} != {}",
            canonical_addr,
            sh_info.canonical_addr
        ));
    }

    Ok(Some(sh_info))
}
