use serde::{Deserialize, Serialize};

/// Which operation to perform
// bincode represents this as a u32
#[derive(Debug, Clone, Copy, Hash, PartialEq, Serialize, Deserialize)]
pub enum Op {
    Get, // = 0
    Put, // = 1
}

/// Both the request type and response type.
///
/// Get:
/// - requests will have val = None
/// - responses val = Some if present and rest copied.
/// Put:
/// - requests will have val = Some() (or None for deletion)
/// - responses, val = Some if update (the old value) and rest copied.
// bincode serialization:
// bytes 0-8 : id (u64)
// bytes 9-12: op (u32)
// bytes 12-18: key length (u64)
// bytes 18-?: key
// byte n: 1 = Some, 0 = None
// bytes n-(n+8) (if Some): val length
// bytes (n+8)-m: val
#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct Msg {
    pub(crate) id: usize,
    pub(crate) op: Op,
    pub(crate) key: String,
    pub(crate) val: Option<String>,
}

impl std::fmt::Debug for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Msg").field("id", &self.id).finish()
    }
}

impl Msg {
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn val(&self) -> Option<String> {
        self.val.clone()
    }

    pub fn into_kv(self) -> (String, Option<String>) {
        (self.key, self.val)
    }

    pub fn op(&self) -> Op {
        self.op
    }

    pub fn get_req(key: impl Into<String>) -> Self {
        Msg {
            id: get_id(),
            op: Op::Get,
            key: key.into(),
            val: None,
        }
    }

    pub fn put_req(key: impl Into<String>, val: impl Into<String>) -> Self {
        Msg {
            id: get_id(),
            op: Op::Put,
            key: key.into(),
            val: Some(val.into()),
        }
    }

    pub fn resp(self, val: impl Into<Option<String>>) -> Self {
        Msg {
            val: val.into(),
            ..self
        }
    }
}

impl bertha::util::MsgId for Msg {
    fn id(&self) -> usize {
        self.id()
    }
}

impl shard_ctl::Kv for Msg {
    type Key = String;
    fn key(&self) -> Self::Key {
        self.key().into()
    }

    type Val = Option<String>;
    fn val(&self) -> Self::Val {
        self.val()
    }
}

fn get_id() -> usize {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}

#[cfg(test)]
mod test {
    use super::Msg;

    #[test]
    fn bincode_test() {
        // make sure bincode's memory layout hasn't changed :)
        let m = Msg {
            id: 0xffff_ffff_ffff_ffff,
            op: super::Op::Get,
            key: String::from("a"),
            val: Some(String::from("b")),
        };

        let buf = bincode::serialize(&m).unwrap();

        assert_eq!(
            &buf,
            &[
                255, 255, 255, 255, 255, 255, 255, 255, // id usize
                0, 0, 0, 0, // op
                1, 0, 0, 0, 0, 0, 0, 0,  // le, u64 len
                97, // 'a'
                1,  // Some
                1, 0, 0, 0, 0, 0, 0, 0,  // le, u64 len
                98  // 'b'
            ],
        );
    }
}
