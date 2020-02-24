use std::error::Error;

type StdError = Box<dyn Error + Send + Sync + 'static>;

// TODO invoke ycsbc-mock
//pub fn generate(specfile: impl AsRef<std::path::Path>) {
//    // hardcode workload b for now
//    let out = std::process::Command::new("./ycsbc-mock/ycsbc")
//        .args(&[
//            "-db",
//            "mock",
//            "-threads",
//            "1",
//            "-P",
//            specfile.as_ref().to_str().unwrap(),
//        ])
//        .output()
//        .unwrap();
//}

#[derive(Debug, Clone)]
pub enum Op {
    Get(usize, String),
    Update(usize, String, String),
}

impl std::str::FromStr for Op {
    type Err = StdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<&str> = s.split_whitespace().collect();
        Ok(if sp.len() == 3 && sp[1] == "GET" {
            Op::Get(sp[0].parse()?, sp[2].into())
        } else if sp.len() == 4 && sp[1] == "UPDATE" {
            Op::Update(sp[0].parse()?, sp[1].into(), sp[2].into())
        } else {
            Err(format!("Invalid line: {:?}", s))?
        })
    }
}

pub fn ops(f: std::path::PathBuf) -> Result<Vec<Op>, StdError> {
    use std::io::BufRead;
    let f = std::fs::File::open(f)?;
    let f = std::io::BufReader::new(f);
    Ok(f.lines().filter_map(|l| l.ok()?.parse().ok()).collect())
}
