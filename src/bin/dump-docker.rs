use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dump-docker-proxy")]
struct Opt {
    #[structopt(short, long)]
    in_addr: std::path::PathBuf,

    #[structopt(short, long)]
    out_addr: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    let opt = Opt::from_args();
    let log = burrito::logger();

    let out_addr = opt.out_addr.clone();

    use hyper_unix_connector::UnixConnector;
    let uc: UnixConnector = tokio::net::UnixListener::bind(&opt.in_addr)?.into();
    let make_service = burrito::MakeDockerProxy{out_addr: out_addr.clone(), log: log.clone()};
    let server = hyper::server::Server::builder(uc).serve(make_service);

    slog::info!(log, "starting"; "listening at" => ?&opt.in_addr, "proxying to" => ?&opt.out_addr);
    if let Err(e) = server.await {
        slog::crit!(log, "server crashed"; "err" => ?e);
    }

    Ok(())
}
