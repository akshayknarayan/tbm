use color_eyre::eyre::Error;
use localname_ctl::ctl;
use structopt::StructOpt;
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, StructOpt)]
#[structopt(name = "burrito")]
struct Opt {
    #[structopt(short, long)]
    force_burrito: bool,

    #[structopt(short, long)]
    burrito_coordinator_addr: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    color_eyre::install()?;
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(ErrorLayer::default());
    let _guard = subscriber.set_default();

    ctl::serve_ctl(opt.burrito_coordinator_addr, opt.force_burrito).await?;
    Ok(())
}
