//! Receive rate histograms and keep a running histogram.

use std::{future::Future, net::SocketAddr, path::PathBuf, pin::Pin};

use color_eyre::eyre::{eyre, Report, WrapErr};
use elk_app_logparser::{
    listen::{serve_local, ProcessLine},
    parse_log::EstOutputRateHist,
    stats, EncrSpec, ProcessRecord,
};
use futures_util::future::ready;
use structopt::StructOpt;
use tracing::{debug, error, info, instrument};
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "consumer")]
struct Opt {
    #[structopt(long)]
    listen_addr: SocketAddr,

    #[structopt(long)]
    hostname: String,

    #[structopt(long)]
    local_root: Option<Option<PathBuf>>,

    #[structopt(long, default_value = "allow-none")]
    encr_spec: EncrSpec,

    #[structopt(long)]
    out_file: Option<PathBuf>,

    #[structopt(long)]
    logging: bool,
}

fn main() -> Result<(), Report> {
    color_eyre::install().unwrap();
    let opt = Opt::from_args();
    if opt.logging {
        let subscriber = tracing_subscriber::registry();
        let subscriber = subscriber
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let d = tracing::Dispatch::new(subscriber);
        d.init();
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .wrap_err("Building tokio runtime")?;
    rt.block_on(consumer(opt))
}

#[derive(Debug)]
struct Process {
    clk: quanta::Clock,
    s: flume::Sender<ProcessRecord>,
}

impl ProcessLine<EstOutputRateHist> for Process {
    fn process_lines<'a>(
        &'a self,
        line_batch: impl Iterator<Item = EstOutputRateHist> + Send + 'a,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + 'a>> {
        let (num_records_observed, msg) = line_batch.fold(
            (0, String::new()),
            |(num_records_observed, mut msg), est_output| {
                let client_ip = est_output.client_ip;
                let num_records = est_output.len();
                if num_records > 0 {
                    msg.push_str(&format!("[{}]: Hist({}) | ", client_ip, num_records));
                    for (q, v, c) in est_output.iter_quantiles(2).map(|iv| {
                        let quantile = iv.quantile_iterated_to();
                        let value = iv.value_iterated_to();
                        let cnt = iv.count_since_last_iteration();
                        (quantile, value, cnt)
                    }) {
                        let m = format!("[{}]({}): {} | ", q, v, c);
                        msg.push_str(&m);
                    }
                }

                (num_records_observed + num_records, msg)
            },
        );

        if num_records_observed > 0 {
            debug!(?num_records_observed, ?msg, "consumer update");
            let recv_ts = self.clk.raw();
            // blocking not possible on unbounded channel
            if let Err(err) = self.s.try_send(ProcessRecord {
                recv_ts,
                num_records_observed: num_records_observed as _,
                num_bytes_observed: None,
            }) {
                error!(?err, "Receiver dropped, exiting");
                return Box::pin(ready(Err(eyre!("Exiting due to channel send failure"))));
            }
        } else {
            debug!("empty update");
        }

        Box::pin(ready(Ok(())))
    }
}

#[instrument(level = "info", skip(opt))]
async fn consumer(opt: Opt) -> Result<(), Report> {
    if let Some(lr) = opt.local_root.as_ref() {
        tokio::spawn(localname_ctl::ctl::serve_ctl(lr.clone(), true));
    }

    info!(?opt, "starting consumer");
    let local_root = opt
        .local_root
        .map(|o| o.unwrap_or_else(|| "/tmp/burrito".parse().unwrap()));
    let (s, r) = flume::unbounded();
    let clk = quanta::Clock::new();
    let p = Process {
        clk: clk.clone(),
        s,
    };

    tokio::spawn(stats(r, clk, opt.out_file));
    serve_local(opt.listen_addr, opt.hostname, local_root, opt.encr_spec, p).await
}
