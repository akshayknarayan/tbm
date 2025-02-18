//! Parse server log lines for Client IP and timestamp.

use std::{
    future::Future,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
    pin::Pin,
    sync::{Arc, Mutex},
};

use bertha::{Chunnel, ChunnelConnection, Negotiate};
use chrono::{DateTime, Duration, Utc};
use color_eyre::{eyre::bail, Report};
use common_log_format::LogEntry;
use futures_util::future::{ready, Ready};
use hdrhistogram::{
    serialization::{Deserializer, Serializer, V2Serializer},
    Histogram,
};
use shard_ctl::Kv;
use tracing::{debug, trace, warn};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum Line {
    Report(String),
    Ack,
}

impl Kv for Line {
    type Key = String;
    fn key(&self) -> Self::Key {
        match self {
            Self::Report(s) => s.clone(),
            Self::Ack => "ack".to_owned(),
        }
    }

    type Val = ();
    fn val(&self) -> Self::Val {
        ()
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ParsedLine {
    pub client_ip: IpAddr,
    pub text: String,
}

const SAMPLE_IPS: [IpAddr; 10] = [
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
];

const SAMPLE_PAYLOAD: &'static str = unsafe { std::str::from_utf8_unchecked(&['a' as _; 128]) };

pub fn sample_parsed_lines() -> impl Iterator<Item = ParsedLine> {
    (0usize..).map(move |i| {
        let ips_idx = i % SAMPLE_IPS.len();
        ParsedLine {
            client_ip: SAMPLE_IPS[ips_idx],
            text: SAMPLE_PAYLOAD.to_owned(),
        }
    })
}

const SAMPLE_STATUS_CODE: usize = 200;
const SAMPLE_OBJ_SIZE: usize = 100;
const SAMPLE_INTERARRIVAL_MS: usize = 19;

pub fn sample_logentry_lines() -> impl Iterator<Item = String> {
    let sample_start_time: DateTime<Utc> =
        DateTime::parse_from_rfc3339("1996-12-19T16:39:57.125-08:00")
            .unwrap()
            .into();
    lines_from_ts(
        (0..)
            .map(move |i| {
                sample_start_time + Duration::milliseconds((i * SAMPLE_INTERARRIVAL_MS) as i64)
            })
            .zip(sample_parsed_lines()),
    )
}

pub fn live_logentry_lines() -> impl Iterator<Item = String> {
    let ts = std::iter::repeat(()).map(|_| chrono::Utc::now());
    lines_from_ts(ts.zip(sample_parsed_lines()))
}

fn lines_from_ts(
    ts: impl Iterator<Item = (DateTime<Utc>, ParsedLine)>,
) -> impl Iterator<Item = String> {
    ts.map(|(timestamp, ParsedLine { client_ip, text })| {
        format!(
            "{ip} - - [{ts}] \"{txt}\" {sc} {os}",
            ip = client_ip,
            ts = timestamp.to_rfc3339(),
            txt = text,
            sc = SAMPLE_STATUS_CODE,
            os = SAMPLE_OBJ_SIZE,
        )
    })
}

pub fn parse_raw(lines: impl Iterator<Item = String>) -> impl Iterator<Item = ParsedLine> {
    lines.filter_map(|line| {
        let (ip, _) = common_log_format::peel_ip(&line).ok()?;
        Some(ParsedLine {
            client_ip: ip?,
            text: line,
        })
    })
}

pub fn parse_lines(
    lines: impl Iterator<Item = ParsedLine>,
) -> impl Iterator<Item = Result<LogEntry, Report>> {
    lines.map(|line| line.text.parse().map_err(Report::from))
}

/// Histogram of estimated output rates  with successful status codes
///
/// Use (object size / inter-entry time) to estimate rate.
pub struct EstOutputRate {
    hist: Histogram<u64>,
    prev_ts: Option<DateTime<Utc>>,
}

impl Default for EstOutputRate {
    fn default() -> Self {
        Self {
            hist: Histogram::new(3).expect("make new histogram"),
            prev_ts: None,
        }
    }
}

impl EstOutputRate {
    pub fn new_entries(&mut self, entries: impl Iterator<Item = LogEntry>) -> usize {
        let mut proc_cnt = 0;
        for (ts, obj_size) in entries.filter_map(|e| {
            if e.status_code.is_some_and(|sc| sc.is_success()) {
                e.time
                    .and_then(|t| e.object_size.and_then(|o| Some((t, o))))
            } else {
                None
            }
        }) {
            if let Some(prev_ts) = self.prev_ts {
                // we are supposed to be guaranteed that ts > prev_ts.
                if ts < prev_ts {
                    warn!(?ts, ?prev_ts, "time ticked backwards");
                    continue;
                }

                let el = ts - prev_ts;
                let est_rate = obj_size as f64
                    / el.to_std()
                        .expect("negative condition checked above")
                        .as_secs_f64();
                let est_rate_int = est_rate as _;
                trace!(?obj_size, ?el, ?est_rate, ?est_rate_int, "rate sample");
                if let Err(err) = self.hist.record(est_rate_int) {
                    warn!(?err, "histogram error");
                }
            }

            self.prev_ts = Some(ts);
            proc_cnt += 1;
        }

        proc_cnt
    }

    pub fn len(&self) -> u64 {
        self.hist.len()
    }
}

#[derive(Debug, Clone)]
pub struct EstOutputRateHist {
    pub client_ip: IpAddr,
    h: Histogram<u64>,
}

impl EstOutputRateHist {
    pub fn new(client_ip: IpAddr, h: EstOutputRate) -> Self {
        EstOutputRateHist {
            client_ip,
            h: h.hist,
        }
    }
}

impl Deref for EstOutputRateHist {
    type Target = Histogram<u64>;
    fn deref(&self) -> &Self::Target {
        &self.h
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EstOutputRateSerializeChunnel;

impl Negotiate for EstOutputRateSerializeChunnel {
    type Capability = ();

    fn guid() -> u64 {
        0xc3502f7c8f67404e
    }
}

impl<I, A> Chunnel<I> for EstOutputRateSerializeChunnel
where
    A: Send + 'static,
    I: ChunnelConnection<Data = (A, Vec<u8>)> + Send + Sync + 'static,
{
    type Future = Ready<Result<Self::Connection, Self::Error>>;
    type Connection = EstOutputRateCn<I>;
    type Error = std::convert::Infallible;

    fn connect_wrap(&mut self, inner: I) -> Self::Future {
        ready(Ok(EstOutputRateCn {
            ser: Arc::new(Mutex::new(V2Serializer::new())),
            des: Arc::new(Mutex::new(Deserializer::new())),
            inner,
        }))
    }
}

pub struct EstOutputRateCn<C> {
    ser: Arc<Mutex<V2Serializer>>,
    des: Arc<Mutex<Deserializer>>,
    inner: C,
}

impl<C> tcp::Connected for EstOutputRateCn<C>
where
    C: tcp::Connected,
{
    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl<A, C> ChunnelConnection for EstOutputRateCn<C>
where
    A: Send + 'static,
    C: ChunnelConnection<Data = (A, Vec<u8>)> + Send + Sync,
{
    type Data = (A, EstOutputRateHist);

    fn send<'cn, B>(
        &'cn self,
        burst: B,
    ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
    where
        B: IntoIterator<Item = Self::Data> + Send + 'cn,
        <B as IntoIterator>::IntoIter: Send,
    {
        let b: Result<Vec<_>, _> = {
            let mut s = self.ser.lock().unwrap();
            burst
                .into_iter()
                .map(|(a, h)| {
                    let mut buf = Vec::with_capacity(16);
                    match h.client_ip {
                        IpAddr::V4(ipv4) => {
                            let oct = ipv4.octets();
                            buf.push(32);
                            buf.extend_from_slice(&oct);
                        }
                        IpAddr::V6(ipv6) => {
                            let oct = ipv6.octets();
                            buf.push(128);
                            buf.extend_from_slice(&oct);
                        }
                    }

                    let curr_len = buf.len();
                    let mut c = Cursor::new(&mut buf);
                    c.set_position(curr_len as u64);
                    s.serialize(&h.h, &mut c)?;
                    Ok::<_, Report>((a, buf))
                })
                .collect() // collect to unlock
        };
        match b {
            Err(e) => Box::pin(ready(Err(e))) as _,
            Ok(b) => self.inner.send(b.into_iter()),
        }
    }

    fn recv<'cn, 'buf>(
        &'cn self,
        msgs_buf: &'buf mut [Option<Self::Data>],
    ) -> Pin<Box<dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>> + Send + 'cn>>
    where
        'buf: 'cn,
    {
        let mut slots: Vec<_> = (0..msgs_buf.len()).map(|_| None).collect();
        Box::pin(async move {
            let ms = self.inner.recv(&mut slots).await?;
            let mut d = self.des.lock().unwrap();
            let mut slot_idx = 0;
            for (a, v) in ms.iter_mut().map_while(Option::take) {
                let l = v[0];
                let (client_ip, offset) = match l as u32 {
                    32 => (
                        IpAddr::V4(
                            {
                                let x: [u8; 4] = v[1..5].try_into()?;
                                x
                            }
                            .into(),
                        ),
                        5,
                    ),
                    128 => (
                        IpAddr::V6(
                            {
                                let x: [u8; 16] = v[1..17].try_into()?;
                                x
                            }
                            .into(),
                        ),
                        17,
                    ),
                    x => bail!("Unknown address size {}", x),
                };

                let mut c = Cursor::new(&v[offset..]);
                match d.deserialize(&mut c) {
                    Ok(h) => {
                        msgs_buf[slot_idx] = Some((a, EstOutputRateHist { client_ip, h }));
                        slot_idx += 1;
                    }
                    Err(err) => {
                        debug!(?err, "Could not deserialize histogram");
                        continue;
                    }
                }
            }

            Ok(&mut msgs_buf[..slot_idx])
        })
    }
}

#[cfg(test)]
mod t {
    use std::{
        cell::Cell,
        future::Future,
        net::{Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::{Arc, Mutex, Once},
    };

    use bertha::ChunnelConnection;
    use color_eyre::eyre::Report;
    use futures_util::future::ready;
    use hdrhistogram::serialization::{Deserializer, V2Serializer};
    use tracing::{info, warn};
    use tracing_error::ErrorLayer;
    use tracing_subscriber::prelude::*;

    use crate::parse_log::{
        EstOutputRateCn, EstOutputRateHist, SAMPLE_INTERARRIVAL_MS, SAMPLE_OBJ_SIZE,
    };

    use super::{parse_lines, parse_raw, sample_logentry_lines, EstOutputRate};

    pub static COLOR_EYRE: Once = Once::new();

    #[test]
    fn pipeline() {
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();

        let raw = sample_logentry_lines();
        let lines = parse_raw(raw);
        let entries = parse_lines(lines);

        let mut or = EstOutputRate::default();
        const NUM_ENTRIES: usize = 25;
        let proc = or.new_entries(entries.take(NUM_ENTRIES).filter_map(|e| {
            if e.is_err() {
                warn!(?e, "entry");
            }
            e.ok()
        }));
        assert_eq!(proc, NUM_ENTRIES);

        let h = or.hist;
        let expected_rate = SAMPLE_OBJ_SIZE * 1000 / SAMPLE_INTERARRIVAL_MS;
        let quantile_matching_expected = h.quantile_below(expected_rate as u64);
        info!(?quantile_matching_expected, ?expected_rate, "checking hist");
        assert!(0.95 < quantile_matching_expected);
        let num_records = h.len();
        if num_records > 0 {
            let msg = h
                .iter_quantiles(2)
                .map(|iv| {
                    let quantile = iv.quantile_iterated_to();
                    let value = iv.value_iterated_to();
                    let cnt = iv.count_since_last_iteration();
                    (quantile, value, cnt)
                })
                .fold(format!("Hist({}) | ", num_records), |mut acc, (q, v, c)| {
                    let m = format!("[{}]({}): {} | ", q, v, c);
                    acc.push_str(&m);
                    acc
                });

            info!(?msg, maxval=?h.max(), "got histogram update");
        }
    }

    #[test]
    fn chunnel() {
        COLOR_EYRE.call_once(|| color_eyre::install().unwrap_or(()));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(ErrorLayer::default());
        let _guard = subscriber.set_default();

        let raw = sample_logentry_lines();
        let lines = parse_raw(raw);
        let entries = parse_lines(lines);
        let mut or = EstOutputRate::default();
        const NUM_ENTRIES: usize = 25;
        let proc = or.new_entries(entries.take(NUM_ENTRIES).filter_map(|e| {
            if e.is_err() {
                warn!(?e, "entry");
            }
            e.ok()
        }));
        assert_eq!(proc, NUM_ENTRIES);

        let cn = EstOutputRateCn {
            ser: Arc::new(Mutex::new(V2Serializer::new())),
            des: Arc::new(Mutex::new(Deserializer::new())),
            inner: FakeConn::default(),
        };

        let h = EstOutputRateHist {
            client_ip: "127.0.0.1".parse().unwrap(),
            h: or.hist.clone(),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Building tokio runtime");
        let r = rt.block_on(async move {
            cn.send(std::iter::once((
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                h,
            )))
            .await
            .unwrap();

            let mut slot = [None];
            let m = cn.recv(&mut slot).await.unwrap();
            m[0].take().unwrap().1
        });
        assert_eq!(r.h, or.hist);

        #[derive(Default)]
        struct FakeConn(Cell<Vec<u8>>);

        // SAFETY: we use a current_thread runtime, so there's only one thread anyway.
        unsafe impl Send for FakeConn {}
        unsafe impl Sync for FakeConn {}

        impl ChunnelConnection for FakeConn {
            type Data = (SocketAddr, Vec<u8>);

            fn send<'cn, B>(
                &'cn self,
                burst: B,
            ) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'cn>>
            where
                B: IntoIterator<Item = Self::Data> + Send + 'cn,
                <B as IntoIterator>::IntoIter: Send,
            {
                Box::pin(ready((|| {
                    for (_, v) in burst {
                        self.0.set(v);
                    }

                    Ok(())
                })()))
            }

            fn recv<'cn, 'buf>(
                &'cn self,
                msgs_buf: &'buf mut [Option<Self::Data>],
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<&'buf mut [Option<Self::Data>], Report>>
                        + Send
                        + 'cn,
                >,
            >
            where
                'buf: 'cn,
            {
                let a = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
                Box::pin(async move {
                    msgs_buf[0] = Some((a, self.0.take()));
                    Ok(&mut msgs_buf[..1])
                })
            }
        }
    }
}
