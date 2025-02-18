//! Shard-compatible client, similar to KvClient. Support TLS and QUIC encryption options.
//!
//! Produce raw messages for `crate::listen` connections to handle.

use std::{
    error::Error,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use bertha::{
    bincode::SerializeChunnel,
    udp::UdpSkChunnel,
    uds::UnixSkChunnel,
    util::{Nothing, ProjectLeft},
    ChunnelConnection, ChunnelConnector, CxList, Either, Select,
};
use color_eyre::eyre::{Report, WrapErr};
use localname_ctl::LocalNameChunnel;
use rustls::{ClientConfig, RootCertStore, ServerName};
use shard_ctl::ClientShardChunnelClient;
use tcp::{ConnectChunnel, TcpChunnelWrapClient};
use tls_tunnel::rustls::TLSChunnel;
use tracing::debug;

use crate::{
    parse_log::{EstOutputRateHist, EstOutputRateSerializeChunnel, Line},
    EncrSpec,
};

#[derive(Clone, Copy, Debug)]
struct DontVerify(pub IpAddr);

#[derive(Clone, Debug)]
struct DontVerifyErr(String);

impl Display for DontVerifyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for DontVerifyErr {}

impl rustls::client::ServerCertVerifier for DontVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        match server_name {
            ServerName::IpAddress(ip) if *ip == self.0 => (),
            ServerName::DnsName(dns) if dns.as_ref() == "localhost" => (),
            _ => {
                let err = DontVerifyErr(format!(
                    "ServerName {:?} mismatched verifier configured IP {:?} or hostname localhost",
                    server_name, self.0,
                ));
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Other(Arc::new(err)),
                ));
            }
        }

        return Ok(rustls::client::ServerCertVerified::assertion());
    }
}

macro_rules! encr_stack {
    (tls => $connect_addr: expr) => {{
        // tcp |> tls
        let mut tls_client_cfg = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut dangerous_cfg = tls_client_cfg.dangerous();
        dangerous_cfg.set_certificate_verifier(Arc::new(DontVerify($connect_addr.ip())));
        let sn: ServerName = ServerName::IpAddress($connect_addr.ip());
        let tls_stack = CxList::from(TLSChunnel::client(tls_client_cfg, sn))
            .wrap(TcpChunnelWrapClient::new($connect_addr));
        tls_stack
    }};
    (quic => $connect_addr: expr) => {{
        // quic
        let mut quic_client_cfg = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        quic_client_cfg.verify_peer(false);
        quic_client_cfg.set_max_idle_timeout(5000);
        quic_client_cfg.set_max_recv_udp_payload_size(1460);
        quic_client_cfg.set_max_send_udp_payload_size(1460);
        quic_client_cfg.set_initial_max_data(10_000_000);
        quic_client_cfg.set_initial_max_stream_data_bidi_local(1_000_000);
        quic_client_cfg.set_initial_max_stream_data_bidi_remote(1_000_000);
        quic_client_cfg.set_initial_max_streams_bidi(100);
        quic_client_cfg.set_initial_max_streams_uni(100);
        quic_client_cfg.set_disable_active_migration(true);
        let quic_stack = quic_chunnel::QuicChunnel::client(quic_client_cfg);
        quic_stack
    }};
    ($connect_addr: expr) => {{
        // either:
        // base |> quic
        // base |> tcp |> tls
        CxList::from(Select::from((encr_stack!(quic => $connect_addr), encr_stack!(tls => $connect_addr)))).wrap(ConnectChunnel($connect_addr))
    }};
}

pub async fn connect(
    addr: SocketAddr,
    redis_addr: Option<String>,
    encr_spec: EncrSpec,
) -> Result<impl ChunnelConnection<Data = Line> + Send + 'static, Report> {
    let base = UdpSkChunnel.connect(addr).await?;
    let cl_shard = if let Some(ra) = redis_addr {
        Some(
            ClientShardChunnelClient::new(addr, &ra)
                .await
                .wrap_err("make ClientShardChunnelClient")?,
        )
    } else {
        None
    };
    // (
    //   client_sharding |> serialize |> udp,
    //   serialize |> ( tls |> tcp [replace udp], quic ) |> udp
    // )
    // client_sharding is not compatible with enc_stack since it requires send_to, which Connected
    // types don't support.
    let cn = match encr_spec {
        EncrSpec::AllowNone => {
            let enc_stack = encr_stack!(addr);
            let stack = Select::from((
                CxList::from(cl_shard).wrap(SerializeChunnel::default()),
                CxList::from(SerializeChunnel::default())
                    .wrap(Select::from((Nothing::<()>::default(), enc_stack))),
            ));
            let cn = bertha::negotiate_client(stack, base, addr).await?;
            Either::Left(Either::Left(cn))
        }
        EncrSpec::AutoOnly => {
            let enc_stack = encr_stack!(addr);
            let stack = CxList::from(SerializeChunnel::default()).wrap(enc_stack);
            let cn = bertha::negotiate_client(stack, base, addr).await?;
            Either::Left(Either::Right(cn))
        }
        EncrSpec::TlsOnly => {
            let enc_stack = encr_stack!(tls => addr);
            let stack = CxList::from(SerializeChunnel::default()).wrap(enc_stack);
            let cn = bertha::negotiate_client(stack, base, addr).await?;
            Either::Right(Either::Left(cn))
        }
        EncrSpec::QuicOnly => {
            let enc_stack = CxList::from(encr_stack!(quic => addr)).wrap(ConnectChunnel(addr));
            let stack = CxList::from(SerializeChunnel::default()).wrap(enc_stack);
            let cn = bertha::negotiate_client(stack, base, addr).await?;
            Either::Right(Either::Right(cn))
        }
    };

    debug!("returning connection");
    let cn = ProjectLeft::new(addr, cn);
    Ok(cn)
}

pub async fn connect_local(
    addr: SocketAddr,
    localname_root: Option<PathBuf>,
    encr_spec: EncrSpec,
) -> Result<impl ChunnelConnection<Data = EstOutputRateHist>, Report> {
    let sk = UdpSkChunnel.connect(addr).await?;
    let local_chunnel = if let Some(lr) = localname_root {
        Some(
            LocalNameChunnel::client(lr.clone(), UnixSkChunnel::with_root(lr), bertha::CxNil)
                .await?,
        )
    } else {
        None
    };

    let cn = match (encr_spec, local_chunnel) {
        (EncrSpec::AllowNone, Some(lch)) => {
            let enc = encr_stack!(addr);
            let stack = CxList::from(EstOutputRateSerializeChunnel)
                .wrap(lch)
                .wrap(Select::from((Nothing::<()>::default(), enc)));
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(Either::Left(addr), cn);
            Either::Left(Either::Left(Either::Left(cn)))
        }
        (EncrSpec::AllowNone, None) => {
            let enc = encr_stack!(addr);
            let stack = CxList::from(EstOutputRateSerializeChunnel)
                .wrap(Select::from((Nothing::<()>::default(), enc)));
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(addr, cn);
            Either::Left(Either::Left(Either::Right(cn)))
        }
        (EncrSpec::AutoOnly, Some(lch)) => {
            let enc = encr_stack!(addr);
            let stack = CxList::from(EstOutputRateSerializeChunnel)
                .wrap(lch)
                .wrap(enc);
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(Either::Left(addr), cn);
            Either::Left(Either::Right(Either::Left(cn)))
        }
        (EncrSpec::AutoOnly, None) => {
            let enc = encr_stack!(addr);
            let stack = CxList::from(EstOutputRateSerializeChunnel).wrap(enc);
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(addr, cn);
            Either::Left(Either::Right(Either::Right(cn)))
        }
        (EncrSpec::TlsOnly, Some(lch)) => {
            let enc = encr_stack!(tls => addr);
            let stack = CxList::from(EstOutputRateSerializeChunnel)
                .wrap(lch)
                .wrap(enc);
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(Either::Left(addr), cn);
            Either::Right(Either::Left(Either::Left(cn)))
        }
        (EncrSpec::TlsOnly, None) => {
            let enc = encr_stack!(tls => addr);
            let stack = CxList::from(EstOutputRateSerializeChunnel).wrap(enc);
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(addr, cn);
            Either::Right(Either::Left(Either::Right(cn)))
        }
        (EncrSpec::QuicOnly, Some(lch)) => {
            let enc = CxList::from(encr_stack!(quic => addr)).wrap(ConnectChunnel(addr));
            let stack = CxList::from(EstOutputRateSerializeChunnel)
                .wrap(lch)
                .wrap(enc);
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(Either::Left(addr), cn);
            Either::Right(Either::Right(Either::Left(cn)))
        }
        (EncrSpec::QuicOnly, None) => {
            let enc = CxList::from(encr_stack!(quic => addr)).wrap(ConnectChunnel(addr));
            let stack = CxList::from(EstOutputRateSerializeChunnel).wrap(enc);
            let cn = bertha::negotiate_client(stack, sk, addr).await?;
            let cn = ProjectLeft::new(addr, cn);
            Either::Right(Either::Right(Either::Right(cn)))
        }
    };
    Ok(cn)
}
