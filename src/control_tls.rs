//! hbbs 控制口的 TLS 监听。
//!
//! 证书与私钥由环境变量给出，二者必须同时设置；未设置时该监听关闭。
//! 复用 relay 的证书也可以，指纹格式与 `RELAY_QUIC_PIN` 一致。

use hbb_common::{anyhow::anyhow, log, ResultType};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::{io::BufReader, path::Path, sync::Arc};
use tokio_rustls::TlsAcceptor;

/// hbbs 控制口的默认 TLS 端口。与信封 UDP 端口同号，协议不同。
pub const DEFAULT_TLS_PORT: u16 = 4443;
/// hbbr 的默认 TLS 端口。与 hbbs 同机部署时不能共用端口。
pub const DEFAULT_RELAY_TLS_PORT: u16 = 4444;

pub struct ControlTls {
    pub port: u16,
    pub acceptor: TlsAcceptor,
}

/// 读取 `port_var` / `cert_var` / `key_var`。证书与私钥都为空时返回 `None`。
pub fn from_env(
    port_var: &str,
    cert_var: &str,
    key_var: &str,
    default_port: u16,
) -> ResultType<Option<ControlTls>> {
    let cert_path = crate::common::get_arg(cert_var);
    let key_path = crate::common::get_arg(key_var);
    if cert_path.trim().is_empty() && key_path.trim().is_empty() {
        return Ok(None);
    }
    if cert_path.trim().is_empty() || key_path.trim().is_empty() {
        return Err(anyhow!("{cert_var} and {key_var} must be set together"));
    }
    let port_text = crate::common::get_arg(port_var);
    let port = if port_text.trim().is_empty() {
        default_port
    } else {
        port_text
            .trim()
            .parse()
            .map_err(|_| anyhow!("invalid {port_var}: {port_text}"))?
    };
    let certs = load_certs(Path::new(cert_path.trim()))?;
    let key = load_key(Path::new(key_path.trim()))?;
    let pin = certs
        .first()
        .map(|cert| cert_pin(cert.as_ref()))
        .unwrap_or_default();
    // 控制面只允许 TLS 1.3，避免与文档、指纹预期不一致。
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    log::info!("control TLS on tcp/{} (pin: {})", port, pin);
    Ok(Some(ControlTls {
        port,
        acceptor: TlsAcceptor::from(Arc::new(config)),
    }))
}

fn load_certs(path: &Path) -> ResultType<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate in {}", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> ResultType<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("no private key in {}", path.display()))
}

/// 与 `RELAY_QUIC_PIN` 相同的指纹格式，便于两端共用一个解析函数。
pub fn cert_pin(der: &[u8]) -> String {
    use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
    use hbb_common::sha2::{Digest, Sha256};
    let digest = Sha256::digest(der);
    format!("sha256:{}", STANDARD.encode(digest))
}
