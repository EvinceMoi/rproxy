use anyhow::{anyhow, bail, Result};
use std::{fs::File, io::BufReader};

use rustls::{ClientConfig, ServerConfig};

use crate::config::config;

pub fn ssl_config_client() -> Result<ClientConfig> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(cafile) = &config().ssl_certificate {
        let mut pem = BufReader::new(File::open(cafile)?);
        for cert in rustls_pemfile::certs(&mut pem) {
            root_cert_store.add(cert?)?;
        }
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(config)
}

pub fn ssl_config_server() -> Result<ServerConfig> {
    let certs = config()
        .ssl_certificate
        .as_ref()
        .and_then(|keyfile| File::open(keyfile).ok())
        .map(BufReader::new)
        .and_then(|mut buf| {
            Some(
                rustls_pemfile::certs(&mut buf)
                    .filter_map(Result::ok)
                    .collect::<Vec<_>>(),
            )
        })
        .ok_or(anyhow!("failed to read cert file"))?;
    if certs.is_empty() {
        bail!("invalid cert file");
    }

    let key = config()
        .ssl_certificate_key
        .as_ref()
        .and_then(|keyfile| File::open(keyfile).ok())
        .map(BufReader::new)
        .and_then(|mut buf| rustls_pemfile::private_key(&mut buf).ok())
        .flatten()
        .ok_or(anyhow!("failed to read key file"))?;

    let verifier = rustls::server::WebPkiClientVerifier::no_client_auth();
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    Ok(config)
}

pub fn base64_encode(dat: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(dat)
}
pub fn base64_decode(dat: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(dat)
        .ok()
}
