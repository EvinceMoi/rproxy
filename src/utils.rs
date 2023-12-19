use anyhow::Result;
use std::{fs::File, io::BufReader};

use rustls::{
    pki_types::{self, ServerName},
    ClientConfig,
};

use crate::config::config;

pub fn ssl_config() -> Result<ClientConfig> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    if let Some(cafile) = &config().ssl_certificate {
        let mut pem = BufReader::new(File::open(cafile)?);
        for cert in rustls_pemfile::certs(&mut pem) {
            root_cert_store.add(cert?)?;
        }
    } else {
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(config)
}

pub fn base64_encode(dat: &str) -> String {
	use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(dat)
}
pub fn base64_decode(dat: &str) -> Option<Vec<u8>> {
	use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(dat).ok()
}
