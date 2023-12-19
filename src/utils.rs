use std::{io::BufReader, fs::File};
use anyhow::Result;

use rustls::{ClientConfig, pki_types::{self, ServerName}};

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
