use clap::Parser;
use url::Url;

mod detail {
	use anyhow::{Result, bail, ensure};
	use url::{Url, ParseError};

	pub fn parse_proxy_pass(arg: &str) -> Result<Url> {
		let supported_scheme = vec!["socks5", "https", "http"];
		match Url::parse(arg) {
			Ok(url) => {
				let scheme_ok = supported_scheme.iter().any(|s| s.eq(&url.scheme()));
				ensure!(scheme_ok, "unsupported scheme");
				ensure!(url.host().is_some(), "host error");
				ensure!(url.port_or_known_default().is_some(), "port error");
				Ok(url)
			},
			Err(e) => {
				bail!(e.to_string());
			},
		}
	}
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(next_line_help = false)]
pub struct Args {
	/// Specify server listening address and port
	#[arg(long, value_name = "ip:port", default_value = "[::1]:1080")]
	pub server_listen: String,

	/// Specify local IP for client TCP connection to server
	#[arg(long, value_name = "ip:port")]
	pub local_ip: Option<String>,

	/// List of authorized users(e.g: user1:pass1,user2:pass2)
	#[arg(
		long, 
		value_name = "usrname:passwd",
		value_delimiter = ',',
		default_values = ["jack:1111"]
	)]
	pub auth_users: Vec<String>,

	/// Specify next proxy pass(e.g: socks5://user:passwd@ip:port)
	#[arg(long, value_name = "next", value_parser = detail::parse_proxy_pass)]
	pub proxy_pass: Option<Url>,

	/// Enable SSL for the next proxy pass
	#[arg(long, value_name = "bool", default_value_t = false)]
	pub proxy_pass_ssl: bool,

	/// Directory containing SSL certificates, auto-locates 'ssl_crt.pem/ssl_crt.pwd/ssl_key.pem/ssl_dh.pem'
	#[arg(long, value_name = "path" )]
	pub ssl_certificate_dir: Option<String>,
	
	/// Path to SSL certificate file
	#[arg(long, value_name = "path" )]
	pub ssl_certificate: Option<String>,

	/// Path to SSL certificate secret key file
	#[arg(long, value_name = "path" )]
	pub ssl_certificate_key: Option<String>,

	/// SSL certificate key passphrase
	#[arg(long, value_name = "path/string" )]
	pub ssl_certificate_passwd: Option<String>,

	/// Specifies a file with DH parameters for DHE ciphers
	#[arg(long, value_name = "path" )]
	pub ssl_dhparam: Option<String>,

	/// Specifies SNI for multiple SSL certificates on one IP
	#[arg(long, value_name = "sni" )]
	pub ssl_sni: Option<String>,

	/// Specify enabled SSL ciphers
	#[arg(long, value_name = "ssl_ciphers" )]
	pub ssl_ciphers: Option<String>,

	/// Prefer server ciphers over client ciphers for SSLv3 and TLS protocols
	#[arg(long, default_value_t = false)]
	pub ssl_prefer_server_ciphers: bool,

	/// Specify document root directory for HTTP server
	#[arg(long, value_name = "doc")]
	pub http_doc: Option<String>,

	/// Enable directory listing
	#[arg(long, default_value_t = false)]
	pub autoindex: bool,

	/// Specify directory for log files
	#[arg(long, value_name = "path", default_value = "./logs" )]
	pub logs_path: Option<String>,

	/// Disable logging
	#[arg(long, default_value_t = false)]
	pub disable_logs: bool,

	/// Disable HTTP protocol
	#[arg(long, default_value_t = false)]
	pub disable_http: bool,

	/// Disable SOCKS proxy protocol
	#[arg(long, default_value_t = false)]
	pub disable_socks: bool,

	/// Disable insecure protocol
	#[arg(long, default_value_t = false)]
	pub disable_insecure: bool,

	/// Noise-based data security
	#[arg(long, default_value_t = false)]
	pub scramble: bool,

	/// Length of the noise data
	#[arg(long, default_value_t = 0x0fff)]
	pub noise_length: u16,
}

use std::sync::OnceLock;

static APP_CONFIG: OnceLock<Args> = OnceLock::new();
pub fn config() -> &'static Args {
    APP_CONFIG.get_or_init(|| {
		Args::parse()
    })
}
