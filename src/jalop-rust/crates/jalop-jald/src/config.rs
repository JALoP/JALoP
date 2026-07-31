/***
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//! This module provides loading and deserialization of the jald TOML config file and CLI options.
use clap::Parser;
use jalop_protocol::control::subscriptions::SubscriberMode;
use jalop_protocol::jnl_types::jalop_types::{DigestAlgorithm, DigestChallenge, PublisherId};
use jalop_sec::seccomp;
use jalop_sys::RecordType;
use reqwest::Url;
use serde::Deserialize;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Parser)]
pub struct CliOpts {
    /// jald config file location
    #[clap(short, long, default_value = "test-input/jald.toml")]
    pub config_path: PathBuf,
    /// enable debug mode
    #[clap(long)]
    pub debug: bool,
    /// experimental: set number of session workers per peer connection
    #[clap(long, default_value = "1")]
    pub worker_count: NonZeroUsize,
}

/// Jald configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct JaldCfg {
    pub general: GeneralCfg,
    pub tls: TlsCfg,
    pub tuning: TuningCfg,
    #[serde(rename = "peer")]
    pub peers: Vec<PeerCfg>,
    #[serde(rename = "control-socket")]
    pub control_socket: ControlSocketCfg,
    #[serde(rename = "record-socket")]
    pub record_socket: RecordSocketCfg,
    #[serde(default)]
    pub seccomp: seccomp::Config,
}

/// Read configuration from TOML file specified on command line, then merge with other command line options.
pub fn from_cli(cli: &CliOpts) -> anyhow::Result<JaldCfg> {
    from_file(&cli.config_path)
}

/// Read configuration from TOML at the specified path
pub fn from_file<P: AsRef<Path>>(config_file: P) -> anyhow::Result<JaldCfg> {
    let cfg_str = fs::read_to_string(config_file)?;
    let cfg: JaldCfg = toml::from_str(&cfg_str)?;
    Ok(cfg)
}

/// Filter Control Socket (tx) Configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ControlSocketCfg {
    pub path: PathBuf,
    #[serde(default = "default_socket_timeout")]
    pub timeout: u16,
    #[serde(default = "default_control_message_buffer")]
    pub buffer: usize,
}

/// Record Socket (rx) configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RecordSocketCfg {
    pub path: PathBuf,
    #[serde(default = "default_socket_timeout")]
    pub timeout: u16,
    #[serde(default = "default_record_socket_buffer")]
    pub buffer: usize,
}

/// General configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GeneralCfg {
    #[serde(flatten)]
    pub publisher_id: PublisherId,
    #[serde(default = "default_digest_algorithm")]
    pub digest_algorithms: Vec<DigestAlgorithm>,
    #[serde(default = "default_schemas_root")]
    pub schemas_root: PathBuf,
}

/// TLS configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TlsCfg {
    pub private_key: PathBuf,
    pub public_cert: PathBuf,
    pub trust_store: PathBuf,
    pub allow_self_signed_certs: bool,
}

/// Tuning configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TuningCfg {
    #[serde(default = "default_poll_time")]
    pub poll_time: u16,
    #[serde(default = "default_retry_interval")]
    pub retry_interval: u64,
    #[serde(default = "default_network_timeout")]
    pub network_timeout: u16,
}

/// Subscriber peer configuration
#[derive(Clone, Debug)]
pub struct PeerCfg {
    url: Url,
    pub mode: SubscriberMode,
    pub digest_challenge: Vec<DigestChallenge>,
    pub record_types: Vec<RecordType>,
    pub cert_dir: PathBuf,
}

impl PeerCfg {
    /// Create endpoint [Url] for the specified [RecordType]
    pub fn endpoint_url(&self, rec_type: RecordType) -> Url {
        let mut ep = self.url.clone();
        ep.set_path(&rec_type.to_string());
        ep
    }
}

// RawPeerCfg maps directly to the toml structure
#[derive(Deserialize)]
struct RawPeerCfg {
    host: String,
    port: u16,
    mode: SubscriberMode,
    digest_challenge: Vec<DigestChallenge>,
    record_types: Vec<RecordType>,
    cert_dir: PathBuf,
}

// Custom Deserialize impl to move the Url parse up to config time, to allow infallible Url usage
impl<'de> Deserialize<'de> for PeerCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cfg = RawPeerCfg::deserialize(deserializer)?;
        let url = Url::parse(&format!("https://{}:{}", cfg.host, cfg.port)).map_err(serde::de::Error::custom)?;
        Ok(PeerCfg {
            url,
            mode: cfg.mode,
            digest_challenge: cfg.digest_challenge,
            record_types: cfg.record_types,
            cert_dir: cfg.cert_dir,
        })
    }
}

fn default_socket_timeout() -> u16 {
    30
}

fn default_control_message_buffer() -> usize {
    4096
}

fn default_record_socket_buffer() -> usize {
    256
}

fn default_poll_time() -> u16 {
    1
}

fn default_retry_interval() -> u64 {
    30
}

fn default_network_timeout() -> u16 {
    60
}

fn default_digest_algorithm() -> Vec<DigestAlgorithm> {
    vec![DigestAlgorithm::Sha256]
}

fn default_schemas_root() -> PathBuf {
    "./schemas/".to_string().into()
}

#[cfg(test)]
mod tests {
    use crate::config::PeerCfg;
    use jalop_sys::RecordType;
    use url::Url;

    fn make_test_url_cfg(url: &str) -> anyhow::Result<PeerCfg> {
        let cfg = format!(
            r#"
        host = "{url}"
        port = 8444
        mode = "archive"
        digest_challenge = ["on"]
        record_types = ["audit", "log", "journal"]
        cert_dir = "foo/bar"
        "#
        );
        Ok(toml::from_str::<PeerCfg>(&cfg)?)
    }

    #[test]
    fn test_peer_parse_url() {
        let expected = Url::parse("https://localhost:8444").unwrap();
        let actual = make_test_url_cfg("localhost").unwrap();
        assert_eq!(actual.url, expected);
    }

    #[test]
    fn test_peer_make_endpoint_url() {
        for rec_type in RecordType::list() {
            // jjnl requires this format: https://<ip>:<port>/<record_type>
            let expected = Url::parse(&format!("https://localhost:8444/{rec_type}")).unwrap();
            let actual = make_test_url_cfg("localhost").unwrap().endpoint_url(rec_type);
            assert_eq!(actual, expected);
        }
    }
}
