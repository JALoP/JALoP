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

//! This module provides loading and deserialization of the filter TOML config file and CLI options.
use clap::Parser;
use jalop_sec::seccomp;
use log::debug;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Parser)]
pub struct CliOpts {
    /// filter config file location
    #[clap(short, long, default_value = "test-input/jaldb-filter.toml")]
    pub config_path: PathBuf,
    /// database home directory
    #[clap(short, long)]
    pub db_home: Option<PathBuf>,
    /// enable debug mode
    #[clap(long)]
    pub debug: bool,
}

/// Inline filter configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct FilterCfg {
    pub db: DbConfig,
    #[serde(default)]
    pub seccomp: seccomp::Config,
    #[serde(rename = "control-socket")]
    pub control_socket: ControlSocketCfg,
    #[serde(rename = "record-socket")]
    pub record_socket: RecordSocketCfg,
}

/// Read configuration from TOML file specified on command line, then merge with other command line options.
pub fn from_cli(cli: &CliOpts) -> anyhow::Result<FilterCfg> {
    let mut cfg = from_file(&cli.config_path)?;
    if let Some(db_path) = cli.db_home.as_ref() {
        cfg.db.path = db_path.clone();
        debug!("override db.path from cli: {}", db_path.display());
    }
    Ok(cfg)
}

/// Read configuration from TOML at the specified path
pub fn from_file<P: AsRef<Path>>(config_file: P) -> anyhow::Result<FilterCfg> {
    let cfg_str = fs::read_to_string(config_file)?;
    let cfg: FilterCfg = toml::from_str(&cfg_str)?;
    Ok(cfg)
}

/// Database configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DbConfig {
    pub path: PathBuf,
    #[serde(default = "default_poll_time_seconds")]
    pub poll_time: u64,
}

/// Control Socket (rx) Configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ControlSocketCfg {
    pub path: PathBuf,
    #[serde(default = "default_socket_timeout")]
    pub timeout: u16,
    #[serde(default = "default_control_message_buffer")]
    pub buffer: usize,
}

/// Record Socket (tx) configuration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RecordSocketCfg {
    pub path: PathBuf,
    #[serde(default = "default_socket_timeout")]
    pub timeout: u16,
    #[serde(default = "default_record_socket_buffer")]
    pub buffer: usize,
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

fn default_poll_time_seconds() -> u64 {
    1
}
