/***
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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
use log::debug;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use libseccomp::ScmpAction;
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
    pub seccomp: FilterSeccomp,
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

/// Inline filter seccomp configuration
/// system calls are specified as `name: phase`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct FilterSeccomp {
    #[allow(unused)]
    enabled: bool,
    debug: bool,
    #[cfg_attr(feature = "rhel7", serde(rename = "rhel7_initial"))]
    initial: Vec<String>,
    #[cfg_attr(feature = "rhel7", serde(rename = "rhel7_final"))]
    r#final: Vec<String>,
    #[cfg_attr(feature = "rhel7", serde(rename = "rhel7_both"))]
    both: Vec<String>,
}

impl FilterSeccomp {
    /// Is seccomp enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn get_seccomp_action(&self) -> libseccomp::ScmpAction {
        if self.debug {
            log::warn!("Seccomp debugging is enabled.");
            ScmpAction::Log
        } else {
            ScmpAction::KillProcess
        }
    }

    /// Is seccomp debug enabled (prints a message at transition point for sorting system calls)
    pub fn is_debug_enabled(&self) -> bool {
        self.debug
    }

    /// The full set of system calls the application requires, used for init stage
    pub fn all(&self) -> Vec<String> {
        [self.initial.clone(), self.r#final.clone(), self.both.clone()].concat()
    }

    /// The initial set of system calls + common system calls, as specified in the configuration.
    pub fn initials(&self) -> Vec<String> {
        [self.initial.clone(), self.both.clone()].concat()
    }

    /// The final set of system calls + common system calls, as specified in the configuration.
    pub fn finals(&self) -> Vec<String> {
        [self.r#final.clone(), self.both.clone()].concat()
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
