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

//! This module provides seccomp configuration functionality for loading the initial and final filters.
use crate::seccomp;
use libseccomp::ScmpAction;
use serde::Deserialize;

use libseccomp::{ScmpFilterContext, ScmpSyscall};

/// Inline filter seccomp configuration
/// system calls are specified as `name: phase`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    #[allow(unused)]
    enabled: bool,
    debug: bool,
    initial: Vec<String>,
    r#final: Vec<String>,
    both: Vec<String>,
}

impl Config {
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

/// Apply the initial seccomp filter from the specified configuration.
pub fn apply_initial(config: &seccomp::Config) -> anyhow::Result<()> {
    if config.is_enabled() {
        let action = config.get_seccomp_action();
        apply(config.all(), ScmpAction::Allow, action)?;
    }
    Ok(())
}

/// Apply the final seccomp filter from the specified configuration.
pub fn apply_final(config: &seccomp::Config) -> anyhow::Result<()> {
    if config.is_enabled() {
        let finals = config.finals();
        let mut blacklist = config.initials();
        // blacklist: start with all calls, retain not in the final list
        blacklist.retain(|s| !finals.contains(s));

        let action = config.get_seccomp_action();
        apply(blacklist, action, ScmpAction::Allow)?;

        if config.is_debug_enabled() {
            // intentionally stdout
            println!("Applying final ruleset DONE");
        }
    }
    Ok(())
}

fn apply(syscalls: Vec<String>, match_action: ScmpAction, default_action: ScmpAction) -> anyhow::Result<()> {
    let mut filter = ScmpFilterContext::new(default_action)?;
    for syscall in syscalls {
        let syscall = ScmpSyscall::from_name(&syscall)?;
        filter.add_rule(match_action, syscall)?;
    }

    filter.load()?;
    Ok(())
}
