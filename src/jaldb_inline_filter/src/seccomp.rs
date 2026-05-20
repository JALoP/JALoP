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
use crate::config::FilterSeccomp;

#[cfg(feature = "rhel7")]
use jalop_sys::jal_seccomp::Enforcer;

#[cfg(not(feature = "rhel7"))]
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

/// Apply the initial seccomp filter from the specified configuration.
#[cfg(not(feature = "rhel7"))]
pub fn apply_initial(config: &FilterSeccomp) -> anyhow::Result<()> {
    if config.is_enabled() {
        let action = config.get_seccomp_action();
        apply(config.all(), ScmpAction::Allow, action)?;
    }
    Ok(())
}

#[cfg(feature = "rhel7")]
/// Apply the initial seccomp filter from the specified configuration.
pub fn apply_initial(config: &FilterSeccomp) -> anyhow::Result<()> {
    if config.is_enabled() {
        Enforcer::new_initial(config.initials(), config.is_debug_enabled())?.apply_initial()?;
    }
    Ok(())
}

/// Apply the final seccomp filter from the specified configuration.
#[cfg(not(feature = "rhel7"))]
pub fn apply_final(config: &FilterSeccomp) -> anyhow::Result<()> {
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

#[cfg(feature = "rhel7")]
/// Apply the final seccomp filter from the specified configuration.
pub fn apply_final(config: &FilterSeccomp) -> anyhow::Result<()> {
    if config.is_enabled() {
        Enforcer::new_final(config.finals(), config.is_debug_enabled())?.apply_final()?;
    }
    Ok(())
}

#[cfg(not(feature = "rhel7"))]
fn apply(syscalls: Vec<String>, match_action: ScmpAction, default_action: ScmpAction) -> anyhow::Result<()> {
    let mut filter = ScmpFilterContext::new(default_action)?;
    for syscall in syscalls {
        let syscall = ScmpSyscall::from_name(&syscall)?;
        filter.add_rule(match_action, syscall)?;
    }

    let _ = filter.load()?;
    Ok(())
}
