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
//! This module provides utility functions that wait for resources to become ready.
use anyhow::bail;
use log::debug;
use std::path::Path;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::interval;

/// wait for the socket file to appear on disk, waiting up to the specified timeout
pub async fn wait_for_socket<P: AsRef<Path>>(
    path: P,
    timeout: u16,
    mut kill: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let mut attempts = 0;
    let mut check_interval = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = kill.recv() => bail!("wait for socket interrupted by kill signal"),
            _ = check_interval.tick() => {
                if path.as_ref().try_exists()? {
                    break Ok(())
                } else if attempts < timeout {
                    debug!("waiting on socket");
                    attempts += 1;
                } else {
                    bail!("socket timeout expired")
                }
            }
        }
    }
}
