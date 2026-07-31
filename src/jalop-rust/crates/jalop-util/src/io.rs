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

//! This module provides asynchronous stream of decoded messages from a single input socket.
use tokio::{
    io,
    io::{AsyncWriteExt, DuplexStream},
    net::UnixStream,
};
// socket receiving and parsing

/// Create an IO Pump that transfers bytes from the [UnixStream] to the [DuplexStream]
pub async fn pump(mut tx: DuplexStream, mut stream: UnixStream) -> anyhow::Result<u64> {
    let res = io::copy(&mut stream, &mut tx).await;
    let _ = tx.shutdown().await;
    Ok(res?)
}
