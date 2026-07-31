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
//! This module provides configuration shared across [jalop_actors::actor::Actor] implementations
use crate::config::{GeneralCfg, PeerCfg};
use jalop_protocol::jnl_types::jalop_types::{DigestAlgorithm, DigestChallenge, PublisherId, SessionId};
use url::Url;

#[derive(Debug, Clone)]
pub struct SessionGroupConfig {
    pub general_cfg: GeneralCfg,
    pub peer_cfg: PeerCfg,
    pub endpoint: Url,
    pub worker_count: usize,
    pub retry_interval: u64,
}

impl SessionGroupConfig {
    pub fn single_worker(general_cfg: GeneralCfg, peer_cfg: PeerCfg, retry_interval: u64, endpoint: Url) -> Self {
        Self::new(general_cfg, peer_cfg, retry_interval, endpoint, 1)
    }

    pub fn new(
        general_cfg: GeneralCfg,
        peer_cfg: PeerCfg,
        retry_interval: u64,
        endpoint: Url,
        worker_count: usize,
    ) -> Self {
        Self {
            general_cfg,
            peer_cfg,
            endpoint,
            worker_count,
            retry_interval,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionWorkerConfig {
    pub endpoint: Url,
    pub publisher_id: PublisherId,
    pub digest_algorithms: Vec<DigestAlgorithm>,
    pub digest_challenges: Vec<DigestChallenge>,
    pub retry_interval: u64,
}

impl From<&SessionGroupConfig> for SessionWorkerConfig {
    fn from(group_cfg: &SessionGroupConfig) -> Self {
        Self {
            endpoint: group_cfg.endpoint.clone(),
            publisher_id: group_cfg.general_cfg.publisher_id,
            digest_algorithms: group_cfg.general_cfg.digest_algorithms.clone(),
            digest_challenges: group_cfg.peer_cfg.digest_challenge.clone(),
            retry_interval: group_cfg.retry_interval,
        }
    }
}

/// Information needed for record publishing, extracted from the negotiation ack
#[derive(Debug)]
pub struct SessionConfig {
    pub session_id: SessionId,
    pub digest_algorithm: DigestAlgorithm,
    pub digest_challenge: DigestChallenge,
}
