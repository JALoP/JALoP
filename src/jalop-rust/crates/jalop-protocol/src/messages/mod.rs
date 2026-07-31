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
//! This module provides serialization/deserialization of Jalop Protocol types to/from header/body
//! pairs compatible with the reqwest crate

mod close_session_message;
pub use close_session_message::{CloseSessionMessage, CloseSessionMessageBuilder};

mod digest_challenge_message;
pub use digest_challenge_message::{DigestChallengeMessage, DigestChallengeMessageBuilder};

mod digest_challenge_response_message;
pub use digest_challenge_response_message::{DigestChallengeResponseMessage, DigestChallengeResponseMessageBuilder};

mod init_ack_message;
pub use init_ack_message::{InitAckMessage, InitAckMessageBuilder, ResumeInfo};

mod init_message;
pub use init_message::{InitMessage, InitMessageBuilder};

mod init_nack_message;
pub use init_nack_message::{InitNackMessage, InitNackMessageBuilder};

mod journal_missing_message;
pub use journal_missing_message::{JournalMissingMessage, JournalMissingMessageBuilder};

mod record_failure_message;
pub use record_failure_message::{RecordFailureMessage, RecordFailureMessageBuilder};

mod record_message;
pub use record_message::{Payload, RecordMessage, RecordMessageBuilder};

mod session_failure_message;
pub use session_failure_message::{SessionFailureMessage, SessionFailureMessageBuilder};

mod sync_failure_message;
pub use sync_failure_message::SyncFailureMessage;

mod sync_message;
pub use sync_message::{SyncMessage, SyncMessageBuilder};

mod jalop_message_type;
pub use jalop_message_type::{peek_message_type, JalopMessageType};

mod jalop_messages;
