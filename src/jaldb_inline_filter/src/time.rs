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

//! This module provides a safe timestamp interface to the underlying JALoP timestamp
use crate::Error;
use anyhow::bail;
use std::fmt::{Display, Formatter};
use std::ops::Sub;

/// Represents a JALoP timestamp
#[derive(Clone, Debug)]
pub struct Timestamp(String);

/// Create a [Timestamp] for the current time
pub fn now() -> Result<Timestamp, Error> {
    Ok(jalop_sys::jald_timestamp().map(Timestamp)?)
}

impl Sub<std::time::Duration> for Timestamp {
    type Output = anyhow::Result<Timestamp>;

    fn sub(self, rhs: std::time::Duration) -> Self::Output {
        static SUFFIX: &str = "+00:00";
        match chrono::DateTime::parse_from_rfc3339(&format!("{}{SUFFIX}", self.0)) {
            Ok(dt) => {
                let dt = dt.sub(rhs);
                Ok(Timestamp(dt.to_rfc3339().trim_end_matches(SUFFIX).to_string()))
            }
            Err(e) => bail!(e),
        }
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Timestamp {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl From<String> for Timestamp {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sub() {
        let ts = now().unwrap();
        let delta = Duration::from_secs(0);
        let same = ts.clone().sub(delta).unwrap();
        assert_eq!(ts.0, same.0);
    }
}
