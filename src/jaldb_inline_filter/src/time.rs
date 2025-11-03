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
