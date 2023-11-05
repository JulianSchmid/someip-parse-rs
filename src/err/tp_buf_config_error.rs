#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TpBufConfigError {
    /// Error if the configured maximum payload is bigger then the possible value.
    MaxPayloadLenTooBig { allowed_max: u32, actual: u32 },
}

impl core::fmt::Display for TpBufConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TpBufConfigError::*;
        match self {
            MaxPayloadLenTooBig {
                allowed_max,
                actual,
            } => write!(f, "TP pool config 'maximum payload value' {actual} is bigger then the maximum allowed value {allowed_max}."),
        }
    }
}

impl std::error::Error for TpBufConfigError {}
