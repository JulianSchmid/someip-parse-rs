#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
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

#[cfg(test)]
mod tests {
    use super::TpBufConfigError::*;

    #[test]
    fn debug() {
        let err = MaxPayloadLenTooBig {
            allowed_max: 10,
            actual: 12,
        };
        let _ = format!("{err:?}");
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let err = MaxPayloadLenTooBig {
            allowed_max: 10,
            actual: 12,
        };
        assert_eq!(err, err.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            err.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            err.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
        assert_eq!(Ordering::Equal, err.cmp(&err));
        assert_eq!(Some(Ordering::Equal), err.partial_cmp(&err));
    }

    #[test]
    fn fmt() {
        assert_eq!(
            format!("{}", &MaxPayloadLenTooBig{ allowed_max: 10, actual: 12 }),
            "TP pool config 'maximum payload value' 12 is bigger then the maximum allowed value 10."
        );
    }

    #[test]
    fn source() {
        use std::error::Error;
        assert!(MaxPayloadLenTooBig {
            allowed_max: 10,
            actual: 12
        }
        .source()
        .is_none());
    }
}
