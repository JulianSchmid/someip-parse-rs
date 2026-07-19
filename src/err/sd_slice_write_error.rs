use super::SdValueError;

/// Error when serializing a SOME/IP-SD message into a slice.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdSliceWriteError {
    /// The slice length was not large enough to write the message.
    UnexpectedEndOfSlice(usize),

    /// Error in the data that was attempted to be written.
    Value(SdValueError),
}

impl core::fmt::Display for SdSliceWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdSliceWriteError::*;
        match self {
            UnexpectedEndOfSlice(required_len) => write!(
                f,
                "SOMEIP SD Error: The slice is too short, at least {required_len} bytes are required to write the SOME/IP-SD message."
            ),
            Value(value) => value.fmt(f),
        }
    }
}

impl core::error::Error for SdSliceWriteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use SdSliceWriteError::*;
        match self {
            UnexpectedEndOfSlice(_) => None,
            Value(err) => Some(err),
        }
    }
}

impl From<SdValueError> for SdSliceWriteError {
    fn from(err: SdValueError) -> SdSliceWriteError {
        SdSliceWriteError::Value(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let err = SdSliceWriteError::UnexpectedEndOfSlice(4);
        assert_eq!(err, err.clone());
        let _ = format!("{:?}", err);
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
        assert!(!format!("{}", SdSliceWriteError::UnexpectedEndOfSlice(4)).is_empty());
        let value = SdValueError::TtlZeroIndicatesStopOffering;
        assert_eq!(
            format!("{}", &value),
            format!("{}", SdSliceWriteError::Value(value.clone()))
        );
    }

    #[test]
    fn source() {
        use core::error::Error;
        assert!(SdSliceWriteError::UnexpectedEndOfSlice(4)
            .source()
            .is_none());
        assert!(
            SdSliceWriteError::Value(SdValueError::TtlZeroIndicatesStopOffering)
                .source()
                .is_some()
        );
    }

    #[test]
    fn from_value_error() {
        let value = SdValueError::TtlZeroIndicatesStopOffering;
        assert_eq!(
            SdSliceWriteError::from(value.clone()),
            SdSliceWriteError::Value(value)
        );
    }
}
