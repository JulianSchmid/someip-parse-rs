use super::{SdError, SdOptionSliceError};

/// Error when decoding a SOME/IP-SD message from a slice.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdSliceError {
    /// The slice length was not large enough to contain the header
    /// or the announced entries/options arrays.
    UnexpectedEndOfSlice(usize),

    /// Error caused by the contents of the SD message.
    Content(SdError),
}

impl core::fmt::Display for SdSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdSliceError::*;
        match self {
            UnexpectedEndOfSlice(required_len) => write!(
                f,
                "SOMEIP SD Error: The slice is too short, at least {required_len} bytes are required to decode the SOME/IP-SD message."
            ),
            Content(value) => value.fmt(f),
        }
    }
}

impl core::error::Error for SdSliceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use SdSliceError::*;
        match self {
            UnexpectedEndOfSlice(_) => None,
            Content(err) => Some(err),
        }
    }
}

impl From<SdError> for SdSliceError {
    fn from(err: SdError) -> SdSliceError {
        SdSliceError::Content(err)
    }
}

impl From<SdOptionSliceError> for SdSliceError {
    fn from(err: SdOptionSliceError) -> SdSliceError {
        SdSliceError::Content(SdError::SdOption(err))
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

        let err = SdSliceError::UnexpectedEndOfSlice(4);
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
        assert!(!format!("{}", SdSliceError::UnexpectedEndOfSlice(4)).is_empty());
        let content = SdError::SdSessionIdZero;
        assert_eq!(
            format!("{}", &content),
            format!("{}", SdSliceError::Content(content.clone()))
        );
    }

    #[test]
    fn source() {
        use core::error::Error;
        assert!(SdSliceError::UnexpectedEndOfSlice(4).source().is_none());
        assert!(SdSliceError::Content(SdError::SdSessionIdZero)
            .source()
            .is_some());
    }

    #[test]
    fn from_impls() {
        assert_eq!(
            SdSliceError::from(SdError::SdSessionIdZero),
            SdSliceError::Content(SdError::SdSessionIdZero)
        );
        assert_eq!(
            SdSliceError::from(SdOptionSliceError::OptionLengthZero),
            SdSliceError::Content(SdError::SdOption(SdOptionSliceError::OptionLengthZero))
        );
    }
}
