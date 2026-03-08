use super::*;

/// Error when decoding an SD option from a slice.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdOptionSliceError {
    /// Error when a length error is encountered (e.g. unexpected
    /// end of slice or wrong length for a known option type).
    Len(LenError),

    /// Error if the `length` field of an option is zero
    /// (minimum valid size is 1).
    OptionLengthZero,
}

impl core::fmt::Display for SdOptionSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdOptionSliceError::*;
        match self {
            Len(err) => err.fmt(f),
            OptionLengthZero => write!(
                f,
                "SOMEIP SD Option Error: The 'length' field of the option is zero (minimum valid size is 1)."
            ),
        }
    }
}

impl std::error::Error for SdOptionSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SdOptionSliceError::*;
        match self {
            Len(err) => Some(err),
            OptionLengthZero => None,
        }
    }
}

impl From<LenError> for SdOptionSliceError {
    fn from(err: LenError) -> Self {
        SdOptionSliceError::Len(err)
    }
}

#[cfg(test)]
mod tests {
    use super::SdOptionSliceError::*;
    use super::*;

    #[test]
    fn debug() {
        let err = OptionLengthZero;
        assert_eq!("OptionLengthZero", format!("{:?}", err));
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let err = OptionLengthZero;
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
            format!("{}", OptionLengthZero),
            "SOMEIP SD Option Error: The 'length' field of the option is zero (minimum valid size is 1)."
        );
        {
            let err = LenError {
                required_len: 4,
                layer: Layer::SdOption,
                len: 2,
                len_source: LenSource::Slice,
            };
            assert_eq!(format!("{}", &err), format!("{}", Len(err)));
        }
    }

    #[test]
    fn source() {
        use std::error::Error;

        assert!(OptionLengthZero.source().is_none());
        assert!(Len(LenError {
            required_len: 4,
            layer: Layer::SdOption,
            len: 2,
            len_source: LenSource::Slice,
        })
        .source()
        .is_some());
    }

    #[test]
    fn from_len_error() {
        let len_err = LenError {
            required_len: 4,
            layer: Layer::SdOption,
            len: 2,
            len_source: LenSource::Slice,
        };
        let err: SdOptionSliceError = len_err.clone().into();
        assert_eq!(err, Len(len_err));
    }
}
