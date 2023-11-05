use super::*;

/// Error when decoding an SOMEIP header & payload from a slice.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SomeipSliceError {
    /// Error when an length error is encountered (e.g. unexpected
    /// end of slice).
    Len(LenError),

    /// Error caused by the contents of the header.
    Content(SomeipHeaderError),
}

impl core::fmt::Display for SomeipSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SomeipSliceError::*;
        match self {
            Len(err) => err.fmt(f),
            Content(value) => value.fmt(f),
        }
    }
}

impl std::error::Error for SomeipSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SomeipSliceError::*;
        match self {
            Len(err) => Some(err),
            Content(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SomeipSliceError::*, *};

    #[test]
    fn debug() {
        let err = SomeipHeaderError::UnsupportedProtocolVersion(5);
        assert_eq!(
            format!("Content({:?})", err.clone()),
            format!("{:?}", Content(err))
        );
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let err = Content(SomeipHeaderError::UnsupportedProtocolVersion(5));
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
        {
            let err = LenError {
                required_len: 1,
                layer: Layer::SomeipHeader,
                len: 2,
                len_source: LenSource::Slice,
            };
            assert_eq!(format!("{}", &err), format!("{}", Len(err)));
        }
        {
            let err = SomeipHeaderError::UnsupportedProtocolVersion(6);
            assert_eq!(format!("{}", &err), format!("{}", Content(err.clone())));
        }
    }

    #[test]
    fn source() {
        use std::error::Error;

        assert!(Len(LenError {
            required_len: 1,
            layer: Layer::SomeipHeader,
            len: 2,
            len_source: LenSource::Slice,
        })
        .source()
        .is_some());
        assert!(Content(SomeipHeaderError::UnsupportedProtocolVersion(6))
            .source()
            .is_some());
    }
}
