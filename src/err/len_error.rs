use crate::err::{Layer, LenSource};

/// Error when different lengths are conflicting with each other (e.g. not
/// enough data in a slice to decode a header).
///
/// This error is triggered whenever there is not enough data to decode
/// an element (e.g. if a slice is too small to decode an header) or
/// if a length that is inhered from an upper layer is too small for the
/// lower layer (e.g. length inherited from an SOMEIP header is too small to
/// to decode the SOMEIP TP header).
///
/// When the error is caused by not enough data beeing available
/// `required_len > len` must be true.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LenError {
    /// Expected minimum or maximum length conflicting with the
    /// `len` value.
    pub required_len: usize,

    /// Length limiting or exceeding the required length.
    pub len: usize,

    /// Source of the outer length (e.g. Slice or a length specified by
    /// an upper level protocol).
    pub len_source: LenSource,

    /// Layer in which the length error was encountered.
    pub layer: Layer,
}

impl core::fmt::Display for LenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len_source: &'static str = {
            use LenSource::*;
            match self.len_source {
                Slice => "slice length",
                SomeipHeaderLength => "length calculated from the SOMEIP header 'length' field",
            }
        };
        write!(
            f,
            "{}: Not enough data to decode '{}'. {} byte(s) would be required, but only {} byte(s) are available based on the {}.",
            self.layer.error_title(),
            self.layer,
            self.required_len,
            self.len,
            len_source
        )
    }
}

impl std::error::Error for LenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::Layer;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            format!(
                "{:?}",
                LenError {
                    required_len: 2,
                    layer: Layer::SomeipHeader,
                    len: 1,
                    len_source: LenSource::Slice,
                }
            ),
            format!(
                "LenError {{ required_len: {:?}, len: {:?}, len_source: {:?}, layer: {:?} }}",
                2,
                1,
                LenSource::Slice,
                Layer::SomeipHeader
            ),
        );
    }

    #[test]
    fn clone_eq_hash_ord() {
        let err = LenError {
            required_len: 2,
            layer: Layer::SomeipHeader,
            len: 1,
            len_source: LenSource::Slice,
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
        use core::cmp::Ordering;
        assert_eq!(Ordering::Equal, err.cmp(&err));
        assert_eq!(Some(Ordering::Equal), err.partial_cmp(&err));
    }

    #[test]
    fn fmt() {
        // len sources based tests (not enough data)
        {
            use LenSource::*;
            let len_source_tests = [
                (Slice, "SOMEIP Header Error: Not enough data to decode 'SOMEIP header'. 2 byte(s) would be required, but only 1 byte(s) are available based on the slice length."),
                (SomeipHeaderLength, "SOMEIP Header Error: Not enough data to decode 'SOMEIP header'. 2 byte(s) would be required, but only 1 byte(s) are available based on the length calculated from the SOMEIP header 'length' field."),
            ];

            for test in len_source_tests {
                assert_eq!(
                    test.1,
                    format!(
                        "{}",
                        LenError {
                            required_len: 2,
                            layer: Layer::SomeipHeader,
                            len: 1,
                            len_source: test.0,
                        }
                    )
                );
            }
        }
    }

    #[test]
    fn source() {
        assert!(LenError {
            required_len: 0,
            len: 0,
            len_source: LenSource::Slice,
            layer: Layer::SomeipHeader,
        }
        .source()
        .is_none());
    }
}
