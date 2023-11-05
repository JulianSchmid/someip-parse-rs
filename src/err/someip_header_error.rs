///Errors that can occur when reading someip headers.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SomeipHeaderError {
    /// Error when the protocol version field contains a version that is not supported by this library (aka != SOMEIP_PROTOCOL_VERSION)
    UnsupportedProtocolVersion(u8),
    /// Error returned when a someip header has a value in the length field that is smaller then the rest of someip header itself (8 bytes).
    LengthFieldTooSmall(u32),
    /// Error when the message type field contains an unknown value
    UnknownMessageType(u8),
}

impl core::fmt::Display for SomeipHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SomeipHeaderError::*;
        match self {
            UnsupportedProtocolVersion(bad_version) => write!(f, "Unsupported protocol version '{bad_version}' found in SOMEIP header."),
            LengthFieldTooSmall(l) => write!(f, "Length '{l}' present in the SOMEIP header is smaller then the minimum allowed lenght of 8."),
            UnknownMessageType(t) => write!(f, "Unknown message type '{t}' found in SOMEIP header."),
        }
    }
}

impl std::error::Error for SomeipHeaderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let err = SomeipHeaderError::UnsupportedProtocolVersion(0);
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
    fn debug_write() {
        use SomeipHeaderError::*;
        let values = [
            UnsupportedProtocolVersion(0),
            LengthFieldTooSmall(0),
            UnknownMessageType(0),
        ];
        for value in values {
            let _ = format!("{:?}", value);
        }
    }

    #[test]
    fn fmt() {
        use SomeipHeaderError::*;
        let tests = [
            (UnsupportedProtocolVersion(123), "Unsupported protocol version '123' found in SOMEIP header."),
            (LengthFieldTooSmall(1), "Length '1' present in the SOMEIP header is smaller then the minimum allowed lenght of 8."),
            (UnknownMessageType(2), "Unknown message type '2' found in SOMEIP header."),
        ];
        for t in tests {
            assert_eq!(format!("{}", t.0), t.1);
        }
    }
}
