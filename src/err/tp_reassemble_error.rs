#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TpReassembleError {
    /// Error if a payload lenght of a SOMEIP TP packet is not a multiple of 16
    /// and the "more segments" flag is set.
    UnalignedTpPayloadLen { offset: u32, payload_len: usize },

    /// Error if a segment is bigger then the maximum allowed size.
    SegmentTooBig {
        offset: u32,
        payload_len: usize,
        max: u32,
    },

    /// Error if multiple TP segments were received with the "more segment"
    /// unset and differing end points.
    ConflictingEnd {
        /// Offset + tp_payload.len() of the previous package with "more segment" unset.
        previous_end: u32,

        /// Offset + tp_payload.len() of the current package.
        conflicting_end: u32,
    },

    /// Error if not enough memory could be allocated to store the TP payload.
    AllocationFailure { len: usize },
}

impl core::fmt::Display for TpReassembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TpReassembleError::*;
        match self {
            UnalignedTpPayloadLen{ offset, payload_len } => write!(f, "Payload length {payload_len} of SOMEIP TP segment (offset {offset}) is not a multiple of 16. This is only allowed for TP packets where the 'more segements' flag is not set."),
            SegmentTooBig{ offset, payload_len, max } => write!(f, "Overall length of TP segment (offset {offset}, payload len: {payload_len}) bigger then the maximum allowed size of {max}."),
            ConflictingEnd { previous_end, conflicting_end } => write!(f, "Received a TP package (offset + len: {conflicting_end}) which conflicts a package that previously set the end to {previous_end}."),
            AllocationFailure { len } => write!(f, "Faield to allocate {len} bytes of memory to reconstruct the SOMEIP TP packets."),
        }
    }
}

impl std::error::Error for TpReassembleError {}


#[cfg(test)]
mod tests {
    use super::TpReassembleError::*;

    #[test]
    fn debug() {
        let err = AllocationFailure{ len: 0 };
        let _ = format!("{err:?}");
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let err = AllocationFailure{ len: 0 };
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
        let tests = [
            (UnalignedTpPayloadLen { offset: 1, payload_len: 2 }, "Payload length 2 of SOMEIP TP segment (offset 1) is not a multiple of 16. This is only allowed for TP packets where the 'more segements' flag is not set."),
            (SegmentTooBig { offset: 1, payload_len: 2, max: 3, }, "Overall length of TP segment (offset 1, payload len: 2) bigger then the maximum allowed size of 3."),
            (ConflictingEnd { previous_end: 1, conflicting_end: 2, }, "Received a TP package (offset + len: 2) which conflicts a package that previously set the end to 1."),
            (AllocationFailure { len: 0 }, "Faield to allocate 0 bytes of memory to reconstruct the SOMEIP TP packets."),
        ];
        for test in tests {
            assert_eq!(format!("{}", test.0), test.1);
        }
    }

    #[test]
    fn source() {
        use std::error::Error;
        assert!(AllocationFailure{ len: 0 }.source().is_none());
    }
}
