
/// Error if the offset of the tp header is not a multiple of 16.
///
/// PRS_SOMEIP_00724: The Offset field shall transport the upper 28 bits of a
/// uint32. The lower 4 bits shall be always interpreted as 0.
/// Note: This means that the offset field can only transport offset values
/// that are multiples of 16 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TpOffsetNotMultipleOf16Error {
    pub bad_offset: u32,
}

impl core::fmt::Display for TpOffsetNotMultipleOf16Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error SOMEIP TP offset {} is not a multiple of 16 (this is required).", self.bad_offset)
    }
}

impl std::error::Error for TpOffsetNotMultipleOf16Error {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug() {
        let err = TpOffsetNotMultipleOf16Error{ bad_offset: 0 };
        let _ = format!("{err:?}");
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let err = TpOffsetNotMultipleOf16Error{ bad_offset: 0 };
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
            format!("{}", TpOffsetNotMultipleOf16Error{ bad_offset: 123 }),
            "Error SOMEIP TP offset 123 is not a multiple of 16 (this is required)."
        );
    }

    #[test]
    fn source() {
        use std::error::Error;
        assert!(TpOffsetNotMultipleOf16Error{ bad_offset: 123 }.source().is_none());
    }
}
