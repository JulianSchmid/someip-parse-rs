use super::*;

/// Error when not enough space is available in a slice
/// to write a packet or header to it.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SliceWriteSpaceError {
    /// Expected minimum length conflicting with the
    /// `actual_len` value.
    pub required_len: usize,

    /// Length limiting or exceeding the required length.
    pub len: usize,

    /// Layer in which could not be written to the slice.
    pub layer: Layer,
}

impl core::fmt::Display for SliceWriteSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Not enough space to write {} to slice. Needed {} byte(s), but only {} byte(s) were available.",
            self.layer,
            self.required_len,
            self.len,
        )
    }
}

impl std::error::Error for SliceWriteSpaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_write() {
        let _ = format!("{:?}", SliceWriteSpaceError{ required_len: 1, len: 0, layer: Layer::SomeipTpHeader });
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let err = SliceWriteSpaceError{ required_len: 1, len: 0, layer: Layer::SomeipTpHeader };
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
            format!("{}", SliceWriteSpaceError{ required_len: 4, len: 1, layer: Layer::SomeipTpHeader }),
            "Not enough space to write SOMEIP TP header to slice. Needed 4 byte(s), but only 1 byte(s) were available."
        );
    }

    #[test]
    fn source() {
        use std::error::Error;
        assert!(SliceWriteSpaceError{
            required_len: 4,
            len: 1,
            layer: Layer::SomeipTpHeader
        }.source()
        .is_none());
    }
}
