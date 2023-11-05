///Range errors in fields of the someip & tp header struct. These can occur when serializing or modifying an error.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdValueError {

    /// Counter value exceeds 4 bit
    CounterTooLarge(u8),

    /// TTL exceeds 24 bit
    TtlTooLarge(u32),

    /// A TTL of zero indicates stop offering of service entry.
    TtlZeroIndicatesStopOffering,

    /// Number of options 1 exceeds 4 bit
    NumberOfOption1TooLarge(u8),

    /// Number of options 2 exceeds 4 bit
    NumberOfOption2TooLarge(u8),

    /// An [`sd::SdOption::UnknownDiscardable`] option has been passed
    /// to the write function.
    ///
    /// [`sd::SdOption::UnknownDiscardable`] are only intended to be used
    /// in read and from_slice functions.
    SdUnknownDiscardableOption(u8),
}

#[cfg(test)]
mod tests {
    use super::SdValueError::*;

    #[test]
    fn debug() {
        let err = CounterTooLarge(0);
        let _ = format!("{err:?}");
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let err = CounterTooLarge(0);
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

}
