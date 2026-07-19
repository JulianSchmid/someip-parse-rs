use crate::err::{self, Layer, LenSource};

/// A zero-copy reference to an unknown SD option's payload.
///
/// This type is returned by [`super::super::SdOptionSlice::from_slice`]
/// when the option type is not recognized. Use [`UnknownSlice::discardable`]
/// to check whether the option may safely be ignored.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnknownSlice<'a> {
    option_type: u8,
    slice: &'a [u8],
}

impl<'a> UnknownSlice<'a> {
    /// Creates a new `UnknownSlice` from the given option type and payload
    /// slice (the `length` bytes starting at the reserved/discardable byte).
    ///
    /// Returns an error if `slice` is empty (at least 1 byte is required
    /// for the reserved/discardable byte).
    #[inline]
    pub fn new(option_type: u8, slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.is_empty() {
            return Err(err::LenError {
                required_len: 1,
                len: 0,
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            });
        }
        Ok(Self { option_type, slice })
    }

    /// Creates a new `UnknownSlice` without checking that `slice` is
    /// non-empty.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `slice` is non-empty (at least 1 byte
    /// for the reserved/discardable byte). Violating this causes undefined
    /// behavior when accessor methods like [`discardable`](Self::discardable)
    /// are called.
    #[inline]
    pub unsafe fn unchecked_new(option_type: u8, slice: &'a [u8]) -> Self {
        debug_assert!(
            !slice.is_empty(),
            "UnknownSlice requires at least 1 byte for the reserved/discardable byte"
        );
        Self { option_type, slice }
    }

    /// Raw option type value from the wire format.
    #[inline]
    pub fn option_type(&self) -> u8 {
        self.option_type
    }

    /// Returns `true` if the discardable flag is set in the reserved byte,
    /// meaning the receiver may safely ignore this option if not supported.
    #[inline]
    pub fn discardable(&self) -> bool {
        // SAFETY: new/unchecked_new guarantee slice.len() >= 1.
        0 != unsafe { *self.slice.get_unchecked(0) } & super::DISCARDABLE_FLAG
    }

    /// The raw payload slice (the `length` bytes starting at the
    /// reserved/discardable byte).
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

#[cfg(test)]
mod test {
    use alloc::format;

    use super::*;
    use crate::sd::options::DISCARDABLE_FLAG;

    #[test]
    fn new() {
        let payload = [DISCARDABLE_FLAG, 0x01, 0x02];
        let s = UnknownSlice::new(0xff, &payload).unwrap();
        assert_eq!(s.option_type(), 0xff);
        assert!(s.discardable());
        assert_eq!(s.slice(), &payload);

        let payload_nd = [0x00, 0x01, 0x02];
        let s = UnknownSlice::new(0xab, &payload_nd).unwrap();
        assert_eq!(s.option_type(), 0xab);
        assert!(!s.discardable());
        assert_eq!(s.slice(), &payload_nd);
    }

    #[test]
    fn new_empty_slice_error() {
        let err = UnknownSlice::new(0xff, &[]).unwrap_err();
        assert_eq!(err.required_len, 1);
        assert_eq!(err.len, 0);
        assert_eq!(err.len_source, LenSource::Slice);
        assert_eq!(err.layer, Layer::SdOption);
    }

    #[test]
    fn unchecked_new_and_accessors() {
        let payload = [DISCARDABLE_FLAG, 0x01, 0x02];
        let s = unsafe { UnknownSlice::unchecked_new(0xff, &payload) };
        assert_eq!(s.option_type(), 0xff);
        assert!(s.discardable());
        assert_eq!(s.slice(), &payload);

        let payload_nd = [0x00, 0x01, 0x02];
        let s = unsafe { UnknownSlice::unchecked_new(0xab, &payload_nd) };
        assert_eq!(s.option_type(), 0xab);
        assert!(!s.discardable());
        assert_eq!(s.slice(), &payload_nd);
    }

    #[test]
    #[should_panic(expected = "UnknownSlice requires at least 1 byte")]
    fn unchecked_new_empty_slice_panics_in_debug() {
        let _ = unsafe { UnknownSlice::unchecked_new(0xff, &[]) };
    }

    #[test]
    fn clone_eq_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let payload = [0x80, 0x01];
        let s = UnknownSlice::new(0xff, &payload).unwrap();
        assert_eq!(s, s.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            s.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn debug() {
        let payload = [0x00];
        let s = UnknownSlice::new(0x99, &payload).unwrap();
        let _ = format!("{:?}", s);
    }
}
