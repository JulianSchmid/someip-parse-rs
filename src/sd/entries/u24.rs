/// 24 bit unsigned integer (values 0 to 16_777_215).
///
/// Used for the `ttl` field in SOME/IP SD entries, which is encoded
/// as a 24 bit value on the wire.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U24(u32);

impl U24 {
    /// U24 with value 0.
    pub const ZERO: U24 = U24(0);

    /// Maximum value of a 24 bit unsigned integer.
    pub const MAX_U32: u32 = 0x00FF_FFFF;

    /// Tries to create a [`U24`] and checks that the passed value
    /// is smaller or equal than [`U24::MAX_U32`] (24 bit unsigned integer).
    ///
    /// In case the passed value is bigger than what can be represented in a 24 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`U24`].
    ///
    /// ```
    /// use someip_parse::sd::entries::U24;
    ///
    /// let v = U24::try_new(3600).unwrap();
    /// assert_eq!(v.value(), 3600);
    ///
    /// // if a number that can not be represented in a 24 bit integer
    /// // gets passed in an error is returned
    /// use someip_parse::sd::entries::U24TooLargeError;
    /// assert_eq!(
    ///     U24::try_new(U24::MAX_U32 + 1),
    ///     Err(U24TooLargeError{
    ///         actual: U24::MAX_U32 + 1,
    ///     })
    /// );
    /// ```
    #[inline]
    pub const fn try_new(value: u32) -> Result<U24, U24TooLargeError> {
        if value <= U24::MAX_U32 {
            Ok(U24(value))
        } else {
            Err(U24TooLargeError { actual: value })
        }
    }

    /// Creates a [`U24`] without checking that the value
    /// is smaller or equal than [`U24::MAX_U32`] (24 bit unsigned integer).
    /// The caller must guarantee that `value <= U24::MAX_U32`.
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`U24::MAX_U32`]
    /// otherwise the behavior of functions or data structures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u32) -> U24 {
        debug_assert!(value <= U24::MAX_U32);
        U24(value)
    }

    /// Returns the underlying unsigned 24 bit value as a `u32` value.
    #[inline]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for U24 {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<U24> for u32 {
    #[inline]
    fn from(value: U24) -> Self {
        value.0
    }
}

impl From<u16> for U24 {
    #[inline]
    fn from(value: u16) -> Self {
        U24(value as u32)
    }
}

impl From<u8> for U24 {
    #[inline]
    fn from(value: u8) -> Self {
        U24(value as u32)
    }
}

impl TryFrom<u32> for U24 {
    type Error = U24TooLargeError;

    #[inline]
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value <= U24::MAX_U32 {
            Ok(U24(value))
        } else {
            Err(U24TooLargeError { actual: value })
        }
    }
}

/// Error when a value provided to construct a [`U24`] exceeds
/// the maximum 24 bit unsigned integer value of 16_777_215.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U24TooLargeError {
    /// The value that was too large.
    pub actual: u32,
}

impl core::fmt::Display for U24TooLargeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "U24 value {} is too large (maximum is {})",
            self.actual,
            U24::MAX_U32
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::format;

    #[test]
    fn derived_traits() {
        // copy & clone
        {
            let a = U24(100);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // default
        {
            let actual: U24 = Default::default();
            assert_eq!(actual.value(), 0);
        }

        // debug
        {
            let a = U24(100);
            assert_eq!(format!("{:?}", a), format!("U24(100)"));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = U24(100);
            let b = a;
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                U24(100).hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                U24(100).hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }

    #[test]
    fn constants() {
        assert_eq!(U24::ZERO.value(), 0);
        assert_eq!(U24::MAX_U32, 0x00FF_FFFF);
    }

    proptest! {
        #[test]
        fn try_new(
            valid_value in 0..=0x00FF_FFFFu32,
            invalid_value in 0x0100_0000u32..=u32::MAX
        ) {
            assert_eq!(
                valid_value,
                U24::try_new(valid_value).unwrap().value()
            );
            assert_eq!(
                U24::try_new(invalid_value).unwrap_err(),
                U24TooLargeError {
                    actual: invalid_value,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn try_from(
            valid_value in 0..=0x00FF_FFFFu32,
            invalid_value in 0x0100_0000u32..=u32::MAX
        ) {
            // try_into
            {
                let actual: U24 = valid_value.try_into().unwrap();
                assert_eq!(actual.value(), valid_value);

                let err: Result<U24, U24TooLargeError> = invalid_value.try_into();
                assert_eq!(
                    err.unwrap_err(),
                    U24TooLargeError {
                        actual: invalid_value,
                    }
                );
            }
            // try_from
            {
                assert_eq!(
                    U24::try_from(valid_value).unwrap().value(),
                    valid_value
                );

                assert_eq!(
                    U24::try_from(invalid_value).unwrap_err(),
                    U24TooLargeError {
                        actual: invalid_value,
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_u16(value in any::<u16>()) {
            let u24: U24 = value.into();
            assert_eq!(u24.value(), value as u32);
        }
    }

    proptest! {
        #[test]
        fn from_u8(value in any::<u8>()) {
            let u24: U24 = value.into();
            assert_eq!(u24.value(), value as u32);
        }
    }

    proptest! {
        #[test]
        fn new_unchecked(valid_value in 0..=0x00FF_FFFFu32) {
            assert_eq!(
                valid_value,
                unsafe {
                    U24::new_unchecked(valid_value).value()
                }
            );
        }
    }

    proptest! {
        #[test]
        fn fmt(valid_value in 0..=0x00FF_FFFFu32) {
            assert_eq!(format!("{}", U24(valid_value)), format!("{}", valid_value));
        }
    }

    proptest! {
        #[test]
        fn from(valid_value in 0..=0x00FF_FFFFu32) {
            let v = U24::try_new(valid_value).unwrap();
            let actual: u32 = v.into();
            assert_eq!(actual, valid_value);
        }
    }

    #[test]
    fn error_display() {
        let err = U24TooLargeError {
            actual: 0x0100_0000,
        };
        assert_eq!(
            format!("{}", err),
            "U24 value 16777216 is too large (maximum is 16777215)"
        );
    }

    #[test]
    fn error_derived_traits() {
        // clone & eq
        {
            let a = U24TooLargeError {
                actual: 0x0100_0000,
            };
            assert_eq!(a, a.clone());
        }

        // debug
        {
            let a = U24TooLargeError {
                actual: 0x0100_0000,
            };
            assert_eq!(format!("{:?}", a), "U24TooLargeError { actual: 16777216 }");
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = U24TooLargeError {
                actual: 0x0100_0000,
            };
            let b = a.clone();
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                U24TooLargeError {
                    actual: 0x0100_0000,
                }
                .hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                U24TooLargeError {
                    actual: 0x0100_0000,
                }
                .hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }
}
