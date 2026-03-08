/// 4 bit unsigned integer (values 0 to 15).
///
/// Used for fields like `number_of_options_1` and `number_of_options_2`
/// in SOME/IP SD entries, which are encoded as 4 bit values on the wire.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U4Bits(u8);

impl U4Bits {
    /// U4Bits with value 0.
    pub const ZERO: U4Bits = U4Bits(0);

    pub const N0: U4Bits = U4Bits(0);
    pub const N1: U4Bits = U4Bits(1);
    pub const N2: U4Bits = U4Bits(2);
    pub const N3: U4Bits = U4Bits(3);
    pub const N4: U4Bits = U4Bits(4);
    pub const N5: U4Bits = U4Bits(5);
    pub const N6: U4Bits = U4Bits(6);
    pub const N7: U4Bits = U4Bits(7);
    pub const N8: U4Bits = U4Bits(8);
    pub const N9: U4Bits = U4Bits(9);
    pub const N10: U4Bits = U4Bits(10);
    pub const N11: U4Bits = U4Bits(11);
    pub const N12: U4Bits = U4Bits(12);
    pub const N13: U4Bits = U4Bits(13);
    pub const N14: U4Bits = U4Bits(14);
    pub const N15: U4Bits = U4Bits(15);

    /// Maximum value of a 4 bit unsigned integer.
    pub const MAX_U8: u8 = 0b0000_1111;

    /// Tries to create a [`U4Bits`] and checks that the passed value
    /// is smaller or equal than [`U4Bits::MAX_U8`] (4 bit unsigned integer).
    ///
    /// In case the passed value is bigger than what can be represented in a 4 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`U4Bits`].
    ///
    /// ```
    /// use someip_parse::sd::entries::U4Bits;
    ///
    /// let v = U4Bits::try_new(10).unwrap();
    /// assert_eq!(v.value(), 10);
    ///
    /// // if a number that can not be represented in a 4 bit integer
    /// // gets passed in an error is returned
    /// use someip_parse::sd::entries::U4BitsTooLargeError;
    /// assert_eq!(
    ///     U4Bits::try_new(U4Bits::MAX_U8 + 1),
    ///     Err(U4BitsTooLargeError{
    ///         actual: U4Bits::MAX_U8 + 1,
    ///     })
    /// );
    /// ```
    #[inline]
    pub const fn try_new(value: u8) -> Result<U4Bits, U4BitsTooLargeError> {
        if value <= U4Bits::MAX_U8 {
            Ok(U4Bits(value))
        } else {
            Err(U4BitsTooLargeError { actual: value })
        }
    }

    /// Creates a [`U4Bits`] without checking that the value
    /// is smaller or equal than [`U4Bits::MAX_U8`] (4 bit unsigned integer).
    /// The caller must guarantee that `value <= U4Bits::MAX_U8`.
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`U4Bits::MAX_U8`]
    /// otherwise the behavior of functions or data structures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u8) -> U4Bits {
        debug_assert!(value <= U4Bits::MAX_U8);
        U4Bits(value)
    }

    /// Returns the underlying unsigned 4 bit value as an `u8` value.
    #[inline]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for U4Bits {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<U4Bits> for u8 {
    #[inline]
    fn from(value: U4Bits) -> Self {
        value.0
    }
}

impl TryFrom<u8> for U4Bits {
    type Error = U4BitsTooLargeError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= U4Bits::MAX_U8 {
            Ok(U4Bits(value))
        } else {
            Err(U4BitsTooLargeError { actual: value })
        }
    }
}

/// Error when a value provided to construct a [`U4Bits`] exceeds
/// the maximum 4 bit unsigned integer value of 15.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U4BitsTooLargeError {
    /// The value that was too large.
    pub actual: u8,
}

impl core::fmt::Display for U4BitsTooLargeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "U4Bits value {} is too large (maximum is {})",
            self.actual,
            U4Bits::MAX_U8
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
            let a = U4Bits(2);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // default
        {
            let actual: U4Bits = Default::default();
            assert_eq!(actual.value(), 0);
        }

        // debug
        {
            let a = U4Bits(2);
            assert_eq!(format!("{:?}", a), format!("U4Bits(2)"));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = U4Bits(2);
            let b = a;
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                U4Bits(2).hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                U4Bits(2).hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }

    #[test]
    fn constants() {
        assert_eq!(U4Bits::ZERO.value(), 0);
        assert_eq!(U4Bits::MAX_U8, 0b0000_1111);

        assert_eq!(U4Bits::N0.value(), 0);
        assert_eq!(U4Bits::N1.value(), 1);
        assert_eq!(U4Bits::N2.value(), 2);
        assert_eq!(U4Bits::N3.value(), 3);
        assert_eq!(U4Bits::N4.value(), 4);
        assert_eq!(U4Bits::N5.value(), 5);
        assert_eq!(U4Bits::N6.value(), 6);
        assert_eq!(U4Bits::N7.value(), 7);
        assert_eq!(U4Bits::N8.value(), 8);
        assert_eq!(U4Bits::N9.value(), 9);
        assert_eq!(U4Bits::N10.value(), 10);
        assert_eq!(U4Bits::N11.value(), 11);
        assert_eq!(U4Bits::N12.value(), 12);
        assert_eq!(U4Bits::N13.value(), 13);
        assert_eq!(U4Bits::N14.value(), 14);
        assert_eq!(U4Bits::N15.value(), 15);
    }

    proptest! {
        #[test]
        fn try_new(
            valid_value in 0..=0b0000_1111u8,
            invalid_value in 0b0001_0000u8..=u8::MAX
        ) {
            assert_eq!(
                valid_value,
                U4Bits::try_new(valid_value).unwrap().value()
            );
            assert_eq!(
                U4Bits::try_new(invalid_value).unwrap_err(),
                U4BitsTooLargeError {
                    actual: invalid_value,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn try_from(
            valid_value in 0..=0b0000_1111u8,
            invalid_value in 0b0001_0000u8..=u8::MAX
        ) {
            // try_into
            {
                let actual: U4Bits = valid_value.try_into().unwrap();
                assert_eq!(actual.value(), valid_value);

                let err: Result<U4Bits, U4BitsTooLargeError> = invalid_value.try_into();
                assert_eq!(
                    err.unwrap_err(),
                    U4BitsTooLargeError {
                        actual: invalid_value,
                    }
                );
            }
            // try_from
            {
                assert_eq!(
                    U4Bits::try_from(valid_value).unwrap().value(),
                    valid_value
                );

                assert_eq!(
                    U4Bits::try_from(invalid_value).unwrap_err(),
                    U4BitsTooLargeError {
                        actual: invalid_value,
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn new_unchecked(valid_value in 0..=0b0000_1111u8) {
            assert_eq!(
                valid_value,
                unsafe {
                    U4Bits::new_unchecked(valid_value).value()
                }
            );
        }
    }

    proptest! {
        #[test]
        fn fmt(valid_value in 0..=0b0000_1111u8) {
            assert_eq!(format!("{}", U4Bits(valid_value)), format!("{}", valid_value));
        }
    }

    proptest! {
        #[test]
        fn from(valid_value in 0..=0b0000_1111u8) {
            let v = U4Bits::try_new(valid_value).unwrap();
            let actual: u8 = v.into();
            assert_eq!(actual, valid_value);
        }
    }

    #[test]
    fn error_display() {
        let err = U4BitsTooLargeError { actual: 16 };
        assert_eq!(
            format!("{}", err),
            "U4Bits value 16 is too large (maximum is 15)"
        );
    }

    #[test]
    fn error_derived_traits() {
        // clone & eq
        {
            let a = U4BitsTooLargeError { actual: 20 };
            assert_eq!(a, a.clone());
        }

        // debug
        {
            let a = U4BitsTooLargeError { actual: 20 };
            assert_eq!(format!("{:?}", a), "U4BitsTooLargeError { actual: 20 }");
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = U4BitsTooLargeError { actual: 20 };
            let b = a.clone();
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                U4BitsTooLargeError { actual: 20 }.hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                U4BitsTooLargeError { actual: 20 }.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }
}
