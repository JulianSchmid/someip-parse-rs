use crate::err::SdReadError;
use crate::sd::entries::*;

/// Zero-copy reference to a serialized SOMEIP SD service entry.
///
/// The slice is guaranteed to contain exactly [`ENTRY_LEN`] bytes and
/// a valid [`SdServiceEntryType`] in byte 0.
///
/// Use the accessor methods to decode individual fields directly from
/// the underlying byte slice.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ServiceEntrySlice<'a> {
    slice: &'a [u8],
}

impl<'a> ServiceEntrySlice<'a> {
    /// Tries to create a [`ServiceEntrySlice`] from the beginning of `slice`.
    ///
    /// On success returns the entry slice and the remaining bytes after
    /// the entry.
    ///
    /// # Errors
    ///
    /// - [`SdReadError::UnexpectedEndOfSlice`] if `slice.len() < ENTRY_LEN`
    /// - [`SdReadError::UnknownSdServiceEntryType`] if byte 0 is not a
    ///   recognised [`SdServiceEntryType`] value
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<(Self, &'a [u8]), SdReadError> {
        if slice.len() < ENTRY_LEN {
            return Err(SdReadError::UnexpectedEndOfSlice(ENTRY_LEN));
        }

        match slice[0] {
            0x00 | 0x01 => {}
            other => return Err(SdReadError::UnknownSdServiceEntryType(other)),
        }

        Ok((
            ServiceEntrySlice {
                slice: &slice[..ENTRY_LEN],
            },
            &slice[ENTRY_LEN..],
        ))
    }

    /// Returns the underlying byte slice (exactly [`ENTRY_LEN`] bytes).
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the service entry type.
    #[inline]
    pub fn entry_type(&self) -> SdServiceEntryType {
        // SAFETY: validated during construction
        match self.slice[0] {
            0x00 => SdServiceEntryType::FindService,
            0x01 => SdServiceEntryType::OfferService,
            _ => unreachable!(),
        }
    }

    /// Returns the index into the options array for the first option run.
    #[inline]
    pub fn index_first_option_run(&self) -> u8 {
        self.slice[1]
    }

    /// Returns the index into the options array for the second option run.
    #[inline]
    pub fn index_second_option_run(&self) -> u8 {
        self.slice[2]
    }

    /// Returns the number of options in the first option run (4 bit value).
    #[inline]
    pub fn number_of_options_1(&self) -> U4 {
        // SAFETY: right-shifting a u8 by 4 guarantees value <= 0x0F
        unsafe { U4::new_unchecked(self.slice[3] >> 4) }
    }

    /// Returns the number of options in the second option run (4 bit value).
    #[inline]
    pub fn number_of_options_2(&self) -> U4 {
        // SAFETY: masking with 0x0F guarantees value <= 0x0F
        unsafe { U4::new_unchecked(self.slice[3] & 0x0F) }
    }

    /// Returns the service id.
    #[inline]
    pub fn service_id(&self) -> u16 {
        u16::from_be_bytes([self.slice[4], self.slice[5]])
    }

    /// Returns the instance id.
    #[inline]
    pub fn instance_id(&self) -> u16 {
        u16::from_be_bytes([self.slice[6], self.slice[7]])
    }

    /// Returns the major version.
    #[inline]
    pub fn major_version(&self) -> u8 {
        self.slice[8]
    }

    /// Returns the time to live (24 bit value).
    #[inline]
    pub fn ttl(&self) -> U24 {
        // SAFETY: leading byte is 0x00, so value is guaranteed to be <= 0x00FF_FFFF
        unsafe {
            U24::new_unchecked(u32::from_be_bytes([
                0x00,
                self.slice[9],
                self.slice[10],
                self.slice[11],
            ]))
        }
    }

    /// Returns the minor version.
    #[inline]
    pub fn minor_version(&self) -> u32 {
        u32::from_be_bytes([
            self.slice[12],
            self.slice[13],
            self.slice[14],
            self.slice[15],
        ])
    }

    /// Converts the slice into an owned [`ServiceEntry`].
    #[inline]
    pub fn to_owned(&self) -> ServiceEntry {
        ServiceEntry {
            _type: self.entry_type(),
            index_first_option_run: self.index_first_option_run(),
            index_second_option_run: self.index_second_option_run(),
            number_of_options_1: self.number_of_options_1(),
            number_of_options_2: self.number_of_options_2(),
            service_id: self.service_id(),
            instance_id: self.instance_id(),
            major_version: self.major_version(),
            ttl: self.ttl(),
            minor_version: self.minor_version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;

    #[test]
    fn from_slice_too_short() {
        let buf = [0u8; ENTRY_LEN - 1];
        assert!(matches!(
            ServiceEntrySlice::from_slice(&buf),
            Err(SdReadError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_unknown_type() {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0xFF;
        assert!(matches!(
            ServiceEntrySlice::from_slice(&buf),
            Err(SdReadError::UnknownSdServiceEntryType(0xFF))
        ));
    }

    #[test]
    fn from_slice_returns_remaining() {
        let mut buf = [0u8; ENTRY_LEN + 4];
        buf[0] = SdServiceEntryType::FindService as u8;
        let (_, rest) = ServiceEntrySlice::from_slice(&buf).unwrap();
        assert_eq!(rest.len(), 4);
    }

    proptest! {
        #[test]
        fn slice_accessors_match_owned(entry in someip_sd_service_entry_any()) {
            let bytes = entry.to_bytes();
            let (slice, rest) = ServiceEntrySlice::from_slice(&bytes).unwrap();
            assert!(rest.is_empty());

            assert_eq!(slice.entry_type(), entry._type);
            assert_eq!(slice.index_first_option_run(), entry.index_first_option_run);
            assert_eq!(slice.index_second_option_run(), entry.index_second_option_run);
            assert_eq!(slice.number_of_options_1(), entry.number_of_options_1);
            assert_eq!(slice.number_of_options_2(), entry.number_of_options_2);
            assert_eq!(slice.service_id(), entry.service_id);
            assert_eq!(slice.instance_id(), entry.instance_id);
            assert_eq!(slice.major_version(), entry.major_version);
            assert_eq!(slice.ttl(), entry.ttl);
            assert_eq!(slice.minor_version(), entry.minor_version);
        }
    }

    proptest! {
        #[test]
        fn to_owned_roundtrip(entry in someip_sd_service_entry_any()) {
            let bytes = entry.to_bytes();
            let (slice, _) = ServiceEntrySlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.to_owned(), entry);
        }
    }

    #[test]
    fn derived_traits() {
        let bytes = [0u8; ENTRY_LEN]; // type 0x00 = FindService
        let (a, _) = ServiceEntrySlice::from_slice(&bytes).unwrap();
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, a.clone());
        let _ = format!("{:?}", a);

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            a.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            b.hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }
}
