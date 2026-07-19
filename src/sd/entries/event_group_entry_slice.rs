use crate::err::SdReadError;
use crate::sd::entries::*;

/// Zero-copy reference to a serialized SOMEIP SD eventgroup entry.
///
/// The slice is guaranteed to contain exactly [`ENTRY_LEN`] bytes and
/// a valid [`EventGroupEntryType`] in byte 0.
///
/// Use the accessor methods to decode individual fields directly from
/// the underlying byte slice.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct EventGroupEntrySlice<'a> {
    slice: &'a [u8],
}

impl<'a> EventGroupEntrySlice<'a> {
    /// Tries to create an [`EventGroupEntrySlice`] from the beginning of `slice`.
    ///
    /// On success returns the entry slice and the remaining bytes after
    /// the entry.
    ///
    /// # Errors
    ///
    /// - [`SdReadError::UnexpectedEndOfSlice`] if `slice.len() < ENTRY_LEN`
    /// - [`SdReadError::UnknownSdEventGroupEntryType`] if byte 0 is not a
    ///   recognised [`EventGroupEntryType`] value
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<(Self, &'a [u8]), SdReadError> {
        if slice.len() < ENTRY_LEN {
            return Err(SdReadError::UnexpectedEndOfSlice(ENTRY_LEN));
        }

        match slice[0] {
            0x06 | 0x07 => {}
            other => return Err(SdReadError::UnknownSdEventGroupEntryType(other)),
        }

        Ok((
            EventGroupEntrySlice {
                // SAFETY: slice.len() >= ENTRY_LEN is checked above.
                slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), ENTRY_LEN) },
            },
            // SAFETY: slice.len() >= ENTRY_LEN is checked above.
            unsafe {
                core::slice::from_raw_parts(slice.as_ptr().add(ENTRY_LEN), slice.len() - ENTRY_LEN)
            },
        ))
    }

    /// Create an [`EventGroupEntrySlice`] from the beginning of `slice` without checking the length
    /// or if the type contains a valid field.
    ///
    /// # Safety
    ///
    /// - The caller must ensure that `slice` is at least [`ENTRY_LEN`] bytes long.
    /// - The caller must ensure that the type byte (index 0) is 0x06 or 0x07.
    ///
    /// Undefined behavior will occur if these conditions are not met.
    #[inline]
    pub unsafe fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        debug_assert!(
            slice.len() >= ENTRY_LEN,
            "Slice must be at least {} bytes long but was {}",
            ENTRY_LEN,
            slice.len()
        );
        debug_assert!(
            matches!(slice[0], 0x06 | 0x07),
            "Slice must start with 0x06 or 0x07 but was {}",
            slice[0]
        );
        EventGroupEntrySlice {
            slice: core::slice::from_raw_parts(slice.as_ptr(), ENTRY_LEN),
        }
    }

    /// Returns the underlying byte slice (exactly [`ENTRY_LEN`] bytes).
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the eventgroup entry type.
    #[inline]
    pub fn entry_type(&self) -> EventGroupEntryType {
        // SAFETY: validated during construction
        match self.slice[0] {
            0x06 => EventGroupEntryType::SubscribeOrStop,
            0x07 => EventGroupEntryType::SubscribeAckOrNack,
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

    /// Returns true if initial data shall be sent by the server.
    #[inline]
    pub fn initial_data_requested(&self) -> bool {
        0 != self.slice[13] & crate::sd::EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG
    }

    /// Returns the counter used to distinguish identical subscribe
    /// eventgroups of the same subscriber (4 bit value).
    #[inline]
    pub fn counter(&self) -> U4 {
        // SAFETY: masking with 0x0F guarantees value <= 0x0F
        unsafe { U4::new_unchecked(self.slice[13] & 0x0F) }
    }

    /// Returns the eventgroup id.
    #[inline]
    pub fn eventgroup_id(&self) -> u16 {
        u16::from_be_bytes([self.slice[14], self.slice[15]])
    }

    /// Converts the slice into an owned [`EventGroupEntry`].
    #[inline]
    pub fn to_owned(&self) -> EventGroupEntry {
        EventGroupEntry {
            entry_type: self.entry_type(),
            index_first_option_run: self.index_first_option_run(),
            index_second_option_run: self.index_second_option_run(),
            number_of_options_1: self.number_of_options_1(),
            number_of_options_2: self.number_of_options_2(),
            service_id: self.service_id(),
            instance_id: self.instance_id(),
            major_version: self.major_version(),
            ttl: self.ttl(),
            initial_data_requested: self.initial_data_requested(),
            counter: self.counter(),
            eventgroup_id: self.eventgroup_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;

    #[test]
    fn from_slice_too_short() {
        let buf = [0u8; ENTRY_LEN - 1];
        assert!(matches!(
            EventGroupEntrySlice::from_slice(&buf),
            Err(SdReadError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_unknown_type() {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0xFF;
        assert!(matches!(
            EventGroupEntrySlice::from_slice(&buf),
            Err(SdReadError::UnknownSdEventGroupEntryType(0xFF))
        ));
    }

    #[test]
    fn from_slice_rejects_service_types() {
        for &typ in &[0x00u8, 0x01] {
            let mut buf = [0u8; ENTRY_LEN];
            buf[0] = typ;
            assert!(matches!(
                EventGroupEntrySlice::from_slice(&buf),
                Err(SdReadError::UnknownSdEventGroupEntryType(_))
            ));
        }
    }

    #[test]
    fn from_slice_returns_remaining() {
        let mut buf = [0u8; ENTRY_LEN + 4];
        buf[0] = EventGroupEntryType::SubscribeOrStop as u8;
        let (_, rest) = EventGroupEntrySlice::from_slice(&buf).unwrap();
        assert_eq!(rest.len(), 4);
    }

    proptest! {
        #[test]
        fn slice_accessors_match_owned(entry in someip_sd_eventgroup_entry_any()) {
            let bytes = entry.to_bytes();
            let (slice, rest) = EventGroupEntrySlice::from_slice(&bytes).unwrap();
            assert!(rest.is_empty());

            assert_eq!(slice.entry_type(), entry.entry_type);
            assert_eq!(slice.index_first_option_run(), entry.index_first_option_run);
            assert_eq!(slice.index_second_option_run(), entry.index_second_option_run);
            assert_eq!(slice.number_of_options_1(), entry.number_of_options_1);
            assert_eq!(slice.number_of_options_2(), entry.number_of_options_2);
            assert_eq!(slice.service_id(), entry.service_id);
            assert_eq!(slice.instance_id(), entry.instance_id);
            assert_eq!(slice.major_version(), entry.major_version);
            assert_eq!(slice.ttl(), entry.ttl);
            assert_eq!(slice.initial_data_requested(), entry.initial_data_requested);
            assert_eq!(slice.counter(), entry.counter);
            assert_eq!(slice.eventgroup_id(), entry.eventgroup_id);
        }
    }

    proptest! {
        #[test]
        fn to_owned_roundtrip(entry in someip_sd_eventgroup_entry_any()) {
            let bytes = entry.to_bytes();
            let (slice, _) = EventGroupEntrySlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.to_owned(), entry);
        }
    }

    #[test]
    fn derived_traits() {
        let mut bytes = [0u8; ENTRY_LEN];
        bytes[0] = 0x06; // Subscribe
        let (a, _) = EventGroupEntrySlice::from_slice(&bytes).unwrap();
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
