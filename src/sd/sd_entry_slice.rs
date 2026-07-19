use crate::err::{SdError, SdSliceError};
use crate::sd::{entries::*, SdEntry};

/// Zero-copy reference to a serialized SOMEIP SD entry.
///
/// Dispatches to [`ServiceEntrySlice`] or [`EventGroupEntrySlice`]
/// based on the entry type byte.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SdEntrySlice<'a> {
    /// A service entry (FindService or OfferService).
    Service(ServiceEntrySlice<'a>),

    /// An eventgroup entry (Subscribe or SubscribeAck).
    Eventgroup(EventGroupEntrySlice<'a>),
}

impl<'a> From<ServiceEntrySlice<'a>> for SdEntrySlice<'a> {
    #[inline]
    fn from(s: ServiceEntrySlice<'a>) -> Self {
        SdEntrySlice::Service(s)
    }
}

impl<'a> From<EventGroupEntrySlice<'a>> for SdEntrySlice<'a> {
    #[inline]
    fn from(e: EventGroupEntrySlice<'a>) -> Self {
        SdEntrySlice::Eventgroup(e)
    }
}

impl<'a> SdEntrySlice<'a> {
    /// Tries to decode the next SD entry from the beginning of `slice`.
    ///
    /// On success returns the entry and the remaining bytes after it.
    ///
    /// # Errors
    ///
    /// - [`SdSliceError::UnexpectedEndOfSlice`] if `slice.len() < ENTRY_LEN`
    /// - [`SdError::UnknownSdServiceEntryType`] if the type byte is
    ///   not a recognised entry type
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<SdEntrySlice<'a>, SdSliceError> {
        if slice.len() < ENTRY_LEN {
            return Err(SdSliceError::UnexpectedEndOfSlice(ENTRY_LEN));
        }

        Ok(match slice[0] {
            0x00 | 0x01 => SdEntrySlice::Service(
                // SAFETY: slice.len() >= ENTRY_LEN is checked above & type byte is 0x00 or 0x01.
                unsafe { ServiceEntrySlice::from_slice_unchecked(slice) },
            ),

            0x06 | 0x07 => SdEntrySlice::Eventgroup(
                // SAFETY: slice.len() >= ENTRY_LEN is checked above & type byte is 0x06 or 0x07.
                unsafe { EventGroupEntrySlice::from_slice_unchecked(slice) },
            ),
            other => return Err(SdSliceError::Content(SdError::UnknownSdServiceEntryType(other))),
        })
    }

    /// Converts the slice into an owned [`SdEntry`].
    #[inline]
    pub fn to_owned(&self) -> SdEntry {
        match self {
            SdEntrySlice::Service(s) => SdEntry::Service(s.to_owned()),
            SdEntrySlice::Eventgroup(e) => SdEntry::Eventgroup(e.to_owned()),
        }
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        match self {
            SdEntrySlice::Service(s) => s.slice(),
            SdEntrySlice::Eventgroup(e) => e.slice(),
        }
    }

    /// Returns the ordinal index into the options array for the first
    /// option run.
    #[inline]
    pub fn start_index_options_1(&self) -> u8 {
        match self {
            SdEntrySlice::Service(s) => s.start_index_options_1(),
            SdEntrySlice::Eventgroup(e) => e.index_first_option_run(),
        }
    }

    /// Returns the ordinal index into the options array for the second
    /// option run.
    #[inline]
    pub fn start_index_options_2(&self) -> u8 {
        match self {
            SdEntrySlice::Service(s) => s.start_index_options_2(),
            SdEntrySlice::Eventgroup(e) => e.index_second_option_run(),
        }
    }

    #[inline]
    pub fn number_of_options_1(&self) -> U4 {
        match self {
            SdEntrySlice::Service(s) => s.number_of_options_1(),
            SdEntrySlice::Eventgroup(e) => e.number_of_options_1(),
        }
    }

    #[inline]
    pub fn number_of_options_2(&self) -> U4 {
        match self {
            SdEntrySlice::Service(s) => s.number_of_options_2(),
            SdEntrySlice::Eventgroup(e) => e.number_of_options_2(),
        }
    }

    #[inline]
    pub fn service_id(&self) -> u16 {
        match self {
            SdEntrySlice::Service(s) => s.service_id(),
            SdEntrySlice::Eventgroup(e) => e.service_id(),
        }
    }

    #[inline]
    pub fn instance_id(&self) -> u16 {
        match self {
            SdEntrySlice::Service(s) => s.instance_id(),
            SdEntrySlice::Eventgroup(e) => e.instance_id(),
        }
    }

    #[inline]
    pub fn major_version(&self) -> u8 {
        match self {
            SdEntrySlice::Service(s) => s.major_version(),
            SdEntrySlice::Eventgroup(e) => e.major_version(),
        }
    }

    #[inline]
    pub fn ttl(&self) -> U24 {
        match self {
            SdEntrySlice::Service(s) => s.ttl(),
            SdEntrySlice::Eventgroup(e) => e.ttl(),
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
            SdEntrySlice::from_slice(&buf),
            Err(SdSliceError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_empty() {
        assert!(matches!(
            SdEntrySlice::from_slice(&[]),
            Err(SdSliceError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_unknown_type() {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0xFF;
        assert!(matches!(
            SdEntrySlice::from_slice(&buf),
            Err(SdSliceError::Content(SdError::UnknownSdServiceEntryType(0xFF)))
        ));
    }

    #[test]
    fn from_slice_service_find() {
        let mut buf = [0u8; ENTRY_LEN + 2];
        buf[0] = 0x00; // FindService
        buf[4] = 0x12;
        buf[5] = 0x34;
        let entry = SdEntrySlice::from_slice(&buf).unwrap();
        match entry {
            SdEntrySlice::Service(s) => {
                assert_eq!(s.entry_type(), SdServiceEntryType::FindService);
                assert_eq!(s.service_id(), 0x1234);
            }
            _ => panic!("expected Service"),
        }
    }

    #[test]
    fn from_slice_service_offer() {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0x01; // OfferService
        buf[6] = 0xAB;
        buf[7] = 0xCD;
        let entry = SdEntrySlice::from_slice(&buf).unwrap();
        match entry {
            SdEntrySlice::Service(s) => {
                assert_eq!(s.entry_type(), SdServiceEntryType::OfferService);
                assert_eq!(s.instance_id(), 0xABCD);
            }
            _ => panic!("expected Service"),
        }
    }

    #[test]
    fn from_slice_eventgroup_subscribe() {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0x06; // Subscribe
        buf[4] = 0xAB;
        buf[5] = 0xCD;
        let entry = SdEntrySlice::from_slice(&buf).unwrap();
        match entry {
            SdEntrySlice::Eventgroup(e) => {
                assert_eq!(e.entry_type(), EventGroupEntryType::SubscribeOrStop);
                assert_eq!(e.service_id(), 0xABCD);
            }
            _ => panic!("expected Eventgroup"),
        }
    }

    #[test]
    fn from_slice_eventgroup_subscribe_ack() {
        let mut buf = [0u8; ENTRY_LEN + 3];
        buf[0] = 0x07; // SubscribeAck
        buf[14] = 0x00;
        buf[15] = 0x42;
        let entry = SdEntrySlice::from_slice(&buf).unwrap();
        match entry {
            SdEntrySlice::Eventgroup(e) => {
                assert_eq!(e.entry_type(), EventGroupEntryType::SubscribeAckOrNack);
                assert_eq!(e.eventgroup_id(), 0x0042);
            }
            _ => panic!("expected Eventgroup"),
        }
    }

    #[test]
    fn from_implementations() {
        let buf = [0u8; ENTRY_LEN]; // type 0x00 = FindService
        let (service_slice, _) = ServiceEntrySlice::from_slice(&buf).unwrap();
        let entry: SdEntrySlice = service_slice.into();
        assert!(matches!(entry, SdEntrySlice::Service(_)));

        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0x06; // Subscribe
        let (eg_slice, _) = EventGroupEntrySlice::from_slice(&buf).unwrap();
        let entry: SdEntrySlice = eg_slice.into();
        assert!(matches!(entry, SdEntrySlice::Eventgroup(_)));
    }

    #[test]
    fn derived_traits() {
        let buf = [0u8; ENTRY_LEN]; // type 0x00 = FindService
        let a = SdEntrySlice::from_slice(&buf).unwrap();
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

    proptest! {
        #[test]
        fn roundtrip_service(entry in someip_sd_service_entry_any()) {
            let bytes = entry.to_bytes();
            let slice = SdEntrySlice::from_slice(&bytes).unwrap();
            match slice {
                SdEntrySlice::Service(s) => assert_eq!(s.to_owned(), entry),
                _ => panic!("expected Service variant"),
            }
        }
    }

    proptest! {
        #[test]
        fn roundtrip_eventgroup(entry in someip_sd_eventgroup_entry_any()) {
            let bytes = entry.to_bytes();
            let slice = SdEntrySlice::from_slice(&bytes).unwrap();
            match slice {
                SdEntrySlice::Eventgroup(e) => assert_eq!(e.to_owned(), entry),
                _ => panic!("expected Eventgroup variant"),
            }
        }
    }

    proptest! {
        #[test]
        fn service_accessors_and_to_owned(
            entry in someip_sd_service_entry_any(),
            trailing in proptest::collection::vec(any::<u8>(), 0..8),
        ) {
            let mut bytes = entry.to_bytes().to_vec();
            bytes.extend_from_slice(&trailing);

            let slice = SdEntrySlice::from_slice(&bytes).unwrap();

            prop_assert_eq!(slice.slice(), &bytes[..ENTRY_LEN]);
            prop_assert_eq!(slice.number_of_options_1(), entry.number_of_options_1);
            prop_assert_eq!(slice.number_of_options_2(), entry.number_of_options_2);
            prop_assert_eq!(slice.service_id(), entry.service_id);
            prop_assert_eq!(slice.instance_id(), entry.instance_id);
            prop_assert_eq!(slice.major_version(), entry.major_version);
            prop_assert_eq!(slice.ttl(), entry.ttl);
            prop_assert_eq!(slice.to_owned(), SdEntry::Service(entry));
        }
    }

    proptest! {
        #[test]
        fn eventgroup_accessors_and_to_owned(
            entry in someip_sd_eventgroup_entry_any(),
            trailing in proptest::collection::vec(any::<u8>(), 0..8),
        ) {
            let mut bytes = entry.to_bytes().to_vec();
            bytes.extend_from_slice(&trailing);

            let slice = SdEntrySlice::from_slice(&bytes).unwrap();

            prop_assert_eq!(slice.slice(), &bytes[..ENTRY_LEN]);
            prop_assert_eq!(slice.number_of_options_1(), entry.number_of_options_1);
            prop_assert_eq!(slice.number_of_options_2(), entry.number_of_options_2);
            prop_assert_eq!(slice.service_id(), entry.service_id);
            prop_assert_eq!(slice.instance_id(), entry.instance_id);
            prop_assert_eq!(slice.major_version(), entry.major_version);
            prop_assert_eq!(slice.ttl(), entry.ttl);
            prop_assert_eq!(slice.to_owned(), SdEntry::Eventgroup(entry));
        }
    }
}
