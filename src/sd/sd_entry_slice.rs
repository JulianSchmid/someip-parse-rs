use crate::err::SdReadError;
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
    /// - [`SdReadError::UnexpectedEndOfSlice`] if `slice.len() < ENTRY_LEN`
    /// - [`SdReadError::UnknownSdServiceEntryType`] if the type byte is
    ///   not a recognised entry type
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<SdEntrySlice<'a>, SdReadError> {
        if slice.len() < ENTRY_LEN {
            return Err(SdReadError::UnexpectedEndOfSlice(ENTRY_LEN));
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
            other => return Err(SdReadError::UnknownSdServiceEntryType(other)),
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
    use super::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;

    #[test]
    fn from_slice_too_short() {
        let buf = [0u8; ENTRY_LEN - 1];
        assert!(matches!(
            SdEntrySlice::from_slice(&buf),
            Err(SdReadError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_empty() {
        assert!(matches!(
            SdEntrySlice::from_slice(&[]),
            Err(SdReadError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_unknown_type() {
        let mut buf = [0u8; ENTRY_LEN];
        buf[0] = 0xFF;
        assert!(matches!(
            SdEntrySlice::from_slice(&buf),
            Err(SdReadError::UnknownSdServiceEntryType(0xFF))
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
    fn service_accessors_delegate_to_service_entry_slice() {
        let mut buf = [0u8; ENTRY_LEN + 2];
        buf[0] = 0x01; // OfferService
        buf[1] = 0x12;
        buf[2] = 0x34;
        buf[3] = 0xAB;
        buf[4] = 0x56;
        buf[5] = 0x78;
        buf[6] = 0x9A;
        buf[7] = 0xBC;
        buf[8] = 0xDE;
        buf[9] = 0x01;
        buf[10] = 0x23;
        buf[11] = 0x45;
        buf[12] = 0x67;
        buf[13] = 0x89;
        buf[14] = 0xAB;
        buf[15] = 0xCD;
        buf[16] = 0xEE;
        buf[17] = 0xFF;

        let entry = SdEntrySlice::from_slice(&buf).unwrap();

        assert_eq!(entry.slice(), &buf[..ENTRY_LEN]);
        assert_eq!(entry.number_of_options_1(), U4::N10);
        assert_eq!(entry.number_of_options_2(), U4::N11);
        assert_eq!(entry.service_id(), 0x5678);
        assert_eq!(entry.instance_id(), 0x9ABC);
        assert_eq!(entry.major_version(), 0xDE);
        assert_eq!(entry.ttl(), unsafe { U24::new_unchecked(0x012345) });
        assert_eq!(
            entry.to_owned(),
            SdEntry::Service(ServiceEntry {
                entry_type: SdServiceEntryType::OfferService,
                start_index_options_1: 0x12,
                start_index_options_2: 0x34,
                number_of_options_1: U4::N10,
                number_of_options_2: U4::N11,
                service_id: 0x5678,
                instance_id: 0x9ABC,
                major_version: 0xDE,
                ttl: unsafe { U24::new_unchecked(0x012345) },
                minor_version: 0x6789ABCD,
            })
        );
    }

    #[test]
    fn eventgroup_accessors_delegate_to_eventgroup_entry_slice() {
        let mut buf = [0u8; ENTRY_LEN + 3];
        buf[0] = 0x07; // SubscribeAck
        buf[1] = 0x11;
        buf[2] = 0x22;
        buf[3] = 0xCD;
        buf[4] = 0x33;
        buf[5] = 0x44;
        buf[6] = 0x55;
        buf[7] = 0x66;
        buf[8] = 0x77;
        buf[9] = 0x89;
        buf[10] = 0xAB;
        buf[11] = 0xCD;
        buf[12] = 0x00;
        buf[13] = 0x8E;
        buf[14] = 0x12;
        buf[15] = 0x34;
        buf[16] = 0xAA;
        buf[17] = 0xBB;
        buf[18] = 0xCC;

        let entry = SdEntrySlice::from_slice(&buf).unwrap();

        assert_eq!(entry.slice(), &buf[..ENTRY_LEN]);
        assert_eq!(entry.number_of_options_1(), U4::N12);
        assert_eq!(entry.number_of_options_2(), U4::N13);
        assert_eq!(entry.service_id(), 0x3344);
        assert_eq!(entry.instance_id(), 0x5566);
        assert_eq!(entry.major_version(), 0x77);
        assert_eq!(entry.ttl(), unsafe { U24::new_unchecked(0x89ABCD) });
        assert_eq!(
            entry.to_owned(),
            SdEntry::Eventgroup(EventGroupEntry {
                entry_type: EventGroupEntryType::SubscribeAckOrNack,
                index_first_option_run: 0x11,
                index_second_option_run: 0x22,
                number_of_options_1: U4::N12,
                number_of_options_2: U4::N13,
                service_id: 0x3344,
                instance_id: 0x5566,
                major_version: 0x77,
                ttl: unsafe { U24::new_unchecked(0x89ABCD) },
                initial_data_requested: true,
                counter: U4::N14,
                eventgroup_id: 0x1234,
            })
        );
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
}
