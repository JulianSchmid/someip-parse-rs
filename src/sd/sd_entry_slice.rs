use crate::err::SdReadError;
use crate::sd::entries::*;

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
    pub fn from_slice(slice: &'a [u8]) -> Result<(SdEntrySlice<'a>, &'a [u8]), SdReadError> {
        if slice.len() < ENTRY_LEN {
            return Err(SdReadError::UnexpectedEndOfSlice(ENTRY_LEN));
        }

        match slice[0] {
            0x00 | 0x01 => {
                let (s, rest) = ServiceEntrySlice::from_slice(slice)?;
                Ok((SdEntrySlice::Service(s), rest))
            }
            0x06 | 0x07 => {
                let (e, rest) = EventGroupEntrySlice::from_slice(slice)?;
                Ok((SdEntrySlice::Eventgroup(e), rest))
            }
            other => Err(SdReadError::UnknownSdServiceEntryType(other)),
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
        let (entry, rest) = SdEntrySlice::from_slice(&buf).unwrap();
        assert_eq!(rest.len(), 2);
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
        let (entry, rest) = SdEntrySlice::from_slice(&buf).unwrap();
        assert!(rest.is_empty());
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
        let (entry, rest) = SdEntrySlice::from_slice(&buf).unwrap();
        assert!(rest.is_empty());
        match entry {
            SdEntrySlice::Eventgroup(e) => {
                assert_eq!(e.entry_type(), EventGroupEntryType::Subscribe);
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
        let (entry, rest) = SdEntrySlice::from_slice(&buf).unwrap();
        assert_eq!(rest.len(), 3);
        match entry {
            SdEntrySlice::Eventgroup(e) => {
                assert_eq!(e.entry_type(), EventGroupEntryType::SubscribeAck);
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
        let (a, _) = SdEntrySlice::from_slice(&buf).unwrap();
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
            let (slice, rest) = SdEntrySlice::from_slice(&bytes).unwrap();
            assert!(rest.is_empty());
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
            let (slice, rest) = SdEntrySlice::from_slice(&bytes).unwrap();
            assert!(rest.is_empty());
            match slice {
                SdEntrySlice::Eventgroup(e) => assert_eq!(e.to_owned(), entry),
                _ => panic!("expected Eventgroup variant"),
            }
        }
    }
}
