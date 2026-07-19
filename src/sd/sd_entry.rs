use crate::sd::{entries::*, *};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdEntry {
    /// SOMEIP service discovery entry for a service.
    Service(ServiceEntry),

    /// SOMEIP service discovery entry for an eventgroup.
    Eventgroup(EventGroupEntry),
}

impl From<ServiceEntry> for SdEntry {
    #[inline]
    fn from(e: ServiceEntry) -> Self {
        SdEntry::Service(e)
    }
}

impl From<EventGroupEntry> for SdEntry {
    #[inline]
    fn from(o: EventGroupEntry) -> Self {
        SdEntry::Eventgroup(o)
    }
}

impl<'a> From<SdEntrySlice<'a>> for SdEntry {
    #[inline]
    fn from(s: SdEntrySlice<'a>) -> Self {
        s.to_owned()
    }
}

impl SdEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new_service_entry(
        entry_type: SdServiceEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    ) -> Result<Self, SdValueError> {
        if number_of_options_1 > U4::MAX_U8 {
            Err(SdValueError::NumberOfOption1TooLarge(number_of_options_1))
        } else if number_of_options_2 > U4::MAX_U8 {
            Err(SdValueError::NumberOfOption2TooLarge(number_of_options_2))
        } else if ttl > U24::MAX_U32 {
            Err(SdValueError::TtlTooLarge(ttl))
        } else {
            Ok(Self::Service(ServiceEntry {
                entry_type,
                start_index_options_1: index_first_option_run,
                start_index_options_2: index_second_option_run,
                number_of_options_1: unsafe { U4::new_unchecked(number_of_options_1) },
                number_of_options_2: unsafe { U4::new_unchecked(number_of_options_2) },
                service_id,
                instance_id,
                major_version,
                ttl: unsafe { U24::new_unchecked(ttl) },
                minor_version,
            }))
        }
    }

    /// Find service instances. Only use when the state of the given service is unknown.
    /// * `service_id` - Set to 0xFFFF if all service instances should be returned.
    /// * `instance_id` - Set to 0xFFFF if all instances should be returned.
    /// * `major_version` - Set to 0xFF if any version should be returned.
    /// * `minor_version` - Set to 0xFFFF_FFFF if any version should be returned.
    /// * `ttl` - Ignored by receivers and retained only for backward compatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn new_find_service_entry(
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    ) -> Result<Self, SdValueError> {
        Self::new_service_entry(
            SdServiceEntryType::FindService,
            index_first_option_run,
            index_second_option_run,
            number_of_options_1,
            number_of_options_2,
            service_id,
            instance_id,
            major_version,
            ttl,
            minor_version,
        )
    }

    /// Create a service offer entry.
    ///
    /// # Errors:
    ///
    /// `ttl` must not be 0 as this indicates a "stop offering". If ttl
    /// 0 is passed [`SdValueError::TtlZeroIndicatesStopOffering`] as an error
    /// is returned.
    #[allow(clippy::too_many_arguments)]
    pub fn new_offer_service_entry(
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    ) -> Result<Self, SdValueError> {
        if ttl == 0 {
            Err(SdValueError::TtlZeroIndicatesStopOffering)
        } else {
            Self::new_service_entry(
                SdServiceEntryType::OfferService,
                index_first_option_run,
                index_second_option_run,
                number_of_options_1,
                number_of_options_2,
                service_id,
                instance_id,
                major_version,
                ttl,
                minor_version,
            )
        }
    }

    /// Stop offering a given service.
    #[allow(clippy::too_many_arguments)]
    pub fn new_stop_offer_service_entry(
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        minor_version: u32,
    ) -> Result<Self, SdValueError> {
        if number_of_options_1 > U4::MAX_U8 {
            Err(SdValueError::NumberOfOption1TooLarge(number_of_options_1))
        } else if number_of_options_2 > U4::MAX_U8 {
            Err(SdValueError::NumberOfOption2TooLarge(number_of_options_2))
        } else {
            Ok(Self::Service(ServiceEntry {
                entry_type: SdServiceEntryType::OfferService,
                start_index_options_1: index_first_option_run,
                start_index_options_2: index_second_option_run,
                number_of_options_1: unsafe { U4::new_unchecked(number_of_options_1) },
                number_of_options_2: unsafe { U4::new_unchecked(number_of_options_2) },
                service_id,
                instance_id,
                major_version,
                ttl: U24::ZERO,
                minor_version,
            }))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_eventgroup(
        entry_type: EventGroupEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        initial_data_requested: bool,
        counter: u8,
        eventgroup_id: u16,
    ) -> Result<Self, SdValueError> {
        if number_of_options_1 > U4::MAX_U8 {
            Err(SdValueError::NumberOfOption1TooLarge(number_of_options_1))
        } else if number_of_options_2 > U4::MAX_U8 {
            Err(SdValueError::NumberOfOption2TooLarge(number_of_options_2))
        } else if ttl > U24::MAX_U32 {
            Err(SdValueError::TtlTooLarge(ttl))
        } else if counter > U4::MAX_U8 {
            Err(SdValueError::CounterTooLarge(counter))
        } else {
            Ok(Self::Eventgroup(EventGroupEntry {
                entry_type,
                index_first_option_run,
                index_second_option_run,
                number_of_options_1: unsafe { U4::new_unchecked(number_of_options_1) },
                number_of_options_2: unsafe { U4::new_unchecked(number_of_options_2) },
                service_id,
                instance_id,
                major_version,
                ttl: unsafe { U24::new_unchecked(ttl) },
                initial_data_requested,
                counter: unsafe { U4::new_unchecked(counter) },
                eventgroup_id,
            }))
        }
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, SdIoReadError> {
        let mut entry_bytes: [u8; ENTRY_LEN] = [0; ENTRY_LEN];
        reader.read_exact(&mut entry_bytes)?;
        Ok(Self::from_bytes(entry_bytes)?)
    }

    /// Read an entry from a slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self, SdSliceError> {
        SdEntrySlice::from_slice(slice).map(|v| v.to_owned())
    }

    /// Read an entry from a byte array.
    #[inline]
    pub fn from_bytes(entry_bytes: [u8; ENTRY_LEN]) -> Result<Self, SdSliceError> {
        Self::from_slice(&entry_bytes)
    }

    /// Writes the eventgroup entry to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdIoWriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    ///Writes the eventgroup entry to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        match self {
            SdEntry::Eventgroup(e) => e.to_bytes(),
            SdEntry::Service(e) => e.to_bytes(),
        }
    }

    /// Length of the serialized header in bytes.
    pub fn header_len(&self) -> usize {
        4 * 4
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn write_read(service_entry in someip_sd_entry_any()) {

            //write
            let mut buffer = Vec::new();
            service_entry.write(&mut buffer).unwrap();

            //read
            let mut cursor = Cursor::new(&buffer);
            let result = SdEntry::read(&mut cursor).unwrap();
            assert_eq!(service_entry, result);
        }
    }

    #[test]
    fn from_impls_and_header_len() {
        let service = ServiceEntry {
            entry_type: SdServiceEntryType::OfferService,
            start_index_options_1: 0,
            start_index_options_2: 0,
            number_of_options_1: U4::ZERO,
            number_of_options_2: U4::ZERO,
            service_id: 0x1234,
            instance_id: 0x5678,
            major_version: 1,
            ttl: U24::try_new(3600).unwrap(),
            minor_version: 0,
        };
        let eventgroup = EventGroupEntry {
            entry_type: EventGroupEntryType::SubscribeOrStop,
            index_first_option_run: 0,
            index_second_option_run: 0,
            number_of_options_1: U4::ZERO,
            number_of_options_2: U4::ZERO,
            service_id: 0x1234,
            instance_id: 0x5678,
            major_version: 1,
            ttl: U24::try_new(3600).unwrap(),
            initial_data_requested: false,
            counter: U4::ZERO,
            eventgroup_id: 0x9abc,
        };

        // From<ServiceEntry> / From<EventGroupEntry>
        assert_eq!(
            SdEntry::from(service.clone()),
            SdEntry::Service(service.clone())
        );
        assert_eq!(
            SdEntry::from(eventgroup.clone()),
            SdEntry::Eventgroup(eventgroup.clone())
        );

        // From<SdEntrySlice>
        let bytes = SdEntry::Service(service.clone()).to_bytes();
        let slice = SdEntrySlice::from_slice(&bytes).unwrap();
        assert_eq!(SdEntry::from(slice), SdEntry::Service(service.clone()));

        // header_len is constant for both variants.
        assert_eq!(SdEntry::Service(service).header_len(), 16);
        assert_eq!(SdEntry::Eventgroup(eventgroup).header_len(), 16);
    }

    #[cfg(feature = "std")]
    #[test]
    fn service_entry_read_unknown_service_entry_type() {
        let mut buffer = [0x00; ENTRY_LEN];
        buffer[0] = 0xFF;
        let mut cursor = std::io::Cursor::new(buffer);
        let result = SdEntry::read(&mut cursor);
        assert_eq!(
            result.unwrap_err().content_error(),
            Some(SdError::UnknownSdServiceEntryType(0xFF))
        );
    }

    #[test]
    fn new_service_entry() {
        // ok
        {
            let result = SdEntry::new_service_entry(
                SdServiceEntryType::OfferService,
                0,
                0,
                0x0F,
                0x0F,
                0,
                0,
                0,
                0x00FF_FFFF,
                0,
            );
            assert!(result.is_ok());
        }
        // number_of_options_1 too large
        {
            let result = SdEntry::new_service_entry(
                SdServiceEntryType::OfferService,
                0,
                0,
                0x10,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            assert_eq!(result, Err(SdValueError::NumberOfOption1TooLarge(0x10)));
        }
        // number_of_options_2 too large
        {
            let result = SdEntry::new_service_entry(
                SdServiceEntryType::OfferService,
                0,
                0,
                0,
                0xFF,
                0,
                0,
                0,
                0,
                0,
            );
            assert_eq!(result, Err(SdValueError::NumberOfOption2TooLarge(0xFF)));
        }
        // ttl too large
        {
            let result = SdEntry::new_service_entry(
                SdServiceEntryType::OfferService,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0x0100_0000,
                0,
            );
            assert_eq!(result, Err(SdValueError::TtlTooLarge(0x0100_0000)));
        }
    }

    #[test]
    fn new_find_service_entry() {
        // ok
        {
            let result = SdEntry::new_find_service_entry(0, 0, 0, 0, 0, 0, 0, 1, 0);
            assert!(result.is_ok());
        }
        // TTL is unused for FindService and may be zero.
        {
            let result = SdEntry::new_find_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
            assert_eq!(result.unwrap().to_bytes()[9..12], [0, 0, 0]);
        }
        // ttl too large
        {
            let result = SdEntry::new_find_service_entry(0, 0, 0, 0, 0, 0, 0, 0xFFFF_FFFF, 0);
            assert_eq!(result, Err(SdValueError::TtlTooLarge(0xFFFF_FFFF)));
        }
        // number_of_options_1 too large
        {
            let result = SdEntry::new_find_service_entry(0, 0, 0x10, 0, 0, 0, 0, 1, 0);
            assert_eq!(result, Err(SdValueError::NumberOfOption1TooLarge(0x10)));
        }
        // number_of_options_2 too large
        {
            let result = SdEntry::new_find_service_entry(0, 0, 0, 0x10, 0, 0, 0, 1, 0);
            assert_eq!(result, Err(SdValueError::NumberOfOption2TooLarge(0x10)));
        }
    }

    #[test]
    fn new_offer_service_entry() {
        // ok
        {
            let result = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 1, 0);
            assert!(result.is_ok());
        }
        // zero ttl
        {
            let result = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
            assert_eq!(result, Err(SdValueError::TtlZeroIndicatesStopOffering));
        }
        // ttl too large
        {
            let result = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 0xFFFF_FFFF, 0);
            assert_eq!(result, Err(SdValueError::TtlTooLarge(0xFFFF_FFFF)));
        }
        // number_of_options_1 too large
        {
            let result = SdEntry::new_offer_service_entry(0, 0, 0x10, 0, 0, 0, 0, 1, 0);
            assert_eq!(result, Err(SdValueError::NumberOfOption1TooLarge(0x10)));
        }
        // number_of_options_2 too large
        {
            let result = SdEntry::new_offer_service_entry(0, 0, 0, 0x10, 0, 0, 0, 1, 0);
            assert_eq!(result, Err(SdValueError::NumberOfOption2TooLarge(0x10)));
        }
    }

    #[test]
    fn new_stop_offer_service_entry() {
        // ok
        {
            let result = SdEntry::new_stop_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 0);
            assert!(result.is_ok());
        }
        // number_of_options_1 too large
        {
            let result = SdEntry::new_stop_offer_service_entry(0, 0, 0x10, 0, 0, 0, 0, 0);
            assert_eq!(result, Err(SdValueError::NumberOfOption1TooLarge(0x10)));
        }
        // number_of_options_2 too large
        {
            let result = SdEntry::new_stop_offer_service_entry(0, 0, 0, 0x10, 0, 0, 0, 0);
            assert_eq!(result, Err(SdValueError::NumberOfOption2TooLarge(0x10)));
        }
    }

    #[test]
    fn new_eventgroup() {
        // ok
        {
            let result = SdEntry::new_eventgroup(
                EventGroupEntryType::SubscribeOrStop,
                0,
                0,
                0x0F,
                0x0F,
                0,
                0,
                0,
                0x00FF_FFFF,
                false,
                0x0F,
                0,
            );
            assert!(result.is_ok());
        }
        // number_of_options_1 too large
        {
            let result = SdEntry::new_eventgroup(
                EventGroupEntryType::SubscribeOrStop,
                0,
                0,
                0x10,
                0,
                0,
                0,
                0,
                0,
                false,
                0,
                0,
            );
            assert_eq!(result, Err(SdValueError::NumberOfOption1TooLarge(0x10)));
        }
        // number_of_options_2 too large
        {
            let result = SdEntry::new_eventgroup(
                EventGroupEntryType::SubscribeOrStop,
                0,
                0,
                0,
                0x10,
                0,
                0,
                0,
                0,
                false,
                0,
                0,
            );
            assert_eq!(result, Err(SdValueError::NumberOfOption2TooLarge(0x10)));
        }
        // ttl too large
        {
            let result = SdEntry::new_eventgroup(
                EventGroupEntryType::SubscribeOrStop,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0x0100_0000,
                false,
                0,
                0,
            );
            assert_eq!(result, Err(SdValueError::TtlTooLarge(0x0100_0000)));
        }
        // counter too large
        {
            let result = SdEntry::new_eventgroup(
                EventGroupEntryType::SubscribeOrStop,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                0x10,
                0,
            );
            assert_eq!(result, Err(SdValueError::CounterTooLarge(0x10)));
        }
    }
}
