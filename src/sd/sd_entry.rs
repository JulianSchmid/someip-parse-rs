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

impl SdEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new_service_entry(
        entry_type: SdServiceEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: U4Bits,
        number_of_options_2: U4Bits,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    ) -> Result<Self, SdValueError> {
        if ttl > 0x00FF_FFFF {
            Err(SdValueError::TtlTooLarge(ttl))
        } else {
            Ok(Self::Service(ServiceEntry {
                _type: entry_type,
                index_first_option_run,
                index_second_option_run,
                number_of_options_1,
                number_of_options_2,
                service_id,
                instance_id,
                major_version,
                ttl,
                minor_version,
            }))
        }
    }

    /// Find service instances. Only use when the state of the given service is unknown.
    /// * `service_id` - Set to 0xFFFF if all service instances should be returned.
    /// * `instance_id` - Set to 0xFFFF if all instances should be returned.
    /// * `major_version` - Set to 0xFF if any version should be returned.
    /// * `minor_version` - Set to 0xFFFF_FFFF if any version should be returned.
    /// * `ttl` - Must not be 0 as this indicates a "stop offering".
    #[allow(clippy::too_many_arguments)]
    pub fn new_find_service_entry(
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: U4Bits,
        number_of_options_2: U4Bits,
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
    }

    /// Createa a service offer entry.
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
        number_of_options_1: U4Bits,
        number_of_options_2: U4Bits,
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
        number_of_options_1: U4Bits,
        number_of_options_2: U4Bits,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        minor_version: u32,
    ) -> Result<Self, SdValueError> {
        Self::new_service_entry(
            SdServiceEntryType::OfferService,
            index_first_option_run,
            index_second_option_run,
            number_of_options_1,
            number_of_options_2,
            service_id,
            instance_id,
            major_version,
            0x00,
            minor_version,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_eventgroup(
        entry_type: EventGroupEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: U4Bits,
        number_of_options_2: U4Bits,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        initial_data_requested: bool,
        counter: U4Bits,
        eventgroup_id: u16,
    ) -> Result<Self, SdValueError> {
        if ttl > 0x00FF_FFFF {
            Err(SdValueError::TtlTooLarge(ttl))
        } else {
            Ok(Self::Eventgroup(EventGroupEntry {
                entry_type,
                index_first_option_run,
                index_second_option_run,
                number_of_options_1,
                number_of_options_2,
                service_id,
                instance_id,
                major_version,
                ttl,
                initial_data_requested,
                counter,
                eventgroup_id,
            }))
        }
    }

    #[inline]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, SdReadError> {
        let mut entry_bytes: [u8; ENTRY_LEN] = [0; ENTRY_LEN];
        reader.read_exact(&mut entry_bytes)?;

        let _type_raw = entry_bytes[0];
        match _type_raw {
            0x00 => Self::read_service(SdServiceEntryType::FindService, entry_bytes),
            0x01 => Self::read_service(SdServiceEntryType::OfferService, entry_bytes),
            0x06 => Self::read_entry_group(EventGroupEntryType::Subscribe, entry_bytes),
            0x07 => Self::read_entry_group(EventGroupEntryType::SubscribeAck, entry_bytes),
            _ => Err(SdReadError::UnknownSdServiceEntryType(_type_raw)),
        }
    }

    /// Read a service entry from a byte array.
    #[inline]
    pub fn read_service(
        _type: SdServiceEntryType,
        entry_bytes: [u8; ENTRY_LEN],
    ) -> Result<Self, SdReadError> {
        //return result
        Ok(Self::Service(ServiceEntry {
            _type,
            index_first_option_run: entry_bytes[1],
            index_second_option_run: entry_bytes[2],
            // Safe: bit-shifted values are guaranteed to be <= 0x0F
            number_of_options_1: unsafe { U4Bits::new_unchecked(entry_bytes[3] >> 4) },
            number_of_options_2: unsafe { U4Bits::new_unchecked(entry_bytes[3] & 0x0F) },
            service_id: u16::from_be_bytes([entry_bytes[4], entry_bytes[5]]),
            instance_id: u16::from_be_bytes([entry_bytes[6], entry_bytes[7]]),
            major_version: entry_bytes[8],
            ttl: u32::from_be_bytes([0x00, entry_bytes[9], entry_bytes[10], entry_bytes[11]]),
            minor_version: u32::from_be_bytes([
                entry_bytes[12],
                entry_bytes[13],
                entry_bytes[14],
                entry_bytes[15],
            ]),
        }))
    }

    /// Read an entry group from byte array.
    #[inline]
    pub fn read_entry_group(
        _type: EventGroupEntryType,
        entry_bytes: [u8; ENTRY_LEN],
    ) -> Result<Self, SdReadError> {
        Ok(Self::Eventgroup(EventGroupEntry {
            entry_type: _type,
            index_first_option_run: entry_bytes[1],
            index_second_option_run: entry_bytes[2],
            // Safe: bit-shifted values are guaranteed to be <= 0x0F
            number_of_options_1: unsafe { U4Bits::new_unchecked(entry_bytes[3] >> 4) },
            number_of_options_2: unsafe { U4Bits::new_unchecked(entry_bytes[3] & 0x0F) },
            service_id: u16::from_be_bytes([entry_bytes[4], entry_bytes[5]]),
            instance_id: u16::from_be_bytes([entry_bytes[6], entry_bytes[7]]),
            major_version: entry_bytes[8],
            ttl: u32::from_be_bytes([0x00, entry_bytes[9], entry_bytes[10], entry_bytes[11]]),
            // skip reserved byte, TODO: should this be verified to be 0x00 ?
            initial_data_requested: 0 != entry_bytes[13] & EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG,
            // Safe: masked value is guaranteed to be <= 0x0F
            counter: unsafe { U4Bits::new_unchecked(entry_bytes[13] & 0x0F) },
            eventgroup_id: u16::from_be_bytes([entry_bytes[14], entry_bytes[15]]),
        }))
    }

    /// Writes the eventgroup entry to the given writer.
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdWriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    ///Writes the eventgroup entry to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        match self {
            SdEntry::Eventgroup(e) => {
                let mut result = [0x00; ENTRY_LEN];

                result[0] = e.entry_type as u8;
                result[1] = e.index_first_option_run;
                result[2] = e.index_second_option_run;
                result[3] = (e.number_of_options_1.value() << 4) | (e.number_of_options_2.value() & 0x0F);

                let service_id_bytes = e.service_id.to_be_bytes();
                result[4] = service_id_bytes[0];
                result[5] = service_id_bytes[1];

                let instance_id_bytes = e.instance_id.to_be_bytes();
                result[6] = instance_id_bytes[0];
                result[7] = instance_id_bytes[1];

                result[8] = e.major_version;

                let ttl_bytes = e.ttl.to_be_bytes();
                result[9] = ttl_bytes[1];
                result[10] = ttl_bytes[2];
                result[11] = ttl_bytes[3];

                // skip reserved byte, already initialized as 0x00
                if e.initial_data_requested {
                    result[13] |= EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG;
                }
                result[13] |= e.counter.value();

                let eventgroup_id_bytes = e.eventgroup_id.to_be_bytes();
                result[14] = eventgroup_id_bytes[0];
                result[15] = eventgroup_id_bytes[1];

                result
            }
            SdEntry::Service(e) => {
                let mut result = [0x00; ENTRY_LEN];

                result[0] = e._type as u8;
                result[1] = e.index_first_option_run;
                result[2] = e.index_second_option_run;
                result[3] = (e.number_of_options_1.value() << 4) | (e.number_of_options_2.value() & 0x0F);

                let service_id_bytes = e.service_id.to_be_bytes();
                result[4] = service_id_bytes[0];
                result[5] = service_id_bytes[1];

                let instance_id_bytes = e.instance_id.to_be_bytes();
                result[6] = instance_id_bytes[0];
                result[7] = instance_id_bytes[1];

                result[8] = e.major_version;

                let ttl_bytes = e.ttl.to_be_bytes();
                result[9] = ttl_bytes[1];
                result[10] = ttl_bytes[2];
                result[11] = ttl_bytes[3];

                let minor_version_bytes = e.minor_version.to_be_bytes();
                result[12] = minor_version_bytes[0];
                result[13] = minor_version_bytes[1];
                result[14] = minor_version_bytes[2];
                result[15] = minor_version_bytes[3];

                result
            }
        }
    }

    /// Length of the serialized header in bytes.
    pub fn header_len(&self) -> usize {
        4 * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;
    use std::io::Cursor;

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
    fn service_entry_read_unknown_service_entry_type() {
        use assert_matches::*;

        let mut buffer = [0x00; ENTRY_LEN];
        buffer[0] = 0xFF; // Unknown Type
        let mut cursor = std::io::Cursor::new(buffer);
        let result = SdEntry::read(&mut cursor);
        assert_matches!(result, Err(SdReadError::UnknownSdServiceEntryType(0xFF)));
    }

    #[test]
    fn new_service_entry_ttl_too_large() {
        use assert_matches::*;

        let result = SdEntry::new_service_entry(
            SdServiceEntryType::OfferService,
            0,
            0,
            U4Bits::ZERO,
            U4Bits::ZERO,
            0,
            0,
            0,
            0xFFFF_FFFF,
            0,
        );
        assert_matches!(result, Err(SdValueError::TtlTooLarge(0xFFFF_FFFF)));
    }

    #[test]
    fn new_service_find_service_entry_zero_ttl() {
        use assert_matches::*;

        let result =
            SdEntry::new_find_service_entry(0, 0, U4Bits::ZERO, U4Bits::ZERO, 0, 0, 0, 0, 0);
        assert_matches!(result, Err(SdValueError::TtlZeroIndicatesStopOffering));
    }

    #[test]
    fn new_service_offer_service_entry_zero_ttl() {
        use assert_matches::*;

        let result =
            SdEntry::new_offer_service_entry(0, 0, U4Bits::ZERO, U4Bits::ZERO, 0, 0, 0, 0, 0);
        assert_matches!(result, Err(SdValueError::TtlZeroIndicatesStopOffering));
    }
}
