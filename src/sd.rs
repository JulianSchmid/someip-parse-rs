use crate::{ReadError, ValueError, WriteError};
use std::io::{Read, Write, Seek};

///Length of someip sd header, flags + reserved + entries length + options length
///excluding entries and options arrays
pub const MIN_SD_HEADER_LENGTH: usize = 1 + 3 + 4 + 4;

pub const EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG: u8 = 0b1000_0000;

/// Constants related to the flags in the sd header
pub mod flags {
    /// Reboot flag in the first byte of the sd header indicating
    /// that the session ids have not yet wrapped around since startup.
    pub const REBOOT_FLAG: u8 = 0b1000_0000;

    /// Unicast flag in the first byte of the sd header indicating
    /// that unicast is supported.
    ///
    /// # Note (from the SOMEIP SD specification):
    ///
    /// The Unicast Flag is left over from historical SOME/IP versions
    /// and is only kept for compatibility reasons. Its use besides this
    /// is very limited.
    pub const UNICAST_FLAG: u8 = 0b0100_0000;

    /// Explicit initial data control is supported.
    ///
    /// # Note:
    ///
    /// This flag has been removed in the release R21-11
    /// of the "SOME/IP Service Discovery Protocol Specification".
    pub const EXPLICIT_INITIAL_DATA_CONTROL_FLAG: u8 = 0b0010_0000;
}

/// Constants related to sd entries.
pub mod entries {
    /// Maximum entry length that is supported by the read & from slice functions.
    ///
    /// This constant is used to make sure no attacks with too large length
    /// values can trigger large allocations. E.g. if a some ip sd header
    /// with an entries length of 4 gigabytes gets passed to the `read` function
    /// it could triggering an allocation of 4 gigabytes. This allocation would then
    /// take a very long time or lead to a failure and potential crash.
    ///
    /// To prevent attacks like these the length gets checked against
    /// this constant before any allocation gets triggered.
    ///
    /// The maximum entry length is calculated from the fact that SOMEIP SD is
    /// only allowed via UDP and that the SOMEIP specification states the following
    /// conceirning the maximum payload size:
    ///
    /// > The size of the SOME/IP payload field depends on the transport protocol used.
    /// > With UDP the SOME/IP payload shall be between 0 and 1400 Bytes.
    ///
    /// With these facts we can calculcuate the maximum length of bytes
    /// the following way:
    ///
    /// `1400 - sd reserved & flags (4) - entries length(4) - options length(4)`
    ///
    /// For sd options array we assume an empty array.
    pub const MAX_ENTRIES_LEN: u32 = crate::SOMEIP_MAX_PAYLOAD_LEN_UDP - 4 - 4 - 4;

    /// Length of an sd entry (note that all entry types currently have
    /// the same length).
    pub const ENTRY_LEN: usize = 16;
}

/// Constants related to sd options.
pub mod options {
    use super::TransportProtocol;

    /// Maximum length of options array that is supported by the read & from slice functions.
    ///
    /// This constant is used to make sure no attacks with large length
    /// values can trigger large allocations. E.g. if a some ip sd header
    /// with an options array length of 4 gigabytes gets passed to the `read` function
    /// it could triggering an allocation of 4 gigabytes. This allocation would then
    /// take a very long time or lead to a failure and potential crash.
    ///
    /// To prevent attacks like these the length gets checked against
    /// this constant before any allocation gets triggered.
    ///
    /// The maximum entry length is calculated from the fact that SOMEIP SD is
    /// only allowed via UDP and that the SOMEIP specification states the following
    /// conceirning the maximum payload size:
    ///
    /// > The size of the SOME/IP payload field depends on the transport protocol used.
    /// > With UDP the SOME/IP payload shall be between 0 and 1400 Bytes.
    ///
    /// With these facts we can calculcuate the maximum length of bytes
    /// the following way:
    ///
    /// `1400 - sd reserved & flags (4) - entries length(4) - options length(4)`
    ///
    /// For the sd entries we assume an empty array.
    pub const MAX_OPTIONS_LEN: u32 = crate::SOMEIP_MAX_PAYLOAD_LEN_UDP - 4 - 4 - 4;

    /// Flag in the 4th byte (reserved) indicating that the option is allowed 
    /// to be discarded by the receiver if not supported.
    pub const DISCARDABLE_FLAG: u8 = 0b1000_0000;
    
    /// Value of the `type` field of a configuration sd option.
    pub const CONFIGURATION_TYPE: u8 = 0x01;

    /// Value of the `length` field of a load balancing sd option.
    pub const LOAD_BALANCING_LEN: u16 = 0x0005;

    /// Value of the `type` field of a load balancing sd option.
    pub const LOAD_BALANCING_TYPE: u8 = 0x02;

    /// Value of the `length` field of an ipv4 endpoint sd option.
    pub const IPV4_ENDPOINT_LEN: u16 = 0x0009;

    /// Value of the `type` field of an ipv4 endpoint sd option.
    pub const IPV4_ENDPOINT_TYPE: u8 = 0x04;

    /// Value of the `length` field of an ipv6 endpoint sd option.
    pub const IPV6_ENDPOINT_LEN: u16 = 0x0015;

    /// Value of the `type` field of an ipv6 endpoint sd option.
    pub const IPV6_ENDPOINT_TYPE: u8 = 0x06;

    /// Value of the `length` field of an ipv4 multicast sd option.
    pub const IPV4_MULTICAST_LEN: u16 = 0x0009;

    /// Value of the `type` field of an ipv4 multicast sd option.
    pub const IPV4_MULTICAST_TYPE: u8 = 0x14;

    /// Value of the `length` field of an ipv6 multicast sd option.
    pub const IPV6_MULTICAST_LEN: u16 = 0x0015;

    /// Value of the `type` field of an ipv6 multicast sd option.
    pub const IPV6_MULTICAST_TYPE: u8 = 0x16;

    /// Value of the `length` field of an ipv4 sd endpoint sd option.
    pub const IPV4_SD_ENDPOINT_LEN: u16 = 0x009;

    /// Value of the `type` field of an ipv4 sd endpoint sd option.
    pub const IPV4_SD_ENDPOINT_TYPE: u8 = 0x24;

    /// Value of the `length` field of an ipv6 sd endpoint sd option.
    pub const IPV6_SD_ENDPOINT_LEN: u16 = 0x0015;

    /// Value of the `type` field of an ipv6 sd endpoint sd option.
    pub const IPV6_SD_ENDPOINT_TYPE: u8 = 0x26;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ConfigurationOption {
        /// Shall be set to `true` if the option can be discarded by the receiver.
        pub discardable: bool,
        // TODO DNS TXT / DNS-SD format
        pub configuration_string: Vec<u8>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct LoadBalancingOption {
        /// Shall be set to `true` if the option can be discarded by the receiver.
        pub discardable: bool,
        pub priority: u16,
        pub weight: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv4EndpointOption {
        pub ipv4_address: [u8;4],
        pub transport_protocol: TransportProtocol,
        pub transport_protocol_number: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv6EndpointOption {
        pub ipv6_address: [u8;16],
        pub transport_protocol: TransportProtocol,
        pub transport_protocol_number: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv4MulticastOption {
        pub ipv4_address: [u8;4],
        pub transport_protocol: TransportProtocol,
        pub transport_protocol_number: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv6MulticastOption {
        pub ipv6_address: [u8;16],
        pub transport_protocol: TransportProtocol,
        pub transport_protocol_number: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv4SdEndpointOption {
        pub ipv4_address: [u8;4],
        pub transport_protocol: TransportProtocol,
        pub transport_protocol_number: u16,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv6SdEndpointOption {
        pub ipv6_address: [u8;16],
        pub transport_protocol: TransportProtocol,
        pub transport_protocol_number: u16,
    }

    /// An unknown option that is flagged as "discardable" and
    /// should be ignored by the receiver if not supported.
    ///
    /// This option is only intended to be used for reading,
    /// to ensure the option indices are still matching. In case
    /// this option is passed to a write function an error will be
    /// triggered.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct UnknownDiscardableOption {
        pub length: u16,
        pub option_type: u8,
    }
}

use self::options::*;

/// Flags at the start of a SOMEIP service discovery
/// header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdHeaderFlags {
    pub reboot: bool,
    pub unicast: bool,
    pub explicit_initial_data_control: bool,
}

impl Default for SdHeaderFlags {
    fn default() -> Self {
        SdHeaderFlags {
            reboot: false,
            // set unicast & explicit_initial_data_control to true
            // by default as they have to be supported by current someip
            // implementations by default.
            unicast: true,
            explicit_initial_data_control: true,
        }
    }
}

impl SdHeaderFlags {
    /// Returns the first 4 bytes of an SOMEIP SD header.
    pub fn to_bytes(&self) -> [u8;4] {
        use sd::flags::*;
        [
            if self.reboot {
                REBOOT_FLAG
            } else {
                0
            } | if self.unicast {
                UNICAST_FLAG
            } else {
                0
            } | if self.explicit_initial_data_control {
                EXPLICIT_INITIAL_DATA_CONTROL_FLAG
            } else {
                0
            },
            0,
            0,
            0,
        ]
    }
}

/// SOMEIP service discovery header
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SdHeader {
    pub flags: SdHeaderFlags,
    // reserved: [u8;3],
    // Length of entries array in bytes
    // length_of_entries: u32,
    pub entries: Vec<SdEntry>,
    // Length of entries array in bytes
    // length_of_options: u32,
    pub options: Vec<SdOption>,
}

impl SdHeader {
    #[inline]
    pub fn new(reboot: bool, entries: Vec<SdEntry>, options: Vec<SdOption>) -> Self {
        Self {
            flags: SdHeaderFlags {
                reboot,
                unicast: true,
                explicit_initial_data_control: true,
            },
            entries,
            options,
        }
    }

    #[inline]
    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, ReadError> {
        use sd::entries::*;
        use sd::options::*;
        
        const HEADER_LENGTH: usize = 1 + 3 + 4; // flags + rev + entries length
        let mut header_bytes: [u8; HEADER_LENGTH] = [0; HEADER_LENGTH];
        reader.read_exact(&mut header_bytes)?;

        let num_entries = {
            let length_entries = u32::from_be_bytes([
                header_bytes[4],
                header_bytes[5],
                header_bytes[6],
                header_bytes[7],
            ]);

            if length_entries > MAX_ENTRIES_LEN {
                return Err(
                    ReadError::SdEntriesArrayLengthTooLarge(length_entries)
                );
            }

            // Note this function only supports 32 & 64 bit systems.
            // `read` has been disabled for 16 bit systems to
            // make this explicit.
            (length_entries as usize) / usize::from(ENTRY_LEN)
        };
        let entries = {
            let mut entries = Vec::new();
            entries.try_reserve(num_entries)?;
            for _ in 0..num_entries {
                entries.push(SdEntry::read(reader)?);
            }
            entries
        };

        let mut options_length = {
            let mut options_length_bytes: [u8; 4] = [0x00; 4];
            reader.read_exact(&mut options_length_bytes)?;
            u32::from_be_bytes(options_length_bytes)
        };

        if options_length > MAX_OPTIONS_LEN {
            return Err(
                ReadError::SdOptionsArrayLengthTooLarge(options_length)
            );
        }

        let mut options = Vec::new();
        // pessimistically reserve memory so if we trigger an
        // allocation failure we trigger it here.
        // (minimum size of an option is 4 bytes)
        options.try_reserve((options_length as usize) / 4)?;

        while options_length > 0 {
            let (read_bytes, option) = SdOption::read(reader)?;
            options.push(option);
            options_length -= read_bytes as u32;
        }

        //return result
        use sd::flags::*;
        Ok(Self {
            flags: SdHeaderFlags {
                reboot: 0 != header_bytes[0] & REBOOT_FLAG,
                unicast: 0 != header_bytes[0] & UNICAST_FLAG,
                explicit_initial_data_control: 0 != header_bytes[0] & EXPLICIT_INITIAL_DATA_CONTROL_FLAG,
            },
            entries,
            options,
        })
    }

    /// Writes the header to the given writer.
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes_vec()?)?;
        Ok(())
    }

    /// Writes the header to a slice.
    #[inline]
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<(), WriteError> {
        let buffer = self.to_bytes_vec()?;
        if slice.len() < buffer.len() {
            use WriteError::*;
            Err(UnexpectedEndOfSlice(buffer.len()))
        } else {
            // TODO figure out a better way
            for (idx, b) in buffer.iter().enumerate() {
                slice[idx] = *b;
            }
            Ok(())
        }
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        use self::entries::*;
        // 4*3 (flags, entries len & options len)
        let options_len: usize = self.options.iter().map(|ref o| o.header_len()).sum();
        4*3 + self.entries.len()*ENTRY_LEN + options_len
    }

    /// Writes the header to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes_vec(&self) -> Result<Vec<u8>, ValueError> {
        use self::entries::*;

        // calculate memory usage
        let entries_len = self.entries.len()*ENTRY_LEN;
        let options_len: usize = self.options.iter().map(|ref o| o.header_len()).sum();

        // pre-allocate the resulting buffer (4*3 for flags, entries len & options len)
        let mut bytes = Vec::with_capacity(4*3 + entries_len + options_len);

        // flags & reserved
        bytes.extend_from_slice(&self.flags.to_bytes());
        // entries len
        bytes.extend_from_slice(&(entries_len as u32).to_be_bytes());

        // entries
        for e in &self.entries {
            bytes.extend_from_slice(&e.to_bytes());
        }

        // options len
        bytes.extend_from_slice(&(options_len as u32).to_be_bytes());
        for o in &self.options {
            o.append_bytes_to_vec(&mut bytes)?;
        }

        Ok(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdEntry {
    ///SOMEIP service discovery entry for a service.
    Service {
        _type: SdServiceEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    },

    ///SOMEIP service discovery entry for an eventgroup.
    Eventgroup {
        _type: SdEventGroupEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        // reserved: u8,
        /// True if initial data shall be sent by server
        initial_data_requested: bool,
        // reserved: 3 bit
        /// distinguish identical subscribe eventgroups of the same subscriber
        /// 4 bit
        counter: u8,
        eventgroup_id: u16,
    },
}

impl SdEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new_service_entry(
        _type: SdServiceEntryType,
        index_first_option_run: u8,
        index_second_option_run: u8,
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    ) -> Result<Self, ValueError> {
        if ttl > 0x00FF_FFFF {
            Err(ValueError::TtlTooLarge(ttl))
        } else if number_of_options_1 > 0x0F {
            Err(ValueError::NumberOfOption1TooLarge(number_of_options_1))
        } else if number_of_options_2 > 0x0F {
            Err(ValueError::NumberOfOption2TooLarge(number_of_options_2))
        } else {
            Ok(Self::Service {
                _type,
                index_first_option_run,
                index_second_option_run,
                number_of_options_1,
                number_of_options_2,
                service_id,
                instance_id,
                major_version,
                ttl,
                minor_version,
            })
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
        number_of_options_1: u8,
        number_of_options_2: u8,
        service_id: u16,
        instance_id: u16,
        major_version: u8,
        ttl: u32,
        minor_version: u32,
    ) -> Result<Self, ValueError> {
        if ttl == 0 {
            Err(ValueError::TtlZeroIndicatesStopOffering)
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
    /// 0 is passed [`ValueError::TtlZeroIndicatesStopOffering`] as an error
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
    ) -> Result<Self, ValueError> {
        if ttl == 0 {
            Err(ValueError::TtlZeroIndicatesStopOffering)
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
    ) -> Result<Self, ValueError> {
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
        _type: SdEventGroupEntryType,
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
    ) -> Result<Self, ValueError> {
        if counter > 0x0F {
            Err(ValueError::CounterTooLarge(counter))
        } else if ttl > 0x00FF_FFFF {
            Err(ValueError::TtlTooLarge(ttl))
        } else if number_of_options_1 > 0x0F {
            Err(ValueError::NumberOfOption1TooLarge(number_of_options_1))
        } else if number_of_options_2 > 0x0F {
            Err(ValueError::NumberOfOption2TooLarge(number_of_options_2))
        } else {
            Ok(Self::Eventgroup {
                _type,
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
            })
        }
    }

    #[inline]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, ReadError> {
        let mut entry_bytes: [u8; entries::ENTRY_LEN] = [0; entries::ENTRY_LEN];
        reader.read_exact(&mut entry_bytes)?;

        let _type_raw = entry_bytes[0];
        match _type_raw {
            0x00 => Self::read_service(SdServiceEntryType::FindService, entry_bytes),
            0x01 => Self::read_service(SdServiceEntryType::OfferService, entry_bytes),
            0x06 => Self::read_entry_group(SdEventGroupEntryType::Subscribe, entry_bytes),
            0x07 => Self::read_entry_group(SdEventGroupEntryType::SubscribeAck, entry_bytes),
            _ => Err(ReadError::UnknownSdServiceEntryType(_type_raw)),
        }
    }

    /// Read a service entry from a byte array.
    #[inline]
    pub fn read_service(
        _type: SdServiceEntryType,
        entry_bytes: [u8; entries::ENTRY_LEN],
    ) -> Result<Self, ReadError> {
        //return result
        Ok(Self::Service {
            _type,
            index_first_option_run: entry_bytes[1],
            index_second_option_run: entry_bytes[2],
            number_of_options_1: entry_bytes[3] >> 4,
            number_of_options_2: entry_bytes[3] & 0x0F,
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
        })
    }

    /// Read an entry group from byte array.
    #[inline]
    pub fn read_entry_group(
        _type: SdEventGroupEntryType,
        entry_bytes: [u8; entries::ENTRY_LEN],
    ) -> Result<Self, ReadError> {
        //return result
        Ok(Self::Eventgroup {
            _type,
            index_first_option_run: entry_bytes[1],
            index_second_option_run: entry_bytes[2],
            number_of_options_1: entry_bytes[3] >> 4,
            number_of_options_2: entry_bytes[3] & 0x0F,
            service_id: u16::from_be_bytes([entry_bytes[4], entry_bytes[5]]),
            instance_id: u16::from_be_bytes([entry_bytes[6], entry_bytes[7]]),
            major_version: entry_bytes[8],
            ttl: u32::from_be_bytes([0x00, entry_bytes[9], entry_bytes[10], entry_bytes[11]]),
            // skip reserved byte, TODO: should this be verified to be 0x00 ?
            initial_data_requested: 0 != entry_bytes[13] & EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG,
            // ignore reserved bits, TODO: should this be verified to be 0x00 ?
            counter: entry_bytes[13] & 0x0F,
            eventgroup_id: u16::from_be_bytes([entry_bytes[14], entry_bytes[15]]),
        })
    }

    /// Writes the eventgroup entry to the given writer.
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    ///Writes the eventgroup entry to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> [u8; entries::ENTRY_LEN] {
        match self {
            SdEntry::Eventgroup {
                _type,
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
            } => {
                let mut result = [0x00; entries::ENTRY_LEN];

                result[0] = _type.clone() as u8;
                result[1] = *index_first_option_run;
                result[2] = *index_second_option_run;
                result[3] = (number_of_options_1 << 4) | (number_of_options_2 & 0x0F);

                let service_id_bytes = service_id.to_be_bytes();
                result[4] = service_id_bytes[0];
                result[5] = service_id_bytes[1];

                let instance_id_bytes = instance_id.to_be_bytes();
                result[6] = instance_id_bytes[0];
                result[7] = instance_id_bytes[1];

                result[8] = *major_version;

                let ttl_bytes = ttl.to_be_bytes();
                result[9] = ttl_bytes[1];
                result[10] = ttl_bytes[2];
                result[11] = ttl_bytes[3];

                // skip reserved byte, already initialized as 0x00

                if *initial_data_requested {
                    result[13] |= EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG;
                }
                result[13] |= counter & 0x0F;

                let eventgroup_id_bytes = eventgroup_id.to_be_bytes();
                result[14] = eventgroup_id_bytes[0];
                result[15] = eventgroup_id_bytes[1];

                result
            }
            SdEntry::Service {
                _type,
                index_first_option_run,
                index_second_option_run,
                number_of_options_1,
                number_of_options_2,
                service_id,
                instance_id,
                major_version,
                ttl,
                minor_version,
            } => {
                let mut result = [0x00; entries::ENTRY_LEN];

                result[0] = _type.clone() as u8;
                result[1] = *index_first_option_run;
                result[2] = *index_second_option_run;
                result[3] = (number_of_options_1 << 4) | (number_of_options_2 & 0x0F);

                let service_id_bytes = service_id.to_be_bytes();
                result[4] = service_id_bytes[0];
                result[5] = service_id_bytes[1];

                let instance_id_bytes = instance_id.to_be_bytes();
                result[6] = instance_id_bytes[0];
                result[7] = instance_id_bytes[1];

                result[8] = *major_version;

                let ttl_bytes = ttl.to_be_bytes();
                result[9] = ttl_bytes[1];
                result[10] = ttl_bytes[2];
                result[11] = ttl_bytes[3];

                let minor_version_bytes = minor_version.to_be_bytes();
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
        4*4
    } 
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdServiceEntryType {
    FindService = 0x00,
    OfferService = 0x01,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdEventGroupEntryType {
    Subscribe = 0x06,
    SubscribeAck = 0x07,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdOptionType {
    Configuration = 0x01,
    LoadBalancing = 0x02,
    Ipv4Endpoint = 0x04,
    Ipv6Endpoint = 0x06,
    Ipv4Multicast = 0x14,
    Ipv6Multicast = 0x16,
    Ipv4SdEndpoint = 0x24,
    Ipv6SdEndpoint = 0x26,
}

/// Protocol numbers based on IANA/IETF
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Generic(u8),
}

impl From<TransportProtocol> for u8 {
    fn from(tp: TransportProtocol) -> u8 {
        match tp {
            TransportProtocol::Tcp => 0x06,
            TransportProtocol::Udp => 0x11,
            TransportProtocol::Generic(tp) => tp,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdOption {
    ///Arbitrary configuration strings.
    Configuration(ConfigurationOption),
    LoadBalancing(LoadBalancingOption),
    Ipv4Endpoint(Ipv4EndpointOption),
    Ipv6Endpoint(Ipv6EndpointOption),
    Ipv4Multicast(Ipv4MulticastOption),
    Ipv6Multicast(Ipv6MulticastOption),
    Ipv4SdEndpoint(Ipv4SdEndpointOption),
    Ipv6SdEndpoint(Ipv6SdEndpointOption),
    /// An unknown option that is flagged as "discardable" and
    /// should be ignored by the receiver if not supported.
    ///
    /// This option is only intended to be used for reading,
    /// to ensure the option indices are still matching. In case
    /// this option is passed to a write function an error will be
    /// triggered.
    UnknownDiscardable(UnknownDiscardableOption),
}

impl From<ConfigurationOption> for SdOption {
    #[inline]
    fn from(o: ConfigurationOption) -> Self { SdOption::Configuration(o) }
}

impl From<LoadBalancingOption> for SdOption {
    #[inline]
    fn from(o: LoadBalancingOption) -> Self { SdOption::LoadBalancing(o) }
}

impl From<Ipv4EndpointOption> for SdOption {
    #[inline]
    fn from(o: Ipv4EndpointOption) -> Self { SdOption::Ipv4Endpoint(o) }
}

impl From<Ipv6EndpointOption> for SdOption {
    #[inline]
    fn from(o: Ipv6EndpointOption) -> Self { SdOption::Ipv6Endpoint(o) }
}

impl From<Ipv4MulticastOption> for SdOption {
    #[inline]
    fn from(o: Ipv4MulticastOption) -> Self { SdOption::Ipv4Multicast(o) }
}

impl From<Ipv6MulticastOption> for SdOption {
    #[inline]
    fn from(o: Ipv6MulticastOption) -> Self { SdOption::Ipv6Multicast(o) }
}

impl From<Ipv4SdEndpointOption> for SdOption {
    #[inline]
    fn from(o: Ipv4SdEndpointOption) -> Self { SdOption::Ipv4SdEndpoint(o) }
}

impl From<Ipv6SdEndpointOption> for SdOption {
    #[inline]
    fn from(o: Ipv6SdEndpointOption) -> Self { SdOption::Ipv6SdEndpoint(o) }
}

impl From<UnknownDiscardableOption> for SdOption {
    #[inline]
    fn from(o: UnknownDiscardableOption) -> Self { SdOption::UnknownDiscardable(o) }
}

impl SdOption {
    /// Read the value from a [`std::io::Read`] source.
    #[inline]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<(u16, Self), ReadError> {
        use ReadError::*;
        use self::SdOption::*;
        use self::options::*;

        let mut option_bytes: [u8; 4] = [0; 4];
        reader.read_exact(&mut option_bytes)?;

        let length = u16::from_be_bytes([option_bytes[0], option_bytes[1]]);
        if length < 1 {
            return Err(SdOptionLengthZero);
        }

        let type_raw = option_bytes[2];
        // reserved byte
        let discardable = 0 != option_bytes[3] & DISCARDABLE_FLAG;

        // Helper function that returns an SdOptionUnexpectedLen error
        // when the expected_len does not match the len.
        let expect_len = |expected_len: u16| -> Result<(), ReadError> {
            if expected_len == length {
                Ok(())
            } else {
                Err(
                    SdOptionUnexpectedLen {
                        expected_len,
                        actual_len: length,
                        option_type: type_raw,
                    }
                )
            }
        };

        let option = match type_raw {
            // Configuration
            CONFIGURATION_TYPE => {
                let length_array = (length - 1) as usize;
                let mut configuration_string = Vec::with_capacity(length_array);
                reader
                    .take(length_array as u64)
                    .read_to_end(&mut configuration_string)?;
                Configuration(
                    ConfigurationOption {
                        discardable,
                        configuration_string,
                    }
                )
            },
            LOAD_BALANCING_TYPE => {
                expect_len(LOAD_BALANCING_LEN)?;

                let mut load_balancing_bytes: [u8; 4] = [0; 4];
                reader.read_exact(&mut load_balancing_bytes)?;
                LoadBalancing(
                    LoadBalancingOption {
                        discardable,
                        priority: u16::from_be_bytes([
                            load_balancing_bytes[0],
                            load_balancing_bytes[1],
                        ]),
                        weight: u16::from_be_bytes([load_balancing_bytes[2], load_balancing_bytes[3]]),
                    }
                )
            },
            IPV4_ENDPOINT_TYPE => {
                expect_len(IPV4_ENDPOINT_LEN)?;

                let (ipv4_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip4_option(reader)?;
                Ipv4Endpoint(
                    Ipv4EndpointOption {
                        ipv4_address,
                        transport_protocol,
                        transport_protocol_number,
                    }
                )
            },
            IPV6_ENDPOINT_TYPE => {
                expect_len(IPV6_ENDPOINT_LEN)?;

                let (ipv6_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip6_option(reader)?;
                Ipv6Endpoint(
                    Ipv6EndpointOption {
                        ipv6_address,
                        transport_protocol,
                        transport_protocol_number,
                    }
                )
            },
            IPV4_MULTICAST_TYPE => {
                expect_len(IPV4_MULTICAST_LEN)?;

                let (ipv4_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip4_option(reader)?;
                Ipv4Multicast(
                    Ipv4MulticastOption {
                        ipv4_address,
                        transport_protocol,
                        transport_protocol_number,
                    }
                )
            },
            IPV6_MULTICAST_TYPE => {
                expect_len(IPV6_MULTICAST_LEN)?;

                let (ipv6_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip6_option(reader)?;
                Ipv6Multicast(
                    Ipv6MulticastOption {
                        ipv6_address,
                        transport_protocol,
                        transport_protocol_number,
                    }
                )
            },
            IPV4_SD_ENDPOINT_TYPE => {
                expect_len(IPV4_SD_ENDPOINT_LEN)?;

                let (ipv4_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip4_option(reader)?;
                Ipv4SdEndpoint(
                    Ipv4SdEndpointOption {
                        ipv4_address,
                        transport_protocol,
                        transport_protocol_number,
                    }
                )
            },
            IPV6_SD_ENDPOINT_TYPE => {
                expect_len(IPV6_SD_ENDPOINT_LEN)?;

                let (ipv6_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip6_option(reader)?;
                Ipv6SdEndpoint(
                    Ipv6SdEndpointOption {
                        ipv6_address,
                        transport_protocol,
                        transport_protocol_number,
                    }
                )
            },
            option_type => if discardable {
                // skip unknown options payload if "discardable"
                // if length is greater then 1 then we need to skip the rest of the option
                // (note that we already read length 1 as this contains the "discardable"
                // flag)
                if length > 1 {

                    // first seek past the payload (except for one byte)
                    if length > 2 {
                        reader.seek(std::io::SeekFrom::Current(i64::from(length) - 2))?;
                    }
                    // do a final read to trigger io errors in case they occur
                    //
                    // NOTE: Seek does not trigger io errors if the end of the file
                    // is reached. Instead it silently fails and just sits there.
                    // We still want to trigger io::Errors so don't remove this read.
                    let mut buf = [0; 1];
                    reader.read_exact(&mut buf)?;
                }

                // return a dummy entry so the option indices are not shifted
                UnknownDiscardable(
                    UnknownDiscardableOption {
                        length,
                        option_type,
                    }
                )
            } else {
                return Err(UnknownSdOptionType(option_type))
            },
        };
        Ok((3 + length, option))
    }

    #[inline]
    fn read_ip4_option<T: Read>(
        reader: &mut T,
    ) -> Result<([u8;4], TransportProtocol, u16), ReadError> {
        let mut ipv4endpoint_bytes: [u8; 8] = [0; 8];
        reader.read_exact(&mut ipv4endpoint_bytes)?;

        // ignore reserved byte
        let ipv4_address = [
            ipv4endpoint_bytes[0],
            ipv4endpoint_bytes[1],
            ipv4endpoint_bytes[2],
            ipv4endpoint_bytes[3],
        ];
        // ignore reserved byte
        let transport_protocol_raw = ipv4endpoint_bytes[5];
        let transport_protocol = match transport_protocol_raw {
            0x06 => TransportProtocol::Tcp,
            0x11 => TransportProtocol::Udp,
            other => TransportProtocol::Generic(other),
        };

        let transport_protocol_number =
            u16::from_be_bytes([ipv4endpoint_bytes[6], ipv4endpoint_bytes[7]]);

        Ok((ipv4_address, transport_protocol, transport_protocol_number))
    }

    #[inline]
    fn read_ip6_option<T: Read>(
        reader: &mut T,
    ) -> Result<([u8;16], TransportProtocol, u16), ReadError> {
        let mut ipv6endpoint_bytes: [u8; 20] = [0; 20];
        reader.read_exact(&mut ipv6endpoint_bytes)?;

        // ignore reserved byte
        let ipv6_address = [
            ipv6endpoint_bytes[0],
            ipv6endpoint_bytes[1],
            ipv6endpoint_bytes[2],
            ipv6endpoint_bytes[3],
            ipv6endpoint_bytes[4],
            ipv6endpoint_bytes[5],
            ipv6endpoint_bytes[6],
            ipv6endpoint_bytes[7],
            ipv6endpoint_bytes[8],
            ipv6endpoint_bytes[9],
            ipv6endpoint_bytes[10],
            ipv6endpoint_bytes[11],
            ipv6endpoint_bytes[12],
            ipv6endpoint_bytes[13],
            ipv6endpoint_bytes[14],
            ipv6endpoint_bytes[15],
        ];
        // ignore reserved byte
        let transport_protocol_raw = ipv6endpoint_bytes[17];
        let transport_protocol = match transport_protocol_raw {
            0x06 => TransportProtocol::Tcp,
            0x11 => TransportProtocol::Udp,
            other => TransportProtocol::Generic(other),
        };

        let transport_protocol_number =
            u16::from_be_bytes([ipv6endpoint_bytes[18], ipv6endpoint_bytes[19]]);

        Ok((ipv6_address, transport_protocol, transport_protocol_number))
    }

    /// Writes the eventgroup entry to the given writer.
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        use self::SdOption::*;
        use self::options::*;

        fn write_ipv4<R: Write>(
            writer: &mut R,
            len: u16,
            t: u8,
            addr: [u8;4],
            tp: TransportProtocol,
            port: u16,
        ) -> Result<(), WriteError> {
            let len_be = len.to_be_bytes();
            let port_be = port.to_be_bytes();
            writer.write_all(&[
                len_be[0], len_be[1], t, 0, 
                addr[0], addr[1], addr[2], addr[3],
                0, tp.into(), port_be[0], port_be[1],
            ])?;
            Ok(())
        }

        fn write_ipv6<R: Write>(
            writer: &mut R,
            len: u16,
            t: u8,
            addr: [u8;16],
            tp: TransportProtocol,
            port: u16,
        ) -> Result<(), WriteError> {
            let len_be = len.to_be_bytes();
            let port_be = port.to_be_bytes();
            writer.write_all(&[
                len_be[0], len_be[1], t, 0, 
                addr[0], addr[1], addr[2], addr[3],
                addr[4], addr[5], addr[6], addr[7],
                addr[8], addr[9], addr[10], addr[11],
                addr[12], addr[13], addr[14], addr[15],
                0, tp.into(), port_be[0], port_be[1],
            ])?;
            Ok(())
        }

        match self {
            Configuration(c) => {
                let len_be = (1u16 + c.configuration_string.len() as u16).to_be_bytes();
                writer.write_all(
                    &[
                        len_be[0],
                        len_be[1],
                        CONFIGURATION_TYPE,
                        if c.discardable { DISCARDABLE_FLAG } else { 0 },
                    ]
                )?;
                writer.write_all(&c.configuration_string)?;
                Ok(())
            },
            LoadBalancing(o) => {
                
                let len_be = LOAD_BALANCING_LEN.to_be_bytes();
                let prio_be = o.priority.to_be_bytes();
                let weight_be = o.weight.to_be_bytes();

                writer.write_all(
                    &[
                        len_be[0],
                        len_be[1],
                        LOAD_BALANCING_TYPE,
                        if o.discardable { DISCARDABLE_FLAG } else { 0 },
                        prio_be[0],
                        prio_be[1],
                        weight_be[0],
                        weight_be[1],
                    ]
                )?;
                Ok(())
            },
            Ipv4Endpoint(o) => write_ipv4(
                writer,
                IPV4_ENDPOINT_LEN,
                IPV4_ENDPOINT_TYPE,
                o.ipv4_address,
                o.transport_protocol,
                o.transport_protocol_number,
            ),
            Ipv6Endpoint(o) => write_ipv6(
                writer,
                IPV6_ENDPOINT_LEN,
                IPV6_ENDPOINT_TYPE,
                o.ipv6_address,
                o.transport_protocol,
                o.transport_protocol_number,
            ),
            Ipv4Multicast(o) => write_ipv4(
                writer,
                IPV4_MULTICAST_LEN,
                IPV4_MULTICAST_TYPE,
                o.ipv4_address,
                o.transport_protocol,
                o.transport_protocol_number,
            ),
            Ipv6Multicast(o) => write_ipv6(
                writer,
                IPV6_MULTICAST_LEN,
                IPV6_MULTICAST_TYPE,
                o.ipv6_address,
                o.transport_protocol,
                o.transport_protocol_number,
            ),
            Ipv4SdEndpoint(o) => write_ipv4(
                writer,
                IPV4_SD_ENDPOINT_LEN,
                IPV4_SD_ENDPOINT_TYPE,
                o.ipv4_address,
                o.transport_protocol,
                o.transport_protocol_number,
            ),
            Ipv6SdEndpoint(o) => write_ipv6(
                writer,
                IPV6_SD_ENDPOINT_LEN,
                IPV6_SD_ENDPOINT_TYPE,
                o.ipv6_address,
                o.transport_protocol,
                o.transport_protocol_number,
            ),
            UnknownDiscardable(o) => {
                Err(
                    WriteError::ValueError(
                        ValueError::SdUnknownDiscardableOption(o.option_type)
                    )
                )
            },
        }
    }

    /// Serializes option and append data to a vec
    pub fn append_bytes_to_vec(&self, buffer: &mut Vec<u8>) -> Result<(), ValueError> {
        use self::SdOption::*;
        use self::options::*;

        fn append_ip4(
            buffer: &mut Vec<u8>,
            ipv4_address: [u8;4],
            transport_protocol: TransportProtocol,
            transport_protocol_number: u16,
        ) {
            buffer.extend_from_slice(&ipv4_address);
            buffer.push(0x00); // reserved
            buffer.push(transport_protocol.into());
            buffer.extend_from_slice(&transport_protocol_number.to_be_bytes());
        }

        fn append_ip6(
            buffer: &mut Vec<u8>,
            ipv6_address: [u8;16],
            transport_protocol: TransportProtocol,
            transport_protocol_number: u16,
        ) {
            buffer.extend_from_slice(&ipv6_address);
            buffer.push(0x00); // reserved
            buffer.push(transport_protocol.into());
            buffer.extend_from_slice(&transport_protocol_number.to_be_bytes());
        }

        match self {
            Configuration(o) => {
                // + 1 for reserved byte
                let length_bytes = (1u16 + o.configuration_string.len() as u16).to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(CONFIGURATION_TYPE);
                buffer.push(if o.discardable { DISCARDABLE_FLAG } else { 0 });
                buffer.extend_from_slice(&o.configuration_string);
            },
            LoadBalancing(o) => {
                buffer.extend_from_slice(&LOAD_BALANCING_LEN.to_be_bytes());
                buffer.push(LOAD_BALANCING_TYPE);
                buffer.push(if o.discardable { DISCARDABLE_FLAG } else { 0 });
                buffer.extend_from_slice(&o.priority.to_be_bytes());
                buffer.extend_from_slice(&o.weight.to_be_bytes());
            },
            Ipv4Endpoint(o) => {
                buffer.extend_from_slice(&IPV4_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV4_ENDPOINT_TYPE);
                buffer.push(0x00u8); // Reserved byte
                append_ip4(
                    buffer,
                    o.ipv4_address,
                    o.transport_protocol,
                    o.transport_protocol_number,
                );
            },
            Ipv6Endpoint(o) => {
                buffer.extend_from_slice(&IPV6_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV6_ENDPOINT_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(
                    buffer,
                    o.ipv6_address,
                    o.transport_protocol,
                    o.transport_protocol_number,
                );
            },
            Ipv4Multicast(o) => {
                buffer.extend_from_slice(&IPV4_MULTICAST_LEN.to_be_bytes());
                buffer.push(IPV4_MULTICAST_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip4(
                    buffer,
                    o.ipv4_address,
                    o.transport_protocol,
                    o.transport_protocol_number,
                );
            },
            Ipv6Multicast(o) => {
                buffer.extend_from_slice(&IPV6_MULTICAST_LEN.to_be_bytes());
                buffer.push(IPV6_MULTICAST_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(
                    buffer,
                    o.ipv6_address,
                    o.transport_protocol,
                    o.transport_protocol_number,
                );
            },
            Ipv4SdEndpoint(o) => {
                buffer.extend_from_slice(&IPV4_SD_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV4_SD_ENDPOINT_TYPE);
                buffer.push(0x00u8); // Reserved byte
                append_ip4(
                    buffer,
                    o.ipv4_address,
                    o.transport_protocol,
                    o.transport_protocol_number,
                );
            },
            Ipv6SdEndpoint(o) => {
                buffer.extend_from_slice(&IPV6_SD_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV6_SD_ENDPOINT_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(
                    buffer,
                    o.ipv6_address,
                    o.transport_protocol,
                    o.transport_protocol_number,
                );
            },
            UnknownDiscardable(o) => {
                return Err(ValueError::SdUnknownDiscardableOption(o.option_type));
            },
        }
        Ok(())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        use self::SdOption::*;
        use self::options::*;

        3 + match self {
            Configuration(o) => 1 + o.configuration_string.len(),
            LoadBalancing(_) => usize::from(LOAD_BALANCING_LEN),
            Ipv4Endpoint(_) => usize::from(IPV4_ENDPOINT_LEN),
            Ipv6Endpoint(_) => usize::from(IPV6_ENDPOINT_LEN),
            Ipv4Multicast(_) => usize::from(IPV4_MULTICAST_LEN),
            Ipv6Multicast(_) => usize::from(IPV6_MULTICAST_LEN),
            Ipv4SdEndpoint(_) => usize::from(IPV4_SD_ENDPOINT_LEN),
            Ipv6SdEndpoint(_) => usize::from(IPV6_SD_ENDPOINT_LEN),
            UnknownDiscardable(o) => usize::from(o.length),
        }
    }
}

#[cfg(test)]
mod tests_sd_header {

    use super::*;
    use proptest::prelude::*;
    use proptest_generators::*;
    use std::io::Cursor;

    proptest! {
        #[test]
        fn write_read(header in sd_header_any()) {

            //non error case
            {
                //serialize
                let mut buffer: [u8; 10000] = [0; 10000];
                header.write_to_slice(&mut buffer).unwrap();

                //deserialize
                let mut cursor = Cursor::new(&buffer);
                let result = SdHeader::read(&mut cursor).unwrap();
                assert_eq!(header, result);
            }
        }
    }

    #[test]
    fn read() {
        // entries array length too large error
        for len in [entries::MAX_ENTRIES_LEN + 1, u32::MAX] {
            let len_be = len.to_be_bytes();
            let buffer = [
                0,0,0,0, // flags
                len_be[0], len_be[1], len_be[2], len_be[3],
                0,0,0,0,
            ];
            let mut cursor = Cursor::new(&buffer);
            assert_matches!(
                SdHeader::read(&mut cursor),
                Err(ReadError::SdEntriesArrayLengthTooLarge(_))
            );
        }

        // options array length too large error
        for len in [options::MAX_OPTIONS_LEN + 1, u32::MAX] {
            let len_be = len.to_be_bytes();
            let buffer = [
                0,0,0,0, // flags
                0,0,0,0, // entries array length
                len_be[0], len_be[1], len_be[2], len_be[3],
                0,0,0,0,
            ];
            let mut cursor = Cursor::new(&buffer);
            assert_matches!(
                SdHeader::read(&mut cursor),
                Err(ReadError::SdOptionsArrayLengthTooLarge(_))
            );
        }
    }
}

#[cfg(test)]
mod tests_sd_entry {

    use super::*;
    use proptest::prelude::*;
    use proptest_generators::*;
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
}

#[cfg(test)]
mod tests_sd_option {

    use super::*;
    use proptest::prelude::*;
    use proptest_generators::*;
    use std::io::Cursor;

    proptest! {
        #[test]
        fn write_read(option in someip_sd_option_any()) {

            //write
            let mut buffer = Vec::with_capacity(option.header_len());
            option.write(&mut buffer).unwrap();

            //read
            let mut cursor = Cursor::new(&buffer);
            let (read_len, result) = SdOption::read(&mut cursor).unwrap();
            assert_eq!(buffer.len() as u16, read_len);
            assert_eq!(option, result);
        }
    }

    #[test]
    fn read() {
        use self::options::*;
        // too small length error
        {
            let buffer = [0x00, 0x00, IPV4_ENDPOINT_TYPE, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(result, Err(ReadError::SdOptionLengthZero));
        }
        // ipv4 length check errors
        for t in [IPV4_ENDPOINT_TYPE, IPV4_MULTICAST_TYPE, IPV4_SD_ENDPOINT_TYPE] {
            let buffer = [0x00, 0x01, t, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(
                result,
                Err(
                    ReadError::SdOptionUnexpectedLen {
                        expected_len: 0x9,
                        actual_len: 0x1,
                        option_type: _,
                    }
                )
            );
        }
        // ipv6 length check errors
        for t in [IPV6_ENDPOINT_TYPE, IPV6_MULTICAST_TYPE, IPV6_SD_ENDPOINT_TYPE] {
            let buffer = [0x00, 0x01, t, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(
                result,
                Err(
                    ReadError::SdOptionUnexpectedLen {
                        expected_len: 0x15,
                        actual_len: 0x1,
                        option_type: _,
                    }
                )
            );
        }
        // unknown option type (non discardable)
        {
            let buffer = [0x00, 0x01, 0xff, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(result, Err(ReadError::UnknownSdOptionType(0xFF)));
        }
        // unknown option type (discardable)
        {
            let buffer = [0x00, 0x01, 0xff, 0b1000_0000];
            let mut cursor = std::io::Cursor::new(buffer);
            let (len, header) = SdOption::read(&mut cursor).unwrap();
            assert_eq!(
                header,
                UnknownDiscardableOption {
                    length: 1,
                    option_type: 0xff,
                }.into()
            );
            assert_eq!(4, len);
        }
    }
}

#[test]
fn sd_header_write_unexpected_end_of_slice() {
    let header = SdHeader::default();
    let result = header.write_to_slice(&mut []);
    assert_matches!(result, Err(WriteError::UnexpectedEndOfSlice(_)));
}

#[test]
fn service_entry_read_unknown_service_entry_type() {
    let mut buffer = [0x00; entries::ENTRY_LEN];
    buffer[0] = 0xFF; // Unknown Type
    let mut cursor = std::io::Cursor::new(buffer);
    let result = SdEntry::read(&mut cursor);
    assert_matches!(result, Err(ReadError::UnknownSdServiceEntryType(0xFF)));
}

#[test]
fn new_service_entry_ttl_too_large() {
    let result = SdEntry::new_service_entry(
        SdServiceEntryType::OfferService,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF_FFFF,
        0,
    );
    assert_matches!(result, Err(ValueError::TtlTooLarge(0xFFFF_FFFF)));
}

#[test]
fn new_service_entry_number_option1_too_large() {
    let result = SdEntry::new_service_entry(
        SdServiceEntryType::OfferService,
        0,
        0,
        0xFF,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    assert_matches!(result, Err(ValueError::NumberOfOption1TooLarge(0xFF)));
}

#[test]
fn new_service_entry_number_option2_too_large() {
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
    assert_matches!(result, Err(ValueError::NumberOfOption2TooLarge(0xFF)));
}

#[test]
fn new_service_find_service_entry_zero_ttl() {
    let result = SdEntry::new_find_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_matches!(result, Err(ValueError::TtlZeroIndicatesStopOffering));
}

#[test]
fn new_service_offer_service_entry_zero_ttl() {
    let result = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_matches!(result, Err(ValueError::TtlZeroIndicatesStopOffering));
}
