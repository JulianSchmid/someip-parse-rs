use crate::{ReadError, ValueError, WriteError};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
};

///Length of someip sd header, flags + reserved + entries length + options length
///excluding entries and options arrays
pub const MIN_SD_HEADER_LENGTH: usize = 1 + 3 + 4 + 4;

pub const SERVICE_ENTRY_LENGTH: usize = 16;

pub const EVENTGROUP_ENTRY_LENGTH: usize = 16;

///Used for detection of reboots.
pub const SD_HEADER_REBOOT_FLAG: u8 = 0b1000_0000;
///Unicast is supported.
///Set for all SD messages.
///Relict from old SOME/IP versions.
pub const SD_HEADER_UNICAST_FLAG: u8 = 0b0100_0000;
///Explicit initial data control is supported.
pub const SD_HEADER_EXPLICIT_INITIAL_DATA_CONTROL_FLAG: u8 = 0b0010_0000;

pub const EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG: u8 = 0b1000_0000;

///SOMEIP service discovery header
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SomeIpSdHeader {
    pub reboot: bool,
    pub unicast: bool,
    pub explicit_initial_data_control: bool,
    // reserved: [u8;3],
    // Length of entries array in bytes
    // length_of_entries: u32,
    pub entries: Vec<SomeIpSdEntry>,
    // Length of entries array in bytes
    // length_of_options: u32,
    pub options: Vec<SomeIpSdOption>,
}

impl SomeIpSdHeader {
    #[inline]
    pub fn new(reboot: bool, entries: Vec<SomeIpSdEntry>, options: Vec<SomeIpSdOption>) -> Self {
        Self {
            reboot,
            unicast: true,
            explicit_initial_data_control: true,
            entries,
            options,
        }
    }

    #[inline]
    pub fn read<T: Read>(reader: &mut T) -> Result<Self, ReadError> {
        const HEADER_LENGTH: usize = 1 + 3 + 4; // flags + rev + entries length
        let mut header_bytes: [u8; HEADER_LENGTH] = [0; HEADER_LENGTH];
        reader.read_exact(&mut header_bytes)?;

        let length_of_entries = u32::from_be_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);
        let num_entries = length_of_entries as usize / SERVICE_ENTRY_LENGTH;
        let entries: Vec<SomeIpSdEntry> = (0..num_entries)
            .map(|_| SomeIpSdEntry::read(reader))
            .collect::<Result<_, _>>()?;

        let mut options_length_bytes: [u8; 4] = [0x00; 4];
        reader.read_exact(&mut options_length_bytes)?;
        let mut options_length = u32::from_be_bytes(options_length_bytes);

        let mut options = Vec::new();
        while options_length > 0 {
            let (read_bytes, option) = SomeIpSdOption::read(reader)?;
            options.push(option);
            options_length -= read_bytes as u32;
        }

        //return result
        Ok(Self {
            reboot: 0 != header_bytes[0] & SD_HEADER_REBOOT_FLAG,
            unicast: 0 != header_bytes[0] & SD_HEADER_UNICAST_FLAG,
            explicit_initial_data_control: 0
                != header_bytes[0] & SD_HEADER_EXPLICIT_INITIAL_DATA_CONTROL_FLAG,
            entries,
            options,
        })
    }

    /// Writes the header to the given writer.
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Writes the header to a slice.
    #[inline]
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<(), WriteError> {
        let buffer = self.to_bytes();
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

    ///Writes the header to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags = 0;
        if self.reboot {
            flags |= SD_HEADER_REBOOT_FLAG;
        }

        if self.unicast {
            flags |= SD_HEADER_UNICAST_FLAG;
        }

        if self.explicit_initial_data_control {
            flags |= SD_HEADER_EXPLICIT_INITIAL_DATA_CONTROL_FLAG;
        }

        let mut entries_bytes: Vec<u8> = self
            .entries
            .iter()
            .map(|e| e.to_bytes())
            .flatten()
            .collect();
        let entries_bytes_len = (entries_bytes.len() as u32).to_be_bytes();
        let mut options_bytes: Vec<u8> = self
            .options
            .iter()
            .map(|o| o.to_bytes())
            .flatten()
            .collect();
        let options_length = options_bytes.len() as u32;
        let options_bytes_len = options_length.to_be_bytes();

        // TODO determine if it's better to reallocate growing the vector or spend more memory.
        // Alternative use e.g. constant generics.
        let mut bytes =
            Vec::with_capacity(MIN_SD_HEADER_LENGTH + entries_bytes.len() + options_bytes.len());
        bytes.push(flags);
        bytes.append(&mut vec![0, 0, 0]); // reserved bytes
        bytes.extend_from_slice(&entries_bytes_len);
        bytes.append(&mut entries_bytes);
        bytes.extend_from_slice(&options_bytes_len);
        bytes.append(&mut options_bytes);
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SomeIpSdEntry {
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

impl SomeIpSdEntry {
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

    /// Offer a service to others.
    /// * `ttl` - Must not be 0 as this indicates a "stop offering".
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
    pub fn read<T: Read>(reader: &mut T) -> Result<Self, ReadError> {
        let mut entry_bytes: [u8; EVENTGROUP_ENTRY_LENGTH] = [0; EVENTGROUP_ENTRY_LENGTH];
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

    /// Read the value from the slice without checking for the minimum length of the slice.
    ///
    /// Safety:
    ///
    /// It is required that the slice has at least the length of TP_HEADER_LENGTH (4 octets/bytes).
    /// If this is not the case undefined behavior will occur.
    #[inline]
    pub fn read_service(
        _type: SdServiceEntryType,
        entry_bytes: [u8; EVENTGROUP_ENTRY_LENGTH],
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

    /// Read the value from the slice without checking for the minimum length of the slice.
    ///
    /// Safety:
    ///
    /// It is required that the slice has at least the length of TP_HEADER_LENGTH (4 octets/bytes).
    /// If this is not the case undefined behavior will occur.
    #[inline]
    pub fn read_entry_group(
        _type: SdEventGroupEntryType,
        entry_bytes: [u8; EVENTGROUP_ENTRY_LENGTH],
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

    ///Serialize the eventgroup entry.
    pub fn write_raw<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    ///Writes the eventgroup entry to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> [u8; EVENTGROUP_ENTRY_LENGTH] {
        match self {
            SomeIpSdEntry::Eventgroup {
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
                let mut result = [0x00; EVENTGROUP_ENTRY_LENGTH];

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
                    result[13] = result[13] | EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG;
                }
                result[13] = result[13] | (counter & 0x0F);

                let eventgroup_id_bytes = eventgroup_id.to_be_bytes();
                result[14] = eventgroup_id_bytes[0];
                result[15] = eventgroup_id_bytes[1];

                result
            }
            SomeIpSdEntry::Service {
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
                let mut result = [0x00; SERVICE_ENTRY_LENGTH];

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
pub enum SomeIpSdOption {
    ///Arbitrary configuration strings.
    /// Type: 0x01.
    Configuration {
        // TODO DNS TXT / DNS-SD format
        configuration_string: Vec<u8>,
    },
    LoadBalancing {
        priority: u16,
        weight: u16,
    },
    Ipv4Endpoint {
        ipv4_address: Ipv4Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    },
    Ipv6Endpoint {
        ipv6_address: Ipv6Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    },
    Ipv4Multicast {
        ipv4_address: Ipv4Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    },
    Ipv6Multicast {
        ipv6_address: Ipv6Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    },
    Ipv4SdEndpoint {
        ipv4_address: Ipv4Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    },
    Ipv6SdEndpoint {
        ipv6_address: Ipv6Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    },
}

impl SomeIpSdOption {
    /// Read the value from the slice without checking for the minimum length of the slice.
    ///
    /// Safety:
    ///
    /// It is required that the slice has at least the length of TP_HEADER_LENGTH (4 octets/bytes).
    /// If this is not the case undefined behavior will occur.
    #[inline]
    pub fn read<T: Read>(reader: &mut T) -> Result<(u16, Self), ReadError> {
        let mut option_bytes: [u8; 4] = [0; 4];
        reader.read_exact(&mut option_bytes)?;

        let length = u16::from_be_bytes([option_bytes[0], option_bytes[1]]);

        let type_raw = option_bytes[2];
        // reserved byte
        let _reserved: u8 = option_bytes[3];

        let option = match type_raw {
            // Configuration
            0x01 => {
                let length_array = (length - 1) as usize;
                let mut configuration_string = Vec::with_capacity(length_array);
                reader
                    .take(length_array as u64)
                    .read_to_end(&mut configuration_string)?;
                SomeIpSdOption::Configuration {
                    configuration_string,
                }
            }
            // LoadBalancing
            0x02 => {
                let mut load_balancing_bytes: [u8; 4] = [0; 4];
                reader.read_exact(&mut load_balancing_bytes)?;
                SomeIpSdOption::LoadBalancing {
                    // ignore reserved byte
                    priority: u16::from_be_bytes([
                        load_balancing_bytes[0],
                        load_balancing_bytes[1],
                    ]),
                    weight: u16::from_be_bytes([load_balancing_bytes[2], load_balancing_bytes[3]]),
                }
            }
            // Ipv4Endpoint
            0x04 => {
                let (ipv4_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip4_option(reader)?;
                SomeIpSdOption::Ipv4Endpoint {
                    ipv4_address,
                    transport_protocol,
                    transport_protocol_number,
                }
            }
            // Ipv6Endpoint
            0x06 => {
                let (ipv6_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip6_option(reader)?;
                SomeIpSdOption::Ipv6Endpoint {
                    ipv6_address,
                    transport_protocol,
                    transport_protocol_number,
                }
            }
            // Ipv4Multicast
            0x14 => {
                let (ipv4_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip4_option(reader)?;
                SomeIpSdOption::Ipv4Multicast {
                    ipv4_address,
                    transport_protocol,
                    transport_protocol_number,
                }
            }
            // Ipv6Multicast
            0x16 => {
                let (ipv6_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip6_option(reader)?;
                SomeIpSdOption::Ipv6Multicast {
                    ipv6_address,
                    transport_protocol,
                    transport_protocol_number,
                }
            }
            // Ipv4SdEndpoint
            0x24 => {
                let (ipv4_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip4_option(reader)?;
                SomeIpSdOption::Ipv4SdEndpoint {
                    ipv4_address,
                    transport_protocol,
                    transport_protocol_number,
                }
            }
            // Ipv6SdEndpoint
            0x26 => {
                let (ipv6_address, transport_protocol, transport_protocol_number) =
                    Self::read_ip6_option(reader)?;
                SomeIpSdOption::Ipv6SdEndpoint {
                    ipv6_address,
                    transport_protocol,
                    transport_protocol_number,
                }
            }
            unknow_type => return Err(ReadError::UnknownSdOptionType(unknow_type)),
        };
        Ok((3 + length, option))
    }

    #[inline]
    fn read_ip4_option<T: Read>(
        reader: &mut T,
    ) -> Result<(Ipv4Addr, TransportProtocol, u16), ReadError> {
        let mut ipv4endpoint_bytes: [u8; 8] = [0; 8];
        reader.read_exact(&mut ipv4endpoint_bytes)?;

        // ignore reserved byte
        let ipv4_address = Ipv4Addr::new(
            ipv4endpoint_bytes[0],
            ipv4endpoint_bytes[1],
            ipv4endpoint_bytes[2],
            ipv4endpoint_bytes[3],
        );
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
    ) -> Result<(Ipv6Addr, TransportProtocol, u16), ReadError> {
        let mut ipv6endpoint_bytes: [u8; 20] = [0; 20];
        reader.read_exact(&mut ipv6endpoint_bytes)?;

        // ignore reserved byte
        let ipv6_address = Ipv6Addr::from([
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
        ]);
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
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    pub fn write_raw<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    ///Writes the option to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            SomeIpSdOption::Configuration {
                configuration_string,
            } => {
                // + 1 for reserved byte
                let length_bytes = (1u16 + configuration_string.len() as u16).to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Configuration as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                buffer.extend_from_slice(&configuration_string);
            }
            SomeIpSdOption::LoadBalancing { priority, weight } => {
                let length_bytes = 0x05u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::LoadBalancing as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                buffer.extend_from_slice(&priority.to_be_bytes());
                buffer.extend_from_slice(&weight.to_be_bytes());
            }
            SomeIpSdOption::Ipv4Endpoint {
                ipv4_address,
                transport_protocol,
                transport_protocol_number,
            } => {
                let length_bytes = 0x09u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Ipv4Endpoint as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                self.to_bytes_ip4(
                    &mut buffer,
                    *ipv4_address,
                    *transport_protocol,
                    *transport_protocol_number,
                );
            }
            SomeIpSdOption::Ipv6Endpoint {
                ipv6_address,
                transport_protocol,
                transport_protocol_number,
            } => {
                let length_bytes = 0x15u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Ipv6Endpoint as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                self.to_bytes_ip6(
                    &mut buffer,
                    *ipv6_address,
                    *transport_protocol,
                    *transport_protocol_number,
                );
            }
            SomeIpSdOption::Ipv4Multicast {
                ipv4_address,
                transport_protocol,
                transport_protocol_number,
            } => {
                let length_bytes = 0x09u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Ipv4Multicast as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                self.to_bytes_ip4(
                    &mut buffer,
                    *ipv4_address,
                    *transport_protocol,
                    *transport_protocol_number,
                );
            }
            SomeIpSdOption::Ipv6Multicast {
                ipv6_address,
                transport_protocol,
                transport_protocol_number,
            } => {
                let length_bytes = 0x15u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Ipv6Multicast as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                self.to_bytes_ip6(
                    &mut buffer,
                    *ipv6_address,
                    *transport_protocol,
                    *transport_protocol_number,
                );
            }
            SomeIpSdOption::Ipv4SdEndpoint {
                ipv4_address,
                transport_protocol,
                transport_protocol_number,
            } => {
                let length_bytes = 0x09u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Ipv4SdEndpoint as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                self.to_bytes_ip4(
                    &mut buffer,
                    *ipv4_address,
                    *transport_protocol,
                    *transport_protocol_number,
                );
            }
            SomeIpSdOption::Ipv6SdEndpoint {
                ipv6_address,
                transport_protocol,
                transport_protocol_number,
            } => {
                let length_bytes = 0x15u16.to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(SdOptionType::Ipv6SdEndpoint as u8); // Type
                buffer.push(0x00u8); // Reserved byte
                self.to_bytes_ip6(
                    &mut buffer,
                    *ipv6_address,
                    *transport_protocol,
                    *transport_protocol_number,
                );
            }
        }
        buffer
    }

    pub fn to_bytes_ip4(
        &self,
        buffer: &mut Vec<u8>,
        ipv4_address: Ipv4Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    ) {
        buffer.extend_from_slice(&ipv4_address.octets());
        buffer.push(0x00); // reserved
        buffer.push(transport_protocol.into());
        buffer.extend_from_slice(&transport_protocol_number.to_be_bytes());
    }

    pub fn to_bytes_ip6(
        &self,
        buffer: &mut Vec<u8>,
        ipv6_address: Ipv6Addr,
        transport_protocol: TransportProtocol,
        transport_protocol_number: u16,
    ) {
        buffer.extend_from_slice(&ipv6_address.octets());
        buffer.push(0x00); // reserved
        buffer.push(transport_protocol.into());
        buffer.extend_from_slice(&transport_protocol_number.to_be_bytes());
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
        fn write_read(header in someip_sd_header_any()) {

            //non error case
            {
                //serialize
                let mut buffer: [u8; 10000] = [0; 10000];
                header.write_to_slice(&mut buffer).unwrap();

                //deserialize
                let mut cursor = Cursor::new(&buffer);
                let result = SomeIpSdHeader::read(&mut cursor).unwrap();
                assert_eq!(header, result);
            }
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
            service_entry.write_raw(&mut buffer).unwrap();

            //read
            let mut cursor = Cursor::new(&buffer);
            let result = SomeIpSdEntry::read(&mut cursor).unwrap();
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
            let mut buffer = Vec::new();
            option.write_raw(&mut buffer).unwrap();

            //read
            let mut cursor = Cursor::new(&buffer);
            let (read_len, result) = SomeIpSdOption::read(&mut cursor).unwrap();
            assert_eq!(buffer.len() as u16, read_len);
            assert_eq!(option, result);
        }
    }
}

#[test]
fn sd_header_write_unexpected_end_of_slice() {
    let header = SomeIpSdHeader::default();
    let result = header.write_to_slice(&mut []);
    assert_matches!(result, Err(WriteError::UnexpectedEndOfSlice(_)));
}

#[test]
fn service_entry_read_unknown_service_entry_type() {
    let mut buffer = [0x00; EVENTGROUP_ENTRY_LENGTH];
    buffer[0] = 0xFF; // Unknown Type
    let mut cursor = std::io::Cursor::new(buffer);
    let result = SomeIpSdEntry::read(&mut cursor);
    assert_matches!(result, Err(ReadError::UnknownSdServiceEntryType(0xFF)));
}

#[test]
fn option_read_unknown_type() {
    let mut buffer = [0x00; 4];
    buffer[2] = 0xFF; // Unknown Type
    let mut cursor = std::io::Cursor::new(buffer);
    let result = SomeIpSdOption::read(&mut cursor);
    assert_matches!(result, Err(ReadError::UnknownSdOptionType(0xFF)));
}

#[test]
fn new_service_entry_ttl_too_large() {
    let result = SomeIpSdEntry::new_service_entry(
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
    let result = SomeIpSdEntry::new_service_entry(
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
    let result = SomeIpSdEntry::new_service_entry(
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
    let result = SomeIpSdEntry::new_find_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_matches!(result, Err(ValueError::TtlZeroIndicatesStopOffering));
}

#[test]
fn new_service_offer_service_entry_zero_ttl() {
    let result = SomeIpSdEntry::new_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_matches!(result, Err(ValueError::TtlZeroIndicatesStopOffering));
}
