use crate::sd::{options::*, *};
use arrayvec::ArrayVec;

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

impl From<options::ConfigurationOption> for SdOption {
    #[inline]
    fn from(o: options::ConfigurationOption) -> Self {
        SdOption::Configuration(o)
    }
}

impl From<options::LoadBalancingOption> for SdOption {
    #[inline]
    fn from(o: options::LoadBalancingOption) -> Self {
        SdOption::LoadBalancing(o)
    }
}

impl From<options::Ipv4EndpointOption> for SdOption {
    #[inline]
    fn from(o: options::Ipv4EndpointOption) -> Self {
        SdOption::Ipv4Endpoint(o)
    }
}

impl From<options::Ipv6EndpointOption> for SdOption {
    #[inline]
    fn from(o: options::Ipv6EndpointOption) -> Self {
        SdOption::Ipv6Endpoint(o)
    }
}

impl From<options::Ipv4MulticastOption> for SdOption {
    #[inline]
    fn from(o: options::Ipv4MulticastOption) -> Self {
        SdOption::Ipv4Multicast(o)
    }
}

impl From<options::Ipv6MulticastOption> for SdOption {
    #[inline]
    fn from(o: options::Ipv6MulticastOption) -> Self {
        SdOption::Ipv6Multicast(o)
    }
}

impl From<options::Ipv4SdEndpointOption> for SdOption {
    #[inline]
    fn from(o: options::Ipv4SdEndpointOption) -> Self {
        SdOption::Ipv4SdEndpoint(o)
    }
}

impl From<options::Ipv6SdEndpointOption> for SdOption {
    #[inline]
    fn from(o: options::Ipv6SdEndpointOption) -> Self {
        SdOption::Ipv6SdEndpoint(o)
    }
}

impl From<options::UnknownDiscardableOption> for SdOption {
    #[inline]
    fn from(o: options::UnknownDiscardableOption) -> Self {
        SdOption::UnknownDiscardable(o)
    }
}

impl SdOption {
    /// Read the value from a [`std::io::Read`] source.
    #[inline]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<(u16, Self), SdReadError> {
        SdOption::read_with_flag(reader, false)
    }

    /// Read the value from a [`std::io::Read`] source.
    #[inline]
    pub fn read_with_flag<T: Read + Seek>(
        reader: &mut T,
        discard_unknown_option: bool,
    ) -> Result<(u16, Self), SdReadError> {
        use self::SdOption::*;
        use SdReadError::*;

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
        let expect_len = |expected_len: u16| -> Result<(), SdReadError> {
            if expected_len == length {
                Ok(())
            } else {
                Err(SdOptionUnexpectedLen {
                    expected_len,
                    actual_len: length,
                    option_type: type_raw,
                })
            }
        };

        let option = match type_raw {
            // Configuration
            CONFIGURATION_TYPE => {
                let length_array = (length - 1) as usize;
                if length_array > ConfigurationOption::MAX_CONFIGURATION_STRING_LEN {
                    return Err(SdConfigurationOptionLenTooLarge(length));
                }
                let mut configuration_string = ArrayVec::new();
                unsafe {
                    configuration_string.set_len(length_array);
                }
                reader.read_exact(&mut configuration_string[..length_array])?;
                Configuration(ConfigurationOption {
                    discardable,
                    configuration_string,
                })
            }
            LOAD_BALANCING_TYPE => {
                expect_len(LOAD_BALANCING_LEN)?;

                let mut load_balancing_bytes: [u8; 4] = [0; 4];
                reader.read_exact(&mut load_balancing_bytes)?;
                LoadBalancing(LoadBalancingOption {
                    discardable,
                    priority: u16::from_be_bytes([
                        load_balancing_bytes[0],
                        load_balancing_bytes[1],
                    ]),
                    weight: u16::from_be_bytes([load_balancing_bytes[2], load_balancing_bytes[3]]),
                })
            }
            IPV4_ENDPOINT_TYPE => {
                expect_len(IPV4_ENDPOINT_LEN)?;

                let (ipv4_address, transport_protocol, port) = Self::read_ip4_option(reader)?;
                Ipv4Endpoint(Ipv4EndpointOption {
                    ipv4_address,
                    transport_protocol,
                    port,
                })
            }
            IPV6_ENDPOINT_TYPE => {
                expect_len(IPV6_ENDPOINT_LEN)?;

                let (ipv6_address, transport_protocol, port) = Self::read_ip6_option(reader)?;
                Ipv6Endpoint(Ipv6EndpointOption {
                    ipv6_address,
                    transport_protocol,
                    port,
                })
            }
            IPV4_MULTICAST_TYPE => {
                expect_len(IPV4_MULTICAST_LEN)?;

                let (ipv4_address, transport_protocol, port) = Self::read_ip4_option(reader)?;
                Ipv4Multicast(Ipv4MulticastOption {
                    ipv4_address,
                    transport_protocol,
                    port,
                })
            }
            IPV6_MULTICAST_TYPE => {
                expect_len(IPV6_MULTICAST_LEN)?;

                let (ipv6_address, transport_protocol, port) = Self::read_ip6_option(reader)?;
                Ipv6Multicast(Ipv6MulticastOption {
                    ipv6_address,
                    transport_protocol,
                    port,
                })
            }
            IPV4_SD_ENDPOINT_TYPE => {
                expect_len(IPV4_SD_ENDPOINT_LEN)?;

                let (ipv4_address, transport_protocol, port) = Self::read_ip4_option(reader)?;
                Ipv4SdEndpoint(Ipv4SdEndpointOption {
                    ipv4_address,
                    transport_protocol,
                    port,
                })
            }
            IPV6_SD_ENDPOINT_TYPE => {
                expect_len(IPV6_SD_ENDPOINT_LEN)?;

                let (ipv6_address, transport_protocol, port) = Self::read_ip6_option(reader)?;
                Ipv6SdEndpoint(Ipv6SdEndpointOption {
                    ipv6_address,
                    transport_protocol,
                    port,
                })
            }
            option_type => {
                if discardable || discard_unknown_option {
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
                    UnknownDiscardable(UnknownDiscardableOption {
                        length,
                        option_type,
                    })
                } else {
                    return Err(UnknownSdOptionType(option_type));
                }
            }
        };
        Ok((3 + length, option))
    }

    #[inline]
    fn read_ip4_option<T: Read>(
        reader: &mut T,
    ) -> Result<([u8; 4], TransportProtocol, u16), SdReadError> {
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
    ) -> Result<([u8; 16], TransportProtocol, u16), SdReadError> {
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
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdWriteError> {
        use self::SdOption::*;

        fn write_ipv4<R: Write>(
            writer: &mut R,
            len: u16,
            t: u8,
            addr: [u8; 4],
            tp: TransportProtocol,
            port: u16,
        ) -> Result<(), SdWriteError> {
            let len_be = len.to_be_bytes();
            let port_be = port.to_be_bytes();
            writer.write_all(&[
                len_be[0],
                len_be[1],
                t,
                0,
                addr[0],
                addr[1],
                addr[2],
                addr[3],
                0,
                tp.into(),
                port_be[0],
                port_be[1],
            ])?;
            Ok(())
        }

        fn write_ipv6<R: Write>(
            writer: &mut R,
            len: u16,
            t: u8,
            addr: [u8; 16],
            tp: TransportProtocol,
            port: u16,
        ) -> Result<(), SdWriteError> {
            let len_be = len.to_be_bytes();
            let port_be = port.to_be_bytes();
            writer.write_all(&[
                len_be[0],
                len_be[1],
                t,
                0,
                addr[0],
                addr[1],
                addr[2],
                addr[3],
                addr[4],
                addr[5],
                addr[6],
                addr[7],
                addr[8],
                addr[9],
                addr[10],
                addr[11],
                addr[12],
                addr[13],
                addr[14],
                addr[15],
                0,
                tp.into(),
                port_be[0],
                port_be[1],
            ])?;
            Ok(())
        }

        match self {
            Configuration(c) => {
                let len_be = (1u16 + c.configuration_string.len() as u16).to_be_bytes();
                writer.write_all(&[
                    len_be[0],
                    len_be[1],
                    CONFIGURATION_TYPE,
                    if c.discardable { DISCARDABLE_FLAG } else { 0 },
                ])?;
                writer.write_all(&c.configuration_string)?;
                Ok(())
            }
            LoadBalancing(o) => {
                let len_be = LOAD_BALANCING_LEN.to_be_bytes();
                let prio_be = o.priority.to_be_bytes();
                let weight_be = o.weight.to_be_bytes();

                writer.write_all(&[
                    len_be[0],
                    len_be[1],
                    LOAD_BALANCING_TYPE,
                    if o.discardable { DISCARDABLE_FLAG } else { 0 },
                    prio_be[0],
                    prio_be[1],
                    weight_be[0],
                    weight_be[1],
                ])?;
                Ok(())
            }
            Ipv4Endpoint(o) => write_ipv4(
                writer,
                IPV4_ENDPOINT_LEN,
                IPV4_ENDPOINT_TYPE,
                o.ipv4_address,
                o.transport_protocol,
                o.port,
            ),
            Ipv6Endpoint(o) => write_ipv6(
                writer,
                IPV6_ENDPOINT_LEN,
                IPV6_ENDPOINT_TYPE,
                o.ipv6_address,
                o.transport_protocol,
                o.port,
            ),
            Ipv4Multicast(o) => write_ipv4(
                writer,
                IPV4_MULTICAST_LEN,
                IPV4_MULTICAST_TYPE,
                o.ipv4_address,
                o.transport_protocol,
                o.port,
            ),
            Ipv6Multicast(o) => write_ipv6(
                writer,
                IPV6_MULTICAST_LEN,
                IPV6_MULTICAST_TYPE,
                o.ipv6_address,
                o.transport_protocol,
                o.port,
            ),
            Ipv4SdEndpoint(o) => write_ipv4(
                writer,
                IPV4_SD_ENDPOINT_LEN,
                IPV4_SD_ENDPOINT_TYPE,
                o.ipv4_address,
                o.transport_protocol,
                o.port,
            ),
            Ipv6SdEndpoint(o) => write_ipv6(
                writer,
                IPV6_SD_ENDPOINT_LEN,
                IPV6_SD_ENDPOINT_TYPE,
                o.ipv6_address,
                o.transport_protocol,
                o.port,
            ),
            UnknownDiscardable(o) => Err(SdWriteError::ValueError(
                SdValueError::SdUnknownDiscardableOption(o.option_type),
            )),
        }
    }

    /// Serializes option and append data to a vec
    pub fn append_bytes_to_vec(&self, buffer: &mut Vec<u8>) -> Result<(), SdValueError> {
        use self::SdOption::*;

        fn append_ip4(
            buffer: &mut Vec<u8>,
            ipv4_address: [u8; 4],
            transport_protocol: TransportProtocol,
            port: u16,
        ) {
            buffer.extend_from_slice(&ipv4_address);
            buffer.push(0x00); // reserved
            buffer.push(transport_protocol.into());
            buffer.extend_from_slice(&port.to_be_bytes());
        }

        fn append_ip6(
            buffer: &mut Vec<u8>,
            ipv6_address: [u8; 16],
            transport_protocol: TransportProtocol,
            port: u16,
        ) {
            buffer.extend_from_slice(&ipv6_address);
            buffer.push(0x00); // reserved
            buffer.push(transport_protocol.into());
            buffer.extend_from_slice(&port.to_be_bytes());
        }

        match self {
            Configuration(o) => {
                // + 1 for reserved byte
                let length_bytes = (1u16 + o.configuration_string.len() as u16).to_be_bytes();
                buffer.extend_from_slice(&length_bytes);
                buffer.push(CONFIGURATION_TYPE);
                buffer.push(if o.discardable { DISCARDABLE_FLAG } else { 0 });
                buffer.extend_from_slice(&o.configuration_string);
            }
            LoadBalancing(o) => {
                buffer.extend_from_slice(&LOAD_BALANCING_LEN.to_be_bytes());
                buffer.push(LOAD_BALANCING_TYPE);
                buffer.push(if o.discardable { DISCARDABLE_FLAG } else { 0 });
                buffer.extend_from_slice(&o.priority.to_be_bytes());
                buffer.extend_from_slice(&o.weight.to_be_bytes());
            }
            Ipv4Endpoint(o) => {
                buffer.extend_from_slice(&IPV4_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV4_ENDPOINT_TYPE);
                buffer.push(0x00u8); // Reserved byte
                append_ip4(buffer, o.ipv4_address, o.transport_protocol, o.port);
            }
            Ipv6Endpoint(o) => {
                buffer.extend_from_slice(&IPV6_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV6_ENDPOINT_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(buffer, o.ipv6_address, o.transport_protocol, o.port);
            }
            Ipv4Multicast(o) => {
                buffer.extend_from_slice(&IPV4_MULTICAST_LEN.to_be_bytes());
                buffer.push(IPV4_MULTICAST_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip4(buffer, o.ipv4_address, o.transport_protocol, o.port);
            }
            Ipv6Multicast(o) => {
                buffer.extend_from_slice(&IPV6_MULTICAST_LEN.to_be_bytes());
                buffer.push(IPV6_MULTICAST_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(buffer, o.ipv6_address, o.transport_protocol, o.port);
            }
            Ipv4SdEndpoint(o) => {
                buffer.extend_from_slice(&IPV4_SD_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV4_SD_ENDPOINT_TYPE);
                buffer.push(0x00u8); // Reserved byte
                append_ip4(buffer, o.ipv4_address, o.transport_protocol, o.port);
            }
            Ipv6SdEndpoint(o) => {
                buffer.extend_from_slice(&IPV6_SD_ENDPOINT_LEN.to_be_bytes());
                buffer.push(IPV6_SD_ENDPOINT_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(buffer, o.ipv6_address, o.transport_protocol, o.port);
            }
            UnknownDiscardable(o) => {
                return Err(SdValueError::SdUnknownDiscardableOption(o.option_type));
            }
        }
        Ok(())
    }

    /// Serializes option and returns data as an ArrayVec (zero-allocation)
    ///
    /// This method provides a zero-allocation alternative to [`append_bytes_to_vec`].
    /// It returns an [`ArrayVec`] with a fixed capacity instead of appending to a [`Vec`].
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{*, options::*};
    ///
    /// let option = SdOption::Ipv4Endpoint(Ipv4EndpointOption {
    ///     ipv4_address: [192, 168, 1, 1],
    ///     transport_protocol: TransportProtocol::Udp,
    ///     port: 8080,
    /// });
    ///
    /// // Zero-allocation serialization
    /// let bytes = option.to_bytes().unwrap();
    /// assert_eq!(bytes.len(), 12); // 2 bytes length + 1 byte type + 1 byte reserved + 8 bytes data
    /// ```
    ///
    /// [`append_bytes_to_vec`]: SdOption::append_bytes_to_vec
    pub fn to_bytes(&self) -> Result<ArrayVec<u8, { MAX_OPTIONS_LEN_USIZE }>, SdValueError> {
        use self::SdOption::*;

        fn append_ip4(
            buffer: &mut ArrayVec<u8, { MAX_OPTIONS_LEN_USIZE }>,
            ipv4_address: [u8; 4],
            transport_protocol: TransportProtocol,
            port: u16,
        ) {
            buffer.try_extend_from_slice(&ipv4_address).unwrap();
            buffer.push(0x00); // reserved
            buffer.push(transport_protocol.into());
            buffer.try_extend_from_slice(&port.to_be_bytes()).unwrap();
        }

        fn append_ip6(
            buffer: &mut ArrayVec<u8, { MAX_OPTIONS_LEN_USIZE }>,
            ipv6_address: [u8; 16],
            transport_protocol: TransportProtocol,
            port: u16,
        ) {
            buffer.try_extend_from_slice(&ipv6_address).unwrap();
            buffer.push(0x00); // reserved
            buffer.push(transport_protocol.into());
            buffer.try_extend_from_slice(&port.to_be_bytes()).unwrap();
        }

        let mut buffer = ArrayVec::new();

        match self {
            Configuration(o) => {
                // + 1 for reserved byte
                let length_bytes = (1u16 + o.configuration_string.len() as u16).to_be_bytes();
                buffer.try_extend_from_slice(&length_bytes).unwrap();
                buffer.push(CONFIGURATION_TYPE);
                buffer.push(if o.discardable { DISCARDABLE_FLAG } else { 0 });
                buffer
                    .try_extend_from_slice(&o.configuration_string)
                    .unwrap();
            }
            LoadBalancing(o) => {
                buffer
                    .try_extend_from_slice(&LOAD_BALANCING_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(LOAD_BALANCING_TYPE);
                buffer.push(if o.discardable { DISCARDABLE_FLAG } else { 0 });
                buffer
                    .try_extend_from_slice(&o.priority.to_be_bytes())
                    .unwrap();
                buffer
                    .try_extend_from_slice(&o.weight.to_be_bytes())
                    .unwrap();
            }
            Ipv4Endpoint(o) => {
                buffer
                    .try_extend_from_slice(&IPV4_ENDPOINT_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(IPV4_ENDPOINT_TYPE);
                buffer.push(0x00u8); // Reserved byte
                append_ip4(&mut buffer, o.ipv4_address, o.transport_protocol, o.port);
            }
            Ipv6Endpoint(o) => {
                buffer
                    .try_extend_from_slice(&IPV6_ENDPOINT_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(IPV6_ENDPOINT_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(&mut buffer, o.ipv6_address, o.transport_protocol, o.port);
            }
            Ipv4Multicast(o) => {
                buffer
                    .try_extend_from_slice(&IPV4_MULTICAST_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(IPV4_MULTICAST_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip4(&mut buffer, o.ipv4_address, o.transport_protocol, o.port);
            }
            Ipv6Multicast(o) => {
                buffer
                    .try_extend_from_slice(&IPV6_MULTICAST_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(IPV6_MULTICAST_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(&mut buffer, o.ipv6_address, o.transport_protocol, o.port);
            }
            Ipv4SdEndpoint(o) => {
                buffer
                    .try_extend_from_slice(&IPV4_SD_ENDPOINT_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(IPV4_SD_ENDPOINT_TYPE);
                buffer.push(0x00u8); // Reserved byte
                append_ip4(&mut buffer, o.ipv4_address, o.transport_protocol, o.port);
            }
            Ipv6SdEndpoint(o) => {
                buffer
                    .try_extend_from_slice(&IPV6_SD_ENDPOINT_LEN.to_be_bytes())
                    .unwrap();
                buffer.push(IPV6_SD_ENDPOINT_TYPE); // Type
                buffer.push(0x00u8); // Reserved byte
                append_ip6(&mut buffer, o.ipv6_address, o.transport_protocol, o.port);
            }
            UnknownDiscardable(o) => {
                return Err(SdValueError::SdUnknownDiscardableOption(o.option_type));
            }
        }
        Ok(buffer)
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        use self::SdOption::*;

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
mod tests {
    use super::*;
    use crate::proptest_generators::*;
    use assert_matches::*;
    use proptest::prelude::*;
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
    fn to_bytes_matches_append_bytes_to_vec() {
        proptest!(|(option in someip_sd_option_any())| {
            // Skip UnknownDiscardable options as they return errors in both methods
            if matches!(option, SdOption::UnknownDiscardable(_)) {
                return Ok(());
            }

            // Test append_bytes_to_vec
            let mut vec_buffer = Vec::new();
            let append_result = option.append_bytes_to_vec(&mut vec_buffer);

            // Test to_bytes
            let array_result = option.to_bytes();

            match (append_result, array_result) {
                (Ok(()), Ok(array_vec)) => {
                    // Both should succeed and produce identical results
                    assert_eq!(vec_buffer, array_vec.as_slice());
                }
                (Err(e1), Err(e2)) => {
                    // Both should fail with the same error type
                    assert_eq!(std::mem::discriminant(&e1), std::mem::discriminant(&e2));
                }
                _ => {
                    panic!("append_bytes_to_vec and to_bytes should have consistent behavior");
                }
            }
        });
    }

    #[test]
    fn read() {
        // too small length error
        {
            let buffer = [0x00, 0x00, IPV4_ENDPOINT_TYPE, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(result, Err(SdReadError::SdOptionLengthZero));
        }
        // configuration option length too large
        {
            let too_large = (ConfigurationOption::MAX_CONFIGURATION_STRING_LEN as u16) + 2;
            let len_be = too_large.to_be_bytes();
            let buffer = [len_be[0], len_be[1], CONFIGURATION_TYPE, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(
                result,
                Err(SdReadError::SdConfigurationOptionLenTooLarge(v)) if v == too_large
            );
        }
        // ipv4 length check errors
        for t in [
            IPV4_ENDPOINT_TYPE,
            IPV4_MULTICAST_TYPE,
            IPV4_SD_ENDPOINT_TYPE,
        ] {
            let buffer = [0x00, 0x01, t, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(
                result,
                Err(SdReadError::SdOptionUnexpectedLen {
                    expected_len: 0x9,
                    actual_len: 0x1,
                    option_type: _,
                })
            );
        }
        // ipv6 length check errors
        for t in [
            IPV6_ENDPOINT_TYPE,
            IPV6_MULTICAST_TYPE,
            IPV6_SD_ENDPOINT_TYPE,
        ] {
            let buffer = [0x00, 0x01, t, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(
                result,
                Err(SdReadError::SdOptionUnexpectedLen {
                    expected_len: 0x15,
                    actual_len: 0x1,
                    option_type: _,
                })
            );
        }
        // unknown option type (non discardable)
        {
            let buffer = [0x00, 0x01, 0xff, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let result = SdOption::read(&mut cursor);
            assert_matches!(result, Err(SdReadError::UnknownSdOptionType(0xFF)));
        }
        // unknown option type (non discardable, discard option set)
        {
            let buffer = [0x00, 0x01, 0xff, 0x00];
            let mut cursor = std::io::Cursor::new(buffer);
            let (len, header) = SdOption::read_with_flag(&mut cursor, true).unwrap();
            assert_eq!(
                header,
                UnknownDiscardableOption {
                    length: 1,
                    option_type: 0xff,
                }
                .into()
            );
            assert_eq!(4, len);
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
                }
                .into()
            );
            assert_eq!(4, len);
        }
    }
}
