use crate::*;

/// Deprecated use [`SomeipHeader`] instead.
#[deprecated(
    since = "0.5.0",
    note = "Use SomeipHeader instead (renamed, 'i' is lower case now)."
)]
pub type SomeIpHeader = SomeipHeader;

///SOMEIP header (including tp header if present).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeipHeader {
    pub message_id: u32,
    pub length: u32,
    pub request_id: u32,
    pub interface_version: u8,
    ///Message type (does not contain the tp flag, this is determined if something is present in the tp_header field).
    pub message_type: MessageType,
    pub return_code: u8, //TODO replace with enum?
    ///Contains a tp header (Transporting large SOME/IP messages of UDP [SOME/IP-TP]).
    ///
    ///If there is a tp header a someip payload is split over multiple messages and the tp header contains the
    ///start offset of the payload of this message relative to the completly assembled payload.
    pub tp_header: Option<TpHeader>,
}

impl SomeipHeader {
    ///Create a service discovery message header.
    pub fn new_sd_header(length: u32, session_id: u16, tp_header: Option<TpHeader>) -> Self {
        Self {
            message_id: SOMEIP_SD_MESSAGE_ID, // defined in spec
            length,
            request_id: session_id as u32, // client-id is 0x00
            interface_version: 0x01,       // defined in spec
            message_type: MessageType::Notification, // defined in spec
            return_code: 0x00,             // defined in spec
            tp_header,
        }
    }

    ///Returns the service id (first 16 bits of the message id)
    #[inline]
    pub fn service_id(&self) -> u16 {
        ((self.message_id & 0xffff_0000) >> 16) as u16
    }

    ///Set the servide id (first 16 bits of the message id)
    #[inline]
    pub fn set_service_id(&mut self, service_id: u16) {
        self.message_id = (self.message_id & 0x0000_ffff) | (u32::from(service_id) << 16);
    }

    ///Set the event id + the event bit.
    #[inline]
    pub fn set_event_id(&mut self, event_id: u16) {
        self.message_id = (self.message_id & 0xffff_0000) | u32::from(0x8000 | event_id);
    }

    ///Set the event id + the event bit to 0. Asserting method_id <= 0x7FFF (otherwise the )
    #[inline]
    pub fn set_method_id(&mut self, method_id: u16) {
        debug_assert!(method_id <= 0x7FFF);
        self.message_id = (self.message_id & 0xffff_0000) | u32::from(0x7fff & method_id);
    }

    ///Sets the event id or method id. This number mjust include the "event bit".
    #[inline]
    pub fn set_method_or_event_id(&mut self, method_id: u16) {
        self.message_id = (self.message_id & 0xffff_0000) | u32::from(method_id);
    }

    ///Returns true if the message has the message id of a some ip service discovery message.
    #[inline]
    pub fn is_someip_sd(&self) -> bool {
        SOMEIP_SD_MESSAGE_ID == self.message_id
    }

    ///Returns true if the event or notification bit in the message id is set
    #[inline]
    pub fn is_event(&self) -> bool {
        0 != self.message_id & 0x8000
    }

    ///Return the event id or method id. This number includes the "event bit".
    #[inline]
    pub fn event_or_method_id(&self) -> u16 {
        (self.message_id & 0x0000_ffff) as u16
    }

    ///Return the event id. `None` if event bit is not set.
    #[inline]
    pub fn event_id(&self) -> Option<u16> {
        if self.is_event() {
            Some(self.event_or_method_id() & 0x7fff)
        } else {
            None
        }
    }

    ///Return the method id. `None` if event bit is set.
    #[inline]
    pub fn method_id(&self) -> Option<u16> {
        if !self.is_event() {
            Some(self.event_or_method_id() & 0x7fff)
        } else {
            None
        }
    }

    ///Serialize the header.
    pub fn write_raw<T: std::io::Write>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.base_to_bytes())?;
        if let Some(ref tp) = self.tp_header {
            tp.write(writer)?;
        }
        Ok(())
    }

    /// Returns the encoded SOMEIP header (without the TP header).
    #[inline]
    pub fn base_to_bytes(&self) -> [u8; SOMEIP_HEADER_LENGTH] {
        let message_id_be = self.message_id.to_be_bytes();
        let length_be = self.length.to_be_bytes();
        let request_id_be = self.request_id.to_be_bytes();
        [
            message_id_be[0],
            message_id_be[1],
            message_id_be[2],
            message_id_be[3],
            length_be[0],
            length_be[1],
            length_be[2],
            length_be[3],
            request_id_be[0],
            request_id_be[1],
            request_id_be[2],
            request_id_be[3],
            SOMEIP_PROTOCOL_VERSION,
            self.interface_version,
            match self.tp_header {
                Some(_) => (self.message_type.clone() as u8) | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
                None => self.message_type.clone() as u8,
            },
            self.return_code,
        ]
    }

    ///Read a header from a byte stream.
    pub fn read<T: std::io::Read>(
        reader: &mut T,
    ) -> Result<SomeipHeader, err::SomeipHeaderReadError> {
        use err::{SomeipHeaderError::*, SomeipHeaderReadError::*};

        // read the header
        let mut header_bytes: [u8; SOMEIP_HEADER_LENGTH] = [0; SOMEIP_HEADER_LENGTH];
        reader.read_exact(&mut header_bytes).map_err(Io)?;

        // validate length
        let length = u32::from_be_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);
        if length < SOMEIP_LEN_OFFSET_TO_PAYLOAD {
            return Err(Content(LengthFieldTooSmall(length)));
        }

        // validate protocol version
        let protocol_version = header_bytes[12];
        if SOMEIP_PROTOCOL_VERSION != protocol_version {
            return Err(Content(UnsupportedProtocolVersion(protocol_version)));
        }

        // validate message type
        let message_type_raw = header_bytes[14];
        let message_type = {
            use MessageType::*;
            //check that message type is valid
            match message_type_raw & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 => Request,
                0x1 => RequestNoReturn,
                0x2 => Notification,
                0x80 => Response,
                0x81 => Error,
                _ => return Err(Content(UnknownMessageType(message_type_raw))),
            }
        };

        Ok(SomeipHeader {
            message_id: u32::from_be_bytes([
                header_bytes[0],
                header_bytes[1],
                header_bytes[2],
                header_bytes[3],
            ]),
            length,
            request_id: u32::from_be_bytes([
                header_bytes[8],
                header_bytes[9],
                header_bytes[10],
                header_bytes[11],
            ]),
            interface_version: header_bytes[13],
            message_type,
            return_code: header_bytes[15],
            //read the tp header if the flag is set
            tp_header: if 0 != message_type_raw & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG {
                Some(TpHeader::read(reader).map_err(Io)?)
            } else {
                None
            },
        })
    }
}

impl Default for SomeipHeader {
    fn default() -> SomeipHeader {
        SomeipHeader {
            message_id: 0,
            length: SOMEIP_LEN_OFFSET_TO_PAYLOAD,
            request_id: 0,
            interface_version: 0,
            message_type: MessageType::Request,
            return_code: 0,
            tp_header: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::proptest_generators::*;
    use super::*;
    use proptest::prelude::*;
    use std::io::{Cursor, Write};
    use MessageType::*;

    const MESSAGE_TYPE_VALUES: &[MessageType; 5] =
        &[Request, RequestNoReturn, Notification, Response, Error];

    const MESSAGE_TYPE_VALUES_RAW: &[u8; 10] = &[
        Request as u8,
        RequestNoReturn as u8,
        Notification as u8,
        Response as u8,
        Error as u8,
        Request as u8 | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
        RequestNoReturn as u8 | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
        Notification as u8 | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
        Response as u8 | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
        Error as u8 | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
    ];

    #[test]
    fn default() {
        let header: SomeipHeader = Default::default();
        assert_eq!(0, header.message_id);
        assert_eq!(SOMEIP_LEN_OFFSET_TO_PAYLOAD, header.length);
        assert_eq!(0, header.request_id);
        assert_eq!(0, header.interface_version);
        assert_eq!(MessageType::Request, header.message_type);
        assert_eq!(None, header.tp_header);
        assert_eq!(0, header.return_code);
    }

    proptest! {
        #[test]
        fn write_read(ref input_base in someip_header_any()) {
            for message_type in MESSAGE_TYPE_VALUES {
                let input = {
                    let mut value = input_base.clone();
                    value.message_type = message_type.clone();
                    value
                };
                let mut buffer = Vec::new();
                input.write_raw(&mut buffer).unwrap();

                //read the header
                let mut cursor = Cursor::new(&buffer);
                let result = SomeipHeader::read(&mut cursor).unwrap();
                assert_eq!(input, result);

                //check that a too smal cursor results in an io error
                {
                    let buffer_len = buffer.len();
                    assert!(SomeipHeader::read(&mut Cursor::new(&buffer[..buffer_len-1])).unwrap_err().io_error().is_some());
                }
            }
        }
    }

    proptest! {
        #[test]
        fn from_slice(length in SOMEIP_LEN_OFFSET_TO_PAYLOAD..1234,
                      ref input_base in someip_header_any(),
                      add in 0usize..15) {
            for message_type in MESSAGE_TYPE_VALUES {
                //calculate the length based on if there tp header is present
                let length = if input_base.tp_header.is_some() {
                    length + TP_HEADER_LENGTH as u32
                } else {
                    length
                };

                let input = {
                    let mut value = input_base.clone();
                    value.length = length;
                    value.message_type = message_type.clone();
                    value
                };

                let mut buffer = Vec::new();
                input.write_raw(&mut buffer).unwrap();

                //add some payload
                let expected_length =
                    length as usize
                    + (SOMEIP_HEADER_LENGTH - SOMEIP_LEN_OFFSET_TO_PAYLOAD as usize);
                buffer.resize(expected_length + add, 0);

                //from_slice
                let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(input.message_id, slice.message_id());
                assert_eq!(input.length, slice.length());
                assert_eq!(input.request_id, slice.request_id());
                assert_eq!(SOMEIP_PROTOCOL_VERSION, slice.protocol_version());
                assert_eq!(input.interface_version, slice.interface_version());
                assert_eq!(input.message_type, slice.message_type());
                assert_eq!(input.tp_header, slice.tp_header());
                assert_eq!(input.tp_header.is_some(), slice.is_tp());
                assert_eq!(input.return_code, slice.return_code());
                assert_eq!(&buffer[(
                    if input.tp_header.is_some() {
                        SOMEIP_HEADER_LENGTH + TP_HEADER_LENGTH
                    } else {
                        SOMEIP_HEADER_LENGTH
                    }
                )..expected_length], slice.payload());

                //internal slice checking
                assert_eq!(&buffer[..expected_length], slice.slice());

                //to_header
                assert_eq!(input, slice.to_header());

                //check that a too small slice triggers an error
                use err::{*, SomeipSliceError::*};
                assert_eq!(
                    SomeipMsgSlice::from_slice(&buffer[..expected_length-1]),
                    Err(Len(LenError {
                        required_len: expected_length,
                        len: expected_length - 1,
                        len_source: LenSource::SomeipHeaderLength,
                        layer: Layer::SomeipPayload
                    }))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn unknown_message_type(length in SOMEIP_LEN_OFFSET_TO_PAYLOAD..1234,
                                ref input_base in someip_header_any(),
                                message_type in any::<u8>().prop_filter("message type must be unknown",
                               |v| !MESSAGE_TYPE_VALUES_RAW.iter().any(|&x| (v == &x ||
                                                                             (SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG | v) == x)))
            )
        {
            //add the tp header length in case the tp flag is set
            let length = if 0 != (SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG & message_type) {
                length + 4
            } else {
                length
            };

            let input = {
                let mut value = input_base.clone();
                value.length = length;
                value
            };

            //serialize to buffer
            let mut buffer = Vec::new();
            input.write_raw(&mut buffer).unwrap();

            //add some payload
            let expected_length = length as usize + (SOMEIP_HEADER_LENGTH - SOMEIP_LEN_OFFSET_TO_PAYLOAD as usize);
            buffer.resize(expected_length, 0);

            //insert the invalid message type
            buffer[14] = message_type;

            //check that deserialization triggers an error
            use err::{SomeipSliceError::*, SomeipHeaderError::*};
            assert_eq!(
                SomeipHeader::read(&mut Cursor::new(&buffer)).unwrap_err().content_error(),
                Some(UnknownMessageType(message_type))
            );
            assert_eq!(
                SomeipMsgSlice::from_slice(&buffer),
                Err(Content(UnknownMessageType(message_type)))
            );
        }
    }

    #[test]
    fn read_unsupported_protocol_version() {
        let mut buffer = Vec::new();
        SomeipHeader::default().write_raw(&mut buffer).unwrap();
        //set the protocol to an unsupported version
        buffer[4 * 3] = 0;
        let mut cursor = Cursor::new(&buffer);
        let result = SomeipHeader::read(&mut cursor);
        use err::{SomeipHeaderError::*, SomeipSliceError::*};
        assert_eq!(
            result.unwrap_err().content_error(),
            Some(UnsupportedProtocolVersion(0))
        );
        assert_eq!(
            SomeipMsgSlice::from_slice(&buffer[..]),
            Err(Content(UnsupportedProtocolVersion(0)))
        );
    }

    #[test]
    fn read_too_small_length_field() {
        //0
        {
            let mut buffer = Vec::new();
            SomeipHeader::default().write_raw(&mut buffer).unwrap();
            //set the length to 0
            {
                buffer[4] = 0;
                buffer[5] = 0;
                buffer[6] = 0;
                buffer[7] = 0;
            }
            let mut cursor = Cursor::new(&buffer);
            let result = SomeipHeader::read(&mut cursor);
            use err::{SomeipHeaderError::*, SomeipSliceError::*};
            assert_eq!(
                result.unwrap_err().content_error(),
                Some(LengthFieldTooSmall(0))
            );
            //check the from_slice method
            assert_eq!(
                SomeipMsgSlice::from_slice(&buffer[..]),
                Err(Content(LengthFieldTooSmall(0)))
            );
        }
        //SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1
        {
            let mut buffer = Vec::new();
            SomeipHeader::default().write_raw(&mut buffer).unwrap();
            //set the length to SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1
            const TOO_SMALL: u32 = SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1;
            {
                let length_be = TOO_SMALL.to_be_bytes();
                buffer[4] = length_be[0];
                buffer[5] = length_be[1];
                buffer[6] = length_be[2];
                buffer[7] = length_be[3];
            }
            let mut cursor = Cursor::new(&buffer);
            let result = SomeipHeader::read(&mut cursor);
            use err::{SomeipHeaderError::*, SomeipSliceError::*};
            assert_eq!(
                result.unwrap_err().content_error(),
                Some(LengthFieldTooSmall(TOO_SMALL))
            );
            assert_eq!(
                SomeipMsgSlice::from_slice(&buffer[..]),
                Err(Content(LengthFieldTooSmall(TOO_SMALL)))
            );
        }
    }

    proptest! {
        #[test]
        fn service_id(packet in someip_header_with_payload_any(),
                      service_id in 0x0u16..std::u16::MAX)
        {
            let mut header = packet.0.clone();
            header.set_service_id(service_id);
            assert_eq!(service_id, header.service_id());

            //serialize and check the slice methods
            let mut buffer = Vec::new();
            header.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();
            let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(service_id, slice.service_id());
        }
    }

    proptest! {
        #[test]
        fn set_get_method_id(packet in someip_header_with_payload_any(),
                             method_id in 0u16..0x7fff)
        {
            let mut header = packet.0.clone();
            header.set_method_id(method_id);

            assert_eq!(method_id, header.event_or_method_id());
            assert_eq!(Some(method_id), header.method_id());
            assert_eq!(false, header.is_event());
            assert_eq!(None, header.event_id());

            //serialize and check the slice methods
            let mut buffer = Vec::new();
            header.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();
            let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(false, slice.is_event());
            assert_eq!(Some(method_id), slice.method_id());
            assert_eq!(method_id, slice.event_or_method_id());
            assert_eq!(None, slice.event_id());
        }
    }

    proptest! {
        #[test]
        fn set_get_event_id(packet in someip_header_with_payload_any(),
                            event_id in 0u16..0x7fff)
        {
            let mut header = packet.0.clone();
            header.set_event_id(event_id);

            let id_with_bit = event_id | 0x8000;

            assert_eq!(id_with_bit, header.event_or_method_id());
            assert_eq!(Some(event_id), header.event_id());
            assert_eq!(true, header.is_event());
            assert_eq!(None, header.method_id());

            //serialize and check the slice methods
            let mut buffer = Vec::new();
            header.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();
            let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(true, slice.is_event());
            assert_eq!(id_with_bit, slice.event_or_method_id());
            assert_eq!(Some(event_id), slice.event_id());
            assert_eq!(None, slice.method_id());
        }
    }

    proptest! {
        #[test]
        fn set_method_or_event_id(packet in someip_header_with_payload_any(),
                                  id in 0x0u16..std::u16::MAX)
        {
            let mut header = packet.0.clone();
            header.set_method_or_event_id(id);

            assert_eq!(id, header.event_or_method_id());
            assert_eq!(id > 0x8000, header.is_event());

            //serialize and check the slice methods
            let mut buffer = Vec::new();
            header.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();
            let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(id > 0x8000, slice.is_event());
            assert_eq!(id, slice.event_or_method_id());
        }
    }

    proptest! {
        #[test]
        fn is_someip_sd(packet in someip_header_with_payload_any())
        {
            const SD_MESSAGE_ID: u32 = 0xFFFF8100;

            let mut header = packet.0.clone();
            header.message_id = SD_MESSAGE_ID;

            assert_eq!(true, header.is_someip_sd());
            assert_eq!(packet.0.message_id == SD_MESSAGE_ID, packet.0.is_someip_sd());

            //serialize and check the slice methods
            //some ip sd packet
            {
                let mut buffer = Vec::new();
                header.write_raw(&mut buffer).unwrap();
                buffer.write(&packet.1[..]).unwrap();
                let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();

                assert_eq!(true, slice.is_someip_sd());
            }
            //random packet
            {
                let mut buffer = Vec::new();
                packet.0.write_raw(&mut buffer).unwrap();
                buffer.write(&packet.1[..]).unwrap();
                let slice = SomeipMsgSlice::from_slice(&buffer[..]).unwrap();

                assert_eq!(packet.0.message_id == SD_MESSAGE_ID, slice.is_someip_sd());
            }
        }
    }
}
