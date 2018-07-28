use std::io::{Read, Write};

extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt, ByteOrder, WriteBytesExt};

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
#[cfg(test)]
#[macro_use]
extern crate proptest;
#[cfg(test)]
mod proptest_generators;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeIpHeader {
    pub message_id: u32,
    length: u32,
    pub request_id: u32,
    pub interface_version: u8,
    pub message_type: MessageType,
    ///If true the tp flag in the message type is set (Transporting large SOME/IP messages of UDP [SOME/IP-TP])
    pub message_type_tp: bool,
    pub return_code: u8 //TODO replace with enum?
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageType {
    Request = 0x0,
    RequestNoReturn = 0x1,
    Notification = 0x2,
    Response = 0x80,
    Error = 0x81
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReturnCode {
    Ok,// = 0x00,
    NotOk,// = 0x01,
    UnknownService,// = 0x02,
    NotReady,// = 0x03,
    NotReachable,// = 0x05,
    Timeout,// = 0x06,
    WrongProtocolVersion,// = 0x07,
    WrongInterfaceVersion,// = 0x08,
    MalformedMessage,// = 0x09,
    WrongMessageType,// = 0x0a,
    Generic(u8),
    InterfaceError(u8),
}

///The currently supported protocol version.
pub const SOMEIP_PROTOCOL_VERSION: u8 = 1;

///Offset that must be substracted from the length field to determine the 
pub const SOMEIP_LEN_OFFSET_TO_PAYLOAD: u32 = 4*2; // 2x 32bits

///Maximum payload length supported by some ip.
pub const SOMEIP_MAX_PAYLOAD_LEN: u32 = std::u32::MAX - SOMEIP_LEN_OFFSET_TO_PAYLOAD;

///Length of a someip header.
pub const SOMEIP_HEADER_LENGTH: usize = 4*4;

///Length of a someip header.
pub const SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG: u8 = 0x20;

impl SomeIpHeader {
    ///Return the length of the payload based on the length field in the header.
    pub fn payload_len(&self) -> u32 {
        debug_assert!(self.length >= SOMEIP_LEN_OFFSET_TO_PAYLOAD);
        self.length - SOMEIP_LEN_OFFSET_TO_PAYLOAD
    }

    ///Set the length of the payload (automatically adds 8 bytes).
    ///
    ///Returns an error if the given value is bigger then SOMEIP_MAX_PAYLOAD_LEN.
    pub fn set_payload_len(&mut self, value: u32) -> Result<(), ValueError> {
        if value > SOMEIP_MAX_PAYLOAD_LEN {
            Err(ValueError::LengthTooLarge(value))
        } else {
            self.length = value + SOMEIP_LEN_OFFSET_TO_PAYLOAD;
            Ok(())
        }
    }

    ///Serialize the header.
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_u32::<BigEndian>(self.message_id)?;
        writer.write_u32::<BigEndian>(self.length)?;
        writer.write_u32::<BigEndian>(self.request_id)?;
        writer.write_u8(SOMEIP_PROTOCOL_VERSION)?;
        writer.write_u8(self.interface_version)?;
        writer.write_u8({
             if self.message_type_tp { 
                (self.message_type.clone() as u8) | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG
            } else {
                (self.message_type.clone() as u8)
            }
        })?;
        writer.write_u8(self.return_code)?;
        Ok(())
    }

    ///Read a header from a byte stream.
    pub fn read<T: Read>(reader: &mut T) -> Result<SomeIpHeader, ReadError> {
        use ReadError::*;
        let message_type;
        Ok(SomeIpHeader {
            message_id: reader.read_u32::<BigEndian>()?,
            length: {
                let len = reader.read_u32::<BigEndian>()?;
                if len < SOMEIP_LEN_OFFSET_TO_PAYLOAD {
                    return Err(LengthFieldTooSmall(len));
                }
                len
            },
            request_id: reader.read_u32::<BigEndian>()?,
            interface_version: {
                //read the protocol version and generate an error if the version is non matching
                let protocol_version = reader.read_u8()?;
                if SOMEIP_PROTOCOL_VERSION != protocol_version {
                    return Err(UnsupportedProtocolVersion(protocol_version));
                }
                //now read the interface version
                reader.read_u8()?
            },
            message_type: {
                use MessageType::*;
                //set message type (required for the flag afterwords)
                message_type = reader.read_u8()?;
                //check that message type is valid
                match message_type & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                    0x0 => Request,
                    0x1 => RequestNoReturn,
                    0x2 => Notification,
                    0x80 => Response,
                    0x81 => Error,
                    _ => return Err(UnknownMessageType(message_type))
                }
            },
            message_type_tp: 0 != message_type & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
            return_code: reader.read_u8()?
        })
    }
}

///A slice containing an some ip header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeIpHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> SomeIpHeaderSlice<'a> {

    #[cfg(target_pointer_width = "64")] 
    pub fn from_slice(slice: &'a[u8]) -> Result<SomeIpHeaderSlice, ReadError> {
        use ReadError::*;
        //first check the length
        if slice.len() < SOMEIP_HEADER_LENGTH {
            Err(UnexpectedEndOfSlice(slice.len()))
        } else {
            //check length
            let len = BigEndian::read_u32(&slice[4..8]);
            if len < SOMEIP_LEN_OFFSET_TO_PAYLOAD {
                return Err(LengthFieldTooSmall(len));
            }
            //NOTE: In case you want to write a 32 bit version, a check needs to be added, so that
            //      no accidental overflow when adding the 4*2 bytes happens.
            let total_length = (len as usize) + 4*2;
            if slice.len() < total_length {
                return Err(UnexpectedEndOfSlice(slice.len()))
            }
            //check protocol version
            let protocol_version = slice[4*3];
            if SOMEIP_PROTOCOL_VERSION != protocol_version {
                return Err(UnsupportedProtocolVersion(protocol_version));
            }
            //check message type
            let message_type = slice[4*3 + 2];
            match message_type & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 | 0x1 | 0x2 | 0x80 | 0x81 => {},
                _ => return Err(UnknownMessageType(message_type))
            }
            //all good generate the slice
            Ok(SomeIpHeaderSlice {
                slice: &slice[..total_length]
            })
        }
    }

    ///Return the slice that contains the someip header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Returns the message id of the message.
    pub fn message_id(&self) -> u32 {
        BigEndian::read_u32(&self.slice[..4])
    }

    //TODO is some ip service discovery message
    //TODO service id
    //TODO method/event id

    ///Returns the length contained in the header. WARNING: the length paritally 
    ///contains the header and partially the payload, use the payload() method 
    ///instead if you want to access the payload slice).
    pub fn length(&self) -> u32 {
        BigEndian::read_u32(&self.slice[4..8])
    }

    ///Returns the request id of the message.
    pub fn request_id(&self) -> u32 {
        BigEndian::read_u32(&self.slice[8..12])
    }

    ///Return the value of the protocol version field of the message (must match SOMEIP_PROTOCOL_VERSION, unless something dark and unsafe is beeing done).
    #[inline]
    pub fn protocol_version(&self) -> u8 {
        debug_assert!(SOMEIP_PROTOCOL_VERSION == self.slice[12]);
        self.slice[12]
    }

    ///Returns the interface version field of the message.
    #[inline]
    pub fn interface_version(&self) -> u8 {
        self.slice[13]
    }

    ///Return the message type (does not contain the tp flag, use the message_type_tp method for 
    ///checking if this is a tp message).
    pub fn message_type(&self) -> MessageType {
        use MessageType::*;
        match self.message_type_raw() & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
            0x0 => Request,
            0x1 => RequestNoReturn,
            0x2 => Notification,
            0x80 => Response,
            0x81 => Error,
            _ => panic!("unknown message type, this should not happen as the message type gets verified during the construction of SomeIpHeaderSlice")
        }
    }

    ///Returns the raw message type value (contains the tp flag).
    #[inline]
    pub fn message_type_raw(&self) -> u8 {
        self.slice[14]
    }

    ///Returns true if the tp flag in the message type is set (Transporting large SOME/IP messages of UDP [SOME/IP-TP])
    pub fn message_type_tp(&self) -> bool {
        0 != self.slice[14] & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG
    }

    ///Returns the return code of the message.
    #[inline]
    pub fn return_code(&self) -> u8 {
        self.slice[15]
    }

    ///Return a slice to the payload of the someip header.
    pub fn payload(&self) -> &'a [u8] {
        &self.slice[SOMEIP_HEADER_LENGTH..]
    }

    ///Decode all the fields and copy the results to a SomeIpHeader struct
    pub fn to_header(&self) -> SomeIpHeader {
        SomeIpHeader {
            message_id: self.message_id(),
            length: self.length(),
            request_id: self.request_id(),
            interface_version: self.interface_version(),
            message_type: self.message_type(),
            message_type_tp: self.message_type_tp(),
            return_code: self.return_code()
        }
    }
}

impl Default for SomeIpHeader {
    fn default() -> SomeIpHeader {
        SomeIpHeader{
            message_id: 0,
            length: SOMEIP_LEN_OFFSET_TO_PAYLOAD,
            request_id: 0,
            interface_version: 0,
            message_type: MessageType::Request,
            message_type_tp: false,
            return_code: 0
        }
    }
}

#[derive(Debug)]
pub enum ReadError {
    IoError(std::io::Error),
    ///The slice length was not large enough to contain the header.
    UnexpectedEndOfSlice(usize),
    ///Error when the protocol version field contains a version that is not supported by this library (aka != SOMEIP_PROTOCOL_VERSION)
    UnsupportedProtocolVersion(u8),
    ///Error returned when a someip header has a value in the length field that is smaller then the rest of someip header itself (8 bytes).
    LengthFieldTooSmall(u32),
    ///Error when the message type field contains an unknown value
    UnknownMessageType(u8),
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueError {
    ///Payload length is too long as 8 bytes for the header have to be added.
    LengthTooLarge(u32)
}

#[cfg(test)]
mod tests_someip_header {
    use super::*;
    use super::proptest_generators::*;
    use proptest::prelude::*;
    use std::io::Cursor;
    use MessageType::*;
    use ReadError::*;

    const MESSAGE_TYPE_VALUES: &'static [MessageType;5] = &[
        Request,
        RequestNoReturn,
        Notification,
        Response,
        Error
    ];

    const MESSAGE_TYPE_VALUES_RAW: &'static [u8;10] = &[
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
        let header: SomeIpHeader = Default::default();
        assert_eq!(0, header.message_id);
        assert_eq!(SOMEIP_LEN_OFFSET_TO_PAYLOAD, header.length);
        assert_eq!(0, header.request_id);
        assert_eq!(0, header.interface_version);
        assert_eq!(MessageType::Request, header.message_type);
        assert_eq!(false, header.message_type_tp);
        assert_eq!(0, header.return_code);
    }

    #[test]
    fn payload_len() {
        //test valid values
        for i in &[0,1,2,3, SOMEIP_MAX_PAYLOAD_LEN - 1, SOMEIP_MAX_PAYLOAD_LEN] {
            let mut header = SomeIpHeader::default();
            assert_eq!(Ok(()), header.set_payload_len(*i));
            assert_eq!(i + SOMEIP_LEN_OFFSET_TO_PAYLOAD, header.length);
            assert_eq!(*i, header.payload_len());
        }

        //test that not allowed payload lengths generate an error
        for i in SOMEIP_MAX_PAYLOAD_LEN + 1..std::u32::MAX {
            let mut header = SomeIpHeader::default();
            assert_eq!(SOMEIP_LEN_OFFSET_TO_PAYLOAD, header.length);
            assert_eq!(Err(ValueError::LengthTooLarge(i)), header.set_payload_len(i));
            assert_eq!(SOMEIP_LEN_OFFSET_TO_PAYLOAD, header.length);
        }
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
                input.write(&mut buffer).unwrap();

                //read the header
                let mut cursor = Cursor::new(&buffer);
                let result = SomeIpHeader::read(&mut cursor).unwrap();
                assert_eq!(input, result);
            }
        }
    }

    proptest! {
        #[test]
        fn from_slice(length in SOMEIP_LEN_OFFSET_TO_PAYLOAD..1234,
                      ref input_base in someip_header_any(),
                      add in 0usize..15) {
            for message_type in MESSAGE_TYPE_VALUES {
                let input = {
                    let mut value = input_base.clone();
                    value.length = length;
                    value.message_type = message_type.clone();
                    value
                };

                let mut buffer = Vec::new();
                input.write(&mut buffer).unwrap();

                //add some payload
                let expected_length = length as usize + (SOMEIP_HEADER_LENGTH - SOMEIP_LEN_OFFSET_TO_PAYLOAD as usize);
                buffer.resize(expected_length + add, 0);

                //from_slice
                let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(input.message_id, slice.message_id());
                assert_eq!(input.length, slice.length());
                assert_eq!(input.request_id, slice.request_id());
                assert_eq!(input.interface_version, slice.interface_version());
                assert_eq!(input.message_type, slice.message_type());
                assert_eq!(input.message_type_tp, slice.message_type_tp());
                assert_eq!(input.return_code, slice.return_code());
                assert_eq!(&buffer[SOMEIP_HEADER_LENGTH..expected_length], slice.payload());
                assert_eq!(&buffer[..expected_length], slice.slice);

                //check that a too small slice triggers an error
                use ReadError::*;
                assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..expected_length-1]), Err(UnexpectedEndOfSlice(_)));
                assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..1]), Err(UnexpectedEndOfSlice(_)));
            }
        }
    }

    proptest! {
        #[test]
        fn unknown_message_type(length in SOMEIP_LEN_OFFSET_TO_PAYLOAD..1234,
                                ref input_base in someip_header_any(),
                                message_type in any::<u8>().prop_filter("message type must be unknown",
                               |v| !MESSAGE_TYPE_VALUES_RAW.iter().any(|&x| v == &x)))
        {
            let input = {
                let mut value = input_base.clone();
                value.length = length;
                value
            };

            //serialize to buffer
            let mut buffer = Vec::new();
            input.write(&mut buffer).unwrap();

            //add some payload
            let expected_length = length as usize + (SOMEIP_HEADER_LENGTH - SOMEIP_LEN_OFFSET_TO_PAYLOAD as usize);
            buffer.resize(expected_length, 0);

            //insert the invalid message type
            buffer[14] = message_type;

            //check that deserialization triggers an error
            assert_matches!(SomeIpHeader::read(&mut Cursor::new(&buffer)), Err(UnknownMessageType(_)));
            assert_matches!(SomeIpHeaderSlice::from_slice(&buffer), Err(UnknownMessageType(_)));
        }
    }

    proptest! {
        #[test]
        #[should_panic]
        fn unknown_message_type_slice_getter(message_type in any::<u8>().prop_filter("message type must be unknown",
                               |v| !MESSAGE_TYPE_VALUES_RAW.iter().any(|&x| v == &x)))
        {
            //serialize to buffer
            let buffer: [u8;16] = {
                let mut value = [0;16];
                value[14] = message_type;
                value
            };

            //create the type
            let slice = SomeIpHeaderSlice {
                slice: &buffer
            };

            //trigger the panic
            slice.message_type()
        }
    }

    #[test]
    fn read_unsupported_protocol_version() {
        let mut buffer = Vec::new();
        SomeIpHeader::default().write(&mut buffer).unwrap();
        //set the protocol to an unsupported version
        buffer[4*3] = 0;
        let mut cursor = Cursor::new(&buffer);
        let result = SomeIpHeader::read(&mut cursor);
        assert_matches!(result, Err(ReadError::UnsupportedProtocolVersion(0)));
        assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..]), Err(ReadError::UnsupportedProtocolVersion(0)));
    }

    #[test]
    fn read_too_small_length() {
        //0
        {
            let mut buffer = Vec::new();
            SomeIpHeader::default().write(&mut buffer).unwrap();
            //set the length to 0
            BigEndian::write_u32(&mut buffer[4..8], 0);
            let mut cursor = Cursor::new(&buffer);
            let result = SomeIpHeader::read(&mut cursor);
            assert_matches!(result, Err(ReadError::LengthFieldTooSmall(0)));
            //check the from_slice method
            assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..]), Err(ReadError::LengthFieldTooSmall(0)));
        }
        //SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1
        {
            let mut buffer = Vec::new();
            SomeIpHeader::default().write(&mut buffer).unwrap();
            //set the length to SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1
            const TOO_SMALL: u32 = SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1;
            BigEndian::write_u32(&mut buffer[4..8], TOO_SMALL);
            let mut cursor = Cursor::new(&buffer);
            let result = SomeIpHeader::read(&mut cursor);
            assert_matches!(result, Err(ReadError::LengthFieldTooSmall(TOO_SMALL)));
            assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..]), Err(ReadError::LengthFieldTooSmall(TOO_SMALL)));
        }
    }
}
