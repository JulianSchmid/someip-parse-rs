//! A Rust library for parsing the SOME/IP network protocol (without payload interpretation).
//!
//! # Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! someip_parse = "0.1.1"
//! ```
//!
//! # Example
//! [examples/print_messages.rs](https://github.com/JulianSchmid/someip-parse-rs/blob/0.1.1/examples/print_messages.rs):
//! ```
//! use someip_parse;
//! # let mut udp_payload = Vec::<u8>::new();
//! # {
//! #     use someip_parse::*;
//! #     let header = SomeIpHeader{
//! #         message_id: 0x1234_8234,
//! #         length: SOMEIP_LEN_OFFSET_TO_PAYLOAD + 4,
//! #         request_id: 1,
//! #         interface_version: 1,
//! #         message_type: MessageType::Notification,
//! #         return_code: ReturnCode::Ok.into(),
//! #         tp_header: None
//! #     };/*
//! #     header.write_raw(&mut udp_payload).unwrap();
//! #     udp_payload.extend_from_slice(&[1,2,3,4]);*/
//! # }
//! 
//! use someip_parse::SliceIterator;
//! 
//! //trying parsing some ip messages located in a udp payload
//! for someip_message in SliceIterator::new(&udp_payload) {
//!     match someip_message {
//!         Ok(value) => {
//!             if value.is_someip_sd() {
//!                 println!("someip service discovery packet");
//!             } else {
//!                 println!("0x{:x} (service id: 0x{:x}, method/event id: 0x{:x})", 
//!                          value.message_id(), 
//!                          value.service_id(),
//!                          value.event_or_method_id());
//!             }
//!             println!("  with payload {:?}", value.payload())
//!         },
//!         Err(_) => {} //error reading a someip packet (based on size, protocol version value or message type value)
//!     }
//! }
//! ```
//! 
//! # Todo
//! * Example how to serialize someip packets
//! * SOMEIP Service Discovery Message Parsing
//! 
//! # References
//! * (AUTOSAR Foundation 1.5.0)[https://www.autosar.org/standards/foundation/foundation-150/] \(contains SOMEIP Protocol Specification 1.5.0 & SOME/IP Service Discovery Protocol Specification 1.5.0\) 
//! * (SOME/IP Protocol Specification 1.3.0)[https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPProtocol.pdf]
//! * (SOME/IP Service Discovery Protocol Specification 1.3.0)[https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf]

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

///The currently supported protocol version.
pub const SOMEIP_PROTOCOL_VERSION: u8 = 1;

///Offset that must be substracted from the length field to determine the length of the actual payload.
pub const SOMEIP_LEN_OFFSET_TO_PAYLOAD: u32 = 4*2; // 2x 32bits

///Maximum payload length supported by some ip. This is NOT the maximum length that is supported when
///sending packets over UDP. This constant is based on the limitation of the length field data type (uint32).
pub const SOMEIP_MAX_PAYLOAD_LEN: u32 = std::u32::MAX - SOMEIP_LEN_OFFSET_TO_PAYLOAD;

///Length of a someip header.
pub const SOMEIP_HEADER_LENGTH: usize = 4*4;

///Length of the tp header that follows a someip header if a someip packet has been flaged as tp.
pub const TP_HEADER_LENGTH: usize = 4;

///Flag in the message type field marking the package a as tp message (transporting large SOME/IP messages of UDP).
pub const SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG: u8 = 0x20;

///Message id of SOMEIP service discovery messages
pub const SOMEIP_SD_MESSAGE_ID: u32 = 0xffff_8100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeIpHeader {
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
    pub tp_header: Option<TpHeader>
}

///Message types of a SOME/IP message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageType {
    Request = 0x0,
    RequestNoReturn = 0x1,
    Notification = 0x2,
    Response = 0x80,
    Error = 0x81
}

///Return code contained in a SOME/IP header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReturnCode {
    Ok,// = 0x00,
    NotOk,// = 0x01,
    UnknownService,// = 0x02,
    UnknownMethod, //= 0x03
    NotReady,// = 0x04,
    NotReachable,// = 0x05,
    Timeout,// = 0x06,
    WrongProtocolVersion,// = 0x07,
    WrongInterfaceVersion,// = 0x08,
    MalformedMessage,// = 0x09,
    WrongMessageType,// = 0x0a,
    Generic(u8),
    InterfaceError(u8),
}

impl Into<u8> for ReturnCode {
    fn into(self) -> u8 {
        use ReturnCode::*;
        match self {
            Ok => 0x00,
            NotOk => 0x01,
            UnknownService => 0x02,
            UnknownMethod => 0x03,
            NotReady=> 0x04,
            NotReachable => 0x05,
            Timeout => 0x06,
            WrongProtocolVersion => 0x07,
            WrongInterfaceVersion => 0x08,
            MalformedMessage => 0x09,
            WrongMessageType => 0x0a,
            Generic(value) => value,
            InterfaceError(value) => value,
        }
    }
}

impl SomeIpHeader {

    ///Returns the service id (first 16 bits of the message id)
    pub fn service_id(&self) -> u16 {
        ((self.message_id & 0xffff_0000) >> 16) as u16
    }

    ///Set the servide id (first 16 bits of the message id)
    pub fn set_service_id(&mut self, service_id: u16) {
        self.message_id = (self.message_id & 0x0000_ffff) | (u32::from(service_id) << 16);
    }

    ///Set the event id + the event bit.
    pub fn set_event_id(&mut self, event_id : u16) {
        self.message_id = (self.message_id & 0xffff_0000) | u32::from(0x8000 | event_id);
    }

    ///Set the event id + the event bit to 0. Asserting method_id <= 0x7FFF (otherwise the )
    pub fn set_method_id(&mut self, method_id : u16) {
        debug_assert!(method_id <= 0x7FFF);
        self.message_id = (self.message_id & 0xffff_0000) | u32::from(0x7fff & method_id);
    }

    ///Sets the event id or method id. This number mjust include the "event bit".
    pub fn set_method_or_event_id(&mut self, method_id : u16) {
        self.message_id = (self.message_id & 0xffff_0000) | u32::from(method_id);
    }

    ///Returns true if the message has the message id of a some ip service discovery message.
    pub fn is_someip_sd(&self) -> bool {
        SOMEIP_SD_MESSAGE_ID == self.message_id
    }

    ///Returns true if the event or notification bit in the message id is set
    pub fn is_event(&self) -> bool {
        0 != self.message_id & 0x8000
    }

    ///Return the event id or method id. This number includes the "event bit".
    pub fn event_or_method_id(&self) -> u16 {
        (self.message_id & 0x0000_ffff) as u16
    }

    ///Serialize the header.
    pub fn write_raw<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_u32::<BigEndian>(self.message_id)?;
        writer.write_u32::<BigEndian>(self.length)?;
        writer.write_u32::<BigEndian>(self.request_id)?;
        writer.write_u8(SOMEIP_PROTOCOL_VERSION)?;
        writer.write_u8(self.interface_version)?;
        writer.write_u8({
            match self.tp_header {
                Some(_) => (self.message_type.clone() as u8) | SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG,
                None => (self.message_type.clone() as u8)
            }
        })?;
        writer.write_u8(self.return_code)?;
        if let Some(ref tp) = self.tp_header {
            tp.write(writer)?;
        }
        Ok(())
    }

    ///Read a header from a byte stream.
    pub fn read<T: Read>(reader: &mut T) -> Result<SomeIpHeader, ReadError> {
        use ReadError::*;
        let message_id = reader.read_u32::<BigEndian>()?;
        let length = {
            let len = reader.read_u32::<BigEndian>()?;
            if len < SOMEIP_LEN_OFFSET_TO_PAYLOAD {
                return Err(LengthFieldTooSmall(len));
            }
            len
        };
        let request_id = reader.read_u32::<BigEndian>()?;
        let interface_version = {
            //read the protocol version and generate an error if the version is non matching
            let protocol_version = reader.read_u8()?;
            if SOMEIP_PROTOCOL_VERSION != protocol_version {
                return Err(UnsupportedProtocolVersion(protocol_version));
            }
            //now read the interface version
            reader.read_u8()?
        };
        let message_type_raw = reader.read_u8()?;
        let message_type = {
            use MessageType::*;
            //check that message type is valid
            match message_type_raw & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 => Request,
                0x1 => RequestNoReturn,
                0x2 => Notification,
                0x80 => Response,
                0x81 => Error,
                _ => return Err(UnknownMessageType(message_type_raw))
            }
        };
        Ok(SomeIpHeader {
            message_id,
            length,
            request_id,
            interface_version,
            message_type,
            return_code: reader.read_u8()?,
            //read the tp header if the flag is set
            tp_header: if 0 != message_type_raw & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG {
                Some(TpHeader::read(reader)?)
            } else {
                None
            }
        })
    }
}

///Additional header when a packet contains a TP header (transporting large SOME/IP messages).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TpHeader {
    ///Offset of the payload relativ the start of the completly assempled payload.
    offset: u32,
    ///Flag signaling that more packets should follow
    pub more_segment: bool
}

impl TpHeader {

    ///Creates a tp header with offset 0 and the given "move_segment" flag.
    ///
    /// # Example:
    ///
    /// ```
    /// use someip_parse::TpHeader;
    /// 
    /// // create a header with the more_segement flag set
    /// let header = TpHeader::new(true);
    ///
    /// assert_eq!(0, header.offset());
    /// assert_eq!(true, header.more_segment);
    /// ```
    pub fn new(more_segment: bool) -> TpHeader {
        TpHeader {
            offset: 0,
            more_segment
        }
    }

    /// Creates a tp header with the given offset & "more_segment" flag if the offset is a multiple of 16.
    /// Otherwise an TpOffsetNotMultipleOf16 error is returned.
    ///
    /// # Example:
    ///
    /// ```
    /// use someip_parse::{TpHeader, ValueError};
    /// 
    /// // create a header with offset 32 (multiple of 16) and the more_segement flag set
    /// let header = TpHeader::with_offset(32, true).unwrap();
    ///
    /// assert_eq!(32, header.offset());
    /// assert_eq!(true, header.more_segment);
    ///
    /// // try to create a header with a bad offset (non multiple of 16)
    /// let error = TpHeader::with_offset(31, false);
    ///
    /// assert_eq!(Err(ValueError::TpOffsetNotMultipleOf16(31)), error);
    /// ```
    pub fn with_offset(offset: u32, more_segment: bool) -> Result<TpHeader, ValueError> {
        use ValueError::*;
        if 0 != offset % 16 {
            Err(TpOffsetNotMultipleOf16(offset))
        } else {
            Ok(TpHeader {
                offset,
                more_segment
            })
        }
    }

    /// Returns the offset field of the tp header. The offset defines 
    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Sets the field of the header and returns Ok(()) on success. Note: The value must be a multiple of 16.
    ///
    /// If the given value is not a multiple of 16, the value is not set and an error 
    /// ValueError::TpOffsetNotMultipleOf16 is returned.
    pub fn set_offset(&mut self, value: u32) -> Result<(), ValueError> {
        use ValueError::*;
        if 0 != value % 16 {
            Err(TpOffsetNotMultipleOf16(value))
        } else {
            self.offset = value;
            Ok(())
        }
    }

    /// Read a header from a byte stream.
    pub fn read<T: Read>(reader: &mut T) -> Result<TpHeader, ReadError> {
        let mut buffer = [0u8;TP_HEADER_LENGTH];
        reader.read_exact(&mut buffer)?;
        let more_segment = 0 != (buffer[3] & 0b0001u8);

        //mask out the flags
        buffer[3] &= !0b1111u8;

        Ok(TpHeader{
            offset: BigEndian::read_u32(&buffer),
            more_segment
        })
    }

    fn read_from_slice_unchecked(slice: &[u8]) -> TpHeader {
        let mut buffer = [0u8;TP_HEADER_LENGTH];
        buffer.copy_from_slice(slice);

        let more_segment = 0 != (buffer[3] & 0b0001u8);
        //mask out the flags
        buffer[3] &= !0b1111u8;
        //return result
        TpHeader{
            offset: BigEndian::read_u32(&buffer),
            more_segment
        }
    }
    
    ///Writes the header to the given writer.
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), WriteError> {
        let mut buffer = [0u8;TP_HEADER_LENGTH];
        self.write_to_slice_unchecked(&mut buffer);
        writer.write_all(&buffer)?;
        Ok(())
    }

    ///Writes the header to a slice.
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<(), WriteError> {
        if slice.len() < TP_HEADER_LENGTH {
            use WriteError::*;
            Err(UnexpectedEndOfSlice(TP_HEADER_LENGTH))
        } else {
            self.write_to_slice_unchecked(slice);
            Ok(())
        }
    }

    ///Writes the header to a slice without checking the slice length.
    fn write_to_slice_unchecked(&self, slice: &mut [u8]) {
        BigEndian::write_u32(slice, self.offset);
        if self.more_segment {
            slice[3] |= 0x1u8; 
        }
    }
}

///A slice containing an some ip header & payload of that message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeIpHeaderSlice<'a> {
    ///If true a TP header is following the SOME/IP header.
    tp: bool,
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

            //check the length is still ok, in case of a tp flag
            let tp = 0 != message_type & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG;
            if tp && len < SOMEIP_LEN_OFFSET_TO_PAYLOAD + 4 {
                return Err(LengthFieldTooSmall(len));
            }

            //make sure the message type is known
            match message_type & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 | 0x1 | 0x2 | 0x80 | 0x81 => {},
                _ => return Err(UnknownMessageType(message_type))
            }
            
            //all good generate the slice
            Ok(SomeIpHeaderSlice {
                tp,
                slice: &slice[..total_length]
            })
        }
    }

    #[cfg(target_pointer_width = "32")] 
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

            //NOTE: This additional check is needed for 32 bit systems, as otherwise an overflow could potentially be happening
            const MAX_SUPPORTED_LEN: usize = std::usize::MAX - 4*2;
            let len_usize = len as usize;
            if len_usize > MAX_SUPPORTED_LEN {
                return Err(UnexpectedEndOfSlice(slice.len()));
            }

            let total_length = len_usize + 4*2;
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

            //check the length is still ok, in case of a tp flag
            let tp = 0 != message_type & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG;
            if tp && len < SOMEIP_LEN_OFFSET_TO_PAYLOAD + 4 {
                return Err(LengthFieldTooSmall(len));
            }

            //make sure the message type is known
            match message_type & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 | 0x1 | 0x2 | 0x80 | 0x81 => {},
                _ => return Err(UnknownMessageType(message_type))
            }
            
            //all good generate the slice
            Ok(SomeIpHeaderSlice {
                tp,
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

    ///Returns the service id (first 16 bits of the message id)
    pub fn service_id(&self) -> u16 {
        BigEndian::read_u16(&self.slice[..2])
    }

    ///Returns true if the event or notification bit in the message id is set
    pub fn is_event(&self) -> bool {
        0 != self.slice[2] & 0x80
    }

    ///Return the event id or method id. This number includes the "event bit".
    pub fn event_or_method_id(&self) -> u16 {
        BigEndian::read_u16(&self.slice[2..4])
    }

    ///Returns true if the message has the message id of a some ip service discovery message.
    pub fn is_someip_sd(&self) -> bool {
        SOMEIP_SD_MESSAGE_ID == self.message_id()
    }

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
    pub fn is_tp(&self) -> bool {
        self.tp
    }

    ///Returns the return code of the message.
    #[inline]
    pub fn return_code(&self) -> u8 {
        self.slice[15]
    }

    ///Return a slice to the payload of the someip header.
    pub fn payload(&self) -> &'a [u8] {
        if self.tp {
            &self.slice[SOMEIP_HEADER_LENGTH + TP_HEADER_LENGTH ..]
        } else {
            &self.slice[SOMEIP_HEADER_LENGTH..]
        }
    }

    ///Returns the tp header if there should be one present.
    pub fn tp_header(&self) -> Option<TpHeader> {
        if self.tp {
            Some(
                TpHeader::read_from_slice_unchecked(
                    &self.slice[SOMEIP_HEADER_LENGTH .. SOMEIP_HEADER_LENGTH + TP_HEADER_LENGTH]
                )
            )
        } else {
            None
        }
    }

    ///Decode all the fields and copy the results to a SomeIpHeader struct
    pub fn to_header(&self) -> SomeIpHeader {
        SomeIpHeader {
            message_id: self.message_id(),
            length: self.length(),
            request_id: self.request_id(),
            interface_version: self.interface_version(),
            message_type: self.message_type(),
            return_code: self.return_code(),
            tp_header: self.tp_header(),
        }
    }
}

///Allows iterating over the someip message in a udp or tcp payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceIterator<'a> {
    slice: &'a [u8]
}

impl<'a> SliceIterator<'a> {
    pub fn new(slice: &'a [u8]) -> SliceIterator<'a> {
        SliceIterator {
            slice
        }
    }
}

impl<'a> Iterator for SliceIterator<'a> {
    type Item = Result<SomeIpHeaderSlice<'a>, ReadError>;

    fn next(&mut self) -> Option<Result<SomeIpHeaderSlice<'a>, ReadError>> {
        if !self.slice.is_empty() {
            //parse
            let result = SomeIpHeaderSlice::from_slice(self.slice);

            //move the slice depending on the result
            match &result {
                Err(_) => {
                    //error => move the slice to an len = 0 position so that the iterator ends
                    let len = self.slice.len();
                    self.slice = &self.slice[len..];
                }
                Ok(ref value) => {
                    //by the length just taken by the slice
                    self.slice = &self.slice[value.slice().len()..];
                }
            }

            //return parse result
            Some(result)
        } else {
            None
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
            return_code: 0,
            tp_header: None
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
    UnknownMessageType(u8)
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

#[derive(Debug)]
pub enum WriteError {
    IoError(std::io::Error),
    ///The slice length was not large enough to write the header.
    UnexpectedEndOfSlice(usize)
}

impl From<std::io::Error> for WriteError {
    fn from(err: std::io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// Payload length is too long as 8 bytes for the header have to be added.
    LengthTooLarge(u32),

    /// Offset of the tp header is not a multiple of 16.
    ///
    /// PRS_SOMEIP_00724: The Offset field shall transport the upper 28 bits of a 
    /// uint32. The lower 4 bits shall be always interpreted as 0.
    /// Note: This means that the offset field can only transport offset values 
    /// that are multiples of 16 bytes.
    TpOffsetNotMultipleOf16(u32)
}

#[cfg(test)]
mod tests_return_code {

    proptest! {
        #[test]
        fn into_u8(generic_error in 0x0bu8..0x20,
                   interface_error in 0x20u8..0x5F)
        {
            use ReturnCode::*;
            let values = [
                (Ok, 0x00),
                (NotOk, 0x01),
                (UnknownService, 0x02),
                (UnknownMethod, 0x03),
                (NotReady, 0x04),
                (NotReachable, 0x05),
                (Timeout, 0x06),
                (WrongProtocolVersion, 0x07),
                (WrongInterfaceVersion, 0x08),
                (MalformedMessage, 0x09),
                (WrongMessageType, 0x0a),
                (Generic(generic_error), generic_error),
                (InterfaceError(interface_error), interface_error),
            ];
            for (ref input, ref expected) in values.iter() {
                let result: u8 = (*input).into();
                assert_eq!(*expected, result);
            }
        }
    }
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
                let result = SomeIpHeader::read(&mut cursor).unwrap();
                assert_eq!(input, result);

                //check that a too smal cursor results in an io error
                {
                    let buffer_len = buffer.len();
                    assert_matches!(SomeIpHeader::read(&mut Cursor::new(&buffer[..buffer_len-1])), Err(IoError(_)));
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
                let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();
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
                assert_eq!(&buffer[..expected_length], slice.slice);

                //to_header
                assert_eq!(input, slice.to_header());

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
                tp: false,
                slice: &buffer
            };

            //trigger the panic
            slice.message_type()
        }
    }

    #[test]
    fn read_unsupported_protocol_version() {
        let mut buffer = Vec::new();
        SomeIpHeader::default().write_raw(&mut buffer).unwrap();
        //set the protocol to an unsupported version
        buffer[4*3] = 0;
        let mut cursor = Cursor::new(&buffer);
        let result = SomeIpHeader::read(&mut cursor);
        assert_matches!(result, Err(ReadError::UnsupportedProtocolVersion(0)));
        assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..]), Err(ReadError::UnsupportedProtocolVersion(0)));
    }

    #[test]
    fn read_too_small_length_field() {
        //0
        {
            let mut buffer = Vec::new();
            SomeIpHeader::default().write_raw(&mut buffer).unwrap();
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
            SomeIpHeader::default().write_raw(&mut buffer).unwrap();
            //set the length to SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1
            const TOO_SMALL: u32 = SOMEIP_LEN_OFFSET_TO_PAYLOAD - 1;
            BigEndian::write_u32(&mut buffer[4..8], TOO_SMALL);
            let mut cursor = Cursor::new(&buffer);
            let result = SomeIpHeader::read(&mut cursor);
            assert_matches!(result, Err(ReadError::LengthFieldTooSmall(TOO_SMALL)));
            assert_matches!(SomeIpHeaderSlice::from_slice(&buffer[..]), Err(ReadError::LengthFieldTooSmall(TOO_SMALL)));
        }
    }

    #[test]
    fn debug_write() {
        //ReadError
        {
            use ReadError::*;
            for value in [
                IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
                UnexpectedEndOfSlice(0),
                UnsupportedProtocolVersion(0),
                LengthFieldTooSmall(0),
                UnknownMessageType(0),
            ].iter() {
                println!("{:?}", value);
            }
        }
        //WriteError
        {
            use WriteError::*;
            for value in [
                IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
                UnexpectedEndOfSlice(0)
            ].iter() {
                println!("{:?}", value);
            }
        }
        //ValueError
        {
            use ValueError::*;
            for value in [
                LengthTooLarge(0),
                TpOffsetNotMultipleOf16(0)
            ].iter() {
                println!("{:?}", value);
            }
        }
        //SomeIpHeaderSlice
        {
            let buffer: [u8;SOMEIP_HEADER_LENGTH] = [0;SOMEIP_HEADER_LENGTH];
            println!("{:?}", SomeIpHeaderSlice{ tp:false, slice: &buffer[..]});
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
            let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();

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
            assert_eq!(false, header.is_event());

            //serialize and check the slice methods
            let mut buffer = Vec::new();
            header.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();
            let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(false, slice.is_event());
            assert_eq!(method_id, slice.event_or_method_id());
        }
    }

    proptest! {
        #[test]
        fn set_get_event_id(packet in someip_header_with_payload_any(),
                            event_id in 0x8000u16..std::u16::MAX)
        {
            let mut header = packet.0.clone();
            header.set_event_id(event_id);

            let id_with_bit = event_id | 0x8000;

            assert_eq!(id_with_bit, header.event_or_method_id());
            assert_eq!(true, header.is_event());

            //serialize and check the slice methods
            let mut buffer = Vec::new();
            header.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();
            let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(true, slice.is_event());
            assert_eq!(id_with_bit, slice.event_or_method_id());
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
            let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();

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
                let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();

                assert_eq!(true, slice.is_someip_sd());
            }
            //random packet
            {
                let mut buffer = Vec::new();
                packet.0.write_raw(&mut buffer).unwrap();
                buffer.write(&packet.1[..]).unwrap();
                let slice = SomeIpHeaderSlice::from_slice(&buffer[..]).unwrap();

                assert_eq!(packet.0.message_id == SD_MESSAGE_ID, slice.is_someip_sd());
            }
        }
    }
}

#[cfg(test)]
mod tests_tp_header {

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn new(more_segment in any::<bool>()) {
            let result = TpHeader::new(more_segment);

            assert_eq!(result.offset, 0);
            assert_eq!(result.offset(), 0);
            assert_eq!(result.more_segment, more_segment);
        }
    }

    proptest! {
        #[test]
        fn with_offset(
            offset in any::<u32>().prop_filter("must be multiple of 16", |v| 0 == v % 16),
            more_segment in any::<bool>()
        ) {
            let result = TpHeader::with_offset(offset, more_segment).unwrap();

            assert_eq!(result.offset, offset);
            assert_eq!(result.more_segment, more_segment);
        }
    }
    
    proptest! {
        #[test]
        fn with_offset_error(
            offset in any::<u32>().prop_filter("must not be multiple of 16", |v| 0 != v % 16),
            more_segment in any::<bool>()
        ) {
            let result = TpHeader::with_offset(offset, more_segment);
            assert_eq!(Err(ValueError::TpOffsetNotMultipleOf16(offset)), result);
        }
    }

    proptest! {
        #[test]
        fn set_offset(
            offset in any::<u32>().prop_filter("must be multiple of 16", |v| 0 == v % 16)
        ) {
            let mut header: TpHeader = Default::default();
            assert_eq!(Ok(()), header.set_offset(offset));
            assert_eq!(header.offset, offset);
        }
    }
    
    proptest! {
        #[test]
        fn set_offset_error(
            offset in any::<u32>().prop_filter("must not be multiple of 16", |v| 0 != v % 16)
        ) {
            let mut header: TpHeader = Default::default();
            assert_eq!(Err(ValueError::TpOffsetNotMultipleOf16(offset)), header.set_offset(offset));
            assert_eq!(0, header.offset);
        }
    }
}

#[cfg(test)]
mod tests_iterator {
    use super::*;
    use super::proptest_generators::*;

    proptest! {
        #[test]
        fn iterator(expected in proptest::collection::vec(someip_header_with_payload_any(), 0..5))
        {
            //serialize
            let mut buffer = Vec::new();
            for (message, payload) in expected.iter() {
                message.write_raw(&mut buffer).unwrap();
                buffer.write(&payload[..]).unwrap();
            }

            //read message with iterator
            let actual = SliceIterator::new(&buffer[..]).fold(
                Vec::with_capacity(expected.len()), 
                |mut acc, x| {
                    let x_unwraped = x.unwrap();
                    acc.push((
                        x_unwraped.to_header(),
                        {
                            let mut vec = Vec::with_capacity(x_unwraped.payload().len());
                            vec.extend_from_slice(x_unwraped.payload());
                            vec
                        })
                    );
                    acc
                });
            assert_eq!(expected, actual);
        }

    }

    proptest! {
        #[test]
        fn iterator_error(packet in someip_header_with_payload_any()) {
            //serialize
            let mut buffer = Vec::new();
            packet.0.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();

            //generate iterator
            let len = buffer.len();
            let mut iterator = SliceIterator::new(&buffer[..len-1]);

            //check that an error is generated
            assert_matches!(iterator.next(), Some(Err(ReadError::UnexpectedEndOfSlice(_))));
            assert_matches!(iterator.next(), None);
            assert_matches!(iterator.next(), None);
        }
    }
}
