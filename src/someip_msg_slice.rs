use crate::*;

/// Deprecated use [`SomeipMsgSlice`] instead.
#[deprecated(since = "0.5.0", note = "Use SomeipMsgSlice instead (renamed).")]
pub type SomeIpHeaderSlice<'a> = SomeipMsgSlice<'a>;

/// A slice containing an some ip header & payload of that message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeipMsgSlice<'a> {
    /// If true a TP header is following the SOME/IP header.
    tp: bool,
    slice: &'a [u8],
}

impl<'a> SomeipMsgSlice<'a> {
    #[cfg(target_pointer_width = "64")]
    pub fn from_slice(slice: &'a [u8]) -> Result<SomeipMsgSlice, err::ReadError> {
        use err::ReadError::*;
        //first check the length
        if slice.len() < SOMEIP_HEADER_LENGTH {
            Err(UnexpectedEndOfSlice(slice.len()))
        } else {
            //check length
            let len = {
                // SAFETY:
                // Read is save as it is checked before that the slice has at least
                // SOMEIP_HEADER_LENGTH 16 bytes.
                unsafe { get_unchecked_be_u32(slice.as_ptr().add(4)) }
            };
            if len < SOMEIP_LEN_OFFSET_TO_PAYLOAD {
                return Err(LengthFieldTooSmall(len));
            }
            //NOTE: In case you want to write a 32 bit version, a check needs to be added, so that
            //      no accidental overflow when adding the 4*2 bytes happens.
            let total_length = (len as usize) + 4 * 2;
            if slice.len() < total_length {
                return Err(UnexpectedEndOfSlice(slice.len()));
            }
            //check protocol version
            let protocol_version = {
                // SAFETY:
                // Read is save as it is checked before that the slice has at least
                // SOMEIP_HEADER_LENGTH 16 (4*4) bytes.
                unsafe { *slice.get_unchecked(4 * 3) }
            };
            if SOMEIP_PROTOCOL_VERSION != protocol_version {
                return Err(UnsupportedProtocolVersion(protocol_version));
            }

            //check message type
            let message_type = {
                // SAFETY:
                // Read is save as it is checked before that the slice has at least
                // SOMEIP_HEADER_LENGTH 16 (4*4) bytes.
                unsafe { *slice.get_unchecked(4 * 3 + 2) }
            };

            //check the length is still ok, in case of a tp flag
            let tp = 0 != message_type & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG;
            if tp && len < SOMEIP_LEN_OFFSET_TO_PAYLOAD + 4 {
                return Err(LengthFieldTooSmall(len));
            }

            //make sure the message type is known
            match message_type & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 | 0x1 | 0x2 | 0x80 | 0x81 => {}
                _ => return Err(UnknownMessageType(message_type)),
            }

            //all good generate the slice
            Ok(SomeipMsgSlice {
                tp,
                // SAFETY: Check is preformed above to ensure slice has at least total length
                slice: unsafe { from_raw_parts(slice.as_ptr(), total_length) },
            })
        }
    }

    #[cfg(target_pointer_width = "32")]
    pub fn from_slice(slice: &'a [u8]) -> Result<SomeipMsgSlice, err::ReadError> {
        use err::ReadError::*;
        //first check the length
        if slice.len() < SOMEIP_HEADER_LENGTH {
            Err(UnexpectedEndOfSlice(slice.len()))
        } else {
            //check length
            let len = {
                // SAFETY:
                // Read is save as it is checked before that the slice has at least
                // SOMEIP_HEADER_LENGTH 16 bytes.
                unsafe { get_unchecked_be_u32(slice.as_ptr().add(4)) }
            };
            if len < SOMEIP_LEN_OFFSET_TO_PAYLOAD {
                return Err(LengthFieldTooSmall(len));
            }

            //NOTE: This additional check is needed for 32 bit systems, as otherwise an overflow could potentially be happening
            const MAX_SUPPORTED_LEN: usize = std::usize::MAX - 4 * 2;
            let len_usize = len as usize;
            if len_usize > MAX_SUPPORTED_LEN {
                return Err(UnexpectedEndOfSlice(slice.len()));
            }

            let total_length = len_usize + 4 * 2;
            if slice.len() < total_length {
                return Err(UnexpectedEndOfSlice(slice.len()));
            }
            //check protocol version
            let protocol_version = {
                // SAFETY:
                // Read is save as it is checked before that the slice has at least
                // SOMEIP_HEADER_LENGTH 16 (4*4) bytes.
                unsafe { *slice.get_unchecked(4 * 3) }
            };
            if SOMEIP_PROTOCOL_VERSION != protocol_version {
                return Err(UnsupportedProtocolVersion(protocol_version));
            }

            //check message type
            let message_type = {
                // SAFETY:
                // Read is save as it is checked before that the slice has at least
                // SOMEIP_HEADER_LENGTH 16 (4*4) bytes.
                unsafe { *slice.get_unchecked(4 * 3 + 2) }
            };

            //check the length is still ok, in case of a tp flag
            let tp = 0 != message_type & SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG;
            if tp && len < SOMEIP_LEN_OFFSET_TO_PAYLOAD + 4 {
                return Err(LengthFieldTooSmall(len));
            }

            //make sure the message type is known
            match message_type & !(SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG) {
                0x0 | 0x1 | 0x2 | 0x80 | 0x81 => {}
                _ => return Err(UnknownMessageType(message_type)),
            }

            //all good generate the slice
            Ok(SomeipMsgSlice {
                tp,
                // SAFETY: Check is preformed above to ensure slice has at least total length
                slice: unsafe { from_raw_parts(slice.as_ptr(), total_length) },
            })
        }
    }

    ///Return the slice that contains the someip header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Returns the message id of the message.
    #[inline]
    pub fn message_id(&self) -> u32 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr()) }
    }

    ///Returns the service id (first 16 bits of the message id)
    #[inline]
    pub fn service_id(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr()) }
    }

    ///Returns true if the event or notification bit in the message id is set
    #[inline]
    pub fn is_event(&self) -> bool {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        0 != unsafe { self.slice.get_unchecked(2) } & 0x80
    }

    ///Return the event id or method id. This number includes the "event bit".
    #[inline]
    pub fn event_or_method_id(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
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

    ///Returns true if the message has the message id of a some ip service discovery message.
    #[inline]
    pub fn is_someip_sd(&self) -> bool {
        SOMEIP_SD_MESSAGE_ID == self.message_id()
    }

    /// Returns the length contained in the header. WARNING: the length paritally
    /// contains the header and partially the payload, use the payload() method
    /// instead if you want to access the payload slice).
    #[inline]
    pub fn length(&self) -> u32 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(4)) }
    }

    ///Returns the request id of the message.
    #[inline]
    pub fn request_id(&self) -> u32 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(8)) }
    }

    ///Return the value of the protocol version field of the message (must match SOMEIP_PROTOCOL_VERSION, unless something dark and unsafe is beeing done).
    #[inline]
    pub fn protocol_version(&self) -> u8 {
        debug_assert!(SOMEIP_PROTOCOL_VERSION == self.slice[12]);
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { *self.slice.get_unchecked(12) }
    }

    ///Returns the interface version field of the message.
    #[inline]
    pub fn interface_version(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { *self.slice.get_unchecked(13) }
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
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { *self.slice.get_unchecked(14) }
    }

    ///Returns true if the tp flag in the message type is set (Transporting large SOME/IP messages of UDP [SOME/IP-TP])
    #[inline]
    pub fn is_tp(&self) -> bool {
        self.tp
    }

    ///Returns the return code of the message.
    #[inline]
    pub fn return_code(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to have at least a length of
        // SOMEIP_HEADER_LENGTH (16) during construction of the struct.
        unsafe { *self.slice.get_unchecked(15) }
    }

    /// Return a slice to the payload of the someip header.
    ///
    /// If the there is tp header present the memory after the tp
    /// header is returned.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        if self.tp {
            const OFFSET: usize = SOMEIP_HEADER_LENGTH + TP_HEADER_LENGTH;
            debug_assert!(OFFSET <= self.slice.len());
            // SAFETY:
            // Safe as it is checked in SomeipHeaderSlice::from_slice that the
            // slice has at least SOMEIP_HEADER_LENGTH + TP_HEADER_LENGTH len
            // if the tp flag is set.
            unsafe { from_raw_parts(self.slice.as_ptr().add(OFFSET), self.slice.len() - OFFSET) }
        } else {
            // SAFETY:
            // Safe as it is checked in SomeipHeaderSlice::from_slice that the
            // slice has at least SOMEIP_HEADER_LENGTH len.
            unsafe {
                from_raw_parts(
                    self.slice.as_ptr().add(SOMEIP_HEADER_LENGTH),
                    self.slice.len() - SOMEIP_HEADER_LENGTH,
                )
            }
        }
    }

    ///Returns the tp header if there should be one present.
    #[inline]
    pub fn tp_header(&self) -> Option<TpHeader> {
        if self.tp {
            Some(
                // SAFETY
                // Safe as the slice len is checked to have SOMEIP_HEADER_LENGTH + TP_HEADER_LENGTH
                // length during SomeIpHeaderSlice::from_slice.
                unsafe {
                    TpHeader::from_slice_unchecked(core::slice::from_raw_parts(
                        self.slice.as_ptr().add(SOMEIP_HEADER_LENGTH),
                        self.slice.len() - SOMEIP_HEADER_LENGTH,
                    ))
                },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MessageType::*;
    use proptest::prelude::*;

    #[test]
    fn debug_write() {
        let buffer: [u8; SOMEIP_HEADER_LENGTH] = [0; SOMEIP_HEADER_LENGTH];
        let _ = format!(
            "{:?}",
            SomeipMsgSlice {
                tp: false,
                slice: &buffer[..]
            }
        );
    }

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
            let slice = SomeipMsgSlice {
                tp: false,
                slice: &buffer
            };

            //trigger the panic
            slice.message_type();
        }
    }
}
