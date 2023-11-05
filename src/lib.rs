//! A Rust library for parsing the SOME/IP network protocol (without payload interpretation).
//!
//! # Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! someip_parse = "0.5.0"
//! ```
//!
//! # Example
//! [examples/print_messages.rs](https://github.com/JulianSchmid/someip-parse-rs/blob/0.2.0/examples/print_messages.rs):
//! ```
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
//! * [AUTOSAR Foundation 1.5.0](https://www.autosar.org/standards/foundation/foundation-150/) \(contains SOMEIP Protocol Specification 1.5.0 & SOME/IP Service Discovery Protocol Specification 1.5.0\)
//! * [SOME/IP Protocol Specification 1.3.0](https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPProtocol.pdf)
//! * [SOME/IP Service Discovery Protocol Specification 1.3.0](https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf)

use std::io::{Read, Write};
use std::slice::from_raw_parts;

#[cfg(test)]
mod proptest_generators;

/// Error types of someip_parse.
pub mod err;

mod message_type;
pub use message_type::*;

mod return_code;
pub use return_code::*;

mod sd;
pub use sd::*;

mod section_range;
pub use section_range::*;

mod slice_iterator;
pub use slice_iterator::*;

mod some_ip_header;
pub use some_ip_header::*;

mod some_ip_header_slice;
pub use some_ip_header_slice::*;

mod tp_buf_config;
pub use tp_buf_config::*;

mod tp_buf;
pub use tp_buf::*;

mod tp_header;
pub use tp_header::*;

mod tp_pool;
pub use tp_pool::*;

/// Maximum allowed TP segment length.
pub const TP_UDP_MAX_SEGMENT_LEN: usize = 1400;

/// Maximum allowed TP aligned segment length.
///
/// All packets except for the last packet (where
/// the "more segments" flag is set to 0) are required
/// to have a len of multiple of 16 bytes.
pub const TP_UDP_MAX_SEGMENT_LEN_ALIGNED: usize = 1392;

///The currently supported protocol version.
pub const SOMEIP_PROTOCOL_VERSION: u8 = 1;

///Offset that must be substracted from the length field to determine the length of the actual payload.
pub const SOMEIP_LEN_OFFSET_TO_PAYLOAD: u32 = 4 * 2; // 2x 32bits

///Maximum payload length supported by some ip. This is NOT the maximum length that is supported when
///sending packets over UDP. This constant is based on the limitation of the length field data type (uint32).
pub const SOMEIP_MAX_PAYLOAD_LEN: u32 = std::u32::MAX - SOMEIP_LEN_OFFSET_TO_PAYLOAD;

/// The maximum payload size of an SOMEIP UDP message.
///
/// This value comes directly from the SOMEIP specification,
/// which states the following:
///
/// > The size of the SOME/IP payload field depends on the transport
/// > protocol used. With UDP the SOME/IP payload shall be between 0
/// > and 1400 Bytes. The limitation to 1400 Bytes is needed in order
/// > to allow for future changes to protocol stack (e.g. changing to
/// > IPv6 or adding security means). Since TCP supports segmentation
/// > of payloads, larger sizes are automatically supported.
pub const SOMEIP_MAX_PAYLOAD_LEN_UDP: u32 = 1400;

///Length of a someip header.
pub const SOMEIP_HEADER_LENGTH: usize = 4 * 4;

///Length of the tp header that follows a someip header if a someip packet has been flaged as tp.
pub const TP_HEADER_LENGTH: usize = 4;

///Flag in the message type field marking the package a as tp message (transporting large SOME/IP messages of UDP).
pub const SOMEIP_HEADER_MESSAGE_TYPE_TP_FLAG: u8 = 0x20;

///Message id of SOMEIP service discovery messages
pub const SOMEIP_SD_MESSAGE_ID: u32 = 0xffff_8100;


/// Helper function for reading big endian u32 values from a ptr unchecked.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 4
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_be_u32(ptr: *const u8) -> u32 {
    u32::from_be_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)])
}

/// Helper function for reading big endian u16 values from a ptr unchecked.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 2
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_be_u16(ptr: *const u8) -> u16 {
    u16::from_be_bytes([*ptr, *ptr.add(1)])
}

#[cfg(test)]
mod tests_iterator {
    use super::*;
    use assert_matches::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;

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
            assert_matches!(iterator.next(), Some(Err(err::ReadError::UnexpectedEndOfSlice(_))));
            assert_matches!(iterator.next(), None);
            assert_matches!(iterator.next(), None);
        }
    }
}
