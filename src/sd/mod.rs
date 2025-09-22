use crate::err::{SdReadError, SdValueError, SdWriteError};
use std::io::{Read, Seek, Write};

/// Constants related to sd entries.
mod sd_entries;
pub use sd_entries::*;

mod sd_entry;
pub use sd_entry::*;

mod sd_event_group_entry_type;
pub use sd_event_group_entry_type::*;

mod sd_header;
pub use sd_header::*;

mod sd_header_flags;
pub use sd_header_flags::*;

mod sd_option;
pub use sd_option::*;

/// Constants related to sd options.
mod sd_options;
pub use sd_options::*;

mod sd_service_entry_type;
pub use sd_service_entry_type::*;

mod transport_protocol;
pub use transport_protocol::*;

///Length of someip sd header, flags + reserved + entries length + options length
///excluding entries and options arrays
pub const MIN_SD_HEADER_LENGTH: usize = 1 + 3 + 4 + 4;

pub const EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG: u8 = 0b1000_0000;

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

#[test]
fn service_entry_read_unknown_service_entry_type() {
    use assert_matches::*;

    let mut buffer = [0x00; sd_entries::ENTRY_LEN];
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
        0,
        0,
        0,
        0,
        0,
        0xFFFF_FFFF,
        0,
    );
    assert_matches!(result, Err(SdValueError::TtlTooLarge(0xFFFF_FFFF)));
}

#[test]
fn new_service_entry_number_option1_too_large() {
    use assert_matches::*;

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
    assert_matches!(result, Err(SdValueError::NumberOfOption1TooLarge(0xFF)));
}

#[test]
fn new_service_entry_number_option2_too_large() {
    use assert_matches::*;

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
    assert_matches!(result, Err(SdValueError::NumberOfOption2TooLarge(0xFF)));
}

#[test]
fn new_service_find_service_entry_zero_ttl() {
    use assert_matches::*;

    let result = SdEntry::new_find_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_matches!(result, Err(SdValueError::TtlZeroIndicatesStopOffering));
}

#[test]
fn new_service_offer_service_entry_zero_ttl() {
    use assert_matches::*;

    let result = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_matches!(result, Err(SdValueError::TtlZeroIndicatesStopOffering));
}
