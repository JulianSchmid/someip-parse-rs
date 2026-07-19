use crate::err::{SdReadError, SdValueError, SdWriteError};
#[cfg(feature = "std")]
use std::io::{Read, Seek, Write};

/// SOMEIP Service Discovery Entries (constants & entry data types).
pub mod entries;

/// SOMEIP Service Discovery Options (constants & options data types).
pub mod options;

mod sd_entries_checked_iterator;
pub use sd_entries_checked_iterator::*;

mod sd_entries_iterator;
pub use sd_entries_iterator::*;

mod sd_entry;
pub use sd_entry::*;

mod sd_entry_slice;
pub use sd_entry_slice::*;

mod sd_entry_with_options;
pub use sd_entry_with_options::*;

mod sd_header;
pub use sd_header::*;

mod sd_header_flags;
pub use sd_header_flags::*;

mod sd_option;
pub use sd_option::*;

mod sd_option_slice;
pub use sd_option_slice::*;

mod sd_option_type;
pub use sd_option_type::*;

mod sd_options_checked_iterator;
pub use sd_options_checked_iterator::*;

mod sd_options_index;
pub use sd_options_index::*;

mod sd_options_iterator;
pub use sd_options_iterator::*;

mod sd_slice;
pub use sd_slice::*;

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
