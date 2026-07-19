mod event_group_entry;
pub use event_group_entry::*;

mod event_group_entry_slice;
pub use event_group_entry_slice::*;

mod event_group_entry_type;
pub use event_group_entry_type::*;

mod service_entry;
pub use service_entry::*;

mod service_entry_slice;
pub use service_entry_slice::*;

mod service_entry_type;
pub use service_entry_type::*;

mod u24;
pub use u24::*;

mod u4;
pub use u4::*;

/// Maximum entry length that is supported by the read & from slice functions.
///
/// This limit both bounds the fixed-capacity parser storage and rejects length
/// fields that cannot fit in a valid SOME/IP-SD UDP payload.
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

/// Maximum entry length that is supported by the read & from slice functions as a
/// `usize`.
///
/// See [`MAX_ENTRIES_LEN`] for details on how this value was
/// calculcated.
pub const MAX_ENTRIES_LEN_USIZE: usize = MAX_ENTRIES_LEN as usize;

/// Length of an sd entry (note that all entry types currently have
/// the same length).
pub const ENTRY_LEN: usize = 16;
