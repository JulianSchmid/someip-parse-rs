mod configuration_option;
pub use configuration_option::*;

mod configuration_slice;
pub use configuration_slice::*;

mod ipv4_endpoint_option;
pub use ipv4_endpoint_option::*;

mod ipv4_endpoint_slice;
pub use ipv4_endpoint_slice::*;

mod ipv4_multicast_option;
pub use ipv4_multicast_option::*;

mod ipv4_multicast_slice;
pub use ipv4_multicast_slice::*;

mod ipv4_sd_endpoint_option;
pub use ipv4_sd_endpoint_option::*;

mod ipv4_sd_endpoint_slice;
pub use ipv4_sd_endpoint_slice::*;

mod ipv6_endpoint_option;
pub use ipv6_endpoint_option::*;

mod ipv6_endpoint_slice;
pub use ipv6_endpoint_slice::*;

mod ipv6_multicast_option;
pub use ipv6_multicast_option::*;

mod ipv6_multicast_slice;
pub use ipv6_multicast_slice::*;

mod ipv6_sd_endpoint_option;
pub use ipv6_sd_endpoint_option::*;

mod ipv6_sd_endpoint_slice;
pub use ipv6_sd_endpoint_slice::*;

mod load_balancing_option;
pub use load_balancing_option::*;

mod load_balancing_slice;
pub use load_balancing_slice::*;

mod transport_protocol;
pub use transport_protocol::*;

mod unknown_discardable_option;
pub use unknown_discardable_option::*;

mod unknown_slice;
pub use unknown_slice::*;

/// Maximum length of options array that is supported by the read & from slice functions.
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
/// For the sd entries we assume an empty array.
pub const MAX_OPTIONS_LEN: u32 = crate::SOMEIP_MAX_PAYLOAD_LEN_UDP - 4 - 4 - 4;

/// Maximum options length that is supported by the read & from slice functions
/// as a `usize`.
///
/// See [`MAX_OPTIONS_LEN`] for details on how this value was
/// calculcated.
pub const MAX_OPTIONS_LEN_USIZE: usize = MAX_OPTIONS_LEN as usize;

/// Flag in the 4th byte (reserved) indicating that the option is allowed
/// to be discarded by the receiver if not supported.
pub const DISCARDABLE_FLAG: u8 = 0b1000_0000;

/// Value of the `type` field of a configuration sd option.
pub const CONFIGURATION_TYPE: u8 = 0x01;

/// Value of the `length` field of a load balancing sd option.
pub const LOAD_BALANCING_LEN: u16 = 0x0005;

/// Value of the `type` field of a load balancing sd option.
pub const LOAD_BALANCING_TYPE: u8 = 0x02;

/// Value of the `length` field of an ipv4 endpoint sd option.
pub const IPV4_ENDPOINT_LEN: u16 = 0x0009;

/// Value of the `type` field of an ipv4 endpoint sd option.
pub const IPV4_ENDPOINT_TYPE: u8 = 0x04;

/// Value of the `length` field of an ipv6 endpoint sd option.
pub const IPV6_ENDPOINT_LEN: u16 = 0x0015;

/// Value of the `type` field of an ipv6 endpoint sd option.
pub const IPV6_ENDPOINT_TYPE: u8 = 0x06;

/// Value of the `length` field of an ipv4 multicast sd option.
pub const IPV4_MULTICAST_LEN: u16 = 0x0009;

/// Value of the `type` field of an ipv4 multicast sd option.
pub const IPV4_MULTICAST_TYPE: u8 = 0x14;

/// Value of the `length` field of an ipv6 multicast sd option.
pub const IPV6_MULTICAST_LEN: u16 = 0x0015;

/// Value of the `type` field of an ipv6 multicast sd option.
pub const IPV6_MULTICAST_TYPE: u8 = 0x16;

/// Value of the `length` field of an ipv4 sd endpoint sd option.
pub const IPV4_SD_ENDPOINT_LEN: u16 = 0x009;

/// Value of the `type` field of an ipv4 sd endpoint sd option.
pub const IPV4_SD_ENDPOINT_TYPE: u8 = 0x24;

/// Value of the `length` field of an ipv6 sd endpoint sd option.
pub const IPV6_SD_ENDPOINT_LEN: u16 = 0x0015;

/// Value of the `type` field of an ipv6 sd endpoint sd option.
pub const IPV6_SD_ENDPOINT_TYPE: u8 = 0x26;
