use crate::sd::*;

/// Maximum length of options array that is supported by the read & from slice functions.
///
/// This constant is used to make sure no attacks with large length
/// values can trigger large allocations. E.g. if a some ip sd header
/// with an options array length of 4 gigabytes gets passed to the `read` function
/// it could triggering an allocation of 4 gigabytes. This allocation would then
/// take a very long time or lead to a failure and potential crash.
///
/// To prevent attacks like these the length gets checked against
/// this constant before any allocation gets triggered.
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
/// See [`crate::sd::MAX_OPTIONS_LEN`] for details on how this value was
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationOption {
    /// Shall be set to `true` if the option can be discarded by the receiver.
    pub discardable: bool,
    // TODO DNS TXT / DNS-SD format
    pub configuration_string: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancingOption {
    /// Shall be set to `true` if the option can be discarded by the receiver.
    pub discardable: bool,
    pub priority: u16,
    pub weight: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4EndpointOption {
    pub ipv4_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6EndpointOption {
    pub ipv6_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4MulticastOption {
    pub ipv4_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6MulticastOption {
    pub ipv6_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4SdEndpointOption {
    pub ipv4_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6SdEndpointOption {
    pub ipv6_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

/// An unknown option that is flagged as "discardable" and
/// should be ignored by the receiver if not supported.
///
/// This option is only intended to be used for reading,
/// to ensure the option indices are still matching. In case
/// this option is passed to a write function an error will be
/// triggered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownDiscardableOption {
    pub length: u16,
    pub option_type: u8,
}
