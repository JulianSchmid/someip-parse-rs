use crate::sd::options::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6EndpointOption {
    pub ipv6_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}
