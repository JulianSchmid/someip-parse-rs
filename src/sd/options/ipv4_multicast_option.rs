use crate::sd::options::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4MulticastOption {
    pub ipv4_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}
