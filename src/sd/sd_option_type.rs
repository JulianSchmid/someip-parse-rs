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
