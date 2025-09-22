/// Protocol numbers based on IANA/IETF
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Generic(u8),
}

impl From<TransportProtocol> for u8 {
    fn from(tp: TransportProtocol) -> u8 {
        match tp {
            TransportProtocol::Tcp => 0x06,
            TransportProtocol::Udp => 0x11,
            TransportProtocol::Generic(tp) => tp,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn from_u8(argu8 in any::<u8>()) {
            use super::TransportProtocol::*;
            assert_eq!(u8::from(Tcp), 0x06);
            assert_eq!(u8::from(Udp), 0x11);
            assert_eq!(u8::from(Generic(argu8)), argu8);
        }
    }
}
