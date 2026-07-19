use crate::err::{self, Layer, LenSource};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ipv4MulticastSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Ipv4MulticastSlice<'a> {
    pub const LEN: usize = 9;

    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() != Self::LEN {
            return Err(err::LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            });
        }
        Ok(Self { slice })
    }

    #[inline]
    pub fn ipv4_address(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the slice length is guaranteed to be 9 during construction.
        unsafe {
            [
                *self.slice.get_unchecked(1),
                *self.slice.get_unchecked(2),
                *self.slice.get_unchecked(3),
                *self.slice.get_unchecked(4),
            ]
        }
    }

    #[inline]
    pub fn transport_protocol(&self) -> super::TransportProtocol {
        // SAFETY:
        // Safe as the slice length is guaranteed to be 9 during construction.
        match unsafe { *self.slice.get_unchecked(6) } {
            0x06 => super::TransportProtocol::Tcp,
            0x11 => super::TransportProtocol::Udp,
            other => super::TransportProtocol::Generic(other),
        }
    }

    #[inline]
    pub fn port(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is guaranteed to be 9 during construction.
        unsafe { u16::from_be_bytes([*self.slice.get_unchecked(7), *self.slice.get_unchecked(8)]) }
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> From<Ipv4MulticastSlice<'a>> for super::Ipv4MulticastOption {
    fn from(s: Ipv4MulticastSlice<'a>) -> Self {
        Self {
            ipv4_address: s.ipv4_address(),
            transport_protocol: s.transport_protocol(),
            port: s.port(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sd::options::{Ipv4MulticastOption, TransportProtocol};

    #[test]
    fn from_slice() {
        assert!(Ipv4MulticastSlice::from_slice(&[]).is_err());
        assert!(Ipv4MulticastSlice::from_slice(&[0u8; 8]).is_err());
        let err = Ipv4MulticastSlice::from_slice(&[]).unwrap_err();
        assert_eq!(err.required_len, Ipv4MulticastSlice::LEN);
        assert_eq!(err.len, 0);
        assert_eq!(err.len_source, LenSource::Slice);
        assert_eq!(err.layer, Layer::SdOption);

        let s = Ipv4MulticastSlice::from_slice(&[0u8; 9]).unwrap();
        assert_eq!(s.slice(), &[0u8; 9]);

        assert!(Ipv4MulticastSlice::from_slice(&[0u8; 12]).is_err());
    }

    #[test]
    fn accessors() {
        let slice = [0x00, 0xc0, 0xa8, 0x01, 0x01, 0x00, 0x06, 0x1f, 0x90];
        let s = Ipv4MulticastSlice::from_slice(&slice).unwrap();
        assert_eq!(s.ipv4_address(), [0xc0, 0xa8, 0x01, 0x01]);
        assert_eq!(s.transport_protocol(), TransportProtocol::Tcp);
        assert_eq!(s.port(), 8080);

        let slice_udp = [0x00, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0x50];
        let s = Ipv4MulticastSlice::from_slice(&slice_udp).unwrap();
        assert_eq!(s.ipv4_address(), [0x7f, 0x00, 0x00, 0x01]);
        assert_eq!(s.transport_protocol(), TransportProtocol::Udp);
        assert_eq!(s.port(), 80);

        let slice_generic = [0x00, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x99, 0x00, 0x50];
        let s = Ipv4MulticastSlice::from_slice(&slice_generic).unwrap();
        assert_eq!(s.transport_protocol(), TransportProtocol::Generic(0x99));
    }

    #[test]
    fn from_conversion() {
        let slice = [0x00, 0xc0, 0xa8, 0x01, 0x01, 0x00, 0x06, 0x1f, 0x90];
        let s = Ipv4MulticastSlice::from_slice(&slice).unwrap();
        let opt = Ipv4MulticastOption::from(s);
        assert_eq!(opt.ipv4_address, [0xc0, 0xa8, 0x01, 0x01]);
        assert_eq!(opt.transport_protocol, TransportProtocol::Tcp);
        assert_eq!(opt.port, 8080);
    }
}
