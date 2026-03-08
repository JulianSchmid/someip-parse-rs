use crate::err::{self, Layer, LenSource};
use crate::sd::options::{Ipv6EndpointOption, TransportProtocol};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ipv6EndpointSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Ipv6EndpointSlice<'a> {
    pub const LEN: usize = 21;

    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() < Self::LEN {
            return Err(err::LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            });
        }
        Ok(Self {
            slice: &slice[..Self::LEN],
        })
    }

    #[inline]
    pub fn ipv6_address(&self) -> [u8; 16] {
        // SAFETY:
        // Safe as the slice length is guaranteed to be 21 during construction,
        // so bytes 1..17 are always accessible.
        unsafe {
            let ptr = self.slice.as_ptr().add(1);
            let s = core::slice::from_raw_parts(ptr, 16);
            s.try_into().unwrap()
        }
    }

    #[inline]
    pub fn transport_protocol(&self) -> TransportProtocol {
        // SAFETY:
        // Safe as the slice length is guaranteed to be 21 during construction.
        match unsafe { *self.slice.get_unchecked(18) } {
            0x06 => TransportProtocol::Tcp,
            0x11 => TransportProtocol::Udp,
            other => TransportProtocol::Generic(other),
        }
    }

    #[inline]
    pub fn port(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is guaranteed to be 21 during construction.
        unsafe {
            u16::from_be_bytes([*self.slice.get_unchecked(19), *self.slice.get_unchecked(20)])
        }
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> From<Ipv6EndpointSlice<'a>> for Ipv6EndpointOption {
    fn from(s: Ipv6EndpointSlice<'a>) -> Self {
        Self {
            ipv6_address: s.ipv6_address(),
            transport_protocol: s.transport_protocol(),
            port: s.port(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sd::options::{Ipv6EndpointOption, TransportProtocol};

    #[test]
    fn from_slice() {
        assert!(Ipv6EndpointSlice::from_slice(&[]).is_err());
        assert!(Ipv6EndpointSlice::from_slice(&[0u8; 20]).is_err());
        let err = Ipv6EndpointSlice::from_slice(&[]).unwrap_err();
        assert_eq!(err.required_len, Ipv6EndpointSlice::LEN);
        assert_eq!(err.len, 0);
        assert_eq!(err.len_source, LenSource::Slice);
        assert_eq!(err.layer, Layer::SdOption);

        let s = Ipv6EndpointSlice::from_slice(&[0u8; 21]).unwrap();
        assert_eq!(s.slice(), &[0u8; 21]);

        let longer = [0u8; 24];
        let s = Ipv6EndpointSlice::from_slice(&longer).unwrap();
        assert_eq!(s.slice(), &longer[..21]);
    }

    #[test]
    fn accessors() {
        let mut slice = [0u8; 21];
        slice[1..17].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        slice[18] = 0x06;
        slice[19] = 0x1f;
        slice[20] = 0x90;
        let s = Ipv6EndpointSlice::from_slice(&slice).unwrap();
        assert_eq!(
            s.ipv6_address(),
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(s.transport_protocol(), TransportProtocol::Tcp);
        assert_eq!(s.port(), 8080);

        let mut slice_udp = [0u8; 21];
        slice_udp[1..17]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        slice_udp[18] = 0x11;
        slice_udp[19] = 0x00;
        slice_udp[20] = 0x50;
        let s = Ipv6EndpointSlice::from_slice(&slice_udp).unwrap();
        assert_eq!(
            s.ipv6_address(),
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        );
        assert_eq!(s.transport_protocol(), TransportProtocol::Udp);
        assert_eq!(s.port(), 80);
    }

    #[test]
    fn from_conversion() {
        let mut slice = [0u8; 21];
        slice[1..17].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        slice[18] = 0x06;
        slice[19] = 0x1f;
        slice[20] = 0x90;
        let s = Ipv6EndpointSlice::from_slice(&slice).unwrap();
        let opt = Ipv6EndpointOption::from(s);
        assert_eq!(
            opt.ipv6_address,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(opt.transport_protocol, TransportProtocol::Tcp);
        assert_eq!(opt.port, 8080);
    }
}
