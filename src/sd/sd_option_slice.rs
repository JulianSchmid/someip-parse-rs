use crate::err::{self, Layer, LenSource, SdOptionSliceError};
use crate::sd::options::*;

/// Zero-copy enum over all SD option slice types.
///
/// Mirrors [`super::SdOption`] but references the underlying byte slice
/// instead of owning the data.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SdOptionSlice<'a> {
    /// Arbitrary configuration strings.
    Configuration(ConfigurationSlice<'a>),
    LoadBalancing(LoadBalancingSlice<'a>),
    Ipv4Endpoint(Ipv4EndpointSlice<'a>),
    Ipv6Endpoint(Ipv6EndpointSlice<'a>),
    Ipv4Multicast(Ipv4MulticastSlice<'a>),
    Ipv6Multicast(Ipv6MulticastSlice<'a>),
    Ipv4SdEndpoint(Ipv4SdEndpointSlice<'a>),
    Ipv6SdEndpoint(Ipv6SdEndpointSlice<'a>),
    /// An option whose type is not recognized.
    ///
    /// Use [`UnknownSlice::discardable`] to check whether the option
    /// may safely be ignored.
    Unknown(UnknownSlice<'a>),
}

impl<'a> From<ConfigurationSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: ConfigurationSlice<'a>) -> Self {
        SdOptionSlice::Configuration(s)
    }
}

impl<'a> From<LoadBalancingSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: LoadBalancingSlice<'a>) -> Self {
        SdOptionSlice::LoadBalancing(s)
    }
}

impl<'a> From<Ipv4EndpointSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: Ipv4EndpointSlice<'a>) -> Self {
        SdOptionSlice::Ipv4Endpoint(s)
    }
}

impl<'a> From<Ipv6EndpointSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: Ipv6EndpointSlice<'a>) -> Self {
        SdOptionSlice::Ipv6Endpoint(s)
    }
}

impl<'a> From<Ipv4MulticastSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: Ipv4MulticastSlice<'a>) -> Self {
        SdOptionSlice::Ipv4Multicast(s)
    }
}

impl<'a> From<Ipv6MulticastSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: Ipv6MulticastSlice<'a>) -> Self {
        SdOptionSlice::Ipv6Multicast(s)
    }
}

impl<'a> From<Ipv4SdEndpointSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: Ipv4SdEndpointSlice<'a>) -> Self {
        SdOptionSlice::Ipv4SdEndpoint(s)
    }
}

impl<'a> From<Ipv6SdEndpointSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: Ipv6SdEndpointSlice<'a>) -> Self {
        SdOptionSlice::Ipv6SdEndpoint(s)
    }
}

impl<'a> From<UnknownSlice<'a>> for SdOptionSlice<'a> {
    #[inline]
    fn from(s: UnknownSlice<'a>) -> Self {
        SdOptionSlice::Unknown(s)
    }
}

impl<'a> SdOptionSlice<'a> {
    /// Reads the next SD option from the beginning of `slice` and returns
    /// it together with the remaining bytes after the option.
    ///
    /// The wire format of each option is:
    ///
    /// ```text
    /// [length: u16 BE] [type: u8] [payload: `length` bytes]
    /// ```
    ///
    /// where the first byte of the payload is the reserved byte carrying
    /// the discardable flag.
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<(SdOptionSlice<'a>, &'a [u8]), SdOptionSliceError> {
        if slice.len() < 3 {
            return Err(SdOptionSliceError::Len(err::LenError {
                required_len: 3,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            }));
        }

        // SAFETY: slice.len() >= 3 is checked above.
        let length =
            u16::from_be_bytes(unsafe { [*slice.get_unchecked(0), *slice.get_unchecked(1)] });
        if length < 1 {
            return Err(SdOptionSliceError::OptionLengthZero);
        }

        // SAFETY: slice.len() >= 3 is checked above.
        let type_raw = unsafe { *slice.get_unchecked(2) };
        let total_len = 3usize + usize::from(length);

        if slice.len() < total_len {
            return Err(SdOptionSliceError::Len(err::LenError {
                required_len: total_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            }));
        }

        // SAFETY: slice.len() >= total_len is checked above, and
        // total_len == 3 + length with length >= 1, so 3 < total_len <= slice.len().
        let payload =
            unsafe { core::slice::from_raw_parts(slice.as_ptr().add(3), usize::from(length)) };
        let rest = unsafe {
            core::slice::from_raw_parts(slice.as_ptr().add(total_len), slice.len() - total_len)
        };

        let map_len_err = |mut e: err::LenError| -> SdOptionSliceError {
            e.len_source = LenSource::SdOptionLength;
            SdOptionSliceError::Len(e)
        };

        let option = match type_raw {
            CONFIGURATION_TYPE => SdOptionSlice::Configuration(
                ConfigurationSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            LOAD_BALANCING_TYPE => SdOptionSlice::LoadBalancing(
                LoadBalancingSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            IPV4_ENDPOINT_TYPE => SdOptionSlice::Ipv4Endpoint(
                Ipv4EndpointSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            IPV6_ENDPOINT_TYPE => SdOptionSlice::Ipv6Endpoint(
                Ipv6EndpointSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            IPV4_MULTICAST_TYPE => SdOptionSlice::Ipv4Multicast(
                Ipv4MulticastSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            IPV6_MULTICAST_TYPE => SdOptionSlice::Ipv6Multicast(
                Ipv6MulticastSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            IPV4_SD_ENDPOINT_TYPE => SdOptionSlice::Ipv4SdEndpoint(
                Ipv4SdEndpointSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            IPV6_SD_ENDPOINT_TYPE => SdOptionSlice::Ipv6SdEndpoint(
                Ipv6SdEndpointSlice::from_slice(payload).map_err(map_len_err)?,
            ),
            option_type => {
                // SAFETY: `length >= 1` is verified above, so `payload` is non-empty.
                SdOptionSlice::Unknown(unsafe { UnknownSlice::unchecked_new(option_type, payload) })
            }
        };

        Ok((option, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err::{Layer, LenSource, SdOptionSliceError};
    use crate::sd::options::{
        ConfigurationSlice, Ipv4EndpointSlice, Ipv4MulticastSlice, Ipv4SdEndpointSlice,
        Ipv6EndpointSlice, Ipv6MulticastSlice, Ipv6SdEndpointSlice, LoadBalancingSlice,
        TransportProtocol, UnknownSlice, CONFIGURATION_TYPE, IPV4_ENDPOINT_TYPE,
        IPV4_MULTICAST_TYPE, IPV4_SD_ENDPOINT_TYPE, IPV6_ENDPOINT_TYPE, IPV6_MULTICAST_TYPE,
        IPV6_SD_ENDPOINT_TYPE, LOAD_BALANCING_TYPE,
    };

    #[test]
    fn from_impls() {
        // Configuration
        {
            let data = [0x00, 0x41, 0x42];
            let s = ConfigurationSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Configuration(s));
        }
        // LoadBalancing
        {
            let data = [0x00, 0x00, 0x01, 0x00, 0x02];
            let s = LoadBalancingSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::LoadBalancing(s));
        }
        // Ipv4Endpoint
        {
            let data = [0u8; 9];
            let s = Ipv4EndpointSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Ipv4Endpoint(s));
        }
        // Ipv6Endpoint
        {
            let data = [0u8; 21];
            let s = Ipv6EndpointSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Ipv6Endpoint(s));
        }
        // Ipv4Multicast
        {
            let data = [0u8; 9];
            let s = Ipv4MulticastSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Ipv4Multicast(s));
        }
        // Ipv6Multicast
        {
            let data = [0u8; 21];
            let s = Ipv6MulticastSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Ipv6Multicast(s));
        }
        // Ipv4SdEndpoint
        {
            let data = [0u8; 9];
            let s = Ipv4SdEndpointSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Ipv4SdEndpoint(s));
        }
        // Ipv6SdEndpoint
        {
            let data = [0u8; 21];
            let s = Ipv6SdEndpointSlice::from_slice(&data).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Ipv6SdEndpoint(s));
        }
        // Unknown
        {
            let payload = [0x80, 0x01, 0x02];
            let s = UnknownSlice::new(0xff, &payload).unwrap();
            let opt: SdOptionSlice = s.into();
            assert_eq!(opt, SdOptionSlice::Unknown(s));
        }
    }

    #[test]
    fn from_slice_too_short_for_header() {
        assert_eq!(
            SdOptionSlice::from_slice(&[]),
            Err(SdOptionSliceError::Len(err::LenError {
                required_len: 3,
                len: 0,
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            }))
        );
        assert_eq!(
            SdOptionSlice::from_slice(&[0x00, 0x01]),
            Err(SdOptionSliceError::Len(err::LenError {
                required_len: 3,
                len: 2,
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            }))
        );
    }

    #[test]
    fn from_slice_length_zero() {
        let data = [0x00, 0x00, IPV4_ENDPOINT_TYPE];
        assert_eq!(
            SdOptionSlice::from_slice(&data),
            Err(SdOptionSliceError::OptionLengthZero)
        );
    }

    #[test]
    fn from_slice_not_enough_data_for_payload() {
        // length says 9 but only 4 bytes of payload available
        let data = [0x00, 0x09, IPV4_ENDPOINT_TYPE, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            SdOptionSlice::from_slice(&data),
            Err(SdOptionSliceError::Len(err::LenError {
                required_len: 12,
                len: 7,
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            }))
        );
    }

    #[test]
    fn from_slice_ipv4_unexpected_len() {
        for t in [
            IPV4_ENDPOINT_TYPE,
            IPV4_MULTICAST_TYPE,
            IPV4_SD_ENDPOINT_TYPE,
        ] {
            let data = [0x00, 0x01, t, 0x00];
            assert_eq!(
                SdOptionSlice::from_slice(&data),
                Err(SdOptionSliceError::Len(err::LenError {
                    required_len: 9,
                    len: 1,
                    len_source: LenSource::SdOptionLength,
                    layer: Layer::SdOption,
                }))
            );
        }
    }

    #[test]
    fn from_slice_ipv6_unexpected_len() {
        for t in [
            IPV6_ENDPOINT_TYPE,
            IPV6_MULTICAST_TYPE,
            IPV6_SD_ENDPOINT_TYPE,
        ] {
            let data = [0x00, 0x01, t, 0x00];
            assert_eq!(
                SdOptionSlice::from_slice(&data),
                Err(SdOptionSliceError::Len(err::LenError {
                    required_len: 21,
                    len: 1,
                    len_source: LenSource::SdOptionLength,
                    layer: Layer::SdOption,
                }))
            );
        }
    }

    #[test]
    fn from_slice_load_balancing_unexpected_len() {
        let data = [0x00, 0x01, LOAD_BALANCING_TYPE, 0x00];
        assert_eq!(
            SdOptionSlice::from_slice(&data),
            Err(SdOptionSliceError::Len(err::LenError {
                required_len: 5,
                len: 1,
                len_source: LenSource::SdOptionLength,
                layer: Layer::SdOption,
            }))
        );
    }

    #[test]
    fn from_slice_configuration() {
        // minimal: length=1, just the reserved byte
        let data = [0x00, 0x01, CONFIGURATION_TYPE, 0x00];
        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Configuration(s) => {
                assert!(!s.discardable());
                assert_eq!(s.configuration_string(), &[] as &[u8]);
            }
            _ => panic!("expected Configuration"),
        }

        // with payload and extra trailing bytes
        let data = [0x00, 0x04, CONFIGURATION_TYPE, 0x80, 0x61, 0x62, 0x63, 0xAA];
        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert_eq!(rest, &[0xAA]);
        match opt {
            SdOptionSlice::Configuration(s) => {
                assert!(s.discardable());
                assert_eq!(s.configuration_string(), b"abc");
            }
            _ => panic!("expected Configuration"),
        }
    }

    #[test]
    fn from_slice_load_balancing() {
        let data = [
            0x00,
            0x05,
            LOAD_BALANCING_TYPE,
            0x00,
            0x12,
            0x34,
            0x56,
            0x78,
        ];
        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::LoadBalancing(s) => {
                assert_eq!(s.priority(), 0x1234);
                assert_eq!(s.weight(), 0x5678);
            }
            _ => panic!("expected LoadBalancing"),
        }
    }

    #[test]
    fn from_slice_ipv4_endpoint() {
        let mut data = [0u8; 12];
        data[0] = 0x00;
        data[1] = 0x09;
        data[2] = IPV4_ENDPOINT_TYPE;
        // reserved byte
        data[3] = 0x00;
        // ipv4 address
        data[4] = 0xc0;
        data[5] = 0xa8;
        data[6] = 0x01;
        data[7] = 0x01;
        // reserved
        data[8] = 0x00;
        // transport protocol (TCP)
        data[9] = 0x06;
        // port
        data[10] = 0x1f;
        data[11] = 0x90;

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Ipv4Endpoint(s) => {
                assert_eq!(s.ipv4_address(), [0xc0, 0xa8, 0x01, 0x01]);
                assert_eq!(s.transport_protocol(), TransportProtocol::Tcp);
                assert_eq!(s.port(), 8080);
            }
            _ => panic!("expected Ipv4Endpoint"),
        }
    }

    #[test]
    fn from_slice_ipv6_endpoint() {
        let mut data = [0u8; 24];
        data[0] = 0x00;
        data[1] = 0x15;
        data[2] = IPV6_ENDPOINT_TYPE;
        data[3] = 0x00; // reserved
        data[4..20].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[21] = 0x11; // UDP
        data[22] = 0x00;
        data[23] = 0x50; // port 80

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Ipv6Endpoint(s) => {
                assert_eq!(
                    s.ipv6_address(),
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
                assert_eq!(s.transport_protocol(), TransportProtocol::Udp);
                assert_eq!(s.port(), 80);
            }
            _ => panic!("expected Ipv6Endpoint"),
        }
    }

    #[test]
    fn from_slice_ipv4_multicast() {
        let mut data = [0u8; 12];
        data[0] = 0x00;
        data[1] = 0x09;
        data[2] = IPV4_MULTICAST_TYPE;
        data[3] = 0x00;
        data[4..8].copy_from_slice(&[0xe0, 0x00, 0x00, 0x01]);
        data[9] = 0x11; // UDP
        data[10] = 0x04;
        data[11] = 0xd2; // port 1234

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Ipv4Multicast(s) => {
                assert_eq!(s.ipv4_address(), [0xe0, 0x00, 0x00, 0x01]);
                assert_eq!(s.transport_protocol(), TransportProtocol::Udp);
                assert_eq!(s.port(), 1234);
            }
            _ => panic!("expected Ipv4Multicast"),
        }
    }

    #[test]
    fn from_slice_ipv6_multicast() {
        let mut data = [0u8; 24];
        data[0] = 0x00;
        data[1] = 0x15;
        data[2] = IPV6_MULTICAST_TYPE;
        data[3] = 0x00;
        data[4..20].copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[21] = 0x11; // UDP
        data[22] = 0x04;
        data[23] = 0xd2; // port 1234

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Ipv6Multicast(s) => {
                assert_eq!(
                    s.ipv6_address(),
                    [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
                assert_eq!(s.transport_protocol(), TransportProtocol::Udp);
                assert_eq!(s.port(), 1234);
            }
            _ => panic!("expected Ipv6Multicast"),
        }
    }

    #[test]
    fn from_slice_ipv4_sd_endpoint() {
        let mut data = [0u8; 12];
        data[0] = 0x00;
        data[1] = 0x09;
        data[2] = IPV4_SD_ENDPOINT_TYPE;
        data[3] = 0x00;
        data[4..8].copy_from_slice(&[0x0a, 0x00, 0x00, 0x01]);
        data[9] = 0x06; // TCP
        data[10] = 0x22;
        data[11] = 0xb8; // port 8888

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Ipv4SdEndpoint(s) => {
                assert_eq!(s.ipv4_address(), [0x0a, 0x00, 0x00, 0x01]);
                assert_eq!(s.transport_protocol(), TransportProtocol::Tcp);
                assert_eq!(s.port(), 8888);
            }
            _ => panic!("expected Ipv4SdEndpoint"),
        }
    }

    #[test]
    fn from_slice_ipv6_sd_endpoint() {
        let mut data = [0u8; 24];
        data[0] = 0x00;
        data[1] = 0x15;
        data[2] = IPV6_SD_ENDPOINT_TYPE;
        data[3] = 0x00;
        data[4..20].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[21] = 0x06; // TCP
        data[22] = 0x00;
        data[23] = 0x50; // port 80

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Ipv6SdEndpoint(s) => {
                assert_eq!(
                    s.ipv6_address(),
                    [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
                assert_eq!(s.transport_protocol(), TransportProtocol::Tcp);
                assert_eq!(s.port(), 80);
            }
            _ => panic!("expected Ipv6SdEndpoint"),
        }
    }

    #[test]
    fn from_slice_unknown_discardable() {
        // type 0xff, discardable flag set, length=3
        let data = [0x00, 0x03, 0xff, 0x80, 0x01, 0x02];
        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Unknown(s) => {
                assert_eq!(s.option_type(), 0xff);
                assert!(s.discardable());
                assert_eq!(s.slice(), &[0x80, 0x01, 0x02]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn from_slice_unknown_not_discardable() {
        // type 0xff, discardable flag NOT set, length=1
        let data = [0x00, 0x01, 0xff, 0x00];
        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(rest.is_empty());
        match opt {
            SdOptionSlice::Unknown(s) => {
                assert_eq!(s.option_type(), 0xff);
                assert!(!s.discardable());
                assert_eq!(s.slice(), &[0x00]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn from_slice_returns_rest() {
        // IPv4 endpoint (12 bytes) followed by 3 trailing bytes
        let mut data = [0xBB; 15];
        data[0] = 0x00;
        data[1] = 0x09;
        data[2] = IPV4_ENDPOINT_TYPE;
        data[3] = 0x00;
        data[4..12].copy_from_slice(&[0xc0, 0xa8, 0x01, 0x01, 0x00, 0x06, 0x1f, 0x90]);

        let (opt, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(matches!(opt, SdOptionSlice::Ipv4Endpoint(_)));
        assert_eq!(rest, &[0xBB, 0xBB, 0xBB]);
    }

    #[test]
    fn from_slice_multiple_sequential() {
        // Two options back to back: load balancing + unknown
        let mut data = Vec::new();
        // Load balancing: length=5, type=0x02
        data.extend_from_slice(&[
            0x00,
            0x05,
            LOAD_BALANCING_TYPE,
            0x00,
            0x00,
            0x01,
            0x00,
            0x02,
        ]);
        // Unknown: length=1, type=0xAA
        data.extend_from_slice(&[0x00, 0x01, 0xAA, 0x00]);

        let (opt1, rest) = SdOptionSlice::from_slice(&data).unwrap();
        assert!(matches!(opt1, SdOptionSlice::LoadBalancing(_)));

        let (opt2, rest) = SdOptionSlice::from_slice(rest).unwrap();
        assert!(matches!(opt2, SdOptionSlice::Unknown(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn clone_copy_debug_eq_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let data = [0x00, 0x01, 0xff, 0x80];
        let (opt, _) = SdOptionSlice::from_slice(&data).unwrap();
        let copy = opt;
        assert_eq!(opt, copy);
        assert_eq!(opt, opt.clone());

        let hash_a = {
            let mut hasher = DefaultHasher::new();
            opt.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            opt.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);

        let _ = format!("{:?}", opt);
    }
}
