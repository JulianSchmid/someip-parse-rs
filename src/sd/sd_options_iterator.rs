use crate::err::SdOptionSliceError;
use crate::sd::SdOptionSlice;

/// Iterator over SD options in a byte slice, yielding [`SdOptionSlice`]
/// values.
///
/// Created from the raw options byte slice (i.e. the payload of the
/// options array, *without* the 4-byte length prefix).
///
/// On the first error the iterator yields the error and then stops
/// (subsequent calls to [`next`](Iterator::next) return `None`).
///
/// # Example
///
/// ```
/// use someip_parse::sd::{SdOptionsIterator, SdOptionSlice};
///
/// let data = [
///     // IPv4 Endpoint option: length=9, type=0x04
///     0x00, 0x09, 0x04,
///     0x00, 0xc0, 0xa8, 0x01, 0x01, 0x00, 0x06, 0x1f, 0x90,
/// ];
///
/// let mut iter = SdOptionsIterator::new(&data);
/// let opt = iter.next().unwrap().unwrap();
/// assert!(matches!(opt, SdOptionSlice::Ipv4Endpoint(_)));
/// assert!(iter.next().is_none());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdOptionsIterator<'a> {
    slice: &'a [u8],
}

impl<'a> SdOptionsIterator<'a> {
    /// Creates a new iterator over the SD options contained in `slice`.
    #[inline]
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice }
    }

    /// Returns the remaining unparsed bytes.
    #[inline]
    pub fn rest(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> Iterator for SdOptionsIterator<'a> {
    type Item = Result<SdOptionSlice<'a>, SdOptionSliceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }

        match SdOptionSlice::from_slice(self.slice) {
            Ok((option, rest)) => {
                self.slice = rest;
                Some(Ok(option))
            }
            Err(err) => {
                self.slice = &self.slice[self.slice.len()..];
                Some(Err(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err::{self, Layer, LenSource};
    use crate::sd::options::*;

    #[test]
    fn new_and_rest() {
        let data = [0x01, 0x02, 0x03];
        let iter = SdOptionsIterator::new(&data);
        assert_eq!(iter.rest(), &data);
    }

    #[test]
    fn empty_slice() {
        let mut iter = SdOptionsIterator::new(&[]);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn single_option() {
        let mut data = [0u8; 12];
        data[0] = 0x00;
        data[1] = 0x09;
        data[2] = IPV4_ENDPOINT_TYPE;
        data[3] = 0x00;
        data[4..8].copy_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        data[9] = 0x06;
        data[10] = 0x1f;
        data[11] = 0x90;

        let mut iter = SdOptionsIterator::new(&data);
        let opt = iter.next().unwrap().unwrap();
        match opt {
            SdOptionSlice::Ipv4Endpoint(s) => {
                assert_eq!(s.ipv4_address(), [0xc0, 0xa8, 0x01, 0x01]);
                assert_eq!(s.transport_protocol(), TransportProtocol::Tcp);
                assert_eq!(s.port(), 8080);
            }
            _ => panic!("expected Ipv4Endpoint"),
        }
        assert!(iter.rest().is_empty());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn multiple_options() {
        let mut data = Vec::new();
        // Load balancing: length=5, type=0x02
        data.extend_from_slice(&[0x00, 0x05, LOAD_BALANCING_TYPE, 0x00, 0x12, 0x34, 0x56, 0x78]);
        // Configuration: length=4, type=0x01
        data.extend_from_slice(&[0x00, 0x04, CONFIGURATION_TYPE, 0x00, 0x61, 0x62, 0x63]);
        // Unknown: length=1, type=0xAA
        data.extend_from_slice(&[0x00, 0x01, 0xAA, 0x80]);

        let items: Vec<_> = SdOptionsIterator::new(&data)
            .collect::<Vec<_>>();
        assert_eq!(items.len(), 3);

        assert!(matches!(items[0], Ok(SdOptionSlice::LoadBalancing(_))));
        assert!(matches!(items[1], Ok(SdOptionSlice::Configuration(_))));
        assert!(matches!(items[2], Ok(SdOptionSlice::Unknown(_))));
    }

    #[test]
    fn error_stops_iteration() {
        // Valid load balancing followed by truncated data
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x05, LOAD_BALANCING_TYPE, 0x00, 0x00, 0x01, 0x00, 0x02]);
        // Truncated: length says 9 but only 2 bytes of payload
        data.extend_from_slice(&[0x00, 0x09, IPV4_ENDPOINT_TYPE, 0x00, 0x00]);

        let mut iter = SdOptionsIterator::new(&data);
        assert!(iter.next().unwrap().is_ok());

        let err = iter.next().unwrap().unwrap_err();
        assert_eq!(
            err,
            SdOptionSliceError::Len(err::LenError {
                required_len: 12,
                len: 5,
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            })
        );

        assert!(iter.rest().is_empty());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn error_on_first_item() {
        let data = [0x00, 0x00, IPV4_ENDPOINT_TYPE];
        let mut iter = SdOptionsIterator::new(&data);

        let err = iter.next().unwrap().unwrap_err();
        assert_eq!(err, SdOptionSliceError::OptionLengthZero);

        assert!(iter.rest().is_empty());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn rest_advances() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x05, LOAD_BALANCING_TYPE, 0x00, 0x00, 0x01, 0x00, 0x02]);
        data.extend_from_slice(&[0x00, 0x01, 0xAA, 0x80]);

        let mut iter = SdOptionsIterator::new(&data);
        assert_eq!(iter.rest().len(), 12);

        iter.next();
        assert_eq!(iter.rest().len(), 4);

        iter.next();
        assert_eq!(iter.rest().len(), 0);
    }

    #[test]
    fn clone_debug_eq() {
        let data = [0x00, 0x01, 0xFF, 0x00];
        let iter = SdOptionsIterator::new(&data);
        assert_eq!(iter, iter.clone());
        let _ = format!("{:?}", iter);
    }
}
