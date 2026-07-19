use crate::sd::SdOptionSlice;

/// Iterator over SD options in a byte slice that has already been
/// validated, yielding [`SdOptionSlice`] values directly.
///
/// Unlike [`super::SdOptionsIterator`], this iterator does **not**
/// wrap items in `Result`. It is intended for slices whose contents
/// are guaranteed to decode without errors (e.g. data that was
/// previously serialized by [`super::SdHeader`]).
///
/// # Panics
///
/// If the underlying data cannot be decoded, [`next`](Iterator::next)
/// will panic. Use [`super::SdOptionsIterator`] when the input may
/// contain invalid data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdOptionsCheckedIterator<'a> {
    slice: &'a [u8],
}

impl<'a> SdOptionsCheckedIterator<'a> {
    /// Creates a new checked iterator over the SD options contained
    /// in `slice`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `slice` contains validly encoded
    /// SD options. If this invariant is violated, iteration will panic
    /// or cause undefined behavior via internal unchecked operations.
    #[inline]
    pub unsafe fn new(slice: &'a [u8]) -> Self {
        Self { slice }
    }

    /// Returns the remaining unparsed bytes.
    #[inline]
    pub fn rest(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> Iterator for SdOptionsCheckedIterator<'a> {
    type Item = SdOptionSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }

        let (option, rest) = SdOptionSlice::from_validated_slice(self.slice)
            .expect("SdOptionsCheckedIterator: corrupt option data");
        self.slice = rest;
        Some(option)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use super::*;
    use crate::sd::options::*;

    #[test]
    fn empty_slice() {
        let mut iter = unsafe { SdOptionsCheckedIterator::new(&[]) };
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

        let mut iter = unsafe { SdOptionsCheckedIterator::new(&data) };
        let opt = iter.next().unwrap();
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
        data.extend_from_slice(&[
            0x00,
            0x05,
            LOAD_BALANCING_TYPE,
            0x00,
            0x12,
            0x34,
            0x56,
            0x78,
        ]);
        data.extend_from_slice(&[
            0x00,
            0x06,
            CONFIGURATION_TYPE,
            0x00,
            0x03,
            0x61,
            0x62,
            0x63,
            0x00,
        ]);
        data.extend_from_slice(&[0x00, 0x01, 0xAA, 0x80]);

        let items: Vec<_> = unsafe { SdOptionsCheckedIterator::new(&data) }.collect();
        assert_eq!(items.len(), 3);

        assert!(matches!(items[0], SdOptionSlice::LoadBalancing(_)));
        assert!(matches!(items[1], SdOptionSlice::Configuration(_)));
        assert!(matches!(items[2], SdOptionSlice::Unknown(_)));
    }

    #[test]
    fn rest_advances() {
        let mut data = Vec::new();
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
        data.extend_from_slice(&[0x00, 0x01, 0xAA, 0x80]);

        let mut iter = unsafe { SdOptionsCheckedIterator::new(&data) };
        assert_eq!(iter.rest().len(), 12);

        iter.next();
        assert_eq!(iter.rest().len(), 4);

        iter.next();
        assert_eq!(iter.rest().len(), 0);
    }

    #[test]
    #[should_panic(expected = "SdOptionsCheckedIterator: corrupt option data")]
    fn panics_on_invalid_data() {
        let data = [0x00, 0x00, IPV4_ENDPOINT_TYPE];
        let mut iter = unsafe { SdOptionsCheckedIterator::new(&data) };
        let _ = iter.next();
    }

    #[test]
    fn clone_debug_eq() {
        let data = [0x00, 0x01, 0xFF, 0x00];
        let iter = unsafe { SdOptionsCheckedIterator::new(&data) };
        assert_eq!(iter, iter.clone());
        let _ = format!("{:?}", iter);
    }
}
