use crate::err::{SdError, SdOptionSliceError, SdSliceError};
use crate::sd::entries::U4;
use crate::sd::{options::MAX_OPTIONS_LEN_USIZE, SdOptionSlice};
use arrayvec::ArrayVec;

/// Maximum number of options that can be present in an SD options array.
///
/// The smallest possible option on the wire consists of a 2 byte `length`
/// field, a 1 byte `type` field and at least 1 byte of payload (the
/// `length` field must be at least 1). This gives a minimum option size of
/// 4 bytes, so at most [`MAX_OPTIONS_LEN_USIZE`] / 4 options can fit into
/// the options array.
pub const MAX_SD_OPTIONS_USIZE: usize = MAX_OPTIONS_LEN_USIZE / 4;

/// Index over the options of an SD message allowing O(1) access to
/// individual options by their ordinal position.
///
/// SD entries reference their options by an ordinal index into the options
/// array (the "index first/second option run" fields) together with a
/// count. As options are variable length, resolving the i-th option would
/// normally require re-parsing all preceding options. This index parses the
/// options array once (validating every option) and stores the byte offset
/// of each option in a fixed capacity [`ArrayVec`], so subsequent lookups
/// are O(1) and require no allocation.
///
/// # Example
///
/// ```
/// use someip_parse::sd::{SdOptionsIndex, SdOptionSlice};
///
/// let data = [
///     // IPv4 Endpoint option: length=9, type=0x04
///     0x00, 0x09, 0x04,
///     0x00, 0xc0, 0xa8, 0x01, 0x01, 0x00, 0x06, 0x1f, 0x90,
/// ];
///
/// let index = SdOptionsIndex::from_slice(&data).unwrap();
/// assert_eq!(index.len(), 1);
/// assert!(matches!(index.get(0), Some(SdOptionSlice::Ipv4Endpoint(_))));
/// assert!(index.get(1).is_none());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdOptionsIndex<'a> {
    options: &'a [u8],
    offsets: ArrayVec<u16, MAX_SD_OPTIONS_USIZE>,
}

impl<'a> SdOptionsIndex<'a> {
    /// Parses the options array once and builds an index of the byte offset
    /// of every option.
    ///
    /// # Errors
    ///
    /// Returns an [`SdOptionSliceError`] if any option in the slice cannot
    /// be decoded (e.g. truncated data or an option with a zero length
    /// field), or if the slice is larger than the maximum SOME/IP-SD
    /// options array.
    pub fn from_slice(options: &'a [u8]) -> Result<Self, SdOptionSliceError> {
        if options.len() > MAX_OPTIONS_LEN_USIZE {
            return Err(SdOptionSliceError::OptionsArrayLengthTooLarge {
                len: options.len(),
                max_len: MAX_OPTIONS_LEN_USIZE,
            });
        }

        let mut offsets = ArrayVec::new();
        let mut rest = options;
        while !rest.is_empty() {
            // offset of the current option relative to the start of `options`
            let offset = (options.len() - rest.len()) as u16;
            // The capacity is derived from the minimum option size, so as
            // long as `options.len() <= MAX_OPTIONS_LEN_USIZE` this can not
            // overflow. Keep this fallible to avoid turning a future change
            // to either invariant into a panic on untrusted input.
            offsets.try_push(offset).map_err(|_| {
                SdOptionSliceError::OptionsArrayLengthTooLarge {
                    len: options.len(),
                    max_len: MAX_OPTIONS_LEN_USIZE,
                }
            })?;

            let (_option, next) = SdOptionSlice::from_slice(rest)?;
            rest = next;
        }
        Ok(Self { options, offsets })
    }

    /// Returns the underlying options byte slice.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        self.options
    }

    /// Returns the number of options in the index.
    #[inline]
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Returns true if there are no options in the index.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Returns the option at the given ordinal index in O(1), or `None`
    /// if the index is out of range.
    #[inline]
    pub fn get(&self, index: usize) -> Option<SdOptionSlice<'a>> {
        let offset = usize::from(*self.offsets.get(index)?);
        // SAFETY (logical): every offset stored in `offsets` was produced
        // by a successful `SdOptionSlice::from_slice` in `from_slice`, so
        // re-parsing from that offset can not fail.
        let (option, _rest) = SdOptionSlice::from_validated_slice(&self.options[offset..])
            .expect("SdOptionsIndex: corrupt option data");
        Some(option)
    }

    /// Returns an iterator over an option run, i.e. `count` consecutive
    /// options starting at the ordinal index `start`.
    ///
    /// If a referenced index is out of range (which can only happen for
    /// malformed entries that reference more options than are present) the
    /// iterator stops early.
    #[inline]
    pub fn run(&self, start: u8, count: U4) -> SdOptionRunIter<'a, '_> {
        SdOptionRunIter {
            index: self,
            next: usize::from(start),
            remaining: count.value(),
        }
    }

    #[inline]
    pub(crate) fn validate_run(&self, run: u8, start: u8, count: U4) -> Result<(), SdSliceError> {
        let count = count.value();
        // PRS_SOMEIPSD_00834: a zero-length run is ignored even if its
        // index is non-zero.
        if count == 0 || usize::from(start) + usize::from(count) <= self.len() {
            Ok(())
        } else {
            Err(SdSliceError::Content(SdError::SdOptionRunOutOfBounds {
                run,
                start_index: start,
                number_of_options: count,
                options_len: self.len(),
            }))
        }
    }
}

/// Iterator over an option run of an SD entry, yielding [`SdOptionSlice`]
/// values resolved through an [`SdOptionsIndex`].
///
/// Stops early if a referenced option index is out of range.
#[derive(Clone, Debug)]
pub struct SdOptionRunIter<'a, 'i> {
    index: &'i SdOptionsIndex<'a>,
    next: usize,
    remaining: u8,
}

impl<'a, 'i> Iterator for SdOptionRunIter<'a, 'i> {
    type Item = SdOptionSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let option = self.index.get(self.next)?;
        self.remaining -= 1;
        self.next += 1;
        Some(option)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(usize::from(self.remaining)))
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use super::*;
    use crate::sd::options::*;

    fn ipv4(port: u16) -> [u8; 12] {
        let p = port.to_be_bytes();
        [
            0x00,
            0x09,
            IPV4_ENDPOINT_TYPE,
            0x00,
            0xc0,
            0xa8,
            0x01,
            0x01,
            0x00,
            0x06,
            p[0],
            p[1],
        ]
    }

    #[test]
    fn empty() {
        let index = SdOptionsIndex::from_slice(&[]).unwrap();
        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
        assert!(index.get(0).is_none());
        assert_eq!(index.options(), &[] as &[u8]);
    }

    #[test]
    fn single() {
        let data = ipv4(8080);
        let index = SdOptionsIndex::from_slice(&data).unwrap();
        assert_eq!(index.len(), 1);
        assert!(!index.is_empty());
        match index.get(0).unwrap() {
            SdOptionSlice::Ipv4Endpoint(s) => assert_eq!(s.port(), 8080),
            _ => panic!("expected Ipv4Endpoint"),
        }
        assert!(index.get(1).is_none());
    }

    #[test]
    fn multiple() {
        let mut data = Vec::new();
        data.extend_from_slice(&ipv4(1));
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
        data.extend_from_slice(&ipv4(2));

        let index = SdOptionsIndex::from_slice(&data).unwrap();
        assert_eq!(index.len(), 3);
        assert!(matches!(index.get(0), Some(SdOptionSlice::Ipv4Endpoint(_))));
        assert!(matches!(
            index.get(1),
            Some(SdOptionSlice::LoadBalancing(_))
        ));
        assert!(matches!(index.get(2), Some(SdOptionSlice::Ipv4Endpoint(_))));

        match (index.get(0).unwrap(), index.get(2).unwrap()) {
            (SdOptionSlice::Ipv4Endpoint(a), SdOptionSlice::Ipv4Endpoint(b)) => {
                assert_eq!(a.port(), 1);
                assert_eq!(b.port(), 2);
            }
            _ => panic!("expected Ipv4Endpoint"),
        }
    }

    #[test]
    fn from_slice_error() {
        // length says 9 but not enough payload
        let data = [0x00, 0x09, IPV4_ENDPOINT_TYPE, 0x00, 0x00];
        assert!(SdOptionsIndex::from_slice(&data).is_err());
    }

    #[test]
    fn from_slice_rejects_oversized_array_without_panicking() {
        let data = alloc::vec![0; MAX_OPTIONS_LEN_USIZE + 1];
        assert_eq!(
            SdOptionsIndex::from_slice(&data),
            Err(SdOptionSliceError::OptionsArrayLengthTooLarge {
                len: MAX_OPTIONS_LEN_USIZE + 1,
                max_len: MAX_OPTIONS_LEN_USIZE,
            })
        );
    }

    #[test]
    fn run_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(&ipv4(1));
        data.extend_from_slice(&ipv4(2));
        data.extend_from_slice(&ipv4(3));
        let index = SdOptionsIndex::from_slice(&data).unwrap();

        let ports: Vec<u16> = index
            .run(1, U4::N2)
            .map(|o| match o {
                SdOptionSlice::Ipv4Endpoint(s) => s.port(),
                _ => panic!("expected Ipv4Endpoint"),
            })
            .collect();
        assert_eq!(ports, alloc::vec![2, 3]);
    }

    #[test]
    fn run_zero_count() {
        let data = ipv4(1);
        let index = SdOptionsIndex::from_slice(&data).unwrap();
        assert_eq!(index.run(0, U4::ZERO).count(), 0);
    }

    #[test]
    fn run_out_of_range_stops_early() {
        let mut data = Vec::new();
        data.extend_from_slice(&ipv4(1));
        data.extend_from_slice(&ipv4(2));
        let index = SdOptionsIndex::from_slice(&data).unwrap();

        // starts at index 1 (valid) and requests 3 -> only 1 available
        assert_eq!(index.run(1, U4::N3).count(), 1);
        // start already out of range -> nothing
        assert_eq!(index.run(5, U4::N3).count(), 0);
    }

    #[test]
    fn run_size_hint() {
        let data = ipv4(1);
        let index = SdOptionsIndex::from_slice(&data).unwrap();
        let iter = index.run(0, U4::N3);
        assert_eq!(iter.size_hint(), (0, Some(3)));
    }

    #[test]
    fn validate_run_rejects_out_of_bounds_references() {
        let data = ipv4(1);
        let index = SdOptionsIndex::from_slice(&data).unwrap();

        assert!(index.validate_run(1, 0, U4::N1).is_ok());
        assert!(index.validate_run(1, u8::MAX, U4::ZERO).is_ok());
        assert!(matches!(
            index.validate_run(2, 1, U4::N1),
            Err(SdSliceError::Content(SdError::SdOptionRunOutOfBounds {
                run: 2,
                start_index: 1,
                number_of_options: 1,
                options_len: 1,
            }))
        ));
    }

    #[test]
    fn clone_debug_eq() {
        let data = ipv4(1);
        let index = SdOptionsIndex::from_slice(&data).unwrap();
        assert_eq!(index, index.clone());
        let _ = format!("{:?}", index);
        let _ = format!("{:?}", index.run(0, U4::N1));
    }
}
