use crate::err::SdReadError;
use crate::sd::{entries::ENTRY_LEN, SdEntrySlice};

/// Iterator over SD entries in a byte slice, yielding [`SdEntrySlice`]
/// values.
///
/// Created from the raw entries byte slice (i.e. the payload of the
/// entries array, *without* the 4-byte length prefix).
///
/// On the first error the iterator yields the error and then stops
/// (subsequent calls to [`next`](Iterator::next) return `None`).
///
/// Unknown entry types are skipped as required by PRS_SOMEIPSD_00841, so the
/// number of yielded items can be smaller than `slice.len() / ENTRY_LEN`.
///
/// # Example
///
/// ```
/// use someip_parse::sd::{SdEntriesIterator, SdEntrySlice};
///
/// // Two FindService entries back-to-back (16 bytes each, type 0x00)
/// let data = [0u8; 32];
///
/// let mut iter = SdEntriesIterator::new(&data);
/// let entry = iter.next().unwrap().unwrap();
/// assert!(matches!(entry, SdEntrySlice::Service(_)));
/// let entry = iter.next().unwrap().unwrap();
/// assert!(matches!(entry, SdEntrySlice::Service(_)));
/// assert!(iter.next().is_none());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdEntriesIterator<'a> {
    slice: &'a [u8],
}

impl<'a> SdEntriesIterator<'a> {
    /// Creates a new iterator over the SD entries contained in `slice`.
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

impl<'a> Iterator for SdEntriesIterator<'a> {
    type Item = Result<SdEntrySlice<'a>, SdReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.slice.is_empty() {
                return None;
            }

            match SdEntrySlice::from_slice(self.slice) {
                Ok(entry) => {
                    let len = entry.slice().len();
                    self.slice = unsafe {
                        core::slice::from_raw_parts(
                            self.slice.as_ptr().add(len),
                            self.slice.len() - len,
                        )
                    };
                    return Some(Ok(entry));
                }
                Err(SdReadError::UnknownSdServiceEntryType(_)) if self.slice.len() >= ENTRY_LEN => {
                    // AUTOSAR PRS_SOMEIPSD_00841 requires receivers to ignore
                    // entries of unknown type and continue with later entries.
                    self.slice = unsafe {
                        core::slice::from_raw_parts(
                            self.slice.as_ptr().add(ENTRY_LEN),
                            self.slice.len() - ENTRY_LEN,
                        )
                    };
                }
                Err(err) => {
                    self.slice = &self.slice[self.slice.len()..];
                    return Some(Err(err));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use super::*;
    use crate::sd::entries::*;

    #[test]
    fn new_and_rest() {
        let data = [0x01, 0x02, 0x03];
        let iter = SdEntriesIterator::new(&data);
        assert_eq!(iter.rest(), &data);
    }

    #[test]
    fn empty_slice() {
        let mut iter = SdEntriesIterator::new(&[]);
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn single_entry() {
        let mut data = [0u8; ENTRY_LEN];
        data[0] = 0x01; // OfferService
        data[4] = 0x12;
        data[5] = 0x34;

        let mut iter = SdEntriesIterator::new(&data);
        let entry = iter.next().unwrap().unwrap();
        match entry {
            SdEntrySlice::Service(s) => {
                assert_eq!(s.entry_type(), SdServiceEntryType::OfferService);
                assert_eq!(s.service_id(), 0x1234);
            }
            _ => panic!("expected Service"),
        }
        assert!(iter.rest().is_empty());
        assert!(iter.next().is_none());
    }

    #[test]
    fn multiple_entries() {
        let mut data = [0u8; ENTRY_LEN * 3];
        data[0] = 0x00; // FindService
        data[ENTRY_LEN] = 0x01; // OfferService
        data[ENTRY_LEN * 2] = 0x06; // Subscribe

        let items: Vec<_> = SdEntriesIterator::new(&data).collect();
        assert_eq!(items.len(), 3);

        assert!(matches!(items[0], Ok(SdEntrySlice::Service(_))));
        assert!(matches!(items[1], Ok(SdEntrySlice::Service(_))));
        assert!(matches!(items[2], Ok(SdEntrySlice::Eventgroup(_))));
    }

    #[test]
    fn error_stops_iteration() {
        let mut data = [0u8; ENTRY_LEN + 4];
        data[0] = 0x01; // valid OfferService
                        // bytes 16..19: only 4 bytes, too short for another entry

        let mut iter = SdEntriesIterator::new(&data);
        assert!(iter.next().unwrap().is_ok());

        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(err, SdReadError::UnexpectedEndOfSlice(_)));

        assert!(iter.rest().is_empty());
        assert!(iter.next().is_none());
    }

    #[test]
    fn ignores_unknown_type_and_continues() {
        let mut data = [0u8; ENTRY_LEN * 3];
        data[0] = 0x01; // valid OfferService
        data[ENTRY_LEN] = 0xFF; // unknown type
        data[ENTRY_LEN * 2] = 0x06; // valid Subscribe

        let mut iter = SdEntriesIterator::new(&data);
        assert!(iter.next().unwrap().is_ok());
        assert!(matches!(iter.next(), Some(Ok(SdEntrySlice::Eventgroup(_)))));
        assert!(iter.rest().is_empty());
        assert!(iter.next().is_none());
    }

    #[test]
    fn error_on_first_item() {
        let data = [0xFF; 4]; // too short
        let mut iter = SdEntriesIterator::new(&data);

        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(err, SdReadError::UnexpectedEndOfSlice(_)));

        assert!(iter.rest().is_empty());
        assert!(iter.next().is_none());
    }

    #[test]
    fn rest_advances() {
        let mut data = [0u8; ENTRY_LEN * 2];
        data[0] = 0x00;
        data[ENTRY_LEN] = 0x06;

        let mut iter = SdEntriesIterator::new(&data);
        assert_eq!(iter.rest().len(), ENTRY_LEN * 2);

        iter.next();
        assert_eq!(iter.rest().len(), ENTRY_LEN);

        iter.next();
        assert_eq!(iter.rest().len(), 0);
    }

    #[test]
    fn clone_debug_eq() {
        let data = [0u8; ENTRY_LEN];
        let iter = SdEntriesIterator::new(&data);
        assert_eq!(iter, iter.clone());
        let _ = format!("{:?}", iter);
    }
}
