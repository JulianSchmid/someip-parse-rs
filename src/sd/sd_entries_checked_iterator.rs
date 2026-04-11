use crate::sd::SdEntrySlice;

/// Iterator over SD entries in a byte slice that has already been
/// validated, yielding [`SdEntrySlice`] values directly.
///
/// Unlike [`super::SdEntriesIterator`], this iterator does **not**
/// wrap items in `Result`. It is intended for slices whose contents
/// are guaranteed to decode without errors (e.g. data that was
/// previously serialized by [`super::SdHeader`]).
///
/// # Panics
///
/// If the underlying data cannot be decoded, [`next`](Iterator::next)
/// will panic. Use [`super::SdEntriesIterator`] when the input may
/// contain invalid data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdEntriesCheckedIterator<'a> {
    slice: &'a [u8],
}

impl<'a> SdEntriesCheckedIterator<'a> {
    /// Creates a new checked iterator over the SD entries contained
    /// in `slice`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `slice` contains validly encoded
    /// SD entries. If this invariant is violated, iteration will panic
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

impl<'a> Iterator for SdEntriesCheckedIterator<'a> {
    type Item = SdEntrySlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }

        let entry = SdEntrySlice::from_slice(self.slice)
            .expect("SdEntriesCheckedIterator: corrupt entry data");
        let len = entry.slice().len();
        // SAFETY: len is guaranteed to be less or equal than self.slice.len()
        self.slice = unsafe {
            core::slice::from_raw_parts(self.slice.as_ptr().add(len), self.slice.len() - len)
        };
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sd::entries::*;

    #[test]
    fn empty_slice() {
        let mut iter = unsafe { SdEntriesCheckedIterator::new(&[]) };
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn single_entry() {
        let mut data = [0u8; ENTRY_LEN];
        data[0] = 0x01; // OfferService
        data[4] = 0x12;
        data[5] = 0x34;

        let mut iter = unsafe { SdEntriesCheckedIterator::new(&data) };
        let entry = iter.next().unwrap();
        match entry {
            SdEntrySlice::Service(s) => {
                assert_eq!(s.entry_type(), SdServiceEntryType::OfferService);
                assert_eq!(s.service_id(), 0x1234);
            }
            _ => panic!("expected Service"),
        }
        assert!(iter.rest().is_empty());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn multiple_entries() {
        let mut data = [0u8; ENTRY_LEN * 3];
        data[0] = 0x00; // FindService
        data[ENTRY_LEN] = 0x01; // OfferService
        data[ENTRY_LEN * 2] = 0x06; // Subscribe

        let items: Vec<_> = unsafe { SdEntriesCheckedIterator::new(&data) }.collect();
        assert_eq!(items.len(), 3);

        assert!(matches!(items[0], SdEntrySlice::Service(_)));
        assert!(matches!(items[1], SdEntrySlice::Service(_)));
        assert!(matches!(items[2], SdEntrySlice::Eventgroup(_)));
    }

    #[test]
    fn rest_advances() {
        let mut data = [0u8; ENTRY_LEN * 2];
        data[0] = 0x00;
        data[ENTRY_LEN] = 0x06;

        let mut iter = unsafe { SdEntriesCheckedIterator::new(&data) };
        assert_eq!(iter.rest().len(), ENTRY_LEN * 2);

        iter.next();
        assert_eq!(iter.rest().len(), ENTRY_LEN);

        iter.next();
        assert_eq!(iter.rest().len(), 0);
    }

    #[test]
    #[should_panic(expected = "SdEntriesCheckedIterator: corrupt entry data")]
    fn panics_on_invalid_data() {
        let mut data = [0u8; ENTRY_LEN];
        data[0] = 0xFF; // unknown type
        let mut iter = unsafe { SdEntriesCheckedIterator::new(&data) };
        let _ = iter.next();
    }

    #[test]
    fn clone_debug_eq() {
        let data = [0u8; ENTRY_LEN]; // type 0x00 = FindService
        let iter = unsafe { SdEntriesCheckedIterator::new(&data) };
        assert_eq!(iter, iter.clone());
        let _ = format!("{:?}", iter);
    }
}
