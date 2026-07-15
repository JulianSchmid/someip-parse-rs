use crate::err::SdReadError;
use crate::sd::{
    SdEntriesCheckedIterator, SdEntriesIterator, SdEntrySlice, SdOptionRunIter, SdOptionsIndex,
};

/// An SD entry together with access to its resolved option runs.
///
/// The options are resolved lazily through a borrowed [`SdOptionsIndex`],
/// so obtaining an [`SdEntryWithOptions`] does not parse any options; only
/// iterating [`options_run_1`](Self::options_run_1) or
/// [`options_run_2`](Self::options_run_2) does.
#[derive(Clone, Debug)]
pub struct SdEntryWithOptions<'a, 'i> {
    entry: SdEntrySlice<'a>,
    options: &'i SdOptionsIndex<'a>,
}

impl<'a, 'i> SdEntryWithOptions<'a, 'i> {
    #[inline]
    pub(crate) fn new(entry: SdEntrySlice<'a>, options: &'i SdOptionsIndex<'a>) -> Self {
        Self { entry, options }
    }

    /// Returns the underlying entry.
    #[inline]
    pub fn entry(&self) -> SdEntrySlice<'a> {
        self.entry
    }

    /// Returns the option index the runs are resolved through.
    #[inline]
    pub fn options_index(&self) -> &'i SdOptionsIndex<'a> {
        self.options
    }

    /// Returns an iterator over the options of the first option run.
    #[inline]
    pub fn options_run_1(&self) -> SdOptionRunIter<'a, 'i> {
        self.options.run(
            self.entry.start_index_options_1(),
            self.entry.number_of_options_1(),
        )
    }

    /// Returns an iterator over the options of the second option run.
    #[inline]
    pub fn options_run_2(&self) -> SdOptionRunIter<'a, 'i> {
        self.options.run(
            self.entry.start_index_options_2(),
            self.entry.number_of_options_2(),
        )
    }
}

/// Iterator over SD entries yielding each entry together with access to its
/// resolved options (see [`SdEntryWithOptions`]).
///
/// On the first error while decoding an entry the iterator yields the error
/// and then stops. Use [`SdEntriesWithOptionsCheckedIterator`] for data that
/// is guaranteed to be valid.
#[derive(Clone, Debug)]
pub struct SdEntriesWithOptionsIterator<'a, 'i> {
    entries: SdEntriesIterator<'a>,
    options: &'i SdOptionsIndex<'a>,
}

impl<'a, 'i> SdEntriesWithOptionsIterator<'a, 'i> {
    /// Creates a new iterator over the entries in `entries`, resolving
    /// options through `options`.
    #[inline]
    pub fn new(entries: &'a [u8], options: &'i SdOptionsIndex<'a>) -> Self {
        Self {
            entries: SdEntriesIterator::new(entries),
            options,
        }
    }
}

impl<'a, 'i> Iterator for SdEntriesWithOptionsIterator<'a, 'i> {
    type Item = Result<SdEntryWithOptions<'a, 'i>, SdReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.entries.next()? {
            Ok(entry) => Some(Ok(SdEntryWithOptions::new(entry, self.options))),
            Err(err) => Some(Err(err)),
        }
    }
}

/// Iterator over SD entries yielding each entry together with access to its
/// resolved options, for entry data that is already known to be valid.
///
/// Unlike [`SdEntriesWithOptionsIterator`] this iterator does not wrap items
/// in `Result`.
///
/// # Panics
///
/// If the underlying entry data cannot be decoded, [`next`](Iterator::next)
/// will panic.
#[derive(Clone, Debug)]
pub struct SdEntriesWithOptionsCheckedIterator<'a, 'i> {
    entries: SdEntriesCheckedIterator<'a>,
    options: &'i SdOptionsIndex<'a>,
}

impl<'a, 'i> SdEntriesWithOptionsCheckedIterator<'a, 'i> {
    /// Creates a new checked iterator over the entries in `entries`,
    /// resolving options through `options`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `entries` contains validly encoded SD
    /// entries.
    #[inline]
    pub unsafe fn new(entries: &'a [u8], options: &'i SdOptionsIndex<'a>) -> Self {
        Self {
            entries: SdEntriesCheckedIterator::new(entries),
            options,
        }
    }
}

impl<'a, 'i> Iterator for SdEntriesWithOptionsCheckedIterator<'a, 'i> {
    type Item = SdEntryWithOptions<'a, 'i>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.next()?;
        Some(SdEntryWithOptions::new(entry, self.options))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sd::entries::*;
    use crate::sd::options::*;
    use crate::sd::{SdOptionSlice, SdOptionsIndex};

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

    fn service_entry(start1: u8, num1: u8, start2: u8, num2: u8) -> [u8; ENTRY_LEN] {
        let mut e = [0u8; ENTRY_LEN];
        e[0] = 0x01; // OfferService
        e[1] = start1;
        e[2] = start2;
        e[3] = (num1 << 4) | (num2 & 0x0F);
        e
    }

    fn ports(iter: SdOptionRunIter<'_, '_>) -> Vec<u16> {
        iter.map(|o| match o {
            SdOptionSlice::Ipv4Endpoint(s) => s.port(),
            _ => panic!("expected Ipv4Endpoint"),
        })
        .collect()
    }

    fn options_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&ipv4(10));
        data.extend_from_slice(&ipv4(20));
        data.extend_from_slice(&ipv4(30));
        data
    }

    #[test]
    fn resolves_runs() {
        let options = options_data();
        let index = SdOptionsIndex::from_slice(&options).unwrap();

        let entries = service_entry(0, 2, 2, 1);
        let mut iter = SdEntriesWithOptionsIterator::new(&entries, &index);
        let item = iter.next().unwrap().unwrap();

        assert_eq!(item.entry().service_id(), 0);
        assert_eq!(ports(item.options_run_1()), vec![10, 20]);
        assert_eq!(ports(item.options_run_2()), vec![30]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn checked_resolves_runs() {
        let options = options_data();
        let index = SdOptionsIndex::from_slice(&options).unwrap();

        let entries = service_entry(1, 1, 0, 0);
        let mut iter = unsafe { SdEntriesWithOptionsCheckedIterator::new(&entries, &index) };
        let item = iter.next().unwrap();
        assert_eq!(ports(item.options_run_1()), vec![20]);
        assert_eq!(item.options_run_2().count(), 0);
        assert!(item.options_index().len() == 3);
        assert!(iter.next().is_none());
    }

    #[test]
    fn error_stops_iteration() {
        let index = SdOptionsIndex::from_slice(&[]).unwrap();
        // too short for an entry
        let entries = [0u8; 4];
        let mut iter = SdEntriesWithOptionsIterator::new(&entries, &index);
        assert!(matches!(
            iter.next(),
            Some(Err(SdReadError::UnexpectedEndOfSlice(_)))
        ));
        assert!(iter.next().is_none());
    }

    #[test]
    fn clone_debug() {
        let options = options_data();
        let index = SdOptionsIndex::from_slice(&options).unwrap();
        let entries = service_entry(0, 1, 0, 0);
        let iter = SdEntriesWithOptionsIterator::new(&entries, &index);
        let _ = format!("{:?}", iter.clone());
        let item = iter.clone().next().unwrap().unwrap();
        let _ = format!("{:?}", item.clone());
    }
}
