use crate::sd::{entries::*, options::*, *};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// SOMEIP service discovery header
///
/// This implementation uses fixed-size arrays instead of `Vec` to avoid allocations.
/// The combined serialized SD payload is limited to the supported SOME/IP UDP payload
/// size of 1400 bytes.
///
/// # Example
///
/// ```
/// use someip_parse::sd::{*, options::*};
///
/// // Create a new header
/// let mut header = SdHeader::default();
///
/// // Add a service entry
/// let service_entry = SdEntry::new_offer_service_entry(
///     0, 0, 0, 0,      // option indices and counts
///     0x1234,          // service ID
///     0x5678,          // instance ID
///     1,               // major version
///     3600,            // TTL
///     0x01000000       // minor version
/// ).unwrap();
///
/// header.add_entry(service_entry).unwrap();
///
/// // Add an IPv4 endpoint option
/// let endpoint = Ipv4EndpointOption {
///     ipv4_address: [192, 168, 1, 1],
///     transport_protocol: TransportProtocol::Tcp,
///     port: 8080,
/// };
/// header.add_option(endpoint.into()).unwrap();
///
/// // The header can now be serialized without any allocations
/// let mut bytes = [0u8; 64];
/// header.write_to_slice(&mut bytes[..header.header_len()]).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdHeader {
    pub flags: SdHeaderFlags,
    // reserved: [u8;3],
    // Length of entries array in bytes
    // length_of_entries: u32,
    entries_data: [u8; MAX_ENTRIES_LEN_USIZE],
    entries_len: usize,
    // Length of entries array in bytes
    // length_of_options: u32,
    options_data: [u8; MAX_OPTIONS_LEN_USIZE],
    options_len: usize,
    discard_unknown_options: bool,
}

impl Default for SdHeader {
    fn default() -> Self {
        Self {
            flags: SdHeaderFlags::default(),
            entries_data: [0; MAX_ENTRIES_LEN_USIZE],
            entries_len: 0,
            options_data: [0; MAX_OPTIONS_LEN_USIZE],
            options_len: 0,
            discard_unknown_options: false,
        }
    }
}

impl SdHeader {
    /// Creates a new SOMEIP SD header with the given entries and options.
    ///
    /// # Arguments
    ///
    /// * `reboot` - Whether the reboot flag should be set
    /// * `entries` - Iterable collection of SD entries to include
    /// * `options` - Iterable collection of SD options to include
    ///
    /// # Returns
    ///
    /// Returns `Ok(SdHeader)` on success, or `Err(SdValueError)` if the serialized
    /// entries or options exceed the fixed-size buffer limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use someip_parse::sd::{SdHeader, SdEntry, SdOption};
    ///
    /// let entries = [
    ///     SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap()
    /// ];
    /// let header = SdHeader::new(false, &entries, &[]).unwrap();
    /// ```
    #[inline]
    pub fn new<'a, 'b, E, O>(reboot: bool, entries: E, options: O) -> Result<Self, SdValueError>
    where
        E: IntoIterator<Item = &'a SdEntry>,
        O: IntoIterator<Item = &'b SdOption>,
    {
        let mut header = Self {
            flags: SdHeaderFlags {
                reboot,
                unicast: true,
                explicit_initial_data_control: false,
            },
            entries_data: [0; MAX_ENTRIES_LEN_USIZE],
            entries_len: 0,
            options_data: [0; MAX_OPTIONS_LEN_USIZE],
            options_len: 0,
            discard_unknown_options: false,
        };

        // Serialize entries
        let mut entries_pos = 0;
        for entry in entries {
            let entry_bytes = entry.to_bytes();
            if entries_pos + entry_bytes.len() > header.entries_data.len() {
                return Err(SdValueError::SdEntriesArrayTooLarge);
            }
            header.entries_data[entries_pos..entries_pos + entry_bytes.len()]
                .copy_from_slice(&entry_bytes);
            entries_pos += entry_bytes.len();
        }
        header.entries_len = entries_pos;

        // Serialize options
        let mut options_pos = 0;
        for option in options {
            let option_bytes = option.to_bytes()?;
            if options_pos + option_bytes.len() > header.options_data.len()
                || MIN_SD_HEADER_LENGTH + header.entries_len + options_pos + option_bytes.len()
                    > crate::SOMEIP_MAX_PAYLOAD_LEN_UDP as usize
            {
                return Err(SdValueError::SdOptionsArrayTooLarge);
            }
            header.options_data[options_pos..options_pos + option_bytes.len()]
                .copy_from_slice(&option_bytes);
            options_pos += option_bytes.len();
        }
        header.options_len = options_pos;

        header.validate_option_runs()?;
        Ok(header)
    }

    /// Creates a new empty SOMEIP SD header with just flags set.
    ///
    /// This is a convenience method for creating headers without any entries or options.
    ///
    /// # Arguments
    ///
    /// * `reboot` - Whether the reboot flag should be set
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::SdHeader;
    ///
    /// let header = SdHeader::empty(false);
    /// assert!(header.is_entries_empty());
    /// assert!(header.is_options_empty());
    /// assert_eq!(header.flags.reboot, false);
    /// ```
    #[inline]
    pub fn empty(reboot: bool) -> Self {
        Self {
            flags: SdHeaderFlags {
                reboot,
                unicast: true,
                explicit_initial_data_control: false,
            },
            entries_data: [0; MAX_ENTRIES_LEN_USIZE],
            entries_len: 0,
            options_data: [0; MAX_OPTIONS_LEN_USIZE],
            options_len: 0,
            discard_unknown_options: false,
        }
    }

    /// Returns an iterator over the entries by parsing the serialized data
    /// on-demand.
    ///
    /// The returned [`SdEntriesCheckedIterator`] yields [`SdEntrySlice`]
    /// values directly (not wrapped in `Result`), since the data stored
    /// in `SdHeader` is guaranteed to be valid.
    ///
    /// # Panics
    ///
    /// Panics if the internal entry data is corrupt, which indicates a
    /// bug in the serialization logic.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{SdHeader, SdEntry, SdEntrySlice};
    ///
    /// let mut header = SdHeader::default();
    /// let entry = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap();
    /// header.add_entry(entry).unwrap();
    ///
    /// assert_eq!(header.entries().count(), 1);
    /// for entry in header.entries() {
    ///     assert!(matches!(entry, SdEntrySlice::Service(_)));
    /// }
    /// ```
    pub fn entries(&self) -> SdEntriesCheckedIterator<'_> {
        // SAFETY: entries_data[..entries_len] is only written to by
        // add_entry which serialises valid SdEntry values.
        unsafe { SdEntriesCheckedIterator::new(&self.entries_data[..self.entries_len]) }
    }

    /// Returns an iterator over the options by parsing the serialized data.
    ///
    /// The returned [`SdOptionsCheckedIterator`] yields [`SdOptionSlice`]
    /// values directly (without `Result`) because the internal buffer
    /// is guaranteed to contain validly encoded options. Unknown option
    /// types are returned as [`SdOptionSlice::Unknown`]; use
    /// [`options::UnknownSlice::discardable`] to decide whether they
    /// can be safely ignored.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{*, options::*};
    ///
    /// let mut header = SdHeader::default();
    /// let option = SdOption::Ipv4Endpoint(Ipv4EndpointOption {
    ///     ipv4_address: [192, 168, 1, 1],
    ///     transport_protocol: TransportProtocol::Tcp,
    ///     port: 8080,
    /// });
    /// header.add_option(option).unwrap();
    ///
    /// for opt in header.options() {
    ///     assert!(matches!(opt, SdOptionSlice::Ipv4Endpoint(_)));
    /// }
    /// ```
    pub fn options(&self) -> SdOptionsCheckedIterator<'_> {
        // SAFETY: options_data[..options_len] is only written to by
        // add_option which serialises valid SdOption values.
        unsafe { SdOptionsCheckedIterator::new(&self.options_data[..self.options_len]) }
    }

    /// Builds an [`SdOptionsIndex`] over the header's options, allowing O(1)
    /// access to individual options by their ordinal position.
    ///
    /// The returned index borrows the header, so it (and any iterators
    /// derived from it) must not outlive the header. Combine it with
    /// [`entries_with_options`](Self::entries_with_options) to iterate over
    /// entries together with their resolved options:
    ///
    /// ```
    /// use someip_parse::sd::{*, options::*};
    ///
    /// let mut header = SdHeader::default();
    /// header.add_option(SdOption::Ipv4Endpoint(Ipv4EndpointOption {
    ///     ipv4_address: [192, 168, 1, 1],
    ///     transport_protocol: TransportProtocol::Udp,
    ///     port: 1234,
    /// })).unwrap();
    /// header.add_entry(
    ///     // index1=0, index2=0, count1=1, count2=0
    ///     SdEntry::new_offer_service_entry(0, 0, 1, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap()
    /// ).unwrap();
    ///
    /// let index = header.options_index();
    /// for entry in header.entries_with_options(&index) {
    ///     let entry = entry.unwrap();
    ///     for option in entry.options_run_1() {
    ///         assert!(matches!(option, SdOptionSlice::Ipv4Endpoint(_)));
    ///     }
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the internal option data is corrupt, which indicates a bug
    /// in the serialization logic.
    pub fn options_index(&self) -> SdOptionsIndex<'_> {
        SdOptionsIndex::from_slice(&self.options_data[..self.options_len])
            .expect("SdHeader: corrupt option data")
    }

    /// Returns an iterator over the entries yielding each entry together with
    /// access to its resolved options.
    ///
    /// The `index` must be obtained from [`options_index`](Self::options_index)
    /// on the same header. Invalid option-run references are returned as
    /// [`SdReadError::SdOptionRunOutOfBounds`].
    pub fn entries_with_options<'s>(
        &'s self,
        index: &'s SdOptionsIndex<'s>,
    ) -> SdEntriesWithOptionsIterator<'s, 's> {
        SdEntriesWithOptionsIterator::new(&self.entries_data[..self.entries_len], index)
    }

    fn validate_option_runs(&self) -> Result<(), SdValueError> {
        let options_len = self.options_index().len();
        for entry in self.entries() {
            for (run, start_index, number_of_options) in [
                (
                    1,
                    entry.start_index_options_1(),
                    entry.number_of_options_1().value(),
                ),
                (
                    2,
                    entry.start_index_options_2(),
                    entry.number_of_options_2().value(),
                ),
            ] {
                if number_of_options != 0
                    && usize::from(start_index) + usize::from(number_of_options) > options_len
                {
                    return Err(SdValueError::SdOptionRunOutOfBounds {
                        run,
                        start_index,
                        number_of_options,
                        options_len,
                    });
                }
            }
        }
        Ok(())
    }

    /// Adds an entry to the header.
    ///
    /// The entry is immediately serialized and stored in the internal buffer.
    ///
    /// # Arguments
    ///
    /// * `entry` - The SD entry to add
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(SdValueError::SdEntriesArrayTooLarge)`
    /// if adding this entry would exceed the fixed-size buffer limit.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{SdHeader, SdEntry};
    ///
    /// let mut header = SdHeader::default();
    /// let entry = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap();
    ///
    /// header.add_entry(entry).unwrap();
    /// assert_eq!(header.entries_count(), 1);
    /// ```
    pub fn add_entry(&mut self, entry: SdEntry) -> Result<(), SdValueError> {
        let entry_bytes = entry.to_bytes();
        if self.entries_len + entry_bytes.len() > self.entries_data.len()
            || MIN_SD_HEADER_LENGTH + self.entries_len + entry_bytes.len() + self.options_len
                > crate::SOMEIP_MAX_PAYLOAD_LEN_UDP as usize
        {
            return Err(SdValueError::SdEntriesArrayTooLarge);
        }

        self.entries_data[self.entries_len..self.entries_len + entry_bytes.len()]
            .copy_from_slice(&entry_bytes);
        self.entries_len += entry_bytes.len();
        Ok(())
    }

    /// Adds an option to the header.
    ///
    /// The option is immediately serialized and stored in the internal buffer.
    ///
    /// # Arguments
    ///
    /// * `option` - The SD option to add
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(SdValueError::SdOptionsArrayTooLarge)`
    /// if adding this option would exceed the fixed-size buffer limit.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{*, options::*};
    ///
    /// let mut header = SdHeader::default();
    /// let option = SdOption::Ipv4Endpoint(Ipv4EndpointOption {
    ///     ipv4_address: [192, 168, 1, 1],
    ///     transport_protocol: TransportProtocol::Tcp,
    ///     port: 8080,
    /// });
    ///
    /// header.add_option(option).unwrap();
    /// ```
    pub fn add_option(&mut self, option: SdOption) -> Result<(), SdValueError> {
        let option_bytes = option.to_bytes()?;

        if self.options_len + option_bytes.len() > self.options_data.len()
            || MIN_SD_HEADER_LENGTH + self.entries_len + self.options_len + option_bytes.len()
                > crate::SOMEIP_MAX_PAYLOAD_LEN_UDP as usize
        {
            return Err(SdValueError::SdOptionsArrayTooLarge);
        }

        self.options_data[self.options_len..self.options_len + option_bytes.len()]
            .copy_from_slice(&option_bytes);
        self.options_len += option_bytes.len();
        Ok(())
    }

    /// Clears all entries from the header.
    ///
    /// This resets the entries length to 0 but does not zero out the buffer data.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{SdHeader, SdEntry};
    ///
    /// let mut header = SdHeader::default();
    /// let entry = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap();
    /// header.add_entry(entry).unwrap();
    ///
    /// assert!(!header.is_entries_empty());
    /// header.clear_entries();
    /// assert!(header.is_entries_empty());
    /// ```
    pub fn clear_entries(&mut self) {
        self.entries_len = 0;
    }

    /// Clears all options from the header.
    ///
    /// This resets the options length to 0 but does not zero out the buffer data.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{*, options::*};
    ///
    /// let mut header = SdHeader::default();
    /// let option = SdOption::Ipv4Endpoint(Ipv4EndpointOption {
    ///     ipv4_address: [192, 168, 1, 1],
    ///     transport_protocol: TransportProtocol::Tcp,
    ///     port: 8080,
    /// });
    /// header.add_option(option).unwrap();
    ///
    /// assert!(!header.is_options_empty());
    /// header.clear_options();
    /// assert!(header.is_options_empty());
    /// ```
    pub fn clear_options(&mut self) {
        self.options_len = 0;
    }

    /// Returns the number of entries in the header.
    ///
    /// Since each entry has a fixed size of 16 bytes, this is calculated
    /// by dividing the entries buffer length by the entry size.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{SdHeader, SdEntry};
    ///
    /// let mut header = SdHeader::default();
    /// assert_eq!(header.entries_count(), 0);
    ///
    /// let entry = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap();
    /// header.add_entry(entry).unwrap();
    /// assert_eq!(header.entries_count(), 1);
    /// ```
    pub fn entries_count(&self) -> usize {
        self.entries_len / ENTRY_LEN
    }

    /// Returns true if there are no entries in the header.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::SdHeader;
    ///
    /// let header = SdHeader::default();
    /// assert!(header.is_entries_empty());
    /// ```
    pub fn is_entries_empty(&self) -> bool {
        self.entries_len == 0
    }

    /// Returns true if there are no options in the header.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::SdHeader;
    ///
    /// let header = SdHeader::default();
    /// assert!(header.is_options_empty());
    /// ```
    pub fn is_options_empty(&self) -> bool {
        self.options_len == 0
    }

    #[inline]
    #[cfg(all(
        feature = "std",
        any(target_pointer_width = "32", target_pointer_width = "64")
    ))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, SdReadError> {
        SdHeader::read_with_flag(reader, false)
    }

    #[inline]
    #[cfg(all(
        feature = "std",
        any(target_pointer_width = "32", target_pointer_width = "64")
    ))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read_with_flag<T: Read + Seek>(
        reader: &mut T,
        discard_unknown_option: bool,
    ) -> Result<Self, SdReadError> {
        const HEADER_LENGTH: usize = 1 + 3 + 4; // flags + rev + entries length
        let mut header_bytes: [u8; HEADER_LENGTH] = [0; HEADER_LENGTH];
        reader.read_exact(&mut header_bytes)?;

        let entries_length = {
            let length_entries = u32::from_be_bytes([
                header_bytes[4],
                header_bytes[5],
                header_bytes[6],
                header_bytes[7],
            ]);

            if length_entries > MAX_ENTRIES_LEN {
                return Err(SdReadError::SdEntriesArrayLengthTooLarge(length_entries));
            }
            if length_entries % ENTRY_LEN as u32 != 0 {
                return Err(SdReadError::SdEntriesArrayLengthInvalid(length_entries));
            }

            length_entries as usize
        };

        let mut entries_data = [0; MAX_ENTRIES_LEN_USIZE];
        if entries_length > 0 {
            if entries_length > entries_data.len() {
                return Err(SdReadError::SdEntriesArrayLengthTooLarge(
                    entries_length as u32,
                ));
            }
            reader.read_exact(&mut entries_data[..entries_length])?;
        }

        let options_length = {
            let mut options_length_bytes: [u8; 4] = [0x00; 4];
            reader.read_exact(&mut options_length_bytes)?;
            let len = u32::from_be_bytes(options_length_bytes);

            if len > MAX_OPTIONS_LEN {
                return Err(SdReadError::SdOptionsArrayLengthTooLarge(len));
            }
            let payload_len = MIN_SD_HEADER_LENGTH as u32 + entries_length as u32 + len;
            if payload_len > crate::SOMEIP_MAX_PAYLOAD_LEN_UDP {
                return Err(SdReadError::SdPayloadLengthTooLarge(payload_len));
            }

            len as usize
        };

        let mut options_data = [0; MAX_OPTIONS_LEN_USIZE];
        if options_length > 0 {
            if options_length > options_data.len() {
                return Err(SdReadError::SdOptionsArrayLengthTooLarge(
                    options_length as u32,
                ));
            }
            reader.read_exact(&mut options_data[..options_length])?;
        }

        // Validate the complete options array before exposing infallible
        // iterators over the internal data.
        let options_index = SdOptionsIndex::from_slice(&options_data[..options_length])?;
        for option_index in 0..options_index.len() {
            let option = options_index
                .get(option_index)
                .expect("option index built from the same options array");
            if let SdOptionSlice::Unknown(unknown) = option {
                if !unknown.discardable() && !discard_unknown_option {
                    return Err(SdReadError::UnknownSdOptionType(unknown.option_type()));
                }
            }
        }

        // PRS_SOMEIPSD_00130 requires every non-empty referenced option run
        // to exist. Checking here keeps the owned checked iterator infallible.
        for entry in SdEntriesIterator::new(&entries_data[..entries_length]) {
            let entry = entry?;
            options_index.validate_run(
                1,
                entry.start_index_options_1(),
                entry.number_of_options_1(),
            )?;
            options_index.validate_run(
                2,
                entry.start_index_options_2(),
                entry.number_of_options_2(),
            )?;
        }

        //return result
        Ok(Self {
            flags: SdHeaderFlags {
                reboot: 0 != header_bytes[0] & REBOOT_FLAG,
                unicast: 0 != header_bytes[0] & UNICAST_FLAG,
                explicit_initial_data_control: 0
                    != header_bytes[0] & EXPLICIT_INITIAL_DATA_CONTROL_FLAG,
            },
            entries_data,
            entries_len: entries_length,
            options_data,
            options_len: options_length,
            discard_unknown_options: discard_unknown_option,
        })
    }

    /// Writes the header to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdWriteError> {
        self.validate_option_runs()?;
        writer.write_all(&self.flags.to_bytes())?;
        writer.write_all(&(self.entries_len as u32).to_be_bytes())?;
        writer.write_all(&self.entries_data[..self.entries_len])?;
        writer.write_all(&(self.options_len as u32).to_be_bytes())?;
        writer.write_all(&self.options_data[..self.options_len])?;
        Ok(())
    }

    /// Writes the header to a slice.
    #[inline]
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<(), SdWriteError> {
        self.validate_option_runs()?;
        let required_len = self.header_len();
        if slice.len() < required_len {
            use crate::err::SdWriteError::*;
            return Err(UnexpectedEndOfSlice(required_len));
        }

        slice[..4].copy_from_slice(&self.flags.to_bytes());
        slice[4..8].copy_from_slice(&(self.entries_len as u32).to_be_bytes());
        let options_len_offset = 8 + self.entries_len;
        slice[8..options_len_offset].copy_from_slice(&self.entries_data[..self.entries_len]);
        slice[options_len_offset..options_len_offset + 4]
            .copy_from_slice(&(self.options_len as u32).to_be_bytes());
        slice[options_len_offset + 4..required_len]
            .copy_from_slice(&self.options_data[..self.options_len]);
        Ok(())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        // 4*3 (flags, entries len & options len)
        4 * 3 + self.entries_len + self.options_len
    }

    /// Writes the header to a slice without checking the slice length.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn to_bytes_vec(&self) -> Result<alloc::vec::Vec<u8>, SdValueError> {
        self.validate_option_runs()?;
        // pre-allocate the resulting buffer (4*3 for flags, entries len & options len)
        let mut bytes = Vec::with_capacity(4 * 3 + self.entries_len + self.options_len);

        // flags & reserved
        bytes.extend_from_slice(&self.flags.to_bytes());
        // entries len
        bytes.extend_from_slice(&(self.entries_len as u32).to_be_bytes());

        // entries
        bytes.extend_from_slice(&self.entries_data[..self.entries_len]);

        // options len
        bytes.extend_from_slice(&(self.options_len as u32).to_be_bytes());
        bytes.extend_from_slice(&self.options_data[..self.options_len]);

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::proptest_generators::*;
    use assert_matches::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn write_read(header in sd_header_any()) {

            //non error case
            {
                //serialize
                let mut buffer: [u8; 10000] = [0; 10000];
                header.write_to_slice(&mut buffer).unwrap();

                //deserialize
                let mut cursor = Cursor::new(&buffer);
                let result = SdHeader::read(&mut cursor).unwrap();
                assert_eq!(header, result);
            }
        }
    }

    #[test]
    fn new_into_iter_ref() {
        let entries = alloc::vec![SdEntry::new_offer_service_entry(
            0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000
        )
        .unwrap(),];
        let options = alloc::vec![SdOption::Ipv4Endpoint(Ipv4EndpointOption {
            ipv4_address: [0; 4],
            transport_protocol: TransportProtocol::Udp,
            port: 1234,
        })];
        assert!(SdHeader::new(true, &entries, &options).is_ok());
    }

    #[test]
    fn write_unexpected_end_of_slice() {
        use assert_matches::*;

        let header = SdHeader::default();
        let result = header.write_to_slice(&mut []);
        assert_matches!(result, Err(SdWriteError::UnexpectedEndOfSlice(_)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn write_rejects_out_of_bounds_option_runs() {
        let entry =
            SdEntry::new_offer_service_entry(0, 0, 1, 0, 0x1234, 0x5678, 1, 3600, 0).unwrap();
        assert_matches!(
            SdHeader::new(false, [&entry], std::iter::empty()),
            Err(SdValueError::SdOptionRunOutOfBounds { .. })
        );

        let mut header = SdHeader::default();
        header.add_entry(entry).unwrap();
        assert_matches!(
            header.to_bytes_vec(),
            Err(SdValueError::SdOptionRunOutOfBounds { .. })
        );
        assert_matches!(
            header.write(&mut Vec::new()),
            Err(SdWriteError::ValueError(
                SdValueError::SdOptionRunOutOfBounds { .. }
            ))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn read() {
        // entries array length too large error
        for len in [MAX_ENTRIES_LEN + 1, u32::MAX] {
            let len_be = len.to_be_bytes();
            let buffer = [
                0, 0, 0, 0, // flags
                len_be[0], len_be[1], len_be[2], len_be[3], 0, 0, 0, 0,
            ];
            let mut cursor = Cursor::new(&buffer);
            assert_matches!(
                SdHeader::read(&mut cursor),
                Err(SdReadError::SdEntriesArrayLengthTooLarge(_))
            );
        }

        // options array length too large error
        for len in [MAX_OPTIONS_LEN + 1, u32::MAX] {
            let len_be = len.to_be_bytes();
            let buffer = [
                0, 0, 0, 0, // flags
                0, 0, 0, 0, // entries array length
                len_be[0], len_be[1], len_be[2], len_be[3], 0, 0, 0, 0,
            ];
            let mut cursor = Cursor::new(&buffer);
            assert_matches!(
                SdHeader::read(&mut cursor),
                Err(SdReadError::SdOptionsArrayLengthTooLarge(_))
            );
        }

        // Entry arrays consist exclusively of 16-byte entries.
        {
            let buffer = [
                0, 0, 0, 0, // flags
                0, 0, 0, 1, // invalid entries array length
                0, // entry data
                0, 0, 0, 0, // options array length
            ];
            assert_matches!(
                SdHeader::read(&mut Cursor::new(buffer)),
                Err(SdReadError::SdEntriesArrayLengthInvalid(1))
            );
        }

        // Options are validated before infallible iterators can access them.
        {
            let buffer = [
                0,
                0,
                0,
                0, // flags
                0,
                0,
                0,
                0, // entries array length
                0,
                0,
                0,
                5, // options array length
                0,
                9,
                IPV4_ENDPOINT_TYPE,
                0,
                0, // truncated option
            ];
            assert_matches!(
                SdHeader::read(&mut Cursor::new(buffer)),
                Err(SdReadError::SdOption(_))
            );
        }

        // An unknown option can only be ignored by default when its
        // discardable flag is set.
        {
            let buffer = [
                0, 0, 0, 0, // flags
                0, 0, 0, 0, // entries array length
                0, 0, 0, 4, // options array length
                0, 1, 0xaa, 0, // unknown, non-discardable option
            ];
            assert_matches!(
                SdHeader::read(&mut Cursor::new(buffer)),
                Err(SdReadError::UnknownSdOptionType(0xaa))
            );
            assert!(SdHeader::read_with_flag(&mut Cursor::new(buffer), true).is_ok());
        }

        // Referenced option runs must fit in the options array.
        {
            let mut buffer = [0u8; 28];
            buffer[4..8].copy_from_slice(&(ENTRY_LEN as u32).to_be_bytes());
            buffer[8] = 0x01; // OfferService
            buffer[11] = 0x10; // first run references one option
            assert_matches!(
                SdHeader::read(&mut Cursor::new(buffer)),
                Err(SdReadError::SdOptionRunOutOfBounds { .. })
            );
        }

        // The entries and options limits apply to their combined payload.
        {
            let entries_len = MAX_ENTRIES_LEN_USIZE - (MAX_ENTRIES_LEN_USIZE % ENTRY_LEN);
            let mut buffer = alloc::vec![0; 8 + entries_len];
            buffer[4..8].copy_from_slice(&(entries_len as u32).to_be_bytes());
            buffer.extend_from_slice(&(ENTRY_LEN as u32).to_be_bytes());
            assert_matches!(
                SdHeader::read(&mut Cursor::new(buffer)),
                Err(SdReadError::SdPayloadLengthTooLarge(_))
            );
        }
    }

    #[test]
    fn new_api_methods() {
        // Test default header creation
        let mut header = SdHeader::default();
        assert!(header.is_entries_empty());
        assert!(header.is_options_empty());
        assert_eq!(header.entries_count(), 0);

        // Test adding entries
        let service_entry =
            SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000)
                .unwrap();

        header.add_entry(service_entry.clone()).unwrap();
        assert_eq!(header.entries_count(), 1);
        assert!(!header.is_entries_empty());

        let entries: Vec<_> = header.entries().collect();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SdEntrySlice::Service(s) => {
                assert_eq!(SdEntry::Service(s.to_owned()), service_entry);
            }
            _ => panic!("expected Service entry"),
        }

        // Test adding options
        let ipv4_option = Ipv4EndpointOption {
            ipv4_address: [192, 168, 1, 1],
            transport_protocol: TransportProtocol::Tcp,
            port: 8080,
        };
        let sd_option = SdOption::Ipv4Endpoint(ipv4_option.clone());

        header.add_option(sd_option).unwrap();
        assert!(!header.is_options_empty());

        let options: Vec<_> = header.options().collect();
        assert_eq!(options.len(), 1);
        match &options[0] {
            SdOptionSlice::Ipv4Endpoint(s) => {
                assert_eq!(s.ipv4_address(), ipv4_option.ipv4_address);
                assert_eq!(s.transport_protocol(), ipv4_option.transport_protocol);
                assert_eq!(s.port(), ipv4_option.port);
            }
            _ => panic!("expected Ipv4Endpoint"),
        }

        // Test clearing
        header.clear_entries();
        assert!(header.is_entries_empty());
        assert_eq!(header.entries_count(), 0);

        header.clear_options();
        assert!(header.is_options_empty());

        // Test that the cleared header produces empty results
        assert_eq!(header.entries().count(), 0);
        assert_eq!(header.options().count(), 0);
    }

    #[test]
    fn array_size_limits() {
        let mut header = SdHeader::default();

        // Try to add too many entries (each entry is 16 bytes)
        let max_entries = MAX_ENTRIES_LEN_USIZE / 16; // 86 entries max
        let service_entry =
            SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000)
                .unwrap();

        // Add maximum entries
        for _ in 0..max_entries {
            header.add_entry(service_entry.clone()).unwrap();
        }

        // Try to add one more - should fail
        let result = header.add_entry(service_entry);
        assert_matches!(result, Err(SdValueError::SdEntriesArrayTooLarge));

        // Exactly 1400 payload bytes are supported, but no more.
        let endpoint = SdOption::Ipv4Endpoint(Ipv4EndpointOption {
            ipv4_address: [127, 0, 0, 1],
            transport_protocol: TransportProtocol::Udp,
            port: 30490,
        });
        header.add_option(endpoint.clone()).unwrap();
        assert_eq!(
            header.header_len(),
            crate::SOMEIP_MAX_PAYLOAD_LEN_UDP as usize
        );
        assert_matches!(
            header.add_option(endpoint),
            Err(SdValueError::SdOptionsArrayTooLarge)
        );
    }

    #[test]
    fn new_with_different_iterator_types() {
        // Test with Vec
        let entries_vec = alloc::vec![SdEntry::new_offer_service_entry(
            0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000
        )
        .unwrap(),];
        let options_vec: Vec<SdOption> = alloc::vec![];
        let header1 = SdHeader::new(false, &entries_vec, &options_vec).unwrap();
        assert_eq!(header1.entries_count(), 1);

        // Test with arrays
        let entries_array =
            [
                SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x5678, 0x1234, 1, 7200, 0x02000000)
                    .unwrap(),
            ];
        let options_array: [SdOption; 0] = [];
        let header2 = SdHeader::new(true, &entries_array, &options_array).unwrap();
        assert_eq!(header2.entries_count(), 1);
        assert!(header2.flags.reboot);

        // Test with iterators
        {
            let entry =
                SdEntry::new_offer_service_entry(0, 0, 0, 0, 0xABCD, 0xEF01, 1, 1800, 0x03000000)
                    .unwrap();
            let entry_iter = std::iter::once(&entry);
            let header3 = SdHeader::new(false, entry_iter, std::iter::empty()).unwrap();
            assert_eq!(header3.entries_count(), 1);
        }

        // Test with slice
        let entries_slice = &[
            SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x9876, 0x5432, 1, 900, 0x04000000)
                .unwrap(),
            SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1111, 0x2222, 1, 1200, 0x05000000)
                .unwrap(),
        ];
        let header4 = SdHeader::new(false, entries_slice, std::iter::empty()).unwrap();
        assert_eq!(header4.entries_count(), 2);

        // Test with empty iterators
        let header5 = SdHeader::new(false, std::iter::empty(), std::iter::empty()).unwrap();
        assert_eq!(header5.entries_count(), 0);
        assert!(header5.is_entries_empty());
        assert!(header5.is_options_empty());
    }

    #[test]
    fn empty_constructor() {
        let header = SdHeader::empty(false);
        assert!(header.is_entries_empty());
        assert!(header.is_options_empty());
        assert_eq!(header.flags.reboot, false);
        assert_eq!(header.flags.unicast, true);
        assert_eq!(header.flags.explicit_initial_data_control, false);

        let header_reboot = SdHeader::empty(true);
        assert_eq!(header_reboot.flags.reboot, true);
    }
}
