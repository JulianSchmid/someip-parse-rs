use crate::sd::{*, options::*};

/// SOMEIP service discovery header
///
/// This implementation uses fixed-size arrays instead of `Vec` to avoid allocations.
/// The maximum size is based on the SOMEIP UDP payload limit of 1400 bytes minus
/// the SOMEIP header size of 8 bytes, giving us 1392 bytes for each array.
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
/// let bytes = header.to_bytes_vec().unwrap();
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
                explicit_initial_data_control: true,
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
            if options_pos + option_bytes.len() > header.options_data.len() {
                return Err(SdValueError::SdOptionsArrayTooLarge);
            }
            header.options_data[options_pos..options_pos + option_bytes.len()]
                .copy_from_slice(&option_bytes);
            options_pos += option_bytes.len();
        }
        header.options_len = options_pos;

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
                explicit_initial_data_control: true,
            },
            entries_data: [0; MAX_ENTRIES_LEN_USIZE],
            entries_len: 0,
            options_data: [0; MAX_OPTIONS_LEN_USIZE],
            options_len: 0,
            discard_unknown_options: false,
        }
    }

    /// Returns entries as a vector by parsing the serialized data.
    ///
    /// This method deserializes the entries from the internal fixed-size buffer
    /// and returns them as a `Vec<SdEntry>`. The parsing is done on-demand,
    /// so there's no memory overhead when entries are not accessed.
    ///
    /// # Example
    ///
    /// ```
    /// use someip_parse::sd::{SdHeader, SdEntry};
    ///
    /// let mut header = SdHeader::default();
    /// let entry = SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000).unwrap();
    /// header.add_entry(entry.clone()).unwrap();
    ///
    /// let entries = header.entries().unwrap();
    /// assert_eq!(entries.len(), 1);
    /// assert_eq!(entries[0], entry);
    /// ```
    pub fn entries(&self) -> Result<Vec<SdEntry>, SdReadError> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos + sd_entries::ENTRY_LEN <= self.entries_len {
            let mut entry_bytes = [0; sd_entries::ENTRY_LEN];
            entry_bytes.copy_from_slice(&self.entries_data[pos..pos + sd_entries::ENTRY_LEN]);

            let _type_raw = entry_bytes[0];
            let entry = match _type_raw {
                0x00 => SdEntry::read_service(SdServiceEntryType::FindService, entry_bytes)?,
                0x01 => SdEntry::read_service(SdServiceEntryType::OfferService, entry_bytes)?,
                0x06 => SdEntry::read_entry_group(SdEventGroupEntryType::Subscribe, entry_bytes)?,
                0x07 => {
                    SdEntry::read_entry_group(SdEventGroupEntryType::SubscribeAck, entry_bytes)?
                }
                _ => return Err(SdReadError::UnknownSdServiceEntryType(_type_raw)),
            };

            entries.push(entry);
            pos += sd_entries::ENTRY_LEN;
        }

        Ok(entries)
    }

    /// Returns options as a vector by parsing the serialized data.
    ///
    /// This method deserializes the options from the internal fixed-size buffer
    /// and returns them as a `Vec<SdOption>`. The parsing is done on-demand,
    /// so there's no memory overhead when options are not accessed.
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
    /// header.add_option(option.clone()).unwrap();
    ///
    /// let options = header.options().unwrap();
    /// assert_eq!(options.len(), 1);
    /// assert_eq!(options[0], option);
    /// ```
    pub fn options(&self) -> Result<Vec<SdOption>, SdReadError> {
        let mut options = Vec::new();
        let mut pos = 0;

        while pos < self.options_len {
            let mut cursor = std::io::Cursor::new(&self.options_data[pos..self.options_len]);
            let (read_bytes, option) =
                SdOption::read_with_flag(&mut cursor, self.discard_unknown_options)?;
            options.push(option);
            pos += read_bytes as usize;
        }

        Ok(options)
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
        if self.entries_len + entry_bytes.len() > self.entries_data.len() {
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
        let mut temp_vec = Vec::new();
        option.append_bytes_to_vec(&mut temp_vec)?;

        if self.options_len + temp_vec.len() > self.options_data.len() {
            return Err(SdValueError::SdOptionsArrayTooLarge);
        }

        self.options_data[self.options_len..self.options_len + temp_vec.len()]
            .copy_from_slice(&temp_vec);
        self.options_len += temp_vec.len();
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
        self.entries_len / sd_entries::ENTRY_LEN
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
    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
    pub fn read<T: Read + Seek>(reader: &mut T) -> Result<Self, SdReadError> {
        SdHeader::read_with_flag(reader, false)
    }

    #[inline]
    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
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
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdWriteError> {
        writer.write_all(&self.to_bytes_vec()?)?;
        Ok(())
    }

    /// Writes the header to a slice.
    #[inline]
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<(), SdWriteError> {
        let buffer = self.to_bytes_vec()?;
        if slice.len() < buffer.len() {
            use crate::err::SdWriteError::*;
            Err(UnexpectedEndOfSlice(buffer.len()))
        } else {
            // TODO figure out a better way
            for (idx, b) in buffer.iter().enumerate() {
                slice[idx] = *b;
            }
            Ok(())
        }
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        // 4*3 (flags, entries len & options len)
        4 * 3 + self.entries_len + self.options_len
    }

    /// Writes the header to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes_vec(&self) -> Result<Vec<u8>, SdValueError> {
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

    use super::*;
    use crate::proptest_generators::*;
    use assert_matches::*;
    use proptest::prelude::*;
    use std::io::Cursor;

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
        let entries =
            vec![
                SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000)
                    .unwrap(),
            ];
        let options = vec![SdOption::Ipv4Endpoint(Ipv4EndpointOption {
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

    #[test]
    fn read() {
        // entries array length too large error
        for len in [sd_entries::MAX_ENTRIES_LEN + 1, u32::MAX] {
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

        let entries = header.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], service_entry);

        // Test adding options
        let ipv4_option = Ipv4EndpointOption {
            ipv4_address: [192, 168, 1, 1],
            transport_protocol: TransportProtocol::Tcp,
            port: 8080,
        };
        let sd_option = SdOption::Ipv4Endpoint(ipv4_option.clone());

        header.add_option(sd_option.clone()).unwrap();
        assert!(!header.is_options_empty());

        let options = header.options().unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0], sd_option);

        // Test clearing
        header.clear_entries();
        assert!(header.is_entries_empty());
        assert_eq!(header.entries_count(), 0);

        header.clear_options();
        assert!(header.is_options_empty());

        // Test that the cleared header produces empty vectors
        assert_eq!(header.entries().unwrap().len(), 0);
        assert_eq!(header.options().unwrap().len(), 0);
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
    }

    #[test]
    fn new_with_different_iterator_types() {
        // Test with Vec
        let entries_vec =
            vec![
                SdEntry::new_offer_service_entry(0, 0, 0, 0, 0x1234, 0x5678, 1, 3600, 0x01000000)
                    .unwrap(),
            ];
        let options_vec: Vec<SdOption> = vec![];
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
        assert_eq!(header.flags.explicit_initial_data_control, true);

        let header_reboot = SdHeader::empty(true);
        assert_eq!(header_reboot.flags.reboot, true);
    }
}
