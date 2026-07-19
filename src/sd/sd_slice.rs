use crate::err::{SdError, SdSliceError};
use crate::sd::{
    entries::{ENTRY_LEN, MAX_ENTRIES_LEN},
    options::MAX_OPTIONS_LEN,
    SdEntriesIterator, SdEntriesWithOptionsIterator, SdHeaderFlags, SdOptionSlice, SdOptionsIndex,
    SdOptionsIterator, EXPLICIT_INITIAL_DATA_CONTROL_FLAG, MIN_SD_HEADER_LENGTH, REBOOT_FLAG,
    UNICAST_FLAG,
};

/// Zero-copy view onto a serialized SOMEIP service discovery payload.
///
/// Unlike [`super::SdHeader`], which copies the entries and options into
/// fixed size buffers, [`SdSlice`] borrows the input slice directly and
/// therefore performs no copying of the payload. The options array is
/// parsed once into an [`SdOptionsIndex`] so that individual options can be
/// resolved in O(1) (e.g. when iterating entries together with their
/// options via [`entries_with_options`](Self::entries_with_options)).
///
/// # Example
///
/// ```
/// use someip_parse::sd::{SdHeader, SdEntry, SdOption, SdSlice, options::*};
///
/// // build & serialize a header
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
/// let mut buffer = [0u8; 64];
/// let len = header.header_len();
/// header.write_to_slice(&mut buffer[..len]).unwrap();
///
/// // parse it back without copying the payload
/// let sd = SdSlice::from_slice(&buffer[..len]).unwrap();
/// for entry in sd.entries_with_options() {
///     let entry = entry.unwrap();
///     for option in entry.options_run_1() {
///         println!("{:?}", option);
///     }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdSlice<'a> {
    flags: SdHeaderFlags,
    entries: &'a [u8],
    options_index: SdOptionsIndex<'a>,
}

impl<'a> SdSlice<'a> {
    /// Parses the payload of a complete SOME/IP-SD message without copying it.
    ///
    /// In addition to the SD payload, this validates the fixed SOME/IP header
    /// values required by PRS_SOMEIPSD_00151 through PRS_SOMEIPSD_00164.
    pub fn from_someip(message: &crate::SomeipMsgSlice<'a>) -> Result<Self, SdSliceError> {
        Self::from_someip_with_flag(message, false)
    }

    /// Parses a complete SOME/IP-SD message, optionally accepting unknown
    /// non-discardable options.
    pub fn from_someip_with_flag(
        message: &crate::SomeipMsgSlice<'a>,
        discard_unknown_option: bool,
    ) -> Result<Self, SdSliceError> {
        if message.message_id() != crate::SOMEIP_SD_MESSAGE_ID {
            return Err(SdSliceError::Content(SdError::SdMessageIdInvalid(
                message.message_id(),
            )));
        }

        let request_id = message.request_id();
        let client_id = (request_id >> 16) as u16;
        if client_id != 0 {
            return Err(SdSliceError::Content(SdError::SdClientIdInvalid(client_id)));
        }
        if request_id as u16 == 0 {
            return Err(SdSliceError::Content(SdError::SdSessionIdZero));
        }
        if message.interface_version() != 1 {
            return Err(SdSliceError::Content(SdError::SdInterfaceVersionInvalid(
                message.interface_version(),
            )));
        }
        if message.message_type_raw() != crate::MessageType::Notification as u8 {
            return Err(SdSliceError::Content(SdError::SdMessageTypeInvalid(
                message.message_type_raw(),
            )));
        }
        if message.return_code() != 0 {
            return Err(SdSliceError::Content(SdError::SdReturnCodeInvalid(
                message.return_code(),
            )));
        }

        Self::from_slice_with_flag(message.payload(), discard_unknown_option)
    }

    /// Parses a SOMEIP SD payload from the given slice without copying it.
    ///
    /// # Errors
    ///
    /// - [`SdSliceError::UnexpectedEndOfSlice`] if the slice is too short to
    ///   contain the header or the announced entries/options arrays.
    /// - [`SdError::SdEntriesArrayLengthTooLarge`] /
    ///   [`SdError::SdOptionsArrayLengthTooLarge`] if an announced array
    ///   length exceeds the maximum allowed value.
    /// - [`SdError::SdPayloadLengthMismatch`] if bytes remain after the
    ///   announced options array.
    /// - [`SdError::SdOption`] if an option can not be decoded.
    /// - [`SdError::UnknownSdOptionType`] for an unknown non-discardable
    ///   option.
    /// - [`SdError::SdOptionRunOutOfBounds`] if an entry references
    ///   options outside the options array.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, SdSliceError> {
        Self::from_slice_with_flag(slice, false)
    }

    /// Parses a SOME/IP-SD payload, optionally accepting unknown
    /// non-discardable options.
    ///
    /// If `discard_unknown_option` is `false`, an unknown option is accepted
    /// only when its discardable flag is set.
    pub fn from_slice_with_flag(
        slice: &'a [u8],
        discard_unknown_option: bool,
    ) -> Result<Self, SdSliceError> {
        if slice.len() < MIN_SD_HEADER_LENGTH {
            return Err(SdSliceError::UnexpectedEndOfSlice(MIN_SD_HEADER_LENGTH));
        }

        // flags (byte 0) followed by 3 reserved bytes
        let flags = SdHeaderFlags {
            reboot: 0 != slice[0] & REBOOT_FLAG,
            unicast: 0 != slice[0] & UNICAST_FLAG,
            explicit_initial_data_control: 0 != slice[0] & EXPLICIT_INITIAL_DATA_CONTROL_FLAG,
        };

        // entries array length
        let entries_len = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
        if entries_len > MAX_ENTRIES_LEN {
            return Err(SdSliceError::Content(
                SdError::SdEntriesArrayLengthTooLarge(entries_len),
            ));
        }
        if entries_len % ENTRY_LEN as u32 != 0 {
            return Err(SdSliceError::Content(SdError::SdEntriesArrayLengthInvalid(
                entries_len,
            )));
        }
        let entries_len = entries_len as usize;

        // entries array + the 4 byte options length that follows it
        let options_len_start = 8 + entries_len;
        if slice.len() < options_len_start + 4 {
            return Err(SdSliceError::UnexpectedEndOfSlice(options_len_start + 4));
        }
        let entries = &slice[8..options_len_start];

        // options array length
        let options_len = u32::from_be_bytes([
            slice[options_len_start],
            slice[options_len_start + 1],
            slice[options_len_start + 2],
            slice[options_len_start + 3],
        ]);
        if options_len > MAX_OPTIONS_LEN {
            return Err(SdSliceError::Content(
                SdError::SdOptionsArrayLengthTooLarge(options_len),
            ));
        }
        let payload_len = MIN_SD_HEADER_LENGTH as u32 + entries_len as u32 + options_len;
        if payload_len > crate::SOMEIP_MAX_PAYLOAD_LEN_UDP {
            return Err(SdSliceError::Content(SdError::SdPayloadLengthTooLarge(
                payload_len,
            )));
        }
        let options_len = options_len as usize;

        let options_start = options_len_start + 4;
        let options_end = options_start + options_len;
        if slice.len() < options_end {
            return Err(SdSliceError::UnexpectedEndOfSlice(options_end));
        }
        if slice.len() != options_end {
            return Err(SdSliceError::Content(SdError::SdPayloadLengthMismatch {
                expected_len: options_end,
                actual_len: slice.len(),
            }));
        }
        let options = &slice[options_start..options_end];

        let options_index = SdOptionsIndex::from_slice(options)?;
        if !discard_unknown_option {
            for option_index in 0..options_index.len() {
                if let Some(SdOptionSlice::Unknown(unknown)) = options_index.get(option_index) {
                    if !unknown.discardable() {
                        return Err(SdSliceError::Content(SdError::UnknownSdOptionType(
                            unknown.option_type(),
                        )));
                    }
                }
            }
        }
        for entry in SdEntriesIterator::new(entries) {
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

        Ok(Self {
            flags,
            entries,
            options_index,
        })
    }

    /// Returns the header flags.
    #[inline]
    pub fn flags(&self) -> &SdHeaderFlags {
        &self.flags
    }

    /// Returns the raw entries byte slice (without the length prefix).
    #[inline]
    pub fn entries_slice(&self) -> &'a [u8] {
        self.entries
    }

    /// Returns an iterator over the entries.
    #[inline]
    pub fn entries(&self) -> SdEntriesIterator<'a> {
        SdEntriesIterator::new(self.entries)
    }

    /// Returns an iterator over the options.
    #[inline]
    pub fn options(&self) -> SdOptionsIterator<'a> {
        SdOptionsIterator::new(self.options_index.options())
    }

    /// Returns the option index used to resolve options by ordinal position.
    #[inline]
    pub fn options_index(&self) -> &SdOptionsIndex<'a> {
        &self.options_index
    }

    /// Returns an iterator over the entries yielding each entry together with
    /// access to its resolved options.
    #[inline]
    pub fn entries_with_options(&self) -> SdEntriesWithOptionsIterator<'a, '_> {
        SdEntriesWithOptionsIterator::new(self.entries, &self.options_index)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use super::*;
    use crate::sd::{entries::*, options::*, SdEntry, SdHeader, SdOption, SdOptionSlice};

    fn sample_header() -> SdHeader {
        let mut header = SdHeader::default();
        header
            .add_option(SdOption::Ipv4Endpoint(Ipv4EndpointOption {
                ipv4_address: [10, 0, 0, 1],
                transport_protocol: TransportProtocol::Udp,
                port: 100,
            }))
            .unwrap();
        header
            .add_option(SdOption::Ipv4Endpoint(Ipv4EndpointOption {
                ipv4_address: [10, 0, 0, 2],
                transport_protocol: TransportProtocol::Tcp,
                port: 200,
            }))
            .unwrap();
        header
            .add_entry(
                // index1=0, index2=0, count1=2, count2=0
                SdEntry::new_offer_service_entry(0, 0, 2, 0, 0x1234, 0x5678, 1, 3600, 0x01000000)
                    .unwrap(),
            )
            .unwrap();
        header
    }

    #[cfg(feature = "std")]
    fn someip_sd_message(payload: &[u8]) -> Vec<u8> {
        let header = crate::SomeipHeader::new_sd_header(
            crate::SOMEIP_LEN_OFFSET_TO_PAYLOAD + payload.len() as u32,
            1,
            None,
        );
        let mut bytes = Vec::with_capacity(crate::SOMEIP_HEADER_LENGTH + payload.len());
        header.write_raw(&mut bytes).unwrap();
        bytes.extend_from_slice(payload);
        bytes
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn from_slice_roundtrip() {
        let header = sample_header();
        let bytes = header.to_bytes_vec().unwrap();

        let sd = SdSlice::from_slice(&bytes).unwrap();
        assert_eq!(sd.flags(), &header.flags);
        assert_eq!(sd.entries().count(), 1);
        assert_eq!(sd.options().count(), 2);
        assert_eq!(sd.options_index().len(), 2);

        // The raw entries slice holds exactly one serialized entry.
        assert_eq!(sd.entries_slice().len(), ENTRY_LEN);
        assert_eq!(
            sd.entries_slice(),
            sd.entries().next().unwrap().unwrap().slice()
        );

        let entry = sd.entries_with_options().next().unwrap().unwrap();
        assert_eq!(entry.entry().service_id(), 0x1234);
        let ports: Vec<u16> = entry
            .options_run_1()
            .map(|o| match o {
                SdOptionSlice::Ipv4Endpoint(s) => s.port(),
                _ => panic!("expected Ipv4Endpoint"),
            })
            .collect();
        assert_eq!(ports, alloc::vec![100, 200]);
        assert_eq!(entry.options_run_2().count(), 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_someip_validates_sd_header() {
        let payload = sample_header().to_bytes_vec().unwrap();
        let bytes = someip_sd_message(&payload);
        let message = crate::SomeipMsgSlice::from_slice(&bytes).unwrap();
        let sd = SdSlice::from_someip(&message).unwrap();
        assert_eq!(sd.entries().count(), 1);

        let mut invalid = bytes.clone();
        invalid[0] = 0;
        let message = crate::SomeipMsgSlice::from_slice(&invalid).unwrap();
        assert!(matches!(
            SdSlice::from_someip(&message),
            Err(SdSliceError::Content(SdError::SdMessageIdInvalid(_)))
        ));

        let mut invalid = bytes.clone();
        invalid[8..10].copy_from_slice(&1u16.to_be_bytes());
        let message = crate::SomeipMsgSlice::from_slice(&invalid).unwrap();
        assert!(matches!(
            SdSlice::from_someip(&message),
            Err(SdSliceError::Content(SdError::SdClientIdInvalid(1)))
        ));

        let mut invalid = bytes.clone();
        invalid[10..12].copy_from_slice(&0u16.to_be_bytes());
        let message = crate::SomeipMsgSlice::from_slice(&invalid).unwrap();
        assert!(matches!(
            SdSlice::from_someip(&message),
            Err(SdSliceError::Content(SdError::SdSessionIdZero))
        ));

        let mut invalid = bytes.clone();
        invalid[13] = 2;
        let message = crate::SomeipMsgSlice::from_slice(&invalid).unwrap();
        assert!(matches!(
            SdSlice::from_someip(&message),
            Err(SdSliceError::Content(SdError::SdInterfaceVersionInvalid(2)))
        ));

        let mut invalid = bytes.clone();
        invalid[14] = crate::MessageType::Request as u8;
        let message = crate::SomeipMsgSlice::from_slice(&invalid).unwrap();
        assert!(matches!(
            SdSlice::from_someip(&message),
            Err(SdSliceError::Content(SdError::SdMessageTypeInvalid(0)))
        ));

        let mut invalid = bytes;
        invalid[15] = 1;
        let message = crate::SomeipMsgSlice::from_slice(&invalid).unwrap();
        assert!(matches!(
            SdSlice::from_someip(&message),
            Err(SdSliceError::Content(SdError::SdReturnCodeInvalid(1)))
        ));
    }

    #[test]
    fn from_slice_too_short() {
        assert!(matches!(
            SdSlice::from_slice(&[0u8; MIN_SD_HEADER_LENGTH - 1]),
            Err(SdSliceError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_entries_len_too_large() {
        let len = (MAX_ENTRIES_LEN + 1).to_be_bytes();
        let buf = [
            0, 0, 0, 0, // flags + reserved
            len[0], len[1], len[2], len[3], // entries length
            0, 0, 0, 0, // options length
        ];
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(
                SdError::SdEntriesArrayLengthTooLarge(_)
            ))
        ));
    }

    #[test]
    fn from_slice_rejects_invalid_entries_array_length() {
        let buf = [
            0, 0, 0, 0, // flags + reserved
            0, 0, 0, 1, // invalid entries length
            0, // entry data
            0, 0, 0, 0, // options length
        ];
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(SdError::SdEntriesArrayLengthInvalid(
                1
            )))
        ));
    }

    #[test]
    fn from_slice_rejects_out_of_bounds_option_run() {
        let mut buf = [0u8; 28];
        buf[4..8].copy_from_slice(&(ENTRY_LEN as u32).to_be_bytes());
        buf[8] = 0x01; // OfferService
        buf[11] = 0x10; // first run references one option

        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(
                SdError::SdOptionRunOutOfBounds { .. }
            ))
        ));
    }

    #[test]
    fn from_slice_options_len_too_large() {
        let len = (MAX_OPTIONS_LEN + 1).to_be_bytes();
        let buf = [
            0, 0, 0, 0, // flags + reserved
            0, 0, 0, 0, // entries length
            len[0], len[1], len[2], len[3], // options length
        ];
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(
                SdError::SdOptionsArrayLengthTooLarge(_)
            ))
        ));
    }

    #[test]
    fn from_slice_rejects_payload_over_udp_limit() {
        let entries_len = MAX_ENTRIES_LEN_USIZE - (MAX_ENTRIES_LEN_USIZE % ENTRY_LEN);
        let options_len = ENTRY_LEN;
        let mut buf = Vec::with_capacity(MIN_SD_HEADER_LENGTH + entries_len + options_len);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&(entries_len as u32).to_be_bytes());
        buf.resize(8 + entries_len, 0);
        buf.extend_from_slice(&(options_len as u32).to_be_bytes());
        buf.resize(MIN_SD_HEADER_LENGTH + entries_len + options_len, 0);

        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(SdError::SdPayloadLengthTooLarge(len)))
                if len > crate::SOMEIP_MAX_PAYLOAD_LEN_UDP
        ));
    }

    #[test]
    fn from_slice_truncated_entries() {
        // entries length announces 16 bytes but none are present
        let buf = [
            0,
            0,
            0,
            0, // flags + reserved
            0,
            0,
            0,
            ENTRY_LEN as u8, // entries length
            0,
            0,
            0,
            0, // (would be options length, but data ends)
        ];
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_truncated_options() {
        let buf = [
            0, 0, 0, 0, // flags + reserved
            0, 0, 0, 0, // entries length
            0, 0, 0, 9, // options length announces 9 bytes, none present
        ];
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::UnexpectedEndOfSlice(_))
        ));
    }

    #[test]
    fn from_slice_rejects_trailing_bytes() {
        let mut buf = alloc::vec![
            0, 0, 0, 0, // flags + reserved
            0, 0, 0, 0, // entries length
            0, 0, 0, 0, // options length
        ];
        buf.push(0xaa);

        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(SdError::SdPayloadLengthMismatch {
                expected_len: MIN_SD_HEADER_LENGTH,
                actual_len,
            })) if actual_len == MIN_SD_HEADER_LENGTH + 1
        ));
    }

    #[test]
    fn from_slice_bad_option() {
        // options length = 5 but the option is truncated
        let mut buf = alloc::vec![
            0, 0, 0, 0, // flags + reserved
            0, 0, 0, 0, // entries length
            0, 0, 0, 5, // options length
        ];
        // option: length=9 (needs 12 bytes) but only 5 available
        buf.extend_from_slice(&[0x00, 0x09, IPV4_ENDPOINT_TYPE, 0x00, 0x00]);
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(SdError::SdOption(_)))
        ));
    }

    #[test]
    fn from_slice_unknown_option_policy() {
        let mut buf = alloc::vec![
            0, 0, 0, 0, // flags + reserved
            0, 0, 0, 0, // entries length
            0, 0, 0, 4, // options length
            0, 1, 0xaa, 0, // unknown, non-discardable option
        ];
        assert!(matches!(
            SdSlice::from_slice(&buf),
            Err(SdSliceError::Content(SdError::UnknownSdOptionType(0xaa)))
        ));
        assert!(SdSlice::from_slice_with_flag(&buf, true).is_ok());

        *buf.last_mut().unwrap() = DISCARDABLE_FLAG;
        assert!(SdSlice::from_slice(&buf).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn clone_debug_eq() {
        let header = sample_header();
        let bytes = header.to_bytes_vec().unwrap();
        let sd = SdSlice::from_slice(&bytes).unwrap();
        assert_eq!(sd, sd.clone());
        let _ = format!("{:?}", sd);
    }

    use crate::proptest_generators::*;
    use proptest::prelude::*;

    #[cfg(feature = "alloc")]
    proptest! {
        // Build a header with some options and entries that reference valid
        // option runs, serialize it, parse it back with SdSlice and assert
        // that every entry resolves to exactly the referenced options.
        #[test]
        fn from_slice_resolves_options(
            options in prop::collection::vec(someip_sd_option_any(), 0..8),
            entry_specs in prop::collection::vec(
                (any::<u8>(), 0..=4u8, any::<u8>(), 0..=4u8),
                0..5,
            ),
        ) {
            let mut header = SdHeader::default();

            // add options (stop if the buffer is full)
            let mut option_count = 0usize;
            for option in &options {
                if header.add_option(option.clone()).is_err() {
                    break;
                }
                option_count += 1;
            }

            // helper to clamp a (start, count) pair into the valid range
            let clamp = |start: u8, count: u8| -> (u8, u8) {
                if option_count == 0 {
                    return (0, 0);
                }
                let start = (start as usize % option_count) as u8;
                let max_count = option_count - start as usize;
                let count = (count as usize).min(max_count) as u8;
                (start, count)
            };

            // add entries with valid option references, remembering the specs
            let mut specs = Vec::new();
            for (s1, c1, s2, c2) in entry_specs {
                let (start1, count1) = clamp(s1, c1);
                let (start2, count2) = clamp(s2, c2);
                let entry = SdEntry::new_offer_service_entry(
                    start1, start2, count1, count2, 0x1234, 0x5678, 1, 3600, 0x01000000,
                )
                .unwrap();
                if header.add_entry(entry).is_err() {
                    break;
                }
                specs.push((start1, count1, start2, count2));
            }

            let bytes = header.to_bytes_vec().unwrap();
            let sd = SdSlice::from_slice(&bytes).unwrap();

            // full list of options as parsed via the plain options iterator
            let all_options: Vec<SdOptionSlice> = sd.options().map(|o| o.unwrap()).collect();
            prop_assert_eq!(all_options.len(), option_count);

            let mut entry_iter = sd.entries_with_options();
            for (start1, count1, start2, count2) in specs {
                let entry = entry_iter.next().unwrap().unwrap();

                let run1: Vec<SdOptionSlice> = entry.options_run_1().collect();
                prop_assert_eq!(run1.len(), count1 as usize);
                for (i, opt) in run1.iter().enumerate() {
                    prop_assert_eq!(*opt, all_options[start1 as usize + i]);
                }

                let run2: Vec<SdOptionSlice> = entry.options_run_2().collect();
                prop_assert_eq!(run2.len(), count2 as usize);
                for (i, opt) in run2.iter().enumerate() {
                    prop_assert_eq!(*opt, all_options[start2 as usize + i]);
                }
            }
            prop_assert!(entry_iter.next().is_none());
        }
    }

    #[cfg(feature = "alloc")]
    proptest! {
        // The zero-copy SdSlice must observe the same entries and options as
        // the owned SdHeader for any serialized header.
        #[test]
        fn sd_slice_matches_header(header in sd_header_any()) {
            let bytes = header.to_bytes_vec().unwrap();
            let sd = SdSlice::from_slice(&bytes).unwrap();

            prop_assert_eq!(sd.flags(), &header.flags);

            let header_entries: Vec<_> = header.entries().collect();
            let slice_entries: Vec<_> = sd.entries().map(|e| e.unwrap()).collect();
            prop_assert_eq!(header_entries, slice_entries);

            let header_options: Vec<_> = header.options().collect();
            let slice_options: Vec<_> = sd.options().map(|o| o.unwrap()).collect();
            prop_assert_eq!(header_options, slice_options);
        }
    }
}
