///Errors that can occur when reading someip headers.
#[derive(Debug)]
pub enum SdReadError {
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    IoError(std::io::Error),
    /// Allocation error when trying to reserving memory.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    AllocationError(alloc::collections::TryReserveError),
    /// The enclosing SOME/IP message does not use the SD message ID.
    SdMessageIdInvalid(u32),
    /// The SOME/IP Client ID of an SD message is not zero.
    SdClientIdInvalid(u16),
    /// The SOME/IP Session ID of an SD message is zero.
    SdSessionIdZero,
    /// The SOME/IP Interface Version of an SD message is not 1.
    SdInterfaceVersionInvalid(u8),
    /// The SOME/IP Message Type of an SD message is not Notification (0x02).
    SdMessageTypeInvalid(u8),
    /// The SOME/IP Return Code of an SD message is not E_OK (0x00).
    SdReturnCodeInvalid(u8),
    /// The slice length was not large enough to contain the header.
    UnexpectedEndOfSlice(usize),
    /// Error when the sd event entry type field contains an unknown value
    UnknownSdEventGroupEntryType(u8),
    /// Error when the sd service entry type field contains an unknown value
    UnknownSdServiceEntryType(u8),
    /// Error when the option type contains an unknown value
    UnknownSdOptionType(u8),
    /// Error when the entries array length is greater then [`crate::sd::entries::MAX_ENTRIES_LEN`].
    SdEntriesArrayLengthTooLarge(u32),
    /// Error when the entries array length is not a multiple of the fixed entry size.
    SdEntriesArrayLengthInvalid(u32),
    /// Error when the options array length is greater then [`crate::sd::options::MAX_OPTIONS_LEN`].
    SdOptionsArrayLengthTooLarge(u32),
    /// Error when the complete SOME/IP-SD payload exceeds the UDP payload limit.
    SdPayloadLengthTooLarge(u32),
    /// Error when an entry's option run references options outside the options array.
    SdOptionRunOutOfBounds {
        run: u8,
        start_index: u8,
        number_of_options: u8,
        options_len: usize,
    },
    /// Error when bytes remain after the announced options array.
    SdPayloadLengthMismatch {
        expected_len: usize,
        actual_len: usize,
    },
    /// Error if the length in an option is zero (minimum valid size is 1).
    SdOptionLengthZero,
    /// Error if the `length` of an option was different then expected.
    SdOptionUnexpectedLen {
        expected_len: u16,
        actual_len: u16,
        option_type: u8,
    },
    /// Error if a configuration option's length exceeds the maximum
    /// allowed configuration string size.
    SdConfigurationOptionLenTooLarge(u16),
    /// Error while decoding an SD option (e.g. when building an option index).
    SdOption(crate::err::SdOptionSliceError),
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for SdReadError {
    fn from(err: std::io::Error) -> SdReadError {
        SdReadError::IoError(err)
    }
}

impl From<crate::err::SdOptionSliceError> for SdReadError {
    fn from(err: crate::err::SdOptionSliceError) -> SdReadError {
        SdReadError::SdOption(err)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<alloc::collections::TryReserveError> for SdReadError {
    fn from(err: alloc::collections::TryReserveError) -> SdReadError {
        SdReadError::AllocationError(err)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn debug_write() {
        use SdReadError::*;

        #[cfg(feature = "std")]
        {
            let _ = format!(
                "{:?}",
                IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
            );
        }

        for value in [
            SdMessageIdInvalid(0),
            SdClientIdInvalid(1),
            SdSessionIdZero,
            SdInterfaceVersionInvalid(0),
            SdMessageTypeInvalid(0),
            SdReturnCodeInvalid(1),
            UnexpectedEndOfSlice(0),
            SdEntriesArrayLengthInvalid(1),
            SdPayloadLengthTooLarge(crate::SOMEIP_MAX_PAYLOAD_LEN_UDP + 1),
            SdOptionRunOutOfBounds {
                run: 1,
                start_index: 1,
                number_of_options: 1,
                options_len: 0,
            },
            SdPayloadLengthMismatch {
                expected_len: 12,
                actual_len: 13,
            },
            SdConfigurationOptionLenTooLarge(0),
        ]
        .iter()
        {
            let _ = format!("{:?}", value);
        }
    }
}
