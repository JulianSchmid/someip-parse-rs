
///Errors that can occur when reading someip headers.
#[derive(Debug)]
pub enum ReadError {
    IoError(std::io::Error),
    /// Allocation error when trying to reserving memory.
    AllocationError(std::collections::TryReserveError),
    /// The slice length was not large enough to contain the header.
    UnexpectedEndOfSlice(usize),
    /// Error when the protocol version field contains a version that is not supported by this library (aka != SOMEIP_PROTOCOL_VERSION)
    UnsupportedProtocolVersion(u8),
    /// Error returned when a someip header has a value in the length field that is smaller then the rest of someip header itself (8 bytes).
    LengthFieldTooSmall(u32),
    /// Error when the message type field contains an unknown value
    UnknownMessageType(u8),
    /// Error when the sd event entry type field contains an unknown value
    UnknownSdEventGroupEntryType(u8),
    /// Error when the sd service entry type field contains an unknown value
    UnknownSdServiceEntryType(u8),
    /// Error when the option type contains an unknown value
    UnknownSdOptionType(u8),
    /// Error when the entries array length is greater then [`sd_entries::MAX_ENTRIES_LEN`].
    SdEntriesArrayLengthTooLarge(u32),
    /// Error when the options array length is greater then [`sd_options::MAX_OPTIONS_LEN`].
    SdOptionsArrayLengthTooLarge(u32),
    /// Error if the length in an option is zero (minimum valid size is 1).
    SdOptionLengthZero,
    /// Error if the `length` of an option was different then expected.
    SdOptionUnexpectedLen {
        expected_len: u16,
        actual_len: u16,
        option_type: u8,
    },
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

impl From<std::collections::TryReserveError> for ReadError {
    fn from(err: std::collections::TryReserveError) -> ReadError {
        ReadError::AllocationError(err)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_write() {
        use ReadError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            UnexpectedEndOfSlice(0),
            UnsupportedProtocolVersion(0),
            LengthFieldTooSmall(0),
            UnknownMessageType(0),
        ]
        .iter()
        {
            let _ = format!("{:?}", value);
        }
    }
}
