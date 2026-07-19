use super::SdOptionSliceError;

/// Errors in the content (values) of a SOME/IP-SD message.
///
/// These errors are independent of the source the data was read from
/// (slice or [`std::io::Read`]) and describe invalid or unsupported
/// values encountered while decoding a service discovery message.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdError {
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
    /// Error when the sd event entry type field contains an unknown value.
    UnknownSdEventGroupEntryType(u8),
    /// Error when the sd service entry type field contains an unknown value.
    UnknownSdServiceEntryType(u8),
    /// Error when the option type contains an unknown value.
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
    SdOption(SdOptionSliceError),
}

impl core::fmt::Display for SdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdError::*;
        match self {
            SdMessageIdInvalid(id) => write!(
                f,
                "SOMEIP SD Error: The message id '{id:#010x}' of the SOME/IP message is not the required SD message id (0xffff8100)."
            ),
            SdClientIdInvalid(id) => write!(
                f,
                "SOMEIP SD Error: The client id '{id}' of the SD message is not zero."
            ),
            SdSessionIdZero => write!(
                f,
                "SOMEIP SD Error: The session id of the SD message is zero (must be non-zero)."
            ),
            SdInterfaceVersionInvalid(v) => write!(
                f,
                "SOMEIP SD Error: The interface version '{v}' of the SD message is not 1."
            ),
            SdMessageTypeInvalid(t) => write!(
                f,
                "SOMEIP SD Error: The message type '{t}' of the SD message is not Notification (0x02)."
            ),
            SdReturnCodeInvalid(c) => write!(
                f,
                "SOMEIP SD Error: The return code '{c}' of the SD message is not E_OK (0x00)."
            ),
            UnknownSdEventGroupEntryType(t) => write!(
                f,
                "SOMEIP SD Error: Encountered an unknown SD eventgroup entry type '{t}'."
            ),
            UnknownSdServiceEntryType(t) => write!(
                f,
                "SOMEIP SD Error: Encountered an unknown SD service entry type '{t}'."
            ),
            UnknownSdOptionType(t) => write!(
                f,
                "SOMEIP SD Error: Encountered an unknown non-discardable SD option type '{t}'."
            ),
            SdEntriesArrayLengthTooLarge(l) => write!(
                f,
                "SOMEIP SD Error: The entries array length of {l} bytes exceeds the maximum supported length."
            ),
            SdEntriesArrayLengthInvalid(l) => write!(
                f,
                "SOMEIP SD Error: The entries array length of {l} bytes is not a multiple of the SD entry size (16 bytes)."
            ),
            SdOptionsArrayLengthTooLarge(l) => write!(
                f,
                "SOMEIP SD Error: The options array length of {l} bytes exceeds the maximum supported length."
            ),
            SdPayloadLengthTooLarge(l) => write!(
                f,
                "SOMEIP SD Error: The SOME/IP-SD payload length of {l} bytes exceeds the maximum allowed UDP payload length."
            ),
            SdOptionRunOutOfBounds {
                run,
                start_index,
                number_of_options,
                options_len,
            } => write!(
                f,
                "SOMEIP SD Error: Option run {run} (start index {start_index}, {number_of_options} option(s)) references options outside the options array of {options_len} entries."
            ),
            SdPayloadLengthMismatch {
                expected_len,
                actual_len,
            } => write!(
                f,
                "SOMEIP SD Error: The SOME/IP-SD payload length of {actual_len} bytes does not match the announced length of {expected_len} bytes."
            ),
            SdOptionLengthZero => write!(
                f,
                "SOMEIP SD Error: The 'length' field of an option is zero (minimum valid size is 1)."
            ),
            SdOptionUnexpectedLen {
                expected_len,
                actual_len,
                option_type,
            } => write!(
                f,
                "SOMEIP SD Error: The option of type '{option_type}' has a length of {actual_len} bytes but {expected_len} bytes were expected."
            ),
            SdConfigurationOptionLenTooLarge(l) => write!(
                f,
                "SOMEIP SD Error: The configuration option length of {l} bytes exceeds the maximum allowed configuration string size."
            ),
            SdOption(err) => err.fmt(f),
        }
    }
}

impl core::error::Error for SdError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use SdError::*;
        match self {
            SdOption(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SdOptionSliceError> for SdError {
    fn from(err: SdOptionSliceError) -> SdError {
        SdError::SdOption(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let err = SdError::SdSessionIdZero;
        assert_eq!(err, err.clone());
        let _ = format!("{:?}", err);
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            err.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            err.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
        assert_eq!(Ordering::Equal, err.cmp(&err));
        assert_eq!(Some(Ordering::Equal), err.partial_cmp(&err));
    }

    #[test]
    fn fmt() {
        use SdError::*;
        let values = [
            SdMessageIdInvalid(0),
            SdClientIdInvalid(1),
            SdSessionIdZero,
            SdInterfaceVersionInvalid(0),
            SdMessageTypeInvalid(0),
            SdReturnCodeInvalid(1),
            UnknownSdEventGroupEntryType(0),
            UnknownSdServiceEntryType(0),
            UnknownSdOptionType(0),
            SdEntriesArrayLengthTooLarge(1),
            SdEntriesArrayLengthInvalid(1),
            SdOptionsArrayLengthTooLarge(1),
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
            SdOptionLengthZero,
            SdOptionUnexpectedLen {
                expected_len: 4,
                actual_len: 5,
                option_type: 1,
            },
            SdConfigurationOptionLenTooLarge(0),
        ];
        for value in values {
            assert!(!format!("{value}").is_empty());
            let _ = format!("{value:?}");
        }
    }

    #[test]
    fn source() {
        use core::error::Error;
        assert!(SdError::SdSessionIdZero.source().is_none());
        assert!(SdError::SdOption(SdOptionSliceError::OptionLengthZero)
            .source()
            .is_some());
    }

    #[test]
    fn from_sd_option_slice_error() {
        let err = SdOptionSliceError::OptionLengthZero;
        assert_eq!(SdError::from(err.clone()), SdError::SdOption(err));
    }
}
