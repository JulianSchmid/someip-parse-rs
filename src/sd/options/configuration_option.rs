use arrayvec::ArrayVec;

/// Error in the DNS-SD formatted configuration string of a Configuration
/// Option.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdConfigurationStringError {
    /// The string does not end with the required zero-length item.
    MissingTerminator,
    /// An item's length field exceeds the bytes remaining in the string.
    ItemLengthExceedsRemaining {
        item_offset: usize,
        item_length: u8,
        remaining: usize,
    },
    /// Bytes follow the terminating zero-length item.
    TrailingDataAfterTerminator { terminator_offset: usize },
    /// A configuration item has an empty key (its first byte is `=`).
    EmptyKey { item_offset: usize },
    /// A key contains a byte outside printable US-ASCII.
    InvalidKeyByte {
        item_offset: usize,
        byte_offset: usize,
        value: u8,
    },
    /// A key consists entirely of spaces.
    KeyContainsOnlyWhitespace { item_offset: usize },
}

impl core::fmt::Display for SdConfigurationStringError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdConfigurationStringError::*;
        match self {
            MissingTerminator => write!(
                f,
                "SOME/IP-SD configuration string has no terminating zero-length item"
            ),
            ItemLengthExceedsRemaining {
                item_offset,
                item_length,
                remaining,
            } => write!(
                f,
                "SOME/IP-SD configuration item at offset {item_offset} announces {item_length} bytes, but only {remaining} remain"
            ),
            TrailingDataAfterTerminator { terminator_offset } => write!(
                f,
                "SOME/IP-SD configuration string contains data after the terminator at offset {terminator_offset}"
            ),
            EmptyKey { item_offset } => write!(
                f,
                "SOME/IP-SD configuration item at offset {item_offset} has an empty key"
            ),
            InvalidKeyByte {
                item_offset,
                byte_offset,
                value,
            } => write!(
                f,
                "SOME/IP-SD configuration item at offset {item_offset} has invalid key byte 0x{value:02x} at item offset {byte_offset}"
            ),
            KeyContainsOnlyWhitespace { item_offset } => write!(
                f,
                "SOME/IP-SD configuration item at offset {item_offset} has a key containing only whitespace"
            ),
        }
    }
}

impl std::error::Error for SdConfigurationStringError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationOption {
    /// Shall be set to `true` if the option can be discarded by the receiver.
    pub discardable: bool,
    /// DNS-SD formatted configuration items, including the final zero-length
    /// terminator.
    pub configuration_string: ArrayVec<u8, { ConfigurationOption::MAX_CONFIGURATION_STRING_LEN }>,
}

impl ConfigurationOption {
    /// Maximum length of [`Self::configuration_string`] in bytes.
    ///
    /// SOME/IP Service Discovery is transported exclusively via UDP,
    /// so the SOME/IP UDP payload limit of 1400 bytes applies. After
    /// subtracting the SD header overhead (flags/reserved 4 + entries
    /// length 4 + options length 4 = 12 bytes) the options array can
    /// be at most [`super::MAX_OPTIONS_LEN`] = 1388 bytes.
    ///
    /// A single configuration option uses 4 bytes of wire overhead
    /// (2 length + 1 type + 1 reserved/flags), leaving at most
    /// `1388 - 4 = 1384` bytes for the configuration string.
    pub const MAX_CONFIGURATION_STRING_LEN: usize = super::MAX_OPTIONS_LEN_USIZE - 4;

    /// Validates the DNS-SD format required by PRS_SOMEIPSD_00277 through
    /// PRS_SOMEIPSD_00287.
    pub fn validate_configuration_string(
        configuration_string: &[u8],
    ) -> Result<(), SdConfigurationStringError> {
        use SdConfigurationStringError::*;

        let mut offset = 0usize;
        while offset < configuration_string.len() {
            let item_offset = offset;
            let item_length = configuration_string[offset];
            offset += 1;

            if item_length == 0 {
                return if offset == configuration_string.len() {
                    Ok(())
                } else {
                    Err(TrailingDataAfterTerminator {
                        terminator_offset: item_offset,
                    })
                };
            }

            let item_length = usize::from(item_length);
            let remaining = configuration_string.len() - offset;
            if item_length > remaining {
                return Err(ItemLengthExceedsRemaining {
                    item_offset,
                    item_length: item_length as u8,
                    remaining,
                });
            }

            let item = &configuration_string[offset..offset + item_length];
            let key_end = item
                .iter()
                .position(|&value| value == b'=')
                .unwrap_or(item.len());
            if key_end == 0 {
                return Err(EmptyKey { item_offset });
            }

            let key = &item[..key_end];
            if let Some((byte_offset, &value)) = key
                .iter()
                .enumerate()
                .find(|(_, value)| !(0x20..=0x7e).contains(*value))
            {
                return Err(InvalidKeyByte {
                    item_offset,
                    byte_offset,
                    value,
                });
            }
            if key.iter().all(|&value| value == b' ') {
                return Err(KeyContainsOnlyWhitespace { item_offset });
            }

            offset += item_length;
        }

        Err(MissingTerminator)
    }

    /// Validates this option's configuration string.
    #[inline]
    pub fn validate(&self) -> Result<(), SdConfigurationStringError> {
        Self::validate_configuration_string(&self.configuration_string)
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigurationOption, SdConfigurationStringError::*};

    #[test]
    fn validates_dns_sd_format() {
        for value in [
            &[0][..],
            &[3, b'k', b'e', b'y', 0],
            &[4, b'k', b'e', b'y', b'=', 0],
            &[7, b'k', b'e', b'y', b'=', 0, 0xff, b'=', 0],
            &[3, b' ', b'k', b' ', 0],
        ] {
            ConfigurationOption::validate_configuration_string(value).unwrap();
        }

        assert_eq!(
            ConfigurationOption::validate_configuration_string(&[]),
            Err(MissingTerminator)
        );
        assert_eq!(
            ConfigurationOption::validate_configuration_string(&[3, b'a', 0]),
            Err(ItemLengthExceedsRemaining {
                item_offset: 0,
                item_length: 3,
                remaining: 2,
            })
        );
        assert_eq!(
            ConfigurationOption::validate_configuration_string(&[0, b'x']),
            Err(TrailingDataAfterTerminator {
                terminator_offset: 0,
            })
        );
        assert_eq!(
            ConfigurationOption::validate_configuration_string(&[1, b'=', 0]),
            Err(EmptyKey { item_offset: 0 })
        );
        assert_eq!(
            ConfigurationOption::validate_configuration_string(&[1, 0x1f, 0]),
            Err(InvalidKeyByte {
                item_offset: 0,
                byte_offset: 0,
                value: 0x1f,
            })
        );
        assert_eq!(
            ConfigurationOption::validate_configuration_string(&[2, b' ', b' ', 0]),
            Err(KeyContainsOnlyWhitespace { item_offset: 0 })
        );
    }
}
