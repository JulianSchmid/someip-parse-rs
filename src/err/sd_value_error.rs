///Range errors in fields of the someip & tp header struct. These can occur when serializing or modifying an error.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SdValueError {
    /// Counter value exceeds 4 bit
    CounterTooLarge(u8),

    /// TTL exceeds 24 bit
    TtlTooLarge(u32),

    /// A TTL of zero indicates stop offering of service entry.
    TtlZeroIndicatesStopOffering,

    /// Number of options 1 exceeds 4 bit
    NumberOfOption1TooLarge(u8),

    /// Number of options 2 exceeds 4 bit
    NumberOfOption2TooLarge(u8),

    /// An [`crate::sd::SdOption::UnknownDiscardable`] option has been passed
    /// to the write function.
    ///
    /// [`crate::sd::SdOption::UnknownDiscardable`] are only intended to be used
    /// in read and from_slice functions.
    SdUnknownDiscardableOption(u8),

    /// The serialized entries array is too large for the fixed-size buffer.
    SdEntriesArrayTooLarge,

    /// The serialized options array is too large for the fixed-size buffer.
    SdOptionsArrayTooLarge,

    /// Error in a Configuration Option's DNS-SD formatted string.
    SdConfigurationString(crate::sd::options::SdConfigurationStringError),

    /// An entry references options outside the header's options array.
    SdOptionRunOutOfBounds {
        run: u8,
        start_index: u8,
        number_of_options: u8,
        options_len: usize,
    },
}

impl core::fmt::Display for SdValueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdValueError::*;
        match self {
            CounterTooLarge(v) => write!(
                f,
                "SOMEIP SD Value Error: The counter value '{v}' exceeds the maximum of 4 bits (15)."
            ),
            TtlTooLarge(v) => write!(
                f,
                "SOMEIP SD Value Error: The TTL value '{v}' exceeds the maximum of 24 bits (16777215)."
            ),
            TtlZeroIndicatesStopOffering => write!(
                f,
                "SOMEIP SD Value Error: A TTL of zero indicates 'stop offering' of a service entry and can not be set explicitly."
            ),
            NumberOfOption1TooLarge(v) => write!(
                f,
                "SOMEIP SD Value Error: The 'number of options 1' value '{v}' exceeds the maximum of 4 bits (15)."
            ),
            NumberOfOption2TooLarge(v) => write!(
                f,
                "SOMEIP SD Value Error: The 'number of options 2' value '{v}' exceeds the maximum of 4 bits (15)."
            ),
            SdUnknownDiscardableOption(t) => write!(
                f,
                "SOMEIP SD Value Error: An 'unknown discardable' option of type '{t}' can not be serialized."
            ),
            SdEntriesArrayTooLarge => write!(
                f,
                "SOMEIP SD Value Error: The serialized entries array is too large for the fixed-size buffer."
            ),
            SdOptionsArrayTooLarge => write!(
                f,
                "SOMEIP SD Value Error: The serialized options array is too large for the fixed-size buffer."
            ),
            SdConfigurationString(err) => err.fmt(f),
            SdOptionRunOutOfBounds {
                run,
                start_index,
                number_of_options,
                options_len,
            } => write!(
                f,
                "SOMEIP SD Value Error: Option run {run} (start index {start_index}, {number_of_options} option(s)) references options outside the options array of {options_len} entries."
            ),
        }
    }
}

impl core::error::Error for SdValueError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use SdValueError::*;
        match self {
            SdConfigurationString(err) => Some(err),
            _ => None,
        }
    }
}

impl From<crate::sd::options::SdConfigurationStringError> for SdValueError {
    fn from(err: crate::sd::options::SdConfigurationStringError) -> Self {
        SdValueError::SdConfigurationString(err)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::SdValueError::*;

    #[test]
    fn debug() {
        let err = CounterTooLarge(0);
        let _ = format!("{err:?}");
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let err = CounterTooLarge(0);
        assert_eq!(err, err.clone());
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
        use crate::sd::options::SdConfigurationStringError;

        // Every variant must produce a non-empty message.
        let variants = [
            CounterTooLarge(0x10),
            TtlTooLarge(0x0100_0000),
            TtlZeroIndicatesStopOffering,
            NumberOfOption1TooLarge(0x10),
            NumberOfOption2TooLarge(0x10),
            SdUnknownDiscardableOption(0xaa),
            SdEntriesArrayTooLarge,
            SdOptionsArrayTooLarge,
            SdOptionRunOutOfBounds {
                run: 1,
                start_index: 2,
                number_of_options: 3,
                options_len: 4,
            },
        ];
        for variant in variants {
            assert!(!format!("{variant}").is_empty());
        }

        // The configuration string variant delegates to the inner error.
        let inner = SdConfigurationStringError::MissingTerminator;
        assert_eq!(
            format!("{inner}"),
            format!("{}", SdConfigurationString(inner))
        );
    }

    #[test]
    fn source() {
        use core::error::Error;
        use crate::sd::options::SdConfigurationStringError;

        assert!(CounterTooLarge(0).source().is_none());
        assert!(SdConfigurationString(SdConfigurationStringError::MissingTerminator)
            .source()
            .is_some());
    }

    #[test]
    fn from_configuration_string_error() {
        use crate::sd::options::SdConfigurationStringError;

        let inner = SdConfigurationStringError::MissingTerminator;
        assert_eq!(
            super::SdValueError::from(inner.clone()),
            SdConfigurationString(inner)
        );
    }
}
