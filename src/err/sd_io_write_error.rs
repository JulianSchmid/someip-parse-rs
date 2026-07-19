use super::SdValueError;

/// Error when serializing a SOME/IP-SD message to a [`std::io::Write`] source.
#[derive(Debug)]
pub enum SdIoWriteError {
    /// IO error was encountered while writing the SD message.
    Io(std::io::Error),

    /// Error in the data that was attempted to be written.
    Value(SdValueError),
}

impl SdIoWriteError {
    /// Returns the `std::io::Error` value if the `SdIoWriteError` is `Io`.
    /// Otherwise `None` is returned.
    #[inline]
    pub fn io_error(self) -> Option<std::io::Error> {
        use SdIoWriteError::*;
        match self {
            Io(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the [`SdValueError`] value if the `SdIoWriteError` is `Value`.
    /// Otherwise `None` is returned.
    #[inline]
    pub fn value_error(self) -> Option<SdValueError> {
        use SdIoWriteError::*;
        match self {
            Value(value) => Some(value),
            _ => None,
        }
    }
}

impl core::fmt::Display for SdIoWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdIoWriteError::*;
        match self {
            Io(err) => write!(f, "SOMEIP SD IO Error: {err}"),
            Value(value) => value.fmt(f),
        }
    }
}

impl core::error::Error for SdIoWriteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use SdIoWriteError::*;
        match self {
            Io(err) => Some(err),
            Value(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for SdIoWriteError {
    fn from(err: std::io::Error) -> SdIoWriteError {
        SdIoWriteError::Io(err)
    }
}

impl From<SdValueError> for SdIoWriteError {
    fn from(err: SdValueError) -> SdIoWriteError {
        SdIoWriteError::Value(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn io_err() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, "oh no!")
    }

    #[test]
    fn debug() {
        let _ = format!("{:?}", SdIoWriteError::Io(io_err()));
        let _ = format!(
            "{:?}",
            SdIoWriteError::Value(SdValueError::TtlZeroIndicatesStopOffering)
        );
    }

    #[test]
    fn fmt() {
        assert_eq!(
            format!("SOMEIP SD IO Error: {}", io_err()),
            format!("{}", SdIoWriteError::Io(io_err()))
        );
        let value = SdValueError::TtlZeroIndicatesStopOffering;
        assert_eq!(
            format!("{}", &value),
            format!("{}", SdIoWriteError::Value(value.clone()))
        );
    }

    #[test]
    fn source() {
        use core::error::Error;
        assert!(SdIoWriteError::Io(io_err()).source().is_some());
        assert!(
            SdIoWriteError::Value(SdValueError::TtlZeroIndicatesStopOffering)
                .source()
                .is_some()
        );
    }

    #[test]
    fn accessors() {
        assert!(SdIoWriteError::Io(io_err()).io_error().is_some());
        assert!(SdIoWriteError::Io(io_err()).value_error().is_none());
        let value = SdValueError::TtlZeroIndicatesStopOffering;
        assert_eq!(
            Some(value.clone()),
            SdIoWriteError::Value(value).value_error()
        );
    }

    #[test]
    fn from_impls() {
        assert!(matches!(SdIoWriteError::from(io_err()), SdIoWriteError::Io(_)));
        assert!(matches!(
            SdIoWriteError::from(SdValueError::TtlZeroIndicatesStopOffering),
            SdIoWriteError::Value(SdValueError::TtlZeroIndicatesStopOffering)
        ));
    }
}
