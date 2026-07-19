use super::{SdError, SdOptionSliceError, SdSliceError};

/// Error when decoding a SOME/IP-SD message via a [`std::io::Read`] source.
#[derive(Debug)]
pub enum SdIoReadError {
    /// IO error was encountered while reading the SD message.
    Io(std::io::Error),

    /// Error caused by the contents of the SD message.
    Content(SdError),
}

impl SdIoReadError {
    /// Returns the `std::io::Error` value if the `SdIoReadError` is `Io`.
    /// Otherwise `None` is returned.
    #[inline]
    pub fn io_error(self) -> Option<std::io::Error> {
        use SdIoReadError::*;
        match self {
            Io(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the [`SdError`] value if the `SdIoReadError` is `Content`.
    /// Otherwise `None` is returned.
    #[inline]
    pub fn content_error(self) -> Option<SdError> {
        use SdIoReadError::*;
        match self {
            Content(value) => Some(value),
            _ => None,
        }
    }
}

impl core::fmt::Display for SdIoReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SdIoReadError::*;
        match self {
            Io(err) => write!(f, "SOMEIP SD IO Error: {err}"),
            Content(value) => value.fmt(f),
        }
    }
}

impl core::error::Error for SdIoReadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use SdIoReadError::*;
        match self {
            Io(err) => Some(err),
            Content(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for SdIoReadError {
    fn from(err: std::io::Error) -> SdIoReadError {
        SdIoReadError::Io(err)
    }
}

impl From<SdError> for SdIoReadError {
    fn from(err: SdError) -> SdIoReadError {
        SdIoReadError::Content(err)
    }
}

impl From<SdOptionSliceError> for SdIoReadError {
    fn from(err: SdOptionSliceError) -> SdIoReadError {
        SdIoReadError::Content(SdError::SdOption(err))
    }
}

impl From<SdSliceError> for SdIoReadError {
    fn from(err: SdSliceError) -> SdIoReadError {
        match err {
            // A "not enough data in slice" error while decoding data that was
            // already read from an io source is reported as an unexpected EOF.
            SdSliceError::UnexpectedEndOfSlice(required_len) => {
                SdIoReadError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    alloc::format!(
                        "not enough data to decode the SOME/IP-SD message (at least {required_len} bytes required)"
                    ),
                ))
            }
            SdSliceError::Content(err) => SdIoReadError::Content(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn io_err() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "oh no!")
    }

    #[test]
    fn debug() {
        let _ = format!("{:?}", SdIoReadError::Io(io_err()));
        let _ = format!("{:?}", SdIoReadError::Content(SdError::SdSessionIdZero));
    }

    #[test]
    fn fmt() {
        assert_eq!(
            format!("SOMEIP SD IO Error: {}", io_err()),
            format!("{}", SdIoReadError::Io(io_err()))
        );
        let content = SdError::SdSessionIdZero;
        assert_eq!(
            format!("{}", &content),
            format!("{}", SdIoReadError::Content(content.clone()))
        );
    }

    #[test]
    fn source() {
        use core::error::Error;
        assert!(SdIoReadError::Io(io_err()).source().is_some());
        assert!(SdIoReadError::Content(SdError::SdSessionIdZero)
            .source()
            .is_some());
    }

    #[test]
    fn io_error() {
        assert!(SdIoReadError::Io(io_err()).io_error().is_some());
        assert!(SdIoReadError::Content(SdError::SdSessionIdZero)
            .io_error()
            .is_none());
    }

    #[test]
    fn content_error() {
        assert!(SdIoReadError::Io(io_err()).content_error().is_none());
        let content = SdError::SdSessionIdZero;
        assert_eq!(
            Some(content.clone()),
            SdIoReadError::Content(content).content_error()
        );
    }

    #[test]
    fn from_impls() {
        assert!(matches!(SdIoReadError::from(io_err()), SdIoReadError::Io(_)));
        assert!(matches!(
            SdIoReadError::from(SdError::SdSessionIdZero),
            SdIoReadError::Content(SdError::SdSessionIdZero)
        ));
        assert!(matches!(
            SdIoReadError::from(SdOptionSliceError::OptionLengthZero),
            SdIoReadError::Content(SdError::SdOption(SdOptionSliceError::OptionLengthZero))
        ));
        assert!(matches!(
            SdIoReadError::from(SdSliceError::Content(SdError::SdSessionIdZero)),
            SdIoReadError::Content(SdError::SdSessionIdZero)
        ));
        assert!(matches!(
            SdIoReadError::from(SdSliceError::UnexpectedEndOfSlice(4)),
            SdIoReadError::Io(_)
        ));
    }
}
