use super::*;

/// Error when decoding an SOMEIP header via a `std::io::Read` source.
#[derive(Debug)]
pub enum SomeipHeaderReadError {
    /// IO error was encoutered while reading header.
    Io(std::io::Error),

    /// Error caused by the contents of the header.
    Content(SomeipHeaderError),
}

impl SomeipHeaderReadError {
    /// Returns the `std::io::Error` value if the `SomeipHeaderReadError` is `Io`.
    /// Otherwise `None` is returned.
    #[inline]
    pub fn io_error(self) -> Option<std::io::Error> {
        use SomeipHeaderReadError::*;
        match self {
            Io(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the [`crate::err::SomeipHeaderError`] value if the `SomeipHeaderReadError` is `Content`.
    /// Otherwise `None` is returned.
    #[inline]
    pub fn content_error(self) -> Option<SomeipHeaderError> {
        use SomeipHeaderReadError::*;
        match self {
            Content(value) => Some(value),
            _ => None,
        }
    }
}

impl core::fmt::Display for SomeipHeaderReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SomeipHeaderReadError::*;
        match self {
            Io(err) => write!(f, "SOMEIP Header IO Error: {}", err),
            Content(value) => value.fmt(f),
        }
    }
}

impl std::error::Error for SomeipHeaderReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SomeipHeaderReadError::*;
        match self {
            Io(err) => Some(err),
            Content(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{SomeipHeaderReadError::*, *};

    #[test]
    fn debug() {
        let err = SomeipHeaderError::UnsupportedProtocolVersion(0);
        assert_eq!(
            format!("Content({:?})", err.clone()),
            format!("{:?}", Content(err))
        );
    }

    #[test]
    fn fmt() {
        {
            let err = std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            );
            assert_eq!(
                format!("SOMEIP Header IO Error: {}", err),
                format!("{}", Io(err))
            );
        }
        {
            let err = SomeipHeaderError::UnsupportedProtocolVersion(0);
            assert_eq!(format!("{}", &err), format!("{}", Content(err.clone())));
        }
    }

    #[test]
    fn source() {
        use std::error::Error;
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .source()
        .is_some());
        assert!(Content(SomeipHeaderError::UnsupportedProtocolVersion(0))
            .source()
            .is_some());
    }

    #[test]
    fn io_error() {
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .io_error()
        .is_some());
        assert!(Content(SomeipHeaderError::UnsupportedProtocolVersion(0))
            .io_error()
            .is_none());
    }

    #[test]
    fn content_error() {
        assert_eq!(
            None,
            Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
            .content_error()
        );
        {
            let err = SomeipHeaderError::UnsupportedProtocolVersion(0);
            assert_eq!(Some(err.clone()), Content(err.clone()).content_error());
        }
    }
}
