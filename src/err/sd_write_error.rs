use super::*;

/// Errors that can occur when serializing a someip & tp header.
#[derive(Debug)]
pub enum SdWriteError {
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    IoError(std::io::Error),
    ///The slice length was not large enough to write the header.
    UnexpectedEndOfSlice(usize),
    /// Error in the data that was attempted to be written
    ValueError(SdValueError),
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for SdWriteError {
    fn from(err: std::io::Error) -> SdWriteError {
        SdWriteError::IoError(err)
    }
}

impl From<SdValueError> for SdWriteError {
    fn from(err: SdValueError) -> SdWriteError {
        SdWriteError::ValueError(err)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn from_io_error() {
        use assert_matches::*;
        assert_matches!(
            SdWriteError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            SdWriteError::IoError(_)
        );
    }

    #[test]
    fn debug_write() {
        use SdWriteError::*;

        #[cfg(feature = "std")]
        {
            let _ = format!(
                "{:?}",
                IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
            );
        }

        for value in [UnexpectedEndOfSlice(0)].iter() {
            let _ = format!("{:?}", value);
        }
    }
}
