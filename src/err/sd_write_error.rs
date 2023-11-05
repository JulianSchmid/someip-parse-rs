use super::*;

/// Errors that can occur when serializing a someip & tp header.
#[derive(Debug)]
pub enum SdWriteError {
    IoError(std::io::Error),
    ///The slice length was not large enough to write the header.
    UnexpectedEndOfSlice(usize),
    /// Error in the data that was attempted to be written
    ValueError(SdValueError),
}

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
    use super::*;
    use assert_matches::*;

    #[test]
    fn from_io_error() {
        assert_matches!(
            SdWriteError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            SdWriteError::IoError(_)
        );
    }

    #[test]
    fn debug_write() {
        use SdWriteError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            UnexpectedEndOfSlice(0),
        ]
        .iter()
        {
            let _ = format!("{:?}", value);
        }
    }
}
