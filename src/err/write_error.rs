use super::*;

/// Errors that can occur when serializing a someip & tp header.
#[derive(Debug)]
pub enum WriteError {
    IoError(std::io::Error),
    ///The slice length was not large enough to write the header.
    UnexpectedEndOfSlice(usize),
    /// Error in the data that was attempted to be written
    ValueError(ValueError),
}

impl From<std::io::Error> for WriteError {
    fn from(err: std::io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

impl From<ValueError> for WriteError {
    fn from(err: ValueError) -> WriteError {
        WriteError::ValueError(err)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::*;

    #[test]
    fn from_io_error() {
        assert_matches!(
            WriteError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            WriteError::IoError(_)
        );
    }

    #[test]
    fn debug_write() {
        use WriteError::*;
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