use super::*;

/// Error when not enough space is available in a slice
/// to write a packet or header to it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SliceWriteSpaceError {
    /// Expected minimum length conflicting with the
    /// `actual_len` value.
    pub required_len: usize,

    /// Length limiting or exceeding the required length.
    pub len: usize,

    /// Layer in which could not be written to the slice.
    pub layer: Layer,

    /// Offset from the start of the parsed data to the layer where the
    /// length error occured.
    pub layer_start_offset: usize,
}

impl core::fmt::Display for SliceWriteSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.layer_start_offset > 0 {
            write!(
                f,
                "Not enough space to write {} to slice. Needed {} byte(s), but only {} byte(s) were available (start offset of {} write was {} byte(s)).",
                self.layer,
                self.required_len,
                self.len,
                self.layer,
                self.layer_start_offset
            )
        } else {
            write!(
                f,
                "Not enough space to write {} to slice. Needed {} byte(s), but only {} byte(s) were available.",
                self.layer,
                self.required_len,
                self.len,
            )
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SliceWriteSpaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
