#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TpReassembleError {
    /// Error if a payload lenght of a SOMEIP TP packet is not a multiple of 16
    /// and the "more segments" flag is set.
    UnalignedTpPayloadLen { offset: u32, payload_len: usize },

    /// Error if a segment is bigger then the maximum allowed size.
    SegmentTooBig {
        offset: u32,
        payload_len: usize,
        max: u32,
    },

    /// Error if multiple TP segments were received with the "more segment"
    /// unset and differing end points.
    ConflictingEnd {
        /// Offset + tp_payload.len() of the previous package with "more segment" unset.
        previous_end: u32,

        /// Offset + tp_payload.len() of the current package.
        conflicting_end: u32,
    },

    /// Error if not enough memory could be allocated to store the TP payload.
    AllocationFailure { len: usize },
}

impl core::fmt::Display for TpReassembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TpReassembleError::*;
        match self {
            UnalignedTpPayloadLen{ offset, payload_len } => write!(f, "Payload length {payload_len} of SOMEIP TP segment (offset {offset}) is not a multiple of 16. This is only allowed for TP packets where the 'more segements' flag is not set."),
            SegmentTooBig{ offset, payload_len, max } => write!(f, "Overall length of TP segment (offset {offset}, payload len: {payload_len}) bigger then the maximum allowed size of {max}."),
            ConflictingEnd { previous_end, conflicting_end } => write!(f, "Received a TP package (offset + len: {conflicting_end}) which conflicts a package that previously set the end to {previous_end}."),
            AllocationFailure { len } => write!(f, "Faield to allocate {len} bytes of memory to reconstruct the SOMEIP TP packets."),
        }
    }
}

impl std::error::Error for TpReassembleError {}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TpBufConfigError {
    /// Error if the configured maximum payload is bigger then the possible value.
    MaxPayloadLenTooBig { allowed_max: u32, actual: u32 },
}

impl core::fmt::Display for TpBufConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TpBufConfigError::*;
        match self {
            MaxPayloadLenTooBig {
                allowed_max,
                actual,
            } => write!(f, "TP pool config 'maximum payload value' {actual} is bigger then the maximum allowed value {allowed_max}."),
        }
    }
}

impl std::error::Error for TpBufConfigError {}
