
///Range errors in fields of the someip & tp header struct. These can occur when serializing or modifying an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// Payload length is too long as 8 bytes for the header have to be added.
    LengthTooLarge(u32),

    /// Offset of the tp header is not a multiple of 16.
    ///
    /// PRS_SOMEIP_00724: The Offset field shall transport the upper 28 bits of a
    /// uint32. The lower 4 bits shall be always interpreted as 0.
    /// Note: This means that the offset field can only transport offset values
    /// that are multiples of 16 bytes.
    TpOffsetNotMultipleOf16(u32),

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

    /// An [`sd::SdOption::UnknownDiscardable`] option has been passed
    /// to the write function.
    ///
    /// [`sd::SdOption::UnknownDiscardable`] are only intended to be used
    /// in read and from_slice functions.
    SdUnknownDiscardableOption(u8),
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_write() {
        use ValueError::*;
        for value in [LengthTooLarge(0), TpOffsetNotMultipleOf16(0)].iter() {
            let _ = format!("{:?}", value);
        }
    }
}
