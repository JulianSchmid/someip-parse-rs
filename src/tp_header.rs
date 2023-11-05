use crate::*;

///Additional header when a packet contains a TP header (transporting large SOME/IP messages).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TpHeader {
    ///Offset of the payload relativ the start of the completly assempled payload.
    offset: u32,
    ///Flag signaling that more packets should follow
    pub more_segment: bool,
}

impl TpHeader {
    ///Creates a tp header with offset 0 and the given "move_segment" flag.
    ///
    /// # Example:
    ///
    /// ```
    /// use someip_parse::TpHeader;
    ///
    /// // create a header with the more_segement flag set
    /// let header = TpHeader::new(true);
    ///
    /// assert_eq!(0, header.offset());
    /// assert_eq!(true, header.more_segment);
    /// ```
    #[inline]
    pub fn new(more_segment: bool) -> TpHeader {
        TpHeader {
            offset: 0,
            more_segment,
        }
    }

    /// Creates a tp header with the given offset & "more_segment" flag if the offset is a multiple of 16.
    /// Otherwise an TpOffsetNotMultipleOf16 error is returned.
    ///
    /// # Example:
    ///
    /// ```
    /// use someip_parse::{TpHeader, err::ValueError};
    ///
    /// // create a header with offset 32 (multiple of 16) and the more_segement flag set
    /// let header = TpHeader::with_offset(32, true).unwrap();
    ///
    /// assert_eq!(32, header.offset());
    /// assert_eq!(true, header.more_segment);
    ///
    /// // try to create a header with a bad offset (non multiple of 16)
    /// let error = TpHeader::with_offset(31, false);
    ///
    /// assert_eq!(Err(ValueError::TpOffsetNotMultipleOf16(31)), error);
    /// ```
    pub fn with_offset(offset: u32, more_segment: bool) -> Result<TpHeader, err::ValueError> {
        use err::ValueError::*;
        if 0 != offset % 16 {
            Err(TpOffsetNotMultipleOf16(offset))
        } else {
            Ok(TpHeader {
                offset,
                more_segment,
            })
        }
    }

    /// Returns the offset field of the tp header. The offset defines
    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Sets the field of the header and returns Ok(()) on success. Note: The value must be a multiple of 16.
    ///
    /// If the given value is not a multiple of 16, the value is not set and an error
    /// ValueError::TpOffsetNotMultipleOf16 is returned.
    pub fn set_offset(&mut self, value: u32) -> Result<(), err::ValueError> {
        use err::ValueError::*;
        if 0 != value % 16 {
            Err(TpOffsetNotMultipleOf16(value))
        } else {
            self.offset = value;
            Ok(())
        }
    }

    /// Read a header from a byte stream.
    pub fn read<T: std::io::Read>(reader: &mut T) -> Result<TpHeader, std::io::Error> {
        let mut buffer = [0u8; TP_HEADER_LENGTH];
        reader.read_exact(&mut buffer)?;
        let more_segment = 0 != (buffer[3] & 0b0001u8);

        //mask out the flags
        buffer[3] &= !0b1111u8;

        Ok(TpHeader {
            offset: u32::from_be_bytes(buffer),
            more_segment,
        })
    }

    /// Reads a tp header from a slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<TpHeader, err::SdReadError> {
        if slice.len() < TP_HEADER_LENGTH {
            use err::SdReadError::*;
            Err(UnexpectedEndOfSlice(TP_HEADER_LENGTH))
        } else {
            Ok(
                // SAFETY:
                // Safe as a length check is preformed that the slice has
                // the minimum size of TP_HEADER_LENGTH.
                unsafe { TpHeader::from_slice_unchecked(slice) },
            )
        }
    }

    /// Read the value from the slice without checking for the minimum length of the slice.
    ///
    /// # Safety
    ///
    /// It is required that the slice has at least the length of TP_HEADER_LENGTH (4 octets/bytes).
    /// If this is not the case undefined behavior will occur.
    #[inline]
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> TpHeader {
        debug_assert!(slice.len() >= 4);

        //return result
        TpHeader {
            offset: u32::from_be_bytes([
                *slice.as_ptr(),
                *slice.as_ptr().add(1),
                *slice.as_ptr().add(2),
                *slice.as_ptr().add(3) & 0b1111_0000u8,
            ]),
            more_segment: 0 != (*slice.as_ptr().add(3) & 0b0001u8),
        }
    }

    /// Writes the header to the given writer.
    #[inline]
    pub fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Writes the header to a slice.
    #[inline]
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<(), err::SliceWriteSpaceError> {
        if slice.len() < TP_HEADER_LENGTH {
            Err(err::SliceWriteSpaceError {
                required_len: TP_HEADER_LENGTH,
                len: slice.len(),
                layer: err::Layer::SomeipTpHeader,
                layer_start_offset: 0,
            })
        } else {
            let buffer = self.to_bytes();
            let target = &mut slice[0..4];
            target[0] = buffer[0];
            target[1] = buffer[1];
            target[2] = buffer[2];
            target[3] = buffer[3];
            Ok(())
        }
    }

    ///Writes the header to a slice without checking the slice length.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut result = self.offset.to_be_bytes();
        if self.more_segment {
            result[3] |= 0x1u8;
        }
        result
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::proptest_generators::*;
    use assert_matches::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn new(more_segment in any::<bool>()) {
            let result = TpHeader::new(more_segment);

            assert_eq!(result.offset, 0);
            assert_eq!(result.offset(), 0);
            assert_eq!(result.more_segment, more_segment);
        }
    }

    proptest! {
        #[test]
        fn with_offset(
            offset in any::<u32>().prop_filter("must be multiple of 16", |v| 0 == v % 16),
            more_segment in any::<bool>()
        ) {
            let result = TpHeader::with_offset(offset, more_segment).unwrap();

            assert_eq!(result.offset, offset);
            assert_eq!(result.more_segment, more_segment);
        }
    }

    proptest! {
        #[test]
        fn with_offset_error(
            offset in any::<u32>().prop_filter("must not be multiple of 16", |v| 0 != v % 16),
            more_segment in any::<bool>()
        ) {
            let result = TpHeader::with_offset(offset, more_segment);
            assert_eq!(Err(err::ValueError::TpOffsetNotMultipleOf16(offset)), result);
        }
    }

    proptest! {
        #[test]
        fn set_offset(
            offset in any::<u32>().prop_filter("must be multiple of 16", |v| 0 == v % 16)
        ) {
            let mut header: TpHeader = Default::default();
            assert_eq!(Ok(()), header.set_offset(offset));
            assert_eq!(header.offset, offset);
        }
    }

    proptest! {
        #[test]
        fn set_offset_error(
            offset in any::<u32>().prop_filter("must not be multiple of 16", |v| 0 != v % 16)
        ) {
            let mut header: TpHeader = Default::default();
            assert_eq!(Err(err::ValueError::TpOffsetNotMultipleOf16(offset)), header.set_offset(offset));
            assert_eq!(0, header.offset);
        }
    }

    proptest! {
        #[test]
        fn write_and_read_to_slice(
            header in someip_tp_any()
        ) {
            //non error case
            {
                //serialize
                let mut buffer: [u8;TP_HEADER_LENGTH] = [0;TP_HEADER_LENGTH];
                header.write_to_slice(&mut buffer).unwrap();

                //deserialize
                let result = TpHeader::read_from_slice(&buffer).unwrap();
                assert_eq!(header, result);
            }

            //error
            {
                //write_to_slice
                let mut buffer: [u8;TP_HEADER_LENGTH] = [0;TP_HEADER_LENGTH];
                assert_eq!(
                    header.write_to_slice(&mut buffer[..TP_HEADER_LENGTH-1]),
                    Err(err::SliceWriteSpaceError{
                        required_len: TP_HEADER_LENGTH,
                        len: TP_HEADER_LENGTH - 1,
                        layer: err::Layer::SomeipTpHeader,
                        layer_start_offset: 0
                    })
                );

                //read_from_slice
                assert_matches!(TpHeader::read_from_slice(&buffer[..TP_HEADER_LENGTH-1]), Err(err::SdReadError::UnexpectedEndOfSlice(_)));
            }
        }
    }
}
