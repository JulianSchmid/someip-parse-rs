use crate::*;

/// Deprecated use [`SomeipMsgsIterator`] instead.
#[deprecated(since = "0.5.0", note = "Use SomeipMsgsIterator instead (renamed).")]
pub type SliceIterator<'a> = SomeipMsgsIterator<'a>;

/// Allows iterating over the someip messages in a udp or tcp payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeipMsgsIterator<'a> {
    slice: &'a [u8],
}

impl<'a> SomeipMsgsIterator<'a> {
    pub fn new(slice: &'a [u8]) -> SomeipMsgsIterator<'a> {
        SomeipMsgsIterator { slice }
    }
}

impl<'a> Iterator for SomeipMsgsIterator<'a> {
    type Item = Result<SomeipMsgSlice<'a>, err::SomeipSliceError>;

    fn next(&mut self) -> Option<Result<SomeipMsgSlice<'a>, err::SomeipSliceError>> {
        if !self.slice.is_empty() {
            // parse
            let result = SomeipMsgSlice::from_slice(self.slice);

            // move the slice depending on the result
            match &result {
                Err(_) => {
                    // error => move the slice to an len = 0 position so that the iterator ends
                    let len = self.slice.len();
                    self.slice = &self.slice[len..];
                }
                Ok(ref value) => {
                    // by the length just taken by the slice
                    self.slice = &self.slice[value.slice().len()..];
                }
            }

            // return parse result
            Some(result)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_generators::*;
    use proptest::prelude::*;
    use std::io::Write;

    proptest! {
        #[test]
        fn iterator(expected in proptest::collection::vec(someip_header_with_payload_any(), 0..5))
        {
            //serialize
            let mut buffer = Vec::new();
            for (message, payload) in expected.iter() {
                message.write_raw(&mut buffer).unwrap();
                buffer.write(&payload[..]).unwrap();
            }

            //read message with iterator
            let actual = SomeipMsgsIterator::new(&buffer[..]).fold(
                Vec::with_capacity(expected.len()),
                |mut acc, x| {
                    let x_unwraped = x.unwrap();
                    acc.push((
                        x_unwraped.to_header(),
                        {
                            let mut vec = Vec::with_capacity(x_unwraped.payload().len());
                            vec.extend_from_slice(x_unwraped.payload());
                            vec
                        })
                    );
                    acc
                });
            assert_eq!(expected, actual);
        }

    }

    proptest! {
        #[test]
        fn iterator_error(packet in someip_header_with_payload_any()) {
            //serialize
            let mut buffer = Vec::new();
            packet.0.write_raw(&mut buffer).unwrap();
            buffer.write(&packet.1[..]).unwrap();

            //generate iterator
            let len = buffer.len();
            let mut iterator = SomeipMsgsIterator::new(&buffer[..len-1]);

            //check that an error is generated
            use err::{*, SomeipSliceError::*};
            assert_eq!(iterator.next(), Some(Err(Len(LenError{
                required_len: len,
                len: len - 1,
                len_source: if len - 1 > SOMEIP_HEADER_LENGTH {
                    LenSource::SomeipHeaderLength
                } else {
                    LenSource::Slice
                },
                layer: if len - 1 > SOMEIP_HEADER_LENGTH {
                    Layer::SomeipPayload
                } else {
                    Layer::SomeipHeader
                }
            }))));
            assert_eq!(iterator.next(), None);
            assert_eq!(iterator.next(), None);
        }
    }
}
