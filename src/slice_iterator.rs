use crate::*;

/// Allows iterating over the someip messages in a udp or tcp payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceIterator<'a> {
    slice: &'a [u8],
}

impl<'a> SliceIterator<'a> {
    pub fn new(slice: &'a [u8]) -> SliceIterator<'a> {
        SliceIterator { slice }
    }
}

impl<'a> Iterator for SliceIterator<'a> {
    type Item = Result<SomeipMsgSlice<'a>, err::ReadError>;

    fn next(&mut self) -> Option<Result<SomeipMsgSlice<'a>, err::ReadError>> {
        if !self.slice.is_empty() {
            //parse
            let result = SomeipMsgSlice::from_slice(self.slice);

            //move the slice depending on the result
            match &result {
                Err(_) => {
                    //error => move the slice to an len = 0 position so that the iterator ends
                    let len = self.slice.len();
                    self.slice = &self.slice[len..];
                }
                Ok(ref value) => {
                    //by the length just taken by the slice
                    self.slice = &self.slice[value.slice().len()..];
                }
            }

            //return parse result
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
    use assert_matches::*;
    use proptest::prelude::*;

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
            let actual = SliceIterator::new(&buffer[..]).fold(
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
            let mut iterator = SliceIterator::new(&buffer[..len-1]);

            //check that an error is generated
            assert_matches!(iterator.next(), Some(Err(err::ReadError::UnexpectedEndOfSlice(_))));
            assert_matches!(iterator.next(), None);
            assert_matches!(iterator.next(), None);
        }
    }
}
