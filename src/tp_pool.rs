use crate::*;
use core::hash::Hash;
use std::collections::HashMap;

/// Pool of buffers to reconstruct multiple SOMEIP TP packet streams in
/// parallel (re-uses buffers to minimize allocations).
///
/// # Issues to keep in mind:
///
/// If you use the [`TpPool`] in an untrusted environment an attacker could
/// cause an "out of memory error" by opening up multiple parallel TP streams,
/// never ending them and filling them up with as much data as possible.
///
/// Mitigations will hopefully be offered in future versions but if you have
/// take care right now you can still use [`TpBuf`] directly and implement the
/// connection handling and mitigation yourself.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TpPool<ChannelId: Hash + Eq + PartialEq + Clone + Sized> {
    /// Currently reconstructing TP streams.
    active: HashMap<(ChannelId, u32), TpBuf>,

    /// Buffers that have finished receiving data and can be re-used.
    finished: Vec<TpBuf>,

    /// Configuration that should be used for new buffers.
    buf_config: TpBufConfig,
}

impl<ChannelId: Hash + Eq + PartialEq + Clone + Sized> TpPool<ChannelId> {
    pub fn new(buf_config: TpBufConfig) -> TpPool<ChannelId> {
        TpPool {
            active: HashMap::new(),
            finished: Vec::new(),
            buf_config,
        }
    }

    pub fn consume<'a: 'c, 'b: 'c, 'c: 'a + 'b>(
        &'a mut self,
        id: ChannelId,
        someip_slice: SomeipMsgSlice<'b>,
    ) -> Result<Option<SomeipMsgSlice<'c>>, err::TpReassembleError> {
        if someip_slice.is_tp() {
            use std::collections::hash_map::Entry::*;
            match self.active.entry((id, someip_slice.request_id())) {
                Occupied(mut o) => {
                    // stream already known consume the data
                    o.get_mut().consume_tp(someip_slice)?;

                    // check if the stream is complete
                    if o.get().is_complete() {
                        // if done move the buffer to the finished list and return the result
                        self.finished.push(o.remove());
                        Ok(Some(
                            self.finished.last_mut().unwrap().try_finalize().unwrap(),
                        ))
                    } else {
                        Ok(None)
                    }
                }
                Vacant(v) => {
                    // new stream get a finished or new buffer
                    let mut buf = if let Some(mut b) = self.finished.pop() {
                        b.clear();
                        b
                    } else {
                        TpBuf::new(self.buf_config.clone())
                    };

                    // consume the data
                    buf.consume_tp(someip_slice)?;

                    // check if the stream is complete
                    if buf.is_complete() {
                        // if done move the buffer to the finished list and return the result
                        self.finished.push(buf);
                        Ok(Some(
                            self.finished.last_mut().unwrap().try_finalize().unwrap(),
                        ))
                    } else {
                        // stream is not yet done, keep it around until done
                        v.insert(buf);
                        Ok(None)
                    }
                }
            }
        } else {
            Ok(Some(someip_slice))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPacket {
        request_id: u32,
        offset: u32,
        more_segments: bool,
        payload: Vec<u8>,
    }

    impl TestPacket {
        fn new(request_id: u32, offset: u32, more_segments: bool, payload: &[u8]) -> TestPacket {
            TestPacket {
                request_id,
                offset,
                more_segments,
                payload: payload.iter().copied().collect(),
            }
        }

        fn to_vec(&self) -> Vec<u8> {
            let header = SomeIpHeader {
                message_id: 1234,
                length: 8 + 4 + self.payload.len() as u32,
                request_id: self.request_id,
                interface_version: 1,
                message_type: MessageType::Notification,
                return_code: 0,
                tp_header: {
                    let mut tp = TpHeader::new(self.more_segments);
                    tp.set_offset(self.offset).unwrap();
                    Some(tp)
                },
            };
            let mut result = Vec::with_capacity(SOMEIP_HEADER_LENGTH + 4 + self.payload.len());
            result.extend_from_slice(&header.base_to_bytes());
            result.extend_from_slice(&header.tp_header.as_ref().unwrap().to_bytes());
            result.extend_from_slice(&self.payload);
            result
        }

        fn result_header(&self, payload_length: u32) -> SomeIpHeader {
            SomeIpHeader {
                message_id: 1234,
                length: payload_length + 8,
                request_id: self.request_id,
                interface_version: 1,
                message_type: MessageType::Notification,
                return_code: 0,
                tp_header: None,
            }
        }
    }

    /// Returns a u8 vec counting up from "start" until len is reached (truncating bits greater then u8).
    fn sequence(start: usize, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in start..start + len {
            result.push((i & 0xff) as u8);
        }
        result
    }

    #[rustfmt::skip]
    #[test]
    fn consume() {
        use err::TpReassembleError::*;

        // simple packet forwarding (without TP effect)
        {
            // build a non tp packet
            let header = SomeIpHeader {
                message_id: 1234,
                length: 8 + 8 as u32,
                request_id: 234,
                interface_version: 1,
                message_type: MessageType::Notification,
                return_code: 0,
                // no tp header
                tp_header: None,
            };
            let mut result = Vec::with_capacity(SOMEIP_HEADER_LENGTH + 8);
            result.extend_from_slice(&header.base_to_bytes());
            result.extend_from_slice(&[0;8]);
            
            let someip_slice = SomeipMsgSlice::from_slice(&result).unwrap();

            let mut pool: TpPool<()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());
            let result = pool.consume((), someip_slice.clone()).unwrap();
            assert_eq!(Some(someip_slice), result);
        }

        // normal reconstruction (without additional id)
        {
            let mut pool: TpPool<()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            let actions = [
                // start two streams in parallel
                (TestPacket::new(1, 0, true, &sequence(1,16)), None),
                (TestPacket::new(2, 0, true, &sequence(2,32)), None),
                // stream 1 ends
                (TestPacket::new(1, 16, false, &sequence(1 + 16,16)), Some(sequence(1,32))),
                // stream 3 which imidiatly ends
                (TestPacket::new(3, 0, false, &sequence(3,16*4)), Some(sequence(3, 16*4))),
                // end stream 2
                (TestPacket::new(2, 32, false, &sequence(32 + 2,16*4)), Some(sequence(2, 16*6))),
            ];
            for a in actions {
                let packet = a.0.to_vec();
                let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
                let result = pool.consume((), slice).unwrap();
                if let Some(expected_payload) = a.1 {
                    let msg = result.unwrap();
                    assert_eq!(msg.to_header(), a.0.result_header(expected_payload.len() as u32));
                    assert_eq!(msg.payload(), expected_payload);
                } else {
                    assert!(result.is_none());
                }
            }
        }

        // normal reconstruction (with additional id)
        {
            let mut pool: TpPool<u32> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            // all actions have the same request id have differing id's
            let actions = [
                // start two streams in parallel
                (123, TestPacket::new(1, 0, true, &sequence(1,16)), None),
                (234, TestPacket::new(1, 0, true, &sequence(2,32)), None),
                // stream 1 ends
                (123, TestPacket::new(1, 16, false, &sequence(1 + 16,16)), Some(sequence(1,32))),
                // stream 3 which imidiatly ends
                (345, TestPacket::new(1, 0, false, &sequence(3,16*4)), Some(sequence(3, 16*4))),
                // end stream 2
                (234, TestPacket::new(1, 32, false, &sequence(32 + 2,16*4)), Some(sequence(2, 16*6))),
            ];
            for a in actions {
                let packet = a.1.to_vec();
                let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
                let result = pool.consume(a.0.clone(), slice).unwrap();
                if let Some(expected_payload) = a.2 {
                    let msg = result.unwrap();
                    assert_eq!(msg.to_header(), a.1.result_header(expected_payload.len() as u32));
                    assert_eq!(msg.payload(), expected_payload);
                } else {
                    assert!(result.is_none());
                }
            }
        }

        // error during reconstruction (at start)
        {
            let mut pool: TpPool<()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            // should trigger an error as the payload is not a multiple of 1
            let packet = TestPacket::new(1, 0, true, &sequence(1,15)).to_vec();
            let someip_slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            assert_eq!(
                pool.consume((), someip_slice).unwrap_err(),
                UnalignedTpPayloadLen { offset: 0, payload_len: 15 }
            );
        }

        // error during reconstruction (after start)
        {
            let mut pool: TpPool<()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            {
                let packet = TestPacket::new(1, 0, true, &sequence(1,16)).to_vec();
                let someip_slice = SomeipMsgSlice::from_slice(&packet).unwrap();
                pool.consume((), someip_slice).unwrap();
            }

            // should trigger an error as the payload is not a multiple of 1
            let packet = TestPacket::new(1, 16, true, &sequence(1,15)).to_vec();
            let someip_slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            assert_eq!(
                pool.consume((), someip_slice).unwrap_err(),
                UnalignedTpPayloadLen { offset: 16, payload_len: 15 }
            );
        }

    }
}
