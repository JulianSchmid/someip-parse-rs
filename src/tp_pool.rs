use crate::*;
use core::hash::Hash;
use std::collections::HashMap;

/// Pool of buffers to reconstruct multiple SOMEIP TP packet streams in
/// parallel (re-uses buffers to minimize allocations).
///
/// # This implementation is NOT safe against "Out of Memory" attacks
///
/// If you use the [`TpPool`] in an untrusted environment an attacker could
/// cause an "out of memory error" by opening up multiple parallel TP streams,
/// never ending them and filling them up with as much data as possible.
///
/// Mitigations will hopefully be offered in future versions but if you have
/// take care right now you can still use [`TpBuf`] directly and implement the
/// connection handling and mitigation yourself.
#[derive(Debug, Clone)]
pub struct TpPool<ChannelId, Timestamp>
where
    ChannelId: Hash + Eq + PartialEq + Clone + Sized,
    Timestamp: Sized + core::fmt::Debug + Clone,
{
    /// Currently reconstructing TP streams.
    active: HashMap<(ChannelId, u32), (TpBuf, Timestamp)>,

    /// Buffers that have finished receiving data and can be re-used.
    finished: Vec<TpBuf>,

    /// Configuration that should be used for new buffers.
    buf_config: TpBufConfig,
}

impl<ChannelId, Timestamp: Sized> TpPool<ChannelId, Timestamp>
where
    ChannelId: Hash + Eq + PartialEq + Clone + Sized,
    Timestamp: core::fmt::Debug + Clone + Sized,
{
    pub fn new(buf_config: TpBufConfig) -> TpPool<ChannelId, Timestamp> {
        TpPool {
            active: HashMap::new(),
            finished: Vec::new(),
            buf_config,
        }
    }

    pub fn with_capacity(
        buf_config: TpBufConfig,
        initial_bufs_count: usize,
    ) -> TpPool<ChannelId, Timestamp> {
        TpPool {
            active: HashMap::with_capacity(initial_bufs_count),
            finished: {
                let mut v = Vec::with_capacity(initial_bufs_count);
                for _ in 0..initial_bufs_count {
                    v.push(TpBuf::new(buf_config.clone()));
                }
                v
            },
            buf_config,
        }
    }

    /// Reserves the given number as buffers.
    pub fn reserve(&mut self, additional: usize) {
        self.finished.reserve(additional);
        for _ in 0..additional {
            self.finished.push(TpBuf::new(self.buf_config.clone()));
        }
        self.active.reserve(self.finished.len());
    }

    #[inline]
    pub fn active_bufs(&self) -> &HashMap<(ChannelId, u32), (TpBuf, Timestamp)> {
        &self.active
    }

    #[inline]
    pub fn finished_bufs(&self) -> &Vec<TpBuf> {
        &self.finished
    }

    #[inline]
    pub fn buf_config(&self) -> &TpBufConfig {
        &self.buf_config
    }

    pub fn consume<'a: 'c, 'b: 'c, 'c: 'a + 'b>(
        &'a mut self,
        id: ChannelId,
        timestamp: Timestamp,
        someip_slice: SomeipMsgSlice<'b>,
    ) -> Result<Option<SomeipMsgSlice<'c>>, err::TpReassembleError> {
        if someip_slice.is_tp() {
            use std::collections::hash_map::Entry::*;
            match self.active.entry((id, someip_slice.request_id())) {
                Occupied(mut o) => {
                    // stream already known consume the data & update the timestamp
                    o.get_mut().0.consume_tp(someip_slice)?;
                    o.get_mut().1 = timestamp;

                    // check if the stream is complete
                    if o.get().0.is_complete() {
                        // if done move the buffer to the finished list and return the result
                        self.finished.push(o.remove().0);
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
                        v.insert((buf, timestamp));
                        Ok(None)
                    }
                }
            }
        } else {
            Ok(Some(someip_slice))
        }
    }

    /// Retains only the elements specified by the predicate.
    pub fn retain<F>(&mut self, f: F)
    where
        F: Fn(&Timestamp) -> bool,
    {
        // check if any entry has to be removed
        if self.active.iter().any(|(_, (_, t))| false == f(t)) {
            self.active = self
                .active
                .drain()
                .filter_map(|(k, v)| {
                    if f(&v.1) {
                        Some((k, v))
                    } else {
                        self.finished.push(v.0);
                        None
                    }
                })
                .collect();
        }
    }
}

impl<ChannelId, Timestamp: Sized> PartialEq for TpPool<ChannelId, Timestamp>
where
    ChannelId: Hash + Eq + PartialEq + Clone + Sized,
    Timestamp: core::fmt::Debug + Clone + Sized + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.active == other.active
            && self.finished == other.finished
            && self.buf_config == other.buf_config
    }
}

impl<ChannelId, Timestamp: Sized> Eq for TpPool<ChannelId, Timestamp>
where
    ChannelId: Hash + Eq + PartialEq + Clone + Sized,
    Timestamp: core::fmt::Debug + Clone + Sized + PartialEq + Eq,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        let pool: TpPool<(), ()> = TpPool::new(Default::default());
        let _ = format!("{:?}", pool);
        assert_eq!(pool, pool.clone());
        assert_eq!(pool.buf_config(), &TpBufConfig::default());
    }

    #[test]
    fn with_capacity() {
        let pool = TpPool::<(), ()>::with_capacity(Default::default(), 3);
        assert_eq!(3, pool.finished_bufs().len());
        assert!(pool.active.capacity() >= 3);
    }

    #[test]
    fn reserve() {
        let mut pool = TpPool::<(), ()>::new(Default::default());
        pool.reserve(2);
        assert_eq!(2, pool.finished_bufs().len());
        assert!(pool.active.capacity() >= 2);
        pool.reserve(3);
        assert_eq!(5, pool.finished_bufs().len());
        assert!(pool.active.capacity() >= 5);
    }

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
            let header = SomeipHeader {
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

        fn result_header(&self, payload_length: u32) -> SomeipHeader {
            SomeipHeader {
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
            let header = SomeipHeader {
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

            let mut pool: TpPool<(), ()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());
            let result = pool.consume((), (), someip_slice.clone()).unwrap();
            assert_eq!(Some(someip_slice), result);
        }

        // normal reconstruction (without additional id)
        {
            let mut pool: TpPool<(), ()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            let actions = [
                // start two streams in parallel
                (TestPacket::new(1, 0, true, &sequence(1,16)), None, 1, 0),
                (TestPacket::new(2, 0, true, &sequence(2,32)), None, 2, 0),
                // stream 1 ends
                (TestPacket::new(1, 16, false, &sequence(1 + 16,16)), Some(sequence(1,32)), 1, 1),
                // stream 3 which imidiatly ends
                (TestPacket::new(3, 0, false, &sequence(3,16*4)), Some(sequence(3, 16*4)), 1, 1),
                // end stream 2
                (TestPacket::new(2, 32, true, &sequence(32 + 2,16*4)), None, 1, 1),
                (TestPacket::new(2, 16*6, false, &sequence(16*6 + 2,16*3)), Some(sequence(2, 16*9)), 0, 2),
            ];
            for a in actions {
                let packet = a.0.to_vec();
                let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
                let result = pool.consume((), (), slice).unwrap();
                if let Some(expected_payload) = a.1 {
                    let msg = result.unwrap();
                    assert_eq!(msg.to_header(), a.0.result_header(expected_payload.len() as u32));
                    assert_eq!(msg.payload(), expected_payload);
                } else {
                    assert!(result.is_none());
                }
                assert_eq!(a.2, pool.active_bufs().len());
                assert_eq!(a.3, pool.finished_bufs().len());
            }
        }

        // normal reconstruction (with additional id)
        {
            let mut pool: TpPool<u32, ()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

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
                (234, TestPacket::new(1, 32, true, &sequence(32 + 2,16*4)), None),
                (234, TestPacket::new(1, 16*6, false, &sequence(16*6 + 2,16*3)), Some(sequence(2, 16*9))),
            ];
            for a in actions {
                let packet = a.1.to_vec();
                let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
                let result = pool.consume(a.0.clone(), (), slice).unwrap();
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
            let mut pool: TpPool<(), ()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            // should trigger an error as the payload is not a multiple of 1
            let packet = TestPacket::new(1, 0, true, &sequence(1,15)).to_vec();
            let someip_slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            assert_eq!(
                pool.consume((), (), someip_slice).unwrap_err(),
                UnalignedTpPayloadLen { offset: 0, payload_len: 15 }
            );
        }

        // error during reconstruction (after start)
        {
            let mut pool: TpPool<(), ()> = TpPool::new(TpBufConfig::new(1024, 2048).unwrap());

            {
                let packet = TestPacket::new(1, 0, true, &sequence(1,16)).to_vec();
                let someip_slice = SomeipMsgSlice::from_slice(&packet).unwrap();
                pool.consume((), (), someip_slice).unwrap();
            }

            // should trigger an error as the payload is not a multiple of 1
            let packet = TestPacket::new(1, 16, true, &sequence(1,15)).to_vec();
            let someip_slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            assert_eq!(
                pool.consume((), (), someip_slice).unwrap_err(),
                UnalignedTpPayloadLen { offset: 16, payload_len: 15 }
            );
        }

    }

    #[test]
    fn retain() {
        let mut pool: TpPool<u16, u32> = TpPool::new(Default::default());
        // request id 1, channel id 2, timestamp 123
        {
            let packet = TestPacket::new(1, 0, true, &sequence(1, 16)).to_vec();
            let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            let result = pool.consume(2u16, 123u32, slice).unwrap();
            assert!(result.is_none());
            assert_eq!(123, pool.active_bufs().get(&(2u16, 1u32)).unwrap().1);
        }
        // request id 1, channel id 2, timestamp 124
        {
            let packet = TestPacket::new(1, 16, true, &sequence(16, 16)).to_vec();
            let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            let result = pool.consume(2u16, 124u32, slice).unwrap();
            assert!(result.is_none());
            // check the timestamp was overwritten by the newer packet
            assert_eq!(124, pool.active_bufs().get(&(2u16, 1u32)).unwrap().1);
        }
        // request id 1, channel id 3, timestamp 125
        {
            let packet = TestPacket::new(1, 16, true, &sequence(16, 16)).to_vec();
            let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            let result = pool.consume(3u16, 125u32, slice).unwrap();
            assert!(result.is_none());
        }

        // discard streams with a timestamp smaller then 125
        pool.retain(|timestamp| *timestamp >= 125);

        assert_eq!(125, pool.active_bufs().get(&(3u16, 1u32)).unwrap().1);
    }
}
