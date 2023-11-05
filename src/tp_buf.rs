use crate::*;

/// Buffer to reconstruct one SOMEIP TP packet stream without checks that the
/// message id & request id are the same for all packets (this has to be done by
/// the caller).
///
/// This buffer only reconstructs one TP stream and assumes that the user
/// only sends data with matching "SOMEIP message id" and matching "SOMEIP request id"
/// as well as matching sender to the buffer.
///
/// In case you want something that also automatically reconstructs multiple TP streams
/// and can handles multiple TP stream with differing request ids and message id's
/// gracefully use [`crate::TpPool`] instead.
///
/// # Example
///
/// ```
/// # #[derive(Debug)]
/// # enum Error {
/// #     TpReassemble(someip_parse::err::TpReassembleError),
/// #     Parse(someip_parse::err::SomeipSliceError),
/// # }
/// # impl From<someip_parse::err::TpReassembleError> for Error {
/// #     fn from(value: someip_parse::err::TpReassembleError) -> Self {
/// #         Error::TpReassemble(value)
/// #     }
/// # }
/// # impl From<someip_parse::err::SomeipSliceError> for Error {
/// #     fn from(value: someip_parse::err::SomeipSliceError) -> Self {
/// #         Error::Parse(value)
/// #     }
/// # }
/// #
/// # fn main() -> Result<(), Error> {
/// #
/// # use someip_parse::*;
/// # let pkt1_header = SomeIpHeader{
/// #     message_id: 1234,
/// #     length: 8 + 4 + 16,
/// #     request_id: 23,
/// #     interface_version: 1,
/// #     message_type: MessageType::Notification,
/// #     return_code: 0,
/// #     tp_header: {
/// #         let mut tp = TpHeader::new(true);
/// #         tp.set_offset(0).unwrap();
/// #         Some(tp)
/// #     },
/// # };
/// # let mut pkt1_bytes = Vec::with_capacity(SOMEIP_HEADER_LENGTH + 4 + 16);
/// # pkt1_bytes.extend_from_slice(&pkt1_header.base_to_bytes());
/// # pkt1_bytes.extend_from_slice(&pkt1_header.tp_header.as_ref().unwrap().to_bytes());
/// # pkt1_bytes.extend_from_slice(&[0;16]);
/// #
/// # let pkt2_header = SomeIpHeader{
/// #     message_id: 1234,
/// #     length: 8 + 4 + 16,
/// #     request_id: 23,
/// #     interface_version: 1,
/// #     message_type: MessageType::Notification,
/// #     return_code: 0,
/// #     tp_header: {
/// #         let mut tp = TpHeader::new(false);
/// #         tp.set_offset(16).unwrap();
/// #         Some(tp)
/// #     },
/// # };
/// # let mut pkt2_bytes = Vec::with_capacity(SOMEIP_HEADER_LENGTH + 4 + 16);
/// # pkt2_bytes.extend_from_slice(&pkt2_header.base_to_bytes());
/// # pkt2_bytes.extend_from_slice(&pkt2_header.tp_header.as_ref().unwrap().to_bytes());
/// # pkt2_bytes.extend_from_slice(&[0;16]);
/// #
/// #
/// use someip_parse::TpBuf;
/// use someip_parse::SomeipMsgSlice;
///
/// // setup the buffer
/// // (replace default if you have knowledge about the upper package sizes)
/// let mut buf = TpBuf::new(Default::default());
///
/// // feed the packets to the buffer
/// let pkt1_slice = SomeipMsgSlice::from_slice(&pkt1_bytes)?;
/// assert!(pkt1_slice.is_tp()); // only tp packets are allowed
/// buf.consume_tp(pkt1_slice.clone())?;
///
/// // incomplete packets will fail to finalize
/// assert_eq!(None, buf.try_finalize());
///
/// let pkt2_slice = SomeipMsgSlice::from_slice(&pkt2_bytes)?;
/// assert!(pkt2_slice.is_tp());
///
/// // user of the TpBuf have to ensure the "message id"
/// // and "request id" are the same for all packets
/// assert_eq!(pkt1_slice.message_id(), pkt2_slice.message_id());
/// assert_eq!(pkt1_slice.request_id(), pkt2_slice.request_id());
///
/// buf.consume_tp(pkt2_slice.clone())?;
///
/// // once the packet is completed you can access the resulting packet
/// // via "try_finalize"
/// let reassembled = buf.try_finalize().unwrap();
///
/// // the re-assembled packet will be provided as a non TP SOMEIP slice
/// assert_eq!(false, reassembled.is_tp());
/// assert_eq!(reassembled.message_id(), pkt1_slice.message_id());
/// println!("Reconstructed payload: {:?}", reassembled.payload());
///
/// // finally you can clear the buffer to re-use the
/// // memory for a new stream
/// buf.clear();
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TpBuf {
    /// Data buffer that should contain the SOMEIP header + reconstructed payload in the end.
    data: Vec<u8>,
    /// Contains the ranges filled with data.
    sections: Vec<TpRange>,
    /// Set to the extended end size.
    end: Option<u32>,
    /// TP config
    config: TpBufConfig,
}

impl TpBuf {
    pub fn new(config: TpBufConfig) -> TpBuf {
        TpBuf {
            data: Vec::with_capacity(
                SOMEIP_HEADER_LENGTH + config.tp_buffer_start_payload_alloc_len,
            ),
            sections: Vec::with_capacity(4),
            end: None,
            config,
        }
    }

    /// Reset buffer to starting state.
    pub fn clear(&mut self) {
        self.data.clear();
        self.sections.clear();
        self.end = None;
    }

    /// Consume a TP SOMEIP slice (caller must ensure that `someip_slice.is_tp()` is `true`).
    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
    pub fn consume_tp(
        &mut self,
        someip_slice: SomeipMsgSlice,
    ) -> Result<(), err::TpReassembleError> {
        use err::TpReassembleError::*;

        assert!(someip_slice.is_tp());

        // validate lengths
        let tp_header = someip_slice.tp_header().unwrap();
        let payload = someip_slice.payload();

        // should be guranteed by config constructor
        debug_assert!(self.config.tp_max_payload_len() <= u32::MAX - (SOMEIP_HEADER_LENGTH as u32));
        if (self.config.tp_max_payload_len() < tp_header.offset())
            || ((self.config.tp_max_payload_len() - tp_header.offset()) as usize) < payload.len()
        {
            return Err(SegmentTooBig {
                offset: tp_header.offset(),
                payload_len: payload.len(),
                max: self.config.tp_max_payload_len(),
            });
        }

        // validate that the payload len is a multiple of 16 in case it is not the end
        if tp_header.more_segment && 0 != payload.len() & 0b1111 {
            return Err(UnalignedTpPayloadLen {
                offset: tp_header.offset(),
                payload_len: payload.len(),
            });
        }

        let end = tp_header.offset() + payload.len() as u32;

        // check the section is not already ended
        if let Some(previous_end) = self.end {
            // either the end is after the current position
            if previous_end < end || ((false == tp_header.more_segment) && end != previous_end) {
                return Err(ConflictingEnd {
                    previous_end,
                    conflicting_end: end,
                });
            }
        }

        // get enough memory to store a SOMEIP header + tp reassembled payload
        let required_len = SOMEIP_HEADER_LENGTH + (tp_header.offset() as usize) + payload.len();
        if self.data.len() < required_len {
            if self
                .data
                .try_reserve(required_len - self.data.len())
                .is_err()
            {
                return Err(AllocationFailure { len: required_len });
            }
            // TODO replace with something faster that does no zero init?
            self.data.resize(required_len, 0);
        }

        if 0 == tp_header.offset() {
            // copy header
            self.data[..SOMEIP_HEADER_LENGTH]
                .clone_from_slice(&someip_slice.slice()[..SOMEIP_HEADER_LENGTH]);
            // remove TP flag
            self.data[4 * 3 + 2] &= 0b1101_1111;
        }

        // insert new data
        let data_offset = SOMEIP_HEADER_LENGTH + (tp_header.offset() as usize);
        self.data[data_offset..data_offset + payload.len()].clone_from_slice(payload);

        // update sections
        let mut new_section = TpRange {
            start: tp_header.offset(),
            end: tp_header.offset() + (payload.len() as u32),
        };
        // merge overlapping section into new section and remove them
        self.sections.retain(|it| -> bool {
            if let Some(merged) = new_section.merge(*it) {
                new_section = merged;
                false
            } else {
                true
            }
        });
        self.sections.push(new_section);

        // set end
        if false == tp_header.more_segment {
            self.end = Some(tp_header.offset() + payload.len() as u32);
        }

        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.end.is_some() && 1 == self.sections.len() && 0 == self.sections[0].start
    }

    /// Try finalizing the reconstructed TP packet and return a reference to it
    /// if the stream reconstruction was completed.
    pub fn try_finalize(&mut self) -> Option<SomeipMsgSlice<'_>> {
        if false == self.is_complete() {
            return None;
        }
        // reinject length into fake header
        let section = self.sections[0];
        {
            let len_be = (section.end + 8).to_be_bytes();
            let len_insert = &mut self.data[4..8];
            len_insert[0] = len_be[0];
            len_insert[1] = len_be[1];
            len_insert[2] = len_be[2];
            len_insert[3] = len_be[3];
        }
        Some(SomeipMsgSlice::from_slice(&self.data).unwrap())
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn debug_clone_eq() {
        let buf = TpBuf::new(Default::default());
        let _ = format!("{:?}", buf);
        assert_eq!(buf, buf.clone());
        assert_eq!(buf.cmp(&buf), core::cmp::Ordering::Equal);
        assert_eq!(buf.partial_cmp(&buf), Some(core::cmp::Ordering::Equal));

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            buf.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            buf.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    struct TestPacket {
        offset: u32,
        more_segments: bool,
        payload: Vec<u8>,
    }

    impl TestPacket {
        fn new(offset: u32, more_segments: bool, payload: &[u8]) -> TestPacket {
            TestPacket {
                offset,
                more_segments,
                payload: payload.iter().copied().collect(),
            }
        }

        fn send_to_buffer(&self, buffer: &mut TpBuf) -> Result<(), err::TpReassembleError> {
            let packet = self.to_vec();
            let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            buffer.consume_tp(slice)
        }

        fn to_vec(&self) -> Vec<u8> {
            let header = SomeipHeader {
                message_id: 1234,
                length: 8 + 4 + self.payload.len() as u32,
                request_id: 23,
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

        fn result_header(payload_length: u32) -> SomeipHeader {
            SomeipHeader {
                message_id: 1234,
                length: payload_length + 8,
                request_id: 23,
                interface_version: 1,
                message_type: MessageType::Notification,
                return_code: 0,
                tp_header: None,
            }
        }
    }

    #[test]
    fn new() {
        let actual = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());
        assert!(actual.data.is_empty());
        assert!(actual.sections.is_empty());
        assert!(actual.end.is_none());
        assert_eq!(1024, actual.config.tp_buffer_start_payload_alloc_len);
        assert_eq!(2048, actual.config.tp_max_payload_len());
    }

    #[test]
    fn clear() {
        let mut actual = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());

        actual.data.push(1);
        actual.sections.push(TpRange { start: 2, end: 3 });
        actual.end = Some(123);

        actual.clear();

        assert!(actual.data.is_empty());
        assert!(actual.sections.is_empty());
        assert!(actual.end.is_none());
        assert_eq!(1024, actual.config.tp_buffer_start_payload_alloc_len);
        assert_eq!(2048, actual.config.tp_max_payload_len());
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

        // normal reconstruction
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());

            let actions = [
                (false, TestPacket::new(0, true, &sequence(0,16))),
                (false, TestPacket::new(16, true, &sequence(16,32))),
                (true, TestPacket::new(48, false, &sequence(48,16))),
            ];
            for a in actions {
                a.1.send_to_buffer(&mut buffer).unwrap();
                assert_eq!(a.0, buffer.is_complete());
            }
            let result = buffer.try_finalize().unwrap();
            assert_eq!(result.to_header(), TestPacket::result_header(16*4));
            assert_eq!(result.payload(), &sequence(0,16*4));
        }

        // overlapping reconstruction
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());

            let actions = [
                (false, TestPacket::new(0, true, &sequence(0,16))),
                // will be overwritten
                (false, TestPacket::new(32, true, &sequence(0,16))),
                // overwrites
                (false, TestPacket::new(32, false, &sequence(32,16))),
                // completes
                (true, TestPacket::new(16, true, &sequence(16,16))),
            ];
            for a in actions {
                a.1.send_to_buffer(&mut buffer).unwrap();
                assert_eq!(a.0, buffer.is_complete());
            }
            let result = buffer.try_finalize().unwrap();
            assert_eq!(result.to_header(), TestPacket::result_header(16*3));
            assert_eq!(result.payload(), &sequence(0,16*3));
        }

        // reverse order
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());

            let actions = [
                (false, TestPacket::new(48, false, &sequence(48,16))),
                (false, TestPacket::new(16, true, &sequence(16,32))),
                (true, TestPacket::new(0, true, &sequence(0,16))),
            ];
            for a in actions {
                a.1.send_to_buffer(&mut buffer).unwrap();
                assert_eq!(a.0, buffer.is_complete());
            }
            let result = buffer.try_finalize().unwrap();
            assert_eq!(result.to_header(), TestPacket::result_header(16*4));
            assert_eq!(result.payload(), &sequence(0,16*4));
        }

        // error tp packet bigger then max (offset only)
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(32, 32).unwrap());
            assert_eq!(
                SegmentTooBig { offset: 32 + 16, payload_len: 16, max: 32 },
                TestPacket::new(32 + 16, true, &sequence(0,16)).send_to_buffer(&mut buffer).unwrap_err()
            );
        }

        // error tp packet bigger then max (offset + payload)
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(32, 32).unwrap());
            assert_eq!(
                SegmentTooBig { offset: 16, payload_len: 32, max: 32 },
                TestPacket::new(16, true, &sequence(0,32)).send_to_buffer(&mut buffer).unwrap_err()
            );
        }

        // check packets that fill exactly to the max work
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(32, 32).unwrap());
            let test_packet = TestPacket::new(16, false, &sequence(0,16));

            let packet = test_packet.to_vec();
            let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            
            assert_eq!(Ok(()), buffer.consume_tp(slice));
        }

        // packets conflicting with previously seen end
        for bad_offset in 1..16 {
            let mut buffer = TpBuf::new(TpBufConfig::new(16*100, 16*100).unwrap());
            let test_packet = TestPacket::new(48, true, &sequence(0,32 + bad_offset));

            let packet = test_packet.to_vec();
            let slice = SomeipMsgSlice::from_slice(&packet).unwrap();
            
            assert_eq!(
                UnalignedTpPayloadLen { offset: 48, payload_len: 32 + bad_offset },
                buffer.consume_tp(slice).unwrap_err()
            );
        }

        // test that conflicting ends trigger errors (received a different end)
        {
            let mut buffer = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());

            // setup an end (aka no more segements)
            TestPacket::new(32, false, &sequence(32,16)).send_to_buffer(&mut buffer).unwrap();

            // test that a "non end" going over the end package triggers an error
            assert_eq!(
                ConflictingEnd { previous_end: 32 + 16, conflicting_end: 48 + 16 },
                TestPacket::new(48, true, &sequence(48,16)).send_to_buffer(&mut buffer).unwrap_err()
            );

            // test that a new end at an earlier position triggers an error
            assert_eq!(
                ConflictingEnd { previous_end: 32 + 16, conflicting_end: 16 + 16 },
                TestPacket::new(16, false, &sequence(16,16)).send_to_buffer(&mut buffer).unwrap_err()
            );
        }
    }

    #[test]
    fn try_finalize() {
        let mut buffer = TpBuf::new(TpBufConfig::new(1024, 2048).unwrap());

        // not ended
        assert_eq!(buffer.try_finalize(), None);
        TestPacket::new(0, true, &sequence(0, 16))
            .send_to_buffer(&mut buffer)
            .unwrap();
        assert_eq!(buffer.try_finalize(), None);

        // ended
        TestPacket::new(16, false, &sequence(16, 16))
            .send_to_buffer(&mut buffer)
            .unwrap();
        let result = buffer.try_finalize().unwrap();
        assert_eq!(result.to_header(), TestPacket::result_header(16 * 2));
        assert_eq!(result.payload(), &sequence(0, 16 * 2));
    }
}
