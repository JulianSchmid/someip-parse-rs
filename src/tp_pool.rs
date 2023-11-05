use crate::*;
use std::collections::HashMap;
use core::hash::Hash;

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
        someip_slice: SomeIpHeaderSlice<'b>,
    ) -> Result<Option<SomeIpHeaderSlice<'c>>, err::ReassembleError> {
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
                        Ok(Some(self.finished.last_mut().unwrap().try_finalize().unwrap()))
                    } else {
                        Ok(None)
                    }
                },
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
                        Ok(Some(self.finished.last_mut().unwrap().try_finalize().unwrap()))
                    } else {
                        // stream is not yet done, keep it around until done
                        v.insert(buf);
                        Ok(None)
                    }
                },
            }
        } else {
            Ok(Some(someip_slice))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
