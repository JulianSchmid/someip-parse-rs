use crate::*;

/// Configuration of a TP buffers maximum allowed size and initial allocated buffer size.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TpBufConfig {
    /// Number of bytes that should be allocated to store payload
    /// when a new [`TpBuf`] gets created.
    pub tp_buffer_start_payload_alloc_len: usize,

    /// Maximum allowed payload length (in bytes) of the final reconstructed packet.
    tp_max_payload_len: u32,
}

impl TpBufConfig {
    /// Maximum representable payload len in a TP packet.
    ///
    /// This is determined by the maximum value the length
    /// field in the SOMEIP header can take - 8 bytes
    pub const MAX_TP_PAYLOAD_LEN: u32 = u32::MAX - (SOMEIP_HEADER_LENGTH as u32);

    /// Maximum allowed payload length (in bytes) of the final reconstructed packet.
    #[inline]
    pub fn tp_max_payload_len(&self) -> u32 {
        self.tp_max_payload_len
    }

    /// Creates a new config with the given initial allocated and maximum allowed payload size.
    ///
    /// # Example
    ///
    /// As long as you don't set the max_payload_len to more then
    /// `TpBufConfig::MAX_TP_PAYLOAD_LEN` (0xFFFFFFFF - 16):
    ///
    /// ```
    /// use someip_parse::TpBufConfig;
    ///
    /// let config = TpBufConfig::new(
    ///     // start alloc size
    ///     1024,
    ///     // maximum allowed size
    ///     // (if you have knowledge about the maximum message size,
    ///     // insert that here and above)
    ///     TpBufConfig::MAX_TP_PAYLOAD_LEN
    /// ).unwrap();
    /// ```
    ///
    /// construction will only fail if you set an upper lenght greater
    /// then `TpBufConfig::MAX_TP_PAYLOAD_LEN`:
    ///
    /// ```
    /// use someip_parse::{TpBufConfig, err::TpBufConfigError::*};
    ///
    /// assert_eq!(
    ///     TpBufConfig::new(1024, TpBufConfig::MAX_TP_PAYLOAD_LEN + 1),
    ///     Err(MaxPayloadLenTooBig{
    ///         allowed_max: TpBufConfig::MAX_TP_PAYLOAD_LEN,
    ///         actual: TpBufConfig::MAX_TP_PAYLOAD_LEN + 1,
    ///     })
    /// );
    /// ```
    pub fn new(
        tp_buffer_start_payload_alloc_len: usize,
        tp_max_payload_len: u32,
    ) -> Result<TpBufConfig, err::TpBufConfigError> {
        if tp_max_payload_len > Self::MAX_TP_PAYLOAD_LEN {
            use err::TpBufConfigError::*;
            Err(MaxPayloadLenTooBig {
                allowed_max: Self::MAX_TP_PAYLOAD_LEN,
                actual: tp_max_payload_len,
            })
        } else {
            Ok(TpBufConfig {
                tp_buffer_start_payload_alloc_len,
                tp_max_payload_len,
            })
        }
    }
}

impl core::default::Default for TpBufConfig {
    fn default() -> Self {
        Self {
            tp_buffer_start_payload_alloc_len: 0x40000,
            tp_max_payload_len: TpBufConfig::MAX_TP_PAYLOAD_LEN,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        let config = TpBufConfig::new(1024, 1024).unwrap();
        let _ = format!("{:?}", config);
        assert_eq!(config, config.clone());
        assert_eq!(config.cmp(&config), core::cmp::Ordering::Equal);
        assert_eq!(
            config.partial_cmp(&config),
            Some(core::cmp::Ordering::Equal)
        );

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            config.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            config.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn default() {
        let actual: TpBufConfig = Default::default();
        assert_eq!(0x40000, actual.tp_buffer_start_payload_alloc_len);
        assert_eq!(TpBufConfig::MAX_TP_PAYLOAD_LEN, actual.tp_max_payload_len);
    }

    #[test]
    fn new() {
        {
            let actual = TpBufConfig::new(
                // start alloc size
                1024,
                // maximum allowed size
                // (if you have knowledge about the maximum message size,
                // insert that here and above)
                TpBufConfig::MAX_TP_PAYLOAD_LEN,
            )
            .unwrap();
            assert_eq!(actual.tp_buffer_start_payload_alloc_len, 1024);
            assert_eq!(actual.tp_max_payload_len(), TpBufConfig::MAX_TP_PAYLOAD_LEN);
        }

        use crate::err::TpBufConfigError::*;
        assert_eq!(
            TpBufConfig::new(1024, TpBufConfig::MAX_TP_PAYLOAD_LEN + 1),
            Err(MaxPayloadLenTooBig {
                allowed_max: TpBufConfig::MAX_TP_PAYLOAD_LEN,
                actual: TpBufConfig::MAX_TP_PAYLOAD_LEN + 1,
            })
        );
    }
}
