use arrayvec::ArrayVec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationOption {
    /// Shall be set to `true` if the option can be discarded by the receiver.
    pub discardable: bool,
    // TODO DNS TXT / DNS-SD format
    pub configuration_string: ArrayVec<u8, { ConfigurationOption::MAX_CONFIGURATION_STRING_LEN }>,
}

impl ConfigurationOption {
    /// Maximum length of [`Self::configuration_string`] in bytes.
    ///
    /// SOME/IP Service Discovery is transported exclusively via UDP,
    /// so the SOME/IP UDP payload limit of 1400 bytes applies. After
    /// subtracting the SD header overhead (flags/reserved 4 + entries
    /// length 4 + options length 4 = 12 bytes) the options array can
    /// be at most [`super::MAX_OPTIONS_LEN`] = 1388 bytes.
    ///
    /// A single configuration option uses 4 bytes of wire overhead
    /// (2 length + 1 type + 1 reserved/flags), leaving at most
    /// `1388 - 4 = 1384` bytes for the configuration string.
    pub const MAX_CONFIGURATION_STRING_LEN: usize = super::MAX_OPTIONS_LEN_USIZE - 4;
}
