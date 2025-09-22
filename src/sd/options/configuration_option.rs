#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationOption {
    /// Shall be set to `true` if the option can be discarded by the receiver.
    pub discardable: bool,
    // TODO DNS TXT / DNS-SD format
    pub configuration_string: Vec<u8>,
}
