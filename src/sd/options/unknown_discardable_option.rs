/// An unknown option that is flagged as "discardable" and
/// should be ignored by the receiver if not supported.
///
/// This option is only intended to be used for reading,
/// to ensure the option indices are still matching. In case
/// this option is passed to a write function an error will be
/// triggered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownDiscardableOption {
    pub length: u16,
    pub option_type: u8,
}
