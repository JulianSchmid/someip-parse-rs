#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdEventGroupEntryType {
    Subscribe = 0x06,
    SubscribeAck = 0x07,
}
