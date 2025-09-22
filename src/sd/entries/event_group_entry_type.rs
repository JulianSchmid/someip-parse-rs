#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventGroupEntryType {
    Subscribe = 0x06,
    SubscribeAck = 0x07,
}
