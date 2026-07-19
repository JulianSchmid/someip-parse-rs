/// The type of a SOMEIP service discovery eventgroup entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EventGroupEntryType {
    /// Subscription to an eventgroup (if `ttl > 0`) or
    /// stop of subscription (if `ttl = 0`).
    SubscribeOrStop = 0x06,
    /// Acknowledgment of a subscription request (if `ttl > 0`)
    /// or negative acknowledgment (if `ttl = 0`).
    SubscribeAckOrNack = 0x07,
}
