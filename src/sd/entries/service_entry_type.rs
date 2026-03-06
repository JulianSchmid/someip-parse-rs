#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdServiceEntryType {
    FindService = 0x00,
    OfferService = 0x01,
}
