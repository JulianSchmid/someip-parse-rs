use crate::sd::entries::*;

/// SOMEIP service discovery entry for a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceEntry {
    pub _type: SdServiceEntryType,
    pub index_first_option_run: u8,
    pub index_second_option_run: u8,
    pub number_of_options_1: u8,
    pub number_of_options_2: u8,
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: u32,
    pub minor_version: u32,
}
