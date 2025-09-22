use crate::sd::entries::*;

/// SOMEIP service discovery entry for an eventgroup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventGroupEntry {
    pub entry_type: EventGroupEntryType,
    pub index_first_option_run: u8,
    pub index_second_option_run: u8,
    pub number_of_options_1: u8,
    pub number_of_options_2: u8,
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: u32,
    /// True if initial data shall be sent by server
    pub initial_data_requested: bool,
    /// distinguish identical subscribe eventgroups of the same subscriber
    /// 4 bit
    pub counter: u8,
    pub eventgroup_id: u16,
}
