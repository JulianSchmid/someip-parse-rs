use crate::err::{SdReadError, SdWriteError};
use crate::sd::entries::*;
use std::io::Write;

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

impl EventGroupEntry {
    /// Serializes the eventgroup entry to bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut result = [0x00; ENTRY_LEN];

        result[0] = self.entry_type.clone() as u8;
        result[1] = self.index_first_option_run;
        result[2] = self.index_second_option_run;
        result[3] = (self.number_of_options_1 << 4) | (self.number_of_options_2 & 0x0F);

        let service_id_bytes = self.service_id.to_be_bytes();
        result[4] = service_id_bytes[0];
        result[5] = service_id_bytes[1];

        let instance_id_bytes = self.instance_id.to_be_bytes();
        result[6] = instance_id_bytes[0];
        result[7] = instance_id_bytes[1];

        result[8] = self.major_version;

        let ttl_bytes = self.ttl.to_be_bytes();
        result[9] = ttl_bytes[1];
        result[10] = ttl_bytes[2];
        result[11] = ttl_bytes[3];

        // skip reserved byte, already initialized as 0x00
        if self.initial_data_requested {
            result[13] |= crate::sd::EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG;
        }
        result[13] |= self.counter & 0x0F;

        let eventgroup_id_bytes = self.eventgroup_id.to_be_bytes();
        result[14] = eventgroup_id_bytes[0];
        result[15] = eventgroup_id_bytes[1];

        result
    }

    /// Deserializes an eventgroup entry from bytes.
    #[inline]
    pub fn from_bytes(
        entry_type: EventGroupEntryType,
        entry_bytes: [u8; ENTRY_LEN],
    ) -> Result<Self, SdReadError> {
        Ok(Self {
            entry_type,
            index_first_option_run: entry_bytes[1],
            index_second_option_run: entry_bytes[2],
            number_of_options_1: entry_bytes[3] >> 4,
            number_of_options_2: entry_bytes[3] & 0x0F,
            service_id: u16::from_be_bytes([entry_bytes[4], entry_bytes[5]]),
            instance_id: u16::from_be_bytes([entry_bytes[6], entry_bytes[7]]),
            major_version: entry_bytes[8],
            ttl: u32::from_be_bytes([0x00, entry_bytes[9], entry_bytes[10], entry_bytes[11]]),
            // skip reserved byte, TODO: should this be verified to be 0x00 ?
            initial_data_requested: 0
                != entry_bytes[13] & crate::sd::EVENT_ENTRY_INITIAL_DATA_REQUESTED_FLAG,
            // ignore reserved bits, TODO: should this be verified to be 0x00 ?
            counter: entry_bytes[13] & 0x0F,
            eventgroup_id: u16::from_be_bytes([entry_bytes[14], entry_bytes[15]]),
        })
    }

    /// Writes the eventgroup entry to the given writer.
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdWriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_generators::*;
    use crate::sd::SdEntry;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn to_bytes_from_bytes_roundtrip(eventgroup_entry in someip_sd_eventgroup_entry_any()) {
            // Serialize to bytes
            let bytes = eventgroup_entry.to_bytes();

            // Deserialize from bytes
            let deserialized = EventGroupEntry::from_bytes(eventgroup_entry.entry_type, bytes).unwrap();

            // Should be equal to original
            assert_eq!(eventgroup_entry, deserialized);
        }
    }

    proptest! {
        #[test]
        fn bytes_serialization_consistency(eventgroup_entry in someip_sd_eventgroup_entry_any()) {
            // EventGroupEntry::to_bytes() should produce same result as SdEntry::to_bytes()
            let eventgroup_bytes = eventgroup_entry.to_bytes();
            let sd_entry_bytes = SdEntry::Eventgroup(eventgroup_entry.clone()).to_bytes();

            assert_eq!(eventgroup_bytes, sd_entry_bytes);
        }
    }
}
