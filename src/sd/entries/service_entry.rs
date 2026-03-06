use crate::err::{SdReadError, SdWriteError};
use crate::sd::entries::*;
use std::io::Write;

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

impl ServiceEntry {
    /// Serializes the service entry to bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut result = [0x00; ENTRY_LEN];

        result[0] = self._type.clone() as u8;
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

        let minor_version_bytes = self.minor_version.to_be_bytes();
        result[12] = minor_version_bytes[0];
        result[13] = minor_version_bytes[1];
        result[14] = minor_version_bytes[2];
        result[15] = minor_version_bytes[3];

        result
    }

    /// Deserializes a service entry from bytes.
    #[inline]
    pub fn from_bytes(
        entry_type: SdServiceEntryType,
        entry_bytes: [u8; ENTRY_LEN],
    ) -> Result<Self, SdReadError> {
        Ok(Self {
            _type: entry_type,
            index_first_option_run: entry_bytes[1],
            index_second_option_run: entry_bytes[2],
            number_of_options_1: entry_bytes[3] >> 4,
            number_of_options_2: entry_bytes[3] & 0x0F,
            service_id: u16::from_be_bytes([entry_bytes[4], entry_bytes[5]]),
            instance_id: u16::from_be_bytes([entry_bytes[6], entry_bytes[7]]),
            major_version: entry_bytes[8],
            ttl: u32::from_be_bytes([0x00, entry_bytes[9], entry_bytes[10], entry_bytes[11]]),
            minor_version: u32::from_be_bytes([
                entry_bytes[12],
                entry_bytes[13],
                entry_bytes[14],
                entry_bytes[15],
            ]),
        })
    }

    /// Writes the service entry to the given writer.
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
        fn to_bytes_from_bytes_roundtrip(service_entry in someip_sd_service_entry_any()) {
            // Serialize to bytes
            let bytes = service_entry.to_bytes();

            // Deserialize from bytes
            let deserialized = ServiceEntry::from_bytes(service_entry._type, bytes).unwrap();

            // Should be equal to original
            assert_eq!(service_entry, deserialized);
        }
    }

    proptest! {
        #[test]
        fn bytes_serialization_consistency(service_entry in someip_sd_service_entry_any()) {
            // ServiceEntry::to_bytes() should produce same result as SdEntry::to_bytes()
            let service_bytes = service_entry.to_bytes();
            let sd_entry_bytes = SdEntry::Service(service_entry.clone()).to_bytes();

            assert_eq!(service_bytes, sd_entry_bytes);
        }
    }
}
