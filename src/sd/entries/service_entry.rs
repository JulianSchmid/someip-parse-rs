#[cfg(feature = "std")]
use crate::err::SdWriteError;
use crate::sd::entries::*;
#[cfg(feature = "std")]
use std::io::Write;

/// SOMEIP service discovery entry for a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceEntry {
    pub entry_type: SdServiceEntryType,
    pub start_index_options_1: u8,
    pub start_index_options_2: u8,
    pub number_of_options_1: U4,
    pub number_of_options_2: U4,
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: U24,
    pub minor_version: u32,
}

impl ServiceEntry {
    /// Serializes the service entry to bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut result = [0x00; ENTRY_LEN];

        result[0] = self.entry_type as u8;
        result[1] = self.start_index_options_1;
        result[2] = self.start_index_options_2;
        result[3] = ((self.number_of_options_1.value() & 0x0F) << 4)
            | (self.number_of_options_2.value() & 0x0F);

        let service_id_bytes = self.service_id.to_be_bytes();
        result[4] = service_id_bytes[0];
        result[5] = service_id_bytes[1];

        let instance_id_bytes = self.instance_id.to_be_bytes();
        result[6] = instance_id_bytes[0];
        result[7] = instance_id_bytes[1];

        result[8] = self.major_version;

        let ttl_bytes = self.ttl.value().to_be_bytes();
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

    /// Writes the service entry to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn write<T: Write>(&self, writer: &mut T) -> Result<(), SdWriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::proptest_generators::*;
    use crate::sd::{SdEntry, SdEntrySlice};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn to_bytes_from_bytes_roundtrip(service_entry in someip_sd_service_entry_any()) {
            let bytes = service_entry.to_bytes();
            assert_eq!(
                SdEntry::Service(service_entry),
                SdEntrySlice::from_slice(&bytes).unwrap().to_owned()
            );
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
