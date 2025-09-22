use crate::sd::*;

/// Flags at the start of a SOMEIP service discovery header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdHeaderFlags {
    pub reboot: bool,
    pub unicast: bool,
    pub explicit_initial_data_control: bool,
}

impl Default for SdHeaderFlags {
    fn default() -> Self {
        SdHeaderFlags {
            reboot: false,
            // set unicast & explicit_initial_data_control to true
            // by default as they have to be supported by current someip
            // implementations by default.
            unicast: true,
            explicit_initial_data_control: true,
        }
    }
}

impl SdHeaderFlags {
    /// Returns the first 4 bytes of an SOMEIP SD header.
    pub fn to_bytes(&self) -> [u8; 4] {
        [
            if self.reboot { REBOOT_FLAG } else { 0 }
                | if self.unicast { UNICAST_FLAG } else { 0 }
                | if self.explicit_initial_data_control {
                    EXPLICIT_INITIAL_DATA_CONTROL_FLAG
                } else {
                    0
                },
            0,
            0,
            0,
        ]
    }
}
