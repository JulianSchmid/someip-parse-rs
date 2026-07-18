use crate::sd::*;

/// Flags at the start of a SOMEIP service discovery header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdHeaderFlags {
    pub reboot: bool,
    pub unicast: bool,
    /// Legacy flag removed from the wire format in AUTOSAR R21-11.
    ///
    /// The value is retained for source compatibility and when inspecting
    /// older messages, but serializers always write this reserved bit as 0.
    pub explicit_initial_data_control: bool,
}

impl Default for SdHeaderFlags {
    fn default() -> Self {
        SdHeaderFlags {
            reboot: false,
            // Current SOME/IP-SD implementations shall support unicast.
            unicast: true,
            explicit_initial_data_control: false,
        }
    }
}

impl SdHeaderFlags {
    /// Returns the first 4 bytes of an SOMEIP SD header.
    pub fn to_bytes(&self) -> [u8; 4] {
        [
            if self.reboot { REBOOT_FLAG } else { 0 } | if self.unicast { UNICAST_FLAG } else { 0 },
            0,
            0,
            0,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_flags_are_not_serialized() {
        let flags = SdHeaderFlags {
            reboot: true,
            unicast: true,
            explicit_initial_data_control: true,
        };
        assert_eq!(flags.to_bytes(), [REBOOT_FLAG | UNICAST_FLAG, 0, 0, 0]);
        assert!(!SdHeaderFlags::default().explicit_initial_data_control);
    }
}
