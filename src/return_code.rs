///Return code contained in a SOME/IP header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReturnCode {
    Ok,                    // 0x00
    NotOk,                 // 0x01
    UnknownService,        // 0x02
    UnknownMethod,         // 0x03
    NotReady,              // 0x04
    NotReachable,          // 0x05
    Timeout,               // 0x06
    WrongProtocolVersion,  // 0x07
    WrongInterfaceVersion, // 0x08
    MalformedMessage,      // 0x09
    WrongMessageType,      // 0x0a
    Generic(u8),
    InterfaceError(u8),
}

impl From<ReturnCode> for u8 {
    fn from(r: ReturnCode) -> u8 {
        use ReturnCode::*;
        match r {
            Ok => 0x00,
            NotOk => 0x01,
            UnknownService => 0x02,
            UnknownMethod => 0x03,
            NotReady => 0x04,
            NotReachable => 0x05,
            Timeout => 0x06,
            WrongProtocolVersion => 0x07,
            WrongInterfaceVersion => 0x08,
            MalformedMessage => 0x09,
            WrongMessageType => 0x0a,
            Generic(value) => value,
            InterfaceError(value) => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn into_u8(generic_error in 0x0bu8..0x20,
                   interface_error in 0x20u8..0x5F)
        {
            use crate::ReturnCode::*;
            let values = [
                (Ok, 0x00),
                (NotOk, 0x01),
                (UnknownService, 0x02),
                (UnknownMethod, 0x03),
                (NotReady, 0x04),
                (NotReachable, 0x05),
                (Timeout, 0x06),
                (WrongProtocolVersion, 0x07),
                (WrongInterfaceVersion, 0x08),
                (MalformedMessage, 0x09),
                (WrongMessageType, 0x0a),
                (Generic(generic_error), generic_error),
                (InterfaceError(interface_error), interface_error),
            ];
            for (ref input, ref expected) in values.iter() {
                let result: u8 = (*input).into();
                assert_eq!(*expected, result);
            }
        }
    }
}
