use super::*;

use proptest::prelude::*;

fn someip_header_message_type() -> impl Strategy<Value = MessageType> {
    prop_oneof![
        Just(MessageType::Request),
        Just(MessageType::RequestNoReturn),
        Just(MessageType::Notification),
        Just(MessageType::Response),
        Just(MessageType::Error),
    ]
}

prop_compose! {
    [pub] fn someip_header_any()(
        message_id in any::<u32>(),
        length in SOMEIP_LEN_OFFSET_TO_PAYLOAD..SOMEIP_MAX_PAYLOAD_LEN + 1,
        request_id in any::<u32>(),
        interface_version in any::<u8>(),
        message_type in someip_header_message_type(),
        message_type_tp in any::<bool>(),
        return_code in any::<u8>())
    -> SomeIpHeader
    {
        SomeIpHeader {
            message_id: message_id,
            length: length,
            request_id: request_id,
            interface_version: interface_version,
            message_type: message_type,
            message_type_tp: message_type_tp,
            return_code: return_code
        }
    }
}

prop_compose! {
    [pub] fn someip_header_with_payload_any()(
        payload_length in 0u32..1234 //limit it a bit so that not too much memory is allocated during testing
    )(
        message_id in any::<u32>(),
        length in proptest::strategy::Just(payload_length + SOMEIP_LEN_OFFSET_TO_PAYLOAD),
        request_id in any::<u32>(),
        interface_version in any::<u8>(),
        message_type in someip_header_message_type(),
        message_type_tp in any::<bool>(),
        return_code in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), payload_length as usize))
    -> (SomeIpHeader, Vec<u8>)
    {
        (SomeIpHeader {
            message_id: message_id,
            length: length,
            request_id: request_id,
            interface_version: interface_version,
            message_type: message_type,
            message_type_tp: message_type_tp,
            return_code: return_code
        }, payload)
    }
}