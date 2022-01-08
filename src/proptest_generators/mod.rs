use super::sd::*;
use super::*;

use proptest::option;
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
    pub fn someip_tp_any()(
        offset in 0..(std::u32::MAX / 16),
        more_segments in any::<bool>())
    -> TpHeader
    {
        TpHeader::with_offset(offset*16, more_segments).unwrap()
    }
}

prop_compose! {
    pub fn someip_header_any()(
        message_id in any::<u32>(),
        length in SOMEIP_LEN_OFFSET_TO_PAYLOAD..SOMEIP_MAX_PAYLOAD_LEN + 1,
        request_id in any::<u32>(),
        interface_version in any::<u8>(),
        message_type in someip_header_message_type(),
        return_code in any::<u8>(),
        tp_header in option::of(someip_tp_any()))
    -> SomeIpHeader
    {
        SomeIpHeader {
            message_id,
            length,
            request_id,
            interface_version,
            message_type,
            return_code,
            tp_header
        }
    }
}

prop_compose! {
    pub fn someip_header_with_payload_any()(
        payload_length in 0u32..1234 //limit it a bit so that not too much memory is allocated during testing
    )(
        message_id in any::<u32>(),
        length in proptest::strategy::Just(payload_length + SOMEIP_LEN_OFFSET_TO_PAYLOAD),
        request_id in any::<u32>(),
        interface_version in any::<u8>(),
        message_type in someip_header_message_type(),
        return_code in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), payload_length as usize))
    -> (SomeIpHeader, Vec<u8>)
    {
        (SomeIpHeader {
            message_id,
            length,
            request_id,
            interface_version,
            message_type,
            return_code,
            tp_header: None
        }, payload)
    }
}

prop_compose! {
    pub fn sd_header_any()(
        reboot in any::<bool>(),
        unicast in any::<bool>(),
        explicit_initial_data_control in any::<bool>(),
        entries in prop::collection::vec(someip_sd_entry_any(), 0..100),
        options in prop::collection::vec(someip_sd_option_any(), 0..100),
        )
    -> sd::SdHeader
    {
        let mut header = sd::SdHeader::new(reboot, entries, options);
        header.flags.unicast = unicast;
        header.flags.explicit_initial_data_control = explicit_initial_data_control;
        header
    }
}

fn someip_sd_eventgroup_entry_type_any() -> impl Strategy<Value = SdEventGroupEntryType> {
    prop_oneof![
        Just(SdEventGroupEntryType::Subscribe),
        Just(SdEventGroupEntryType::SubscribeAck),
    ]
}

prop_compose! {
    pub fn someip_sd_eventgroup_entry_any()(
            _type in someip_sd_eventgroup_entry_type_any(),
            index_first_option_run in any::<u8>(),
            index_second_option_run in any::<u8>(),
            number_of_options_1 in 0..0x0Fu8,
            number_of_options_2 in 0..0x0Fu8,
            service_id in any::<u16>(),
            instance_id in any::<u16>(),
            major_version in any::<u8>(),
            ttl in 0..0x00FF_FFFFu32,
            initial_data_requested in any::<bool>(),
            counter in 0..0x0Fu8,
            eventgroup_id in any::<u16>(),
        )
    -> sd::SdEntry
    {
        sd::SdEntry::new_eventgroup(
            _type,
            index_first_option_run,
            index_second_option_run,
            number_of_options_1,
            number_of_options_2,
            service_id,
            instance_id,
            major_version,
            ttl,
            initial_data_requested,
            counter,
            eventgroup_id,
        ).unwrap()
    }
}

fn someip_sd_service_entry_type_any() -> impl Strategy<Value = SdServiceEntryType> {
    prop_oneof![
        Just(SdServiceEntryType::FindService),
        Just(SdServiceEntryType::OfferService),
    ]
}

prop_compose! {
    pub fn someip_sd_service_entry_any()(
            _type in someip_sd_service_entry_type_any(),
            index_first_option_run in any::<u8>(),
            index_second_option_run in any::<u8>(),
            number_of_options_1 in 0..0x0Fu8,
            number_of_options_2 in 0..0x0Fu8,
            service_id in any::<u16>(),
            instance_id in any::<u16>(),
            major_version in any::<u8>(),
            ttl in 0..0x00FF_FFFFu32,
            minor_version in any::<u32>(),
        )
    -> sd::SdEntry
    {
        sd::SdEntry::new_service_entry(
            _type,
            index_first_option_run,
            index_second_option_run,
            number_of_options_1,
            number_of_options_2,
            service_id,
            instance_id,
            major_version,
            ttl,
            minor_version,
        ).unwrap()
    }
}

pub fn someip_sd_entry_any() -> impl Strategy<Value = sd::SdEntry> {
    prop_oneof![
        someip_sd_eventgroup_entry_any(),
        someip_sd_service_entry_any(),
    ]
}

prop_compose! {
    pub fn someip_sd_transport_protocol_generic_any()(
            generic in 0x12..u8::MAX, // 0x12 skips tcp and udp
        )
    -> TransportProtocol
    {
        TransportProtocol::Generic(generic)
    }
}

pub fn someip_sd_transport_protocol_any() -> impl Strategy<Value = TransportProtocol> {
    prop_oneof![
        Just(TransportProtocol::Tcp),
        Just(TransportProtocol::Udp),
        someip_sd_transport_protocol_generic_any(),
    ]
}

prop_compose! {
    pub fn someip_sd_option_configuration_any()(
        discardable in any::<bool>(),
        configuration_string in any::<Vec<u8>>(),
    ) -> sd::SdOption {
        sd::SdOption::Configuration { discardable, configuration_string }
    }
}

prop_compose! {
    pub fn someip_sd_option_load_balancing_any()(
        discardable in any::<bool>(),
        priority in any::<u16>(),
        weight in any::<u16>(),
    ) -> sd::SdOption {
        sd::SdOption::LoadBalancing { discardable, priority, weight }
    }
}

prop_compose! {
    pub fn someip_sd_option_ipv4_endpoint_any()(
            ipv4_address in any::<[u8;4]>(),
            transport_protocol in someip_sd_transport_protocol_any(),
            transport_protocol_number in any::<u16>(),
        )
    -> sd::SdOption
    {
        sd::SdOption::Ipv4Endpoint { ipv4_address, transport_protocol, transport_protocol_number }
    }
}

prop_compose! {
    pub fn someip_sd_option_ipv6_endpoint_any()(
            ipv6_address in any::<[u8;16]>(),
            transport_protocol in someip_sd_transport_protocol_any(),
            transport_protocol_number in any::<u16>(),
        )
    -> sd::SdOption
    {
        sd::SdOption::Ipv6Endpoint { ipv6_address, transport_protocol, transport_protocol_number }
    }
}

prop_compose! {
    pub fn someip_sd_option_ipv4_multicast_any()(
            ipv4_address in any::<[u8;4]>(),
            transport_protocol in someip_sd_transport_protocol_any(),
            transport_protocol_number in any::<u16>(),
        )
    -> sd::SdOption
    {
        sd::SdOption::Ipv4Multicast { ipv4_address, transport_protocol, transport_protocol_number }
    }
}

prop_compose! {
    pub fn someip_sd_option_ipv6_multicast_any()(
            ipv6_address in any::<[u8;16]>(),
            transport_protocol in someip_sd_transport_protocol_any(),
            transport_protocol_number in any::<u16>(),
        )
    -> sd::SdOption
    {
        sd::SdOption::Ipv6Multicast { ipv6_address, transport_protocol, transport_protocol_number }
    }
}

prop_compose! {
    pub fn someip_sd_option_ipv4_sd_endpoint_any()(
            ipv4_address in any::<[u8;4]>(),
            transport_protocol in someip_sd_transport_protocol_any(),
            transport_protocol_number in any::<u16>(),
        )
    -> sd::SdOption
    {
        sd::SdOption::Ipv4SdEndpoint { ipv4_address, transport_protocol, transport_protocol_number }
    }
}

prop_compose! {
    pub fn someip_sd_option_ipv6_sd_endpoint_any()(
            ipv6_address in any::<[u8;16]>(),
            transport_protocol in someip_sd_transport_protocol_any(),
            transport_protocol_number in any::<u16>(),
        )
    -> sd::SdOption
    {
        sd::SdOption::Ipv6SdEndpoint { ipv6_address, transport_protocol, transport_protocol_number }
    }
}

pub fn someip_sd_option_any() -> impl Strategy<Value = sd::SdOption> {
    prop_oneof![
        someip_sd_option_configuration_any(),
        someip_sd_option_load_balancing_any(),
        someip_sd_option_ipv4_endpoint_any(),
        someip_sd_option_ipv6_endpoint_any(),
        someip_sd_option_ipv4_multicast_any(),
        someip_sd_option_ipv6_multicast_any(),
        someip_sd_option_ipv4_sd_endpoint_any(),
        someip_sd_option_ipv6_sd_endpoint_any(),
    ]
}
