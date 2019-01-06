# SOMEIP Parse
[![Build Status][build_badge]][build_status]
[![Code Coverage][coverage_badge]][coverage_report]
[![pipeline status][gitlab_badge]][gitlab_link]

A Rust library for parsing the SOME/IP network protocol (without payload interpretation).

## Usage

First, add the following to your `Cargo.toml`:

```toml
[dependencies]
someip_parse = "0.1.1"
```

Next, add this to your crate root:

```rust
extern crate someip_parse;
```

## Example
[examples/print_messages.rs](examples/print_messages.rs):
```Rust
//trying parsing some ip messages located in a udp payload
for someip_message in SliceIterator::new(value.payload) {
    match someip_message {
        Ok(value) => {
            if value.is_someip_sd() {
                println!("someip service discovery packet");
            } else {
                println!("0x{:x} (service id: 0x{:x}, method/event id: 0x{:x})", 
                         value.message_id(), 
                         value.service_id(),
                         value.event_or_method_id());
            }
            println!("  with payload {:?}", value.payload())
        },
        Err(_) => {} //error reading a someip packet (based on size, protocol version value or message type value)
    }
}
```

## Todo
* Example how to serialize someip packets
* SOMEIP Service Discovery Message Parsing

## References
* (AUTOSAR Foundation 1.5.0)[https://www.autosar.org/standards/foundation/foundation-150/] \(contains SOMEIP Protocol Specification 1.5.0 & SOME/IP Service Discovery Protocol Specification 1.5.0\) 
* (SOME/IP Protocol Specification 1.3.0)[https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPProtocol.pdf]
* (SOME/IP Service Discovery Protocol Specification 1.3.0)[https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf]

[build_badge]: https://travis-ci.org/JulianSchmid/someip-parse-rs.svg?branch=master
[build_status]: https://travis-ci.org/JulianSchmid/someip-parse-rs
[coverage_badge]: https://codecov.io/gh/JulianSchmid/someip-parse-rs/branch/master/graph/badge.svg
[coverage_report]: https://codecov.io/gh/JulianSchmid/someip-parse-rs/branch/master
[gitlab_badge]: https://gitlab.com/julian.schmid/someip-parse-rs/badges/master/pipeline.svg
[gitlab_link]: https://gitlab.com/julian.schmid/someip-parse-rs/commits/master
