[![Crates.io](https://img.shields.io/crates/v/someip_parse.svg)](https://crates.io/crates/someip_parse)
[![docs.rs](https://docs.rs/someip_parse/badge.svg)](https://docs.rs/someip_parse)
[![Build Status Github](https://github.com/JulianSchmid/someip-parse-rs/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/JulianSchmid/someip-parse-rs/actions/workflows/main.yml)
[![Coverage Status](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/JulianSchmid/09a90a219054946fd93359b73002ed28/raw/someip-parse-coverage.json)](https://github.com/JulianSchmid/someip-parse-rs/actions/workflows/coverage.yml)

# someip_parse

A Rust library for parsing the SOME/IP network protocol (without payload interpretation).

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
someip_parse = "0.7.2"
```

## Feature Flags

* `std` (default): Enables `std::io` read/write helpers and the `TpPool`
  helper.
* `alloc`: Enables heap-using APIs such as `TpBuf` and
  `sd::SdHeader::to_bytes_vec` (automatically enabled by `std`).

The crate can be used in `no_std` environments with
`default-features = false`. Add the `alloc` feature if heap allocation is
available.

## Example
[examples/print_messages.rs](examples/print_messages.rs):
```rust
use someip_parse::SomeipMsgsIterator;

//trying parsing some ip messages located in a udp payload
for someip_message in SomeipMsgsIterator::new(&udp_payload) {
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

## References
* [AUTOSAR Foundation](https://www.autosar.org/standards/foundation) \(contains SOMEIP Protocol Specification & SOME/IP Service Discovery Protocol Specification\)
* [SOME/IP Protocol Specification R22-11](https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_PRS_SOMEIPProtocol.pdf)
* [SOME/IP Service Discovery Protocol Specification R22-11](https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf)

## License
Licensed under either of Apache License, Version 2.0 or MIT license at your option. The corresponding license texts can be found in the LICENSE-APACHE file and the LICENSE-MIT file.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be licensed as above, without any additional terms or conditions.
