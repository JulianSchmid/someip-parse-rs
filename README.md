[![Crates.io](https://img.shields.io/crates/v/someip_parse.svg)](https://crates.io/crates/someip_parse)
[![docs.rs](https://docs.rs/someip_parse/badge.svg)](https://docs.rs/someip_parse)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/JulianSchmid/someip-parse-rs?branch=master&svg=true)](https://ci.appveyor.com/project/JulianSchmid/someip-parse-rs/branch/master)
[![Build Status](https://gitlab.com/julian.schmid/someip-parse-rs/badges/master/build.svg)](https://gitlab.com/julian.schmid/someip-parse-rs/commits/master)
[![Build Status](https://travis-ci.org/JulianSchmid/someip-parse-rs.svg?branch=master)](https://travis-ci.org/JulianSchmid/someip-parse-rs)
[![Coverage Status](https://codecov.io/gh/JulianSchmid/someip-parse-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/JulianSchmid/someip-parse-rs)

# someip_parse

A Rust library for parsing the SOME/IP network protocol (without payload interpretation).

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
someip_parse = "0.1.1"
```

## Example
[examples/print_messages.rs](examples/print_messages.rs):
```rust
use someip_parse;

use someip_parse::SliceIterator;

//trying parsing some ip messages located in a udp payload
for someip_message in SliceIterator::new(&udp_payload) {
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
* [AUTOSAR Foundation 1.5.0](https://www.autosar.org/standards/foundation/foundation-150/) \(contains SOMEIP Protocol Specification 1.5.0 & SOME/IP Service Discovery Protocol Specification 1.5.0\)
* [SOME/IP Protocol Specification 1.3.0](https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPProtocol.pdf)
* [SOME/IP Service Discovery Protocol Specification 1.3.0](https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-3/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf)

## License
Licensed under the BSD 3-Clause license. Please see the LICENSE file for more information.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be licensed as above, without any additional terms or conditions.
