use etherparse::*;
use rpcap::read::PcapReader;
use someip_parse::*;
use std::fs::File;
use std::io::BufReader;

fn main() -> Result<(), Error> {
    let pcap_path = std::env::args()
        .nth(1)
        .expect("Expected PCAP file as argument");

    let (_, mut reader) = PcapReader::new(BufReader::new(File::open(pcap_path)?))?;

    while let Some(packet) = reader.next()? {
        // parse ethernet to udp layer
        let eth_slice = if let Ok(e) = SlicedPacket::from_ethernet(packet.data) {
            e
        } else {
            // skip broken ethernet packets
            continue;
        };

        // check that the packet is an UDP packet
        use TransportSlice::*;
        let _ = if let Some(Udp(u)) = eth_slice.transport {
            u
        } else {
            // skip non udp packets
            continue;
        };

        // trying parsing some ip messages located in a udp payload
        for someip_message in SliceIterator::new(eth_slice.payload) {
            match someip_message {
                Ok(value) => {
                    if value.is_someip_sd() {
                        println!("someip service discovery packet");
                    } else {
                        println!(
                            "0x{:x} (service id: 0x{:x}, method/event id: 0x{:x})",
                            value.message_id(),
                            value.service_id(),
                            value.event_or_method_id()
                        );
                    }
                    println!("  with payload {:?}", value.payload())
                }
                Err(_) => {} //error reading a someip packet (based on size, protocol version value or message type value)
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
    PcapError(rpcap::PcapError),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<rpcap::PcapError> for Error {
    fn from(err: rpcap::PcapError) -> Error {
        Error::PcapError(err)
    }
}
