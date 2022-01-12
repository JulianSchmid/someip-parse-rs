extern crate clap;
use clap::{Arg, App};

extern crate etherparse;
use self::etherparse::*;

extern crate rpcap;
use self::rpcap::read::PcapReader;

use std::io::BufReader;
use std::fs::File;

extern crate someip_parse;
use someip_parse::*;


fn main() {

    let matches = App::new("print someip message ids (also service id & method/event id)")
                      .author("Julian Schmid")
                      .about("")
                          .arg(Arg::with_name("INPUT")
                               .help("input pcap file")
                               .required(true)
                               .index(1))
                      .get_matches();

    match read(matches.value_of("INPUT").unwrap()) {
        Ok(_) => {},
        Err(err) => {
            println!("Error: {:?}", err);
        }
    }
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

fn read(in_file_path: &str) -> Result<(),Error> {
    let mut reader = PcapReader::new(BufReader::new(File::open(in_file_path)?))?;

    while let Some(packet) = reader.next()? {
        let sliced = SlicedPacket::from_ethernet(packet.data);

        match sliced {
            Err(_) => {},
            Ok(value) => {
                use TransportSlice::*;

                match value.transport {
                    Some(Udp(_)) => {

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
                    },
                    //ignore tcp or packets without transport layer
                    _ => {}
                }
            }
        }
    }
    Ok(())
}