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
        let sliced = SlicedPacket::from_ethernet(&packet.data);

        match sliced {
            Err(_) => {},
            Ok(value) => {
                use TransportSlice::*;

                match value.transport {
                    Some(Udp(_)) => {

                        //try parsing some ip message
                        for someip_message in SliceIterator::new(value.payload) {
                            match someip_message {
                                Ok(value) => {
                                    println!("{} (service id: {}, method/event id: {})", 
                                             value.message_id(), 
                                             value.service_id(),
                                             value.event_or_method_id());
                                },
                                Err(_) => {}
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