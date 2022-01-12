extern crate clap;
use clap::{Arg, App};

extern crate etherparse;
use self::etherparse::*;

extern crate rpcap;
use self::rpcap::read::PcapReader;

use std::io::BufReader;
use std::fs::File;
use std::collections::HashMap;

extern crate someip_parse;
use someip_parse::*;

extern crate time;
use time::Instant;

fn main() {

    let matches = App::new("count the some ip messages by message id")
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

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Stats {
    total_payload_size: usize,
    ipv4: usize,
    ipv6: usize,
    udp: usize,
    tcp: usize,
    someip_message_count: HashMap<u32,usize>,
    someip_message_ok: usize,
    someip_message_err: usize,
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

    let in_file_metadata = std::fs::metadata(&in_file_path).unwrap();
    let mut stats: Stats = Default::default();

    let start = Instant::now();
    let mut reader = PcapReader::new(BufReader::new(File::open(in_file_path)?))?;

    while let Some(packet) = reader.next()? {
        stats.total_payload_size += packet.data.len();

        let sliced = SlicedPacket::from_ethernet(packet.data);

        match sliced {
            Err(_) => {},
            Ok(value) => {
                use TransportSlice::*;
                use InternetSlice::*;

                match &value.ip {
                    Some(Ipv4(_)) => {
                        stats.ipv4 += 1;
                    },
                    Some(Ipv6(_,_)) => {
                        stats.ipv6 += 1;
                    },
                    None => {}
                }

                match value.transport {
                    Some(Udp(_)) => {
                        stats.udp += 1;

                        //try parsing some ip message
                        for someip_message in SliceIterator::new(value.payload) {
                            match someip_message {
                                Ok(value) => {
                                    stats.someip_message_ok += 1;
                                    let count = stats.someip_message_count.entry(value.message_id()).or_insert(0);
                                    *count += 1;
                                },
                                Err(_) => {
                                    stats.someip_message_err += 1;
                                }
                            }
                        }
                    },
                    Some(Tcp(_)) => {
                        stats.tcp += 1;
                    },
                    None => {}
                }
            }
        }
    }

    let duration = start.elapsed();
    let duration_secs = duration.as_seconds_f64();
    //let gigabits_per_sec = in_file_metadata.len() as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_file = in_file_metadata.len() as f64 / duration_secs /  1_000_000_000.0;
    //let gigabits_per_sec_payload = stats.total_payload_size as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_packets = stats.total_payload_size as f64 / duration_secs / 1_000_000_000.0;

    println!("{}", in_file_path);
    println!("{:?}", stats);
    println!("{:?}", duration);
    println!("{:?}GB/s (file)", gigabytes_per_sec_file);
    println!("{:?}GB/s (packets data)", gigabytes_per_sec_packets);

    for (key, value) in &stats.someip_message_count {
        println!("message id {:x}: {}", key, value);
    }

    Ok(())
}