use etherparse::*;
use someip_parse::*;
use rpcap::read::PcapReader;
use std::collections::HashMap;
use std::{fs::File, io::BufReader, time::Instant};

/// Count the SOMEIP messages by message id.
fn main() -> Result<(), Error> {

    let pcap_path = std::env::args().nth(1).expect("Expected PCAP file as argument");

    let in_file_metadata = std::fs::metadata(&pcap_path).unwrap();
    let mut stats: Stats = Default::default();

    let start = Instant::now();
    let (_, mut reader) = PcapReader::new(BufReader::new(File::open(&pcap_path)?))?;

    while let Some(packet) = reader.next()? {
        stats.total_payload_size += packet.data.len();

        // parse ethernet to udp layer
        let eth_slice = if let Ok(e) = SlicedPacket::from_ethernet(packet.data) {
            e
        } else {
            // skip broken ethernet packets
            continue;
        };

        // count based on ip versions
        use InternetSlice::*;
        match eth_slice.ip {
            Some(Ipv4(_, _)) => {
                stats.ipv4 += 1;
            }
            Some(Ipv6(_, _)) => {
                stats.ipv6 += 1;
            }
            None => {}
        }

        // count transport layers
        use TransportSlice::*;
        match eth_slice.transport {
            Some(Udp(_)) => {
                stats.udp += 1;

                //try parsing some ip message
                for someip_message in SliceIterator::new(eth_slice.payload) {
                    match someip_message {
                        Ok(value) => {
                            stats.someip_message_ok += 1;
                            let count = stats
                                .someip_message_count
                                .entry(value.message_id())
                                .or_insert(0);
                            *count += 1;
                        }
                        Err(_) => {
                            stats.someip_message_err += 1;
                        }
                    }
                }
            }
            Some(Tcp(_)) => {
                stats.tcp += 1;
            }
            Some(_) => {},
            None => {}
        }
    }

    let duration = start.elapsed();
    let duration_secs = duration.as_secs_f64();
    //let gigabits_per_sec = in_file_metadata.len() as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_file = in_file_metadata.len() as f64 / duration_secs / 1_000_000_000.0;
    //let gigabits_per_sec_payload = stats.total_payload_size as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_packets =
        stats.total_payload_size as f64 / duration_secs / 1_000_000_000.0;

    println!("{}", pcap_path);
    println!("{:?}", stats);
    println!("{:?}", duration);
    println!("{:?}GB/s (file)", gigabytes_per_sec_file);
    println!("{:?}GB/s (packets data)", gigabytes_per_sec_packets);

    for (key, value) in &stats.someip_message_count {
        println!("message id {:x}: {}", key, value);
    }

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Stats {
    total_payload_size: usize,
    ipv4: usize,
    ipv6: usize,
    udp: usize,
    tcp: usize,
    someip_message_count: HashMap<u32, usize>,
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
