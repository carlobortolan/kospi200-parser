#![forbid(unsafe_code)]

use std::env;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

struct PcapHeader {
    version_major: u16,
    version_minor: u16,
    snaplen: u32,
    network: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <pcap_file>", args[0]);
        std::process::exit(1);
    }

    let file = File::open(&args[1])?;
    let mut reader = BufReader::new(file);

    let mut global_header = [0u8; 24];

    reader.read_exact(&mut global_header)?;

    let magic = u32::from_le_bytes([
        global_header[0],
        global_header[1],
        global_header[2],
        global_header[3],
    ]);

    if magic != 0xa1b2c3d4 {
        return Err(Box::new(Error::new(
            ErrorKind::InvalidData,
            "unsupported pcap format",
        )));
    }

    let header = PcapHeader {
        version_major: u16::from_le_bytes([global_header[4], global_header[5]]),
        version_minor: u16::from_le_bytes([global_header[6], global_header[7]]),
        snaplen: u32::from_le_bytes([
            global_header[16],
            global_header[17],
            global_header[18],
            global_header[19],
        ]),
        network: u32::from_le_bytes([
            global_header[20],
            global_header[21],
            global_header[22],
            global_header[23],
        ]),
    };

    println!(
        "pcap version {}.{} snaplen={} network={}",
        header.version_major, header.version_minor, header.snaplen, header.network
    );

    let mut packet_header = [0u8; 16];

    loop {
        match reader.read_exact(&mut packet_header) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Box::new(e)),
        }

        let timestamp_seconds = u32::from_le_bytes([
            packet_header[0],
            packet_header[1],
            packet_header[2],
            packet_header[3],
        ]);

        let timestamp_fraction = u32::from_le_bytes([
            packet_header[4],
            packet_header[5],
            packet_header[6],
            packet_header[7],
        ]);

        let captured_length = u32::from_le_bytes([
            packet_header[8],
            packet_header[9],
            packet_header[10],
            packet_header[11],
        ]);

        let original_length = u32::from_le_bytes([
            packet_header[12],
            packet_header[13],
            packet_header[14],
            packet_header[15],
        ]);

        println!(
            "packet timestamp={}.{:06} captured={} original={}",
            timestamp_seconds, timestamp_fraction, captured_length, original_length
        );

        let mut packet_data = vec![0u8; captured_length as usize];

        reader.read_exact(&mut packet_data)?;

        println!("read {} bytes", packet_data.len());
    }

    Ok(())
}
