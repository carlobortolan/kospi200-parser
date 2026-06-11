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

struct PcapContext {
    swapped: bool,
}

fn read_u16(data: &[u8], swapped: bool) -> u16 {
    let value = u16::from_ne_bytes([data[0], data[1]]);
    if swapped { value.swap_bytes() } else { value }
}

fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    if swapped { value.swap_bytes() } else { value }
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

    let magic = u32::from_ne_bytes([
        global_header[0],
        global_header[1],
        global_header[2],
        global_header[3],
    ]);

    let swapped = match magic {
        0xa1b2c3d4 => false,
        0xd4c3b2a1 => true,
        _ => {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "unsupported pcap magic",
            )));
        }
    };

    let ctx = PcapContext { swapped };

    let header = PcapHeader {
        version_major: read_u16(&global_header[4..6], swapped),
        version_minor: read_u16(&global_header[6..8], swapped),
        snaplen: read_u32(&global_header[16..20], swapped),
        network: read_u32(&global_header[20..24], swapped),
    };

    println!(
        "pcap version {}.{} snaplen={} network={} swapped={}",
        header.version_major, header.version_minor, header.snaplen, header.network, ctx.swapped
    );

    let mut packet_header = [0u8; 16];

    loop {
        match reader.read_exact(&mut packet_header) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Box::new(e)),
        }

        let timestamp_seconds = read_u32(&packet_header[0..4], ctx.swapped);

        let timestamp_fraction = read_u32(&packet_header[4..8], ctx.swapped);

        let captured_length = read_u32(&packet_header[8..12], ctx.swapped);

        let original_length = read_u32(&packet_header[12..16], ctx.swapped);

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
