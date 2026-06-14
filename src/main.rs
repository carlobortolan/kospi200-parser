#![forbid(unsafe_code)]

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::env;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

const TARGET_PORTS: [u16; 2] = [15515, 15516];
const QUOTE_PACKET_MAGIC: &[u8] = b"B6034";
const QUOTE_PACKET_LENGTH: usize = 215;
const MAX_DELAY_MICROSECONDS: u64 = 3_000_000;
const MAX_CAPTURE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct QuotePacket {
    accept_key: u64,
    pkt_time: u64,
    output: String,
}

impl Ord for QuotePacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.accept_key
            .cmp(&other.accept_key)
            .then_with(|| self.pkt_time.cmp(&other.pkt_time))
    }
}

impl PartialOrd for QuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct PcapContext {
    swapped: bool,
    is_nano: bool,
    link_type: u32,
}

fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    if swapped { value.swap_bytes() } else { value }
}

fn timestamp_to_micros(seconds: u32, fraction: u32, nano: bool) -> u64 {
    let micros = if nano { fraction / 1000 } else { fraction };

    seconds as u64 * 1_000_000 + micros as u64
}

fn ethernet_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 14 {
        return None;
    }

    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);

    if ethertype == 0x8100 {
        if packet.len() < 18 {
            return None;
        }

        Some(18)
    } else {
        Some(14)
    }
}

fn extract_udp_payload(packet: &[u8], link_type: u32) -> Option<&[u8]> {
    let offset = match link_type {
        1 => ethernet_offset(packet)?,
        113 => 16,
        12 => 0,
        _ => return None,
    };

    if packet.len() < offset + 20 {
        return None;
    }

    if packet[offset] >> 4 != 4 {
        return None;
    }

    let ip_len = ((packet[offset] & 0x0f) as usize) * 4;

    if ip_len < 20 {
        return None;
    }

    let udp_offset = offset + ip_len;

    if packet.len() < udp_offset + 8 {
        return None;
    }

    if packet[offset + 9] != 17 {
        return None;
    }

    let dst_port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]);

    if !TARGET_PORTS.contains(&dst_port) {
        return None;
    }

    Some(&packet[udp_offset + 8..])
}

fn extract_quote(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < QUOTE_PACKET_LENGTH {
        return None;
    }

    if &payload[..5] != QUOTE_PACKET_MAGIC {
        return None;
    }

    Some(&payload[..QUOTE_PACKET_LENGTH])
}

fn format_output_string(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> String {
    let issue = std::str::from_utf8(&payload[5..17]).unwrap_or("");

    let accept = std::str::from_utf8(&payload[206..214]).unwrap_or("");

    let mut output = String::with_capacity(256);

    output.push_str(&format!("{}.{:06} {} {}", ts_sec, ts_usec, accept, issue));

    let bid_offsets = [
        (77, 82, 82, 89),
        (65, 70, 70, 77),
        (53, 58, 58, 65),
        (41, 46, 46, 53),
        (29, 34, 34, 41),
    ];

    for &(ps, pe, qs, qe) in &bid_offsets {
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");

        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");

        output.push_str(&format!(" {}@{}", qty, price));
    }

    let ask_offsets = [
        (96, 101, 101, 108),
        (108, 113, 113, 120),
        (120, 125, 125, 132),
        (132, 137, 137, 144),
        (144, 149, 149, 156),
    ];

    for &(ps, pe, qs, qe) in &ask_offsets {
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");

        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");

        output.push_str(&format!(" {}@{}", qty, price));
    }

    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut reorder = false;
    let mut filename = None;

    for arg in args.iter().skip(1) {
        if arg == "-r" {
            reorder = true;
        } else {
            filename = Some(arg);
        }
    }

    let filename = filename.ok_or("missing pcap filename")?;

    let file = File::open(filename)?;

    let mut reader = BufReader::with_capacity(256 * 1024, file);

    let mut global = [0u8; 24];
    reader.read_exact(&mut global)?;

    let magic = u32::from_ne_bytes([global[0], global[1], global[2], global[3]]);

    let (swapped, is_nano) = match magic {
        0xa1b2c3d4 => (false, false),
        0xd4c3b2a1 => (true, false),
        0xa1b23c4d => (false, true),
        0x4d3cb2a1 => (true, true),
        _ => {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "invalid pcap magic",
            )));
        }
    };

    let ctx = PcapContext {
        swapped,
        is_nano,
        link_type: read_u32(&global[20..24], swapped),
    };

    let mut heap = BinaryHeap::<Reverse<QuotePacket>>::new();

    let mut packet_buffer = Vec::new();
    let mut max_pkt_time_seen = 0u64;

    let mut header = [0u8; 16];

    while reader.read_exact(&mut header).is_ok() {
        let ts_sec = read_u32(&header[0..4], ctx.swapped);

        let ts_fraction = read_u32(&header[4..8], ctx.swapped);

        let incl_len = read_u32(&header[8..12], ctx.swapped) as usize;

        if incl_len > MAX_CAPTURE_SIZE {
            continue;
        }

        let pkt_time = timestamp_to_micros(ts_sec, ts_fraction, ctx.is_nano);

        max_pkt_time_seen = max_pkt_time_seen.max(pkt_time);

        packet_buffer.resize(incl_len, 0);

        reader.read_exact(&mut packet_buffer)?;

        if let Some(payload) = extract_udp_payload(&packet_buffer, ctx.link_type) {
            if let Some(quote) = extract_quote(payload) {
                let key = u64::from_be_bytes(quote[206..214].try_into().unwrap());

                let output = format_output_string(
                    ts_sec,
                    if ctx.is_nano {
                        ts_fraction / 1000
                    } else {
                        ts_fraction
                    },
                    quote,
                );

                if !reorder {
                    println!("{}", output);
                    continue;
                }

                heap.push(Reverse(QuotePacket {
                    accept_key: key,
                    pkt_time,
                    output,
                }));

                while let Some(Reverse(packet)) = heap.peek() {
                    if packet.pkt_time + MAX_DELAY_MICROSECONDS <= max_pkt_time_seen {
                        println!("{}", heap.pop().unwrap().0.output);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    if reorder {
        while let Some(Reverse(packet)) = heap.pop() {
            println!("{}", packet.output);
        }
    }

    Ok(())
}
