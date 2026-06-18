#![forbid(unsafe_code)]

/*
 * Time Complexity: O(N * log K) where N is the total number of packets, and K
 * is the maximum number of packets concurrently buffered within any 3-second window.
 * Space Complexity: O(K) where K is the number of packets fitting within the
 * sliding window, ensuring strict memory bounds well below available RAM.
 */

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::env;
use std::fmt::Write as _; // Required for the write! macro optimization
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

const MAX_DELAY_MICROSECONDS: u64 = 3_000_000; // 3 seconds
const MAX_CAPTURE_SIZE: usize = 16 * 1024 * 1024;
const QUOTE_PACKET_MAGIC: &[u8] = b"B6034";
const QUOTE_PACKET_LENGTH: usize = 215;
const TARGET_PORTS: [u16; 2] = [15515, 15516];

// Store the raw bytes in the heap, not a String.
#[derive(Eq, PartialEq)]
struct QuotePacket {
    accept_key: u64,
    pkt_time: u64,
    ts_sec: u32,
    ts_usec: u32,
    payload: [u8; QUOTE_PACKET_LENGTH],
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
    is_swapped: bool,
    is_nano: bool,
    link_type: u32,
}

fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    if swapped { value.swap_bytes() } else { value }
}

fn read_pcap_context(
    reader: &mut BufReader<File>,
) -> Result<PcapContext, Box<dyn std::error::Error>> {
    let mut global_hdr = [0u8; 24];
    reader.read_exact(&mut global_hdr)?;

    let magic = u32::from_ne_bytes(global_hdr[0..4].try_into().unwrap());
    let (is_swapped, is_nano) = match magic {
        0xa1b2c3d4 => (false, false),
        0xd4c3b2a1 => (true, false),
        0xa1b23c4d => (false, true),
        0x4d3cb2a1 => (true, true),
        _ => {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "invalid PCAP magic",
            )));
        }
    };

    let link_type = read_u32(&global_hdr[20..24], is_swapped);

    Ok(PcapContext {
        is_swapped,
        is_nano,
        link_type,
    })
}

fn extract_udp_payload(packet: &[u8], link_type: u32) -> Option<&[u8]> {
    let mut offset = match link_type {
        1 => 14,
        113 => 16,
        12 => 0,
        _ => return None,
    };

    if link_type == 1 {
        if packet.len() < 14 {
            return None;
        }
        let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
        if eth_type == 0x8100 {
            offset += 4;
        }
    }

    if packet.len() < offset + 20 {
        return None;
    }
    if packet[offset] >> 4 != 4 {
        return None;
    }

    let ip_header_len = ((packet[offset] & 0x0f) as usize) * 4;
    let udp_offset = offset + ip_header_len;

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

    let mut out = String::with_capacity(256);
    let _ = write!(out, "{}.{:06} {} {}", ts_sec, ts_usec, accept, issue);

    // Bids: 5th to 1st
    let bid_offsets = [
        (77, 82, 82, 89), // 5th
        (65, 70, 70, 77), // 4th
        (53, 58, 58, 65), // 3rd
        (41, 46, 46, 53), // 2nd
        (29, 34, 34, 41), // 1st
    ];
    for &(ps, pe, qs, qe) in &bid_offsets {
        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");
        let _ = write!(out, " {}@{}", qty, price);
    }

    // Asks: 1st to 5th
    let ask_offsets = [
        (96, 101, 101, 108),  // 1st
        (108, 113, 113, 120), // 2nd
        (120, 125, 125, 132), // 3rd
        (132, 137, 137, 144), // 4th
        (144, 149, 149, 156), // 5th
    ];
    for &(ps, pe, qs, qe) in &ask_offsets {
        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");
        let _ = write!(out, " {}@{}", qty, price);
    }

    out
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

    let file = File::open(filename.ok_or("missing file")?)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let ctx = read_pcap_context(&mut reader)?;
    let mut heap = BinaryHeap::<Reverse<QuotePacket>>::new();

    let mut packet_buf = Vec::new();
    let mut header = [0u8; 16];
    let mut max_time = 0u64;

    while reader.read_exact(&mut header).is_ok() {
        let incl_len = read_u32(&header[8..12], ctx.is_swapped) as usize;
        if incl_len > MAX_CAPTURE_SIZE {
            continue;
        }

        let ts_sec = read_u32(&header[0..4], ctx.is_swapped);
        let ts_fraction = read_u32(&header[4..8], ctx.is_swapped);
        let ts_usec = if ctx.is_nano {
            ts_fraction / 1000
        } else {
            ts_fraction
        };
        let pkt_time = (ts_sec as u64) * 1_000_000 + (ts_usec as u64);

        max_time = max_time.max(pkt_time);
        packet_buf.resize(incl_len, 0);
        reader.read_exact(&mut packet_buf)?;

        if let Some(payload) = extract_udp_payload(&packet_buf, ctx.link_type) {
            if let Some(quote) = extract_quote(payload) {
                if !reorder {
                    // Fast path: Just print it directly
                    println!("{}", format_output_string(ts_sec, ts_usec, quote));
                    continue;
                }

                let key = u64::from_be_bytes(quote[206..214].try_into().unwrap());

                // Copy bytes safely into fixed-size array
                let mut payload_arr = [0u8; QUOTE_PACKET_LENGTH];
                payload_arr.copy_from_slice(quote);

                heap.push(Reverse(QuotePacket {
                    accept_key: key,
                    pkt_time,
                    ts_sec,
                    ts_usec,
                    payload: payload_arr,
                }));

                while let Some(Reverse(packet)) = heap.peek() {
                    if packet.pkt_time + MAX_DELAY_MICROSECONDS <= max_time {
                        let popped = heap.pop().unwrap().0;
                        // Format ONLY right before printing
                        println!(
                            "{}",
                            format_output_string(popped.ts_sec, popped.ts_usec, &popped.payload)
                        );
                    } else {
                        break;
                    }
                }
            }
        }
    }

    if reorder {
        while let Some(Reverse(packet)) = heap.pop() {
            println!(
                "{}",
                format_output_string(packet.ts_sec, packet.ts_usec, &packet.payload)
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_quote() {
        // Create a fake payload that is too short
        let short_payload = vec![0u8; 100];
        assert_eq!(extract_quote(&short_payload), None);

        // Create a valid payload with the magic bytes
        let mut valid_payload = vec![0u8; 215];
        valid_payload[0..5].copy_from_slice(b"B6034");

        let result = extract_quote(&valid_payload);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 215);
    }

    #[test]
    fn test_format_output_string() {
        let mut payload = vec![b'0'; 215]; // Fill with ASCII '0'

        // Mock the Magic Bytes, ISIN, and Accept Time
        payload[0..5].copy_from_slice(b"B6034");
        payload[5..17].copy_from_slice(b"KR7005930003"); // Issue Code
        payload[206..214].copy_from_slice(b"09000123"); // Accept Time

        // Mock 1st Bid (Qty: 10, Price: 500)
        payload[29..34].copy_from_slice(b"00500");
        payload[34..41].copy_from_slice(b"0000010");

        let output = format_output_string(1297846801, 123456, &payload);

        // Verify time headers and ISIN
        assert!(output.starts_with("1297846801.123456 09000123 KR7005930003"));
        // Verify the 1st bid is correctly positioned at the end of the bid block
        assert!(output.contains(" 0000010@00500"));
    }
}
