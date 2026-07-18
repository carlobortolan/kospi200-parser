use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn main() {
    let target_addr = "127.0.0.1:15515";
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind sender socket");

    println!("Loading KOSPI PCAP...");
    let mut input_file =
        File::open("data/mdf-kospi200.20110216-0.pcap").expect("Failed to open PCAP");
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data).unwrap();

    let mut cursor = 24; // Skip global header
    let mut packets_sent = 0;

    println!("Starting UDP broadcast to {}...", target_addr);

    while cursor < input_data.len() {
        let incl_len =
            u32::from_le_bytes(input_data[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        let payload = &input_data[cursor + 16..cursor + 16 + incl_len];

        // Strip 42-byte Ethernet/IP/UDP header offset for capture
        let kospi_payload = if payload.len() > 42 {
            &payload[42..]
        } else {
            payload
        };

        socket.send_to(kospi_payload, target_addr).unwrap();
        packets_sent += 1;
        cursor += 16 + incl_len;

        // Micro-sleep to prevent completely overwhelming the local OS loopback buffer instantly.
        // A 10-microsecond sleep yields roughly 100,000 packets per second.
        thread::sleep(Duration::from_micros(10));
    }

    println!("Finished! Sent {} market data packets.", packets_sent);
}
