use std::net::UdpSocket;

fn main() {
    let listen_addr = "127.0.0.1:9999";
    let socket = UdpSocket::bind(listen_addr).expect("Failed to bind receiver socket");

    println!("Mock Orderbook listening on {}...", listen_addr);

    let mut buf = [0u8; 1024];
    let mut last_accept_key: u64 = 0;
    let mut out_of_order_count = 0;
    let mut packets_received = 0;

    while let Ok((len, _src)) = socket.recv_from(&mut buf) {
        if len == 223 {
            packets_received += 1;

            // 1. Decode the exchange's accept key
            // The payload starts at index 8. The Accept Key is at payload offset 206 (8 + 206 = 214)
            let accept_key = u64::from_be_bytes(buf[214..222].try_into().unwrap());

            // 2. Regression check
            if accept_key < last_accept_key {
                out_of_order_count += 1;
                eprintln!(
                    "!!! OUT OF ORDER !!! Packet {} | Current: {} | Last: {}",
                    packets_received, accept_key, last_accept_key
                );
            }

            last_accept_key = accept_key.max(last_accept_key);

            if packets_received % 5000 == 0 {
                println!(
                    "Processed {} packets. Out-of-order count: {}",
                    packets_received, out_of_order_count
                );
            }
        }
    }
}
