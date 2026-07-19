use std::env;
use std::io::{BufWriter, Write, stdout};
use std::net::UdpSocket;

use kospi200_parser::QuoteData;
use kospi200_parser::kospi::KospiHandler;
use kospi200_parser::sources::{run_pcap_source, run_udp_source};

enum DataSource {
    Pcap(String),
    Udp(String),
}

enum QuoteAction {
    Stdout,          // Parses everything, outputs to stdout
    Benchmark,       // Parses everything, outputs nothing (for profiling)
    Forward(String), // Forwards parsed quotes over internal UDP, outputs nothing
}

/// Generic execution pipeline.
fn run_pipeline<F>(
    source: DataSource,
    mut kospi_handler: KospiHandler,
    mut on_quote: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&QuoteData),
{
    match source {
        DataSource::Pcap(filename) => {
            eprintln!("Replaying PCAP file: {}", filename);
            run_pcap_source(&filename, |sec, usec, payload| {
                kospi_handler.on_packet(sec, usec, payload, &mut on_quote);
            })?;
        }
        DataSource::Udp(addr) => {
            eprintln!("Listening on UDP feed: {}", addr);
            run_udp_source(&addr, |sec, usec, payload| {
                kospi_handler.on_packet(sec, usec, payload, &mut on_quote);
                true
            })?;
        }
    }

    // Flush remaining heap items
    kospi_handler.flush_all(&mut on_quote);

    eprintln!("quotes parsed: {}", kospi_handler.quotes_parsed);
    if kospi_handler.max_heap_size > 0 {
        eprintln!("maximum heap size: {}", kospi_handler.max_heap_size);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut reorder = false;
    let mut source = None;
    let mut quote_action = QuoteAction::Stdout;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-r" => reorder = true,
            "--benchmark" => quote_action = QuoteAction::Benchmark,
            "--forward" => {
                quote_action = QuoteAction::Forward(
                    args.next()
                        .expect("Missing forward IP:Port [--forward <ip:port>]"),
                )
            }
            "--pcap" => {
                source = Some(DataSource::Pcap(
                    args.next()
                        .expect("Missing PCAP filename [--pcap <file.pcap>]"),
                ))
            }
            "--udp" => {
                source = Some(DataSource::Udp(
                    args.next().expect("Missing UDP IP:Port [--udp <ip:port>]"),
                ))
            }
            _ => {
                eprintln!(
                    "Usage: {} [-r] [--benchmark | --forward <ip:port>] [--pcap <file.pcap> | --udp <ip:port>]",
                    env::args().next().unwrap()
                );
                std::process::exit(1);
            }
        }
    }

    let source = source.expect("Must specify either [--pcap <file.pcap>] or [--udp <ip:port>]");

    // Instantiate stateful KOSPI parser
    let kospi_handler = KospiHandler::new(reorder);

    // Switch strategy based on args
    match quote_action {
        QuoteAction::Stdout => {
            let stdout = stdout();
            let mut output = BufWriter::new(stdout.lock());

            // Batch I/O string formatting, preventing repeated syscalls to `StdoutLock`
            let mut format_buf: Vec<u8> = Vec::with_capacity(256);

            run_pipeline(source, kospi_handler, |quote| {
                quote.format_and_write(&mut format_buf, &mut output);
            })?;
            output.flush()?;
        }
        QuoteAction::Benchmark => {
            eprintln!("Running in Benchmark mode (I/O disabled)...");
            run_pipeline(source, kospi_handler, |_quote| {})?;
        }
        QuoteAction::Forward(target_addr) => {
            eprintln!("Forwarding normalized stream to {}...", target_addr);
            let socket = UdpSocket::bind("0.0.0.0:0")?;

            // Pre-allocate 223-bytes = 4 (sec) + 4 (usec) + 215 (payload)
            let mut out_buf = [0u8; 223];

            run_pipeline(source, kospi_handler, |quote| {
                // Serialize ints explicitly to Little Endian for network transport
                out_buf[0..4].copy_from_slice(&quote.ts_sec.to_le_bytes());
                out_buf[4..8].copy_from_slice(&quote.ts_usec.to_le_bytes());

                // Blit the raw KOSPI application data
                out_buf[8..223].copy_from_slice(&quote.payload);

                // Forward raw 223 bytes
                let _ = socket.send_to(&out_buf, &target_addr);
            })?;
        }
    }

    Ok(())
}
