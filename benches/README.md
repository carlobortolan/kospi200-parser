### Create a large PCAP file

```sh
# Create 1G file
mergecap -F pcap -w data/test-medium1g.pcap \
$(yes data/mdf-kospi200.20110216-0.pcap | head -200)

# Create 10G file
mergecap -w data/test-large10g.pcap \
$(for i in $(seq 0 9); do
    editcap -t $((i * 30)) data/test-medium1g.pcap data/shifted$i.pcap
    echo data/shifted$i.pcap
done)
```

### Test with large file

```sh
# Run with a large file
ls -lh data/test-medium1g.pcap
/usr/bin/time -v target/release/parse-quote -r data/test-large10g.pcap > /dev/null

# Run tests including ignored large-file tests
cargo test -- --ignored
```

### Run basic benchmark

```sh
/usr/bin/time -v target/release/parse-quote -r --pcap data/test-large10g.pcap > /dev/null
```

This will output:

```
Replaying PCAP file: data/test-large10g.pcap
quotes parsed: 28807200
maximum heap size: 2765
        Command being timed: "target/release/parse-quote -r --pcap data/test-large10g.pcap"
        User time (seconds): 8.16
        System time (seconds): 0.46
        Percent of CPU this job got: 99%
        Elapsed (wall clock) time (h:mm:ss or m:ss): 0:08.68
        Average shared text size (kbytes): 0
        Average unshared data size (kbytes): 0
        Average stack size (kbytes): 0
        Average total size (kbytes): 0
        Maximum resident set size (kbytes): 10312680
        Average resident set size (kbytes): 0
        Major (requiring I/O) page faults: 0
        Minor (reclaiming a frame) page faults: 51010
        Voluntary context switches: 1
        Involuntary context switches: 97
        Swaps: 0
        File system inputs: 0
        File system outputs: 0
        Socket messages sent: 0
        Socket messages received: 0
        Signals delivered: 0
        Page size (bytes): 4096
        Exit status: 0
```

### Run benchmarks

```sh
cargo bench
```

### Reproducing the Flamegraph

```sh
cargo flamegraph --bin parse-quote -- -r --pcap data/test-large10g.pcap > /dev/null
```

If you are profiling on Linux and want clean stack traces without `[unknown]` blocks, create a local `.cargo/config.toml` file with the following linker flag before running `cargo flamegraph`:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-Clink-arg=-Wl,--no-rosegment"]
```

### The Math Behind the ~256 MB

The object pool (arena) is sized for 1_000_000 concurrent packets to avoid runtime allocations, remain stable at O(K) regardless of total file/input size.

The `KospiHandler::new` function pre-allocates three primary collections to a capacity of 1_000_000 items. Because it utilizes static arrays and explicit primitive types rather than pointers, the memory overhead is completely deterministic:

- Arena (`Vec<QuoteData>`): `QuoteData` is 224 bytes (8 bytes of timestamps + 215 bytes payload + 1 byte padding for alignment).
  - 1_000_000 \* 224 bytes = 224 MB

- Heap (`BinaryHeap<Reverse<HeapItem>>`): HeapItem is exactly 24 bytes (16 bytes of u64 keys + 4 byte u32 index + 4 bytes padding).
  - 1_000_000 \* 24 bytes = 24 MB

- Free List (`Vec<u32>`): Stores a 4-byte index.
  - 1_000_000 \* 4 bytes = 4 MB

Total Pre-allocation: 252 MB, rounded to ~256 MB.
