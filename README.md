# felica

[![CI](https://github.com/soltia48/felica/actions/workflows/ci.yml/badge.svg)](https://github.com/soltia48/felica/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/felica.svg)](https://crates.io/crates/felica)
[![docs.rs](https://docs.rs/felica/badge.svg)](https://docs.rs/felica)

An implementation of the FeliCa protocol in Rust: mutual authentication and
encrypted block access on Standard cards, a card emulator, and drivers for
Sony's PaSoRi readers.

The reader drivers sit behind the default `usb` feature. Turned off, the crate
has no USB dependency at all and leaves the protocol, the emulator and a TCP
driver — which is what a server driving authentication over a relay needs
rather than a reader of its own.

## Features

- **Port-100 (RC-S380) Support** - Full support for Sony RC-S380 NFC readers
- **Port-400 (RC-S300) Support** - Support for Sony RC-S300 NFC readers
- **RC-S320 Support** - Support for older Sony RC-S320 readers
- **RC-S956 (RC-S330/RC-S360/RC-S370) Support** - Support for RC-S956-based readers
- **FeliCa Standard Protocol** - Complete implementation of the FeliCa Standard protocol
- **USB Transport Layer** - Direct USB communication with NFC readers
- **Remote Client/Server** - Network-based NFC operations via TCP

## Requirements

- Rust 1.88 or newer (2024 edition)
- USB access permissions for NFC readers — only when the `usb` feature is on

## Installation

```sh
cargo add felica
```

or, in `Cargo.toml`:

```toml
[dependencies]
felica = "1.0"
```

The default `usb` feature pulls in `rusb` and the PaSoRi drivers. Turn it off
to build only the hardware-independent parts — the FeliCa Standard protocol,
the card emulator, and the TCP `driver::remote` — with no USB dependency:

```sh
cargo add felica --no-default-features
```

```toml
[dependencies]
felica = { version = "1.0", default-features = false }
```

## Quick Start

```rust
use felica::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open the first available reader
    let mut reader = open_reader(ReaderPreference::Auto)?;

    println!("Reader: {} - {}",
        reader.vendor_name().unwrap_or("Unknown"),
        reader.product_name().unwrap_or("Unknown"));

    Ok(())
}
```

## Examples

### Dump FeliCa Card Information

Scan and dump all readable information from a FeliCa card:

```bash
cargo run --example dump
```

The tool waits until a card is placed on the reader, polling at both 212F and
424F (424F preferred, 212F fallback), and the output includes the FeliCa data
rate (`212F` or `424F`) the card was read at.

By default this prints a human-friendly, colorized tree showing:
- Reader information
- System codes (with friendly names for well-known ones)
- Service areas and their hierarchies
- Service attributes and key versions (AES/DES)
- Readable block data as a hex + ASCII dump

Colors are used only when stdout is a terminal; set `NO_COLOR` to disable them.

Pass `--json` (or `--format json`) for machine-readable JSON output instead:

```bash
cargo run --example dump -- --json
```

### Remote Server

Start a TCP server that exposes NFC reader functionality:

```bash
cargo run --example remote_server -- [address:port]
# Default: 127.0.0.1:7878
```

The server accepts JSON-formatted commands:

**DetectTypeF (Polling):**
```json
{"type": "detect_type_f", "bitrate": "212F", "system_code": 65535, "request_code": 0, "time_slots": 0}
```

**Transceive (Raw command):**
```json
{"type": "transceive", "bitrate": "212F", "data": "0A02...", "timeout_ms": 1000}
```

### Remote Client

Interactive client that connects to a remote NFC server:

```bash
cargo run --example remote_client -- [address:port]
# Default: 127.0.0.1:7878
```

Available commands:
- `poll [system_code] [bitrate]` - Poll for NFC-F target (bitrate optional; defaults to both 212F and 424F, 424F preferred)
- `system_code [sc] [bitrate]` - Request system codes from card (bitrate optional; defaults to both)
- `request_service <codes...>` - Request service key versions
- `read <service> <block>` - Read block without encryption
- `search <index>` - Search service code by index
- `dump [system_code]` - Dump all readable blocks

## Module Structure

| Module | Description |
|--------|-------------|
| `clf` | Contactless Frontend utilities (CRC, errors, targets) |
| `driver` | Hardware driver implementations for NFC readers |
| `driver::framing` | Sony SOF frame envelope shared by the Port-100, RC-S320 and RC-S956 drivers |
| `driver::port100` | Sony Port-100 (RC-S380) driver |
| `driver::port400` | Sony Port-400 (RC-S300) driver |
| `driver::rcs320` | Sony RC-S320 driver |
| `driver::rcs956` | Sony RC-S956 (RC-S330/RC-S360/RC-S370) driver |
| `driver::remote` | Remote driver for network-based NFC operations |
| `felica_standard` | FeliCa Standard protocol implementation |
| `reader` | High-level reader abstraction |
| `transport` | Transport layer abstractions (USB) |
| `prelude` | Convenient re-exports of common types |

## API Overview

The complete reference is on [docs.rs](https://docs.rs/felica), built with
all features so that the reader drivers are included. What follows is a sketch
of the entry points.

### Reader Selection

```rust
use felica::{open_reader, ReaderPreference};

// Auto-detect reader
let reader = open_reader(ReaderPreference::Auto)?;

// Force specific reader type
let reader = open_reader(ReaderPreference::ForcePort100)?;
let reader = open_reader(ReaderPreference::ForcePort400)?;
let reader = open_reader(ReaderPreference::ForceRcs320)?;
let reader = open_reader(ReaderPreference::ForceRcs956)?;
```

### FeliCa Standard Operations

```rust
use felica::felica_standard::{FelicaStandard, ServiceCode, BlockListElement};

// Poll for a card. When both FeliCa bitrates are requested, 424F is tried
// first and 212F is used as a fallback for cards that do not support 424F.
let (mut felica, polling) = FelicaStandard::polling_multi(
    reader.driver_mut(),
    &["212F", "424F"], // Bit rates to try (424F preferred)
    0xFFFF,            // System code (wildcard)
    0x00,              // Request code
    0x00,              // Time slots
)?;

// To poll at a single bitrate, use FelicaStandard::polling(driver, "212F", ...).

// Bitrate the card was activated at ("212F" or "424F")
let data_rate = felica.bitrate();

// Get IDm and PMm
let idm = felica.idm();
let pmm = felica.pmm();

// Request system codes
let system_codes = felica.request_system_code()?;

// Request service key versions
let service_codes = vec![ServiceCode::new(0x000B)];
let versions = felica.request_service(&service_codes)?;

// Read without encryption
let blocks = vec![BlockListElement::new(0, 0, 0)];
let data = felica.read_without_encryption(&service_codes, &blocks)?;

// Search service codes
let result = felica.search_service_code(0)?;
```

## Supported Hardware

| Device | VID:PID | Status |
|--------|---------|--------|
| Sony RC-S380 (Port-100) | 054C:06C1, 054C:06C3 | ✅ Supported |
| Sony RC-S300 (Port-400) | 054C:0DC8, 054C:0DC9, 054C:0D8F | ✅ Supported |
| Sony RC-S320 | 054C:01BB | ✅ Supported |
| Sony RC-S330/RC-S360/RC-S370 (RC-S956) | 054C:02E1, 054C:0193 | ✅ Supported |

## Continuous integration

Every push and pull request runs, in `.github/workflows/ci.yml`:

| job | what it checks |
|---|---|
| Lint | `cargo fmt --check`, `cargo clippy -D warnings` for both feature settings, `cargo doc -D warnings` |
| Test | the suite on Linux, macOS and Windows |
| Feature combinations | `--all-features` and `--no-default-features`, and that `rusb` really leaves the dependency graph with the latter |
| MSRV | the whole suite on the `rust-version` declared in `Cargo.toml` |
| Security advisories | `cargo audit` over the dependency graph |
| Package | `cargo package`, checking that `keys.jsonl` and the CI configuration stay out of the crate |

Tagging a commit `v<version>` runs `.github/workflows/release.yml`, which
checks the tag against `Cargo.toml`, runs the suite on both feature settings
and publishes to crates.io.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Before opening one, the checks below are what CI will run, and all of them
should pass locally:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
```

The last one matters: the crate is meant to build and pass its tests with the
`usb` feature turned off, and an example or doctest that needs a reader has to
say so with `required-features = ["usb"]` or a feature-gated doc fence.
