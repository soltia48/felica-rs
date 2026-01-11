# nfc-rs

A Rust library for interacting with NFC (Near Field Communication) devices, with support for Sony's NFC Port-100 (RC-S380) and Port-400 (Sony RC-S300) readers.

## Features

- **Port-100 (RC-S380) Support** - Full support for Sony RC-S380 NFC readers
- **Port-400 (RC-S300) Support** - Support for Sony RC-S300 NFC readers
- **FeliCa Standard Protocol** - Complete implementation of the FeliCa Standard protocol
- **USB Transport Layer** - Direct USB communication with NFC readers
- **Remote Client/Server** - Network-based NFC operations via TCP

## Requirements

- Rust 2024 edition
- USB access permissions for NFC readers

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
nfc-rs = { git = "https://github.com/soltia48/nfc-rs.git" }
```

## Quick Start

```rust
use nfc_rs::prelude::*;

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

This outputs JSON with:
- Reader information
- System codes
- Service areas and their hierarchies
- Key versions (AES/DES)
- Readable block data

### Remote Server

Start a TCP server that exposes NFC reader functionality:

```bash
cargo run --example remote_server -- [address:port]
# Default: 127.0.0.1:7878
```

The server accepts JSON-formatted commands:

**DetectTypeF (Polling):**
```json
{"type": "detect_type_f", "brty": "212F", "system_code": 65535, "request_code": 0, "time_slots": 0}
```

**Transceive (Raw command):**
```json
{"type": "transceive", "brty": "212F", "data": "0A02...", "timeout_ms": 1000}
```

### Remote Client

Interactive client that connects to a remote NFC server:

```bash
cargo run --example remote_client -- [address:port]
# Default: 127.0.0.1:7878
```

Available commands:
- `poll [system_code] [brty]` - Poll for NFC-F target
- `system_code [sc] [brty]` - Request system codes from card
- `request_service <codes...>` - Request service key versions
- `read <service> <block>` - Read block without encryption
- `search <index>` - Search service code by index
- `dump [system_code]` - Dump all readable blocks

## Module Structure

| Module | Description |
|--------|-------------|
| `clf` | Contactless Frontend utilities (CRC, errors, targets) |
| `driver` | Hardware driver implementations for NFC readers |
| `driver::port100` | Sony Port-100 (RC-S380) driver |
| `driver::port400` | Sony Port-400 (RC-S300) driver |
| `driver::remote` | Remote driver for network-based NFC operations |
| `felica_standard` | FeliCa Standard protocol implementation |
| `reader` | High-level reader abstraction |
| `transport` | Transport layer abstractions (USB) |
| `prelude` | Convenient re-exports of common types |

## API Overview

### Reader Selection

```rust
use nfc_rs::{open_reader, ReaderPreference};

// Auto-detect reader
let reader = open_reader(ReaderPreference::Auto)?;

// Force specific reader type
let reader = open_reader(ReaderPreference::ForcePort100)?;
let reader = open_reader(ReaderPreference::ForcePort400)?;
```

### FeliCa Standard Operations

```rust
use nfc_rs::felica_standard::{FelicaStandard, ServiceCode, BlockListElement};

// Poll for a card
let (mut felica, polling) = FelicaStandard::polling(
    reader.driver_mut(),
    "212F",      // Bit rate
    0xFFFF,      // System code (wildcard)
    0x00,        // Request code
    0x00,        // Time slots
)?;

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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
