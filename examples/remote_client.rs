//! NFC-F Remote Command Client
//!
//! This client connects to the NFC-F remote server and uses the FelicaStandard
//! API to communicate with NFC-F tags through the remote reader.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example remote_client -- [address:port]
//! ```
//!
//! Default address is 127.0.0.1:7878

use hex::encode as hex_encode;
use nfc_rs::RemoteDriver;
use nfc_rs::felica_standard::{BlockListElement, FelicaStandard, ServiceCode};
use std::error::Error;
use std::io::{Write, stdin, stdout};

fn main() -> Result<(), Box<dyn Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7878".to_string());

    println!("NFC-F Remote Client");
    println!("Connecting to {}...", addr);

    let mut driver = RemoteDriver::connect(&addr)?;
    println!("Connected!");
    println!();
    print_help();

    loop {
        print!("> ");
        stdout().flush()?;

        let mut input = String::new();
        if stdin().read_line(&mut input)? == 0 {
            break; // EOF
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        if let Err(e) = execute_command(&mut driver, input) {
            println!("Error: {}", e);
        }
    }

    println!("Goodbye!");
    Ok(())
}

fn print_help() {
    println!("Commands:");
    println!("  poll [system_code] [brty]    - Poll for NFC-F target and show IDm/PMm");
    println!("                                 system_code: hex (default: FFFF)");
    println!("                                 brty: 212F or 424F (default: 212F)");
    println!("  system_code [sc] [brty]      - Request system codes from card");
    println!("  request_service <codes...>   - Request service (hex codes)");
    println!("  read <service> <block>       - Read block without encryption");
    println!("  search <index>               - Search service code by index");
    println!("  dump [system_code]           - Dump all readable blocks");
    println!("  help                         - Show this help");
    println!("  quit                         - Exit the client");
    println!();
}

fn execute_command(driver: &mut RemoteDriver, input: &str) -> Result<(), Box<dyn Error>> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let cmd = parts[0].to_lowercase();
    match cmd.as_str() {
        "help" | "h" | "?" => {
            print_help();
        }
        "quit" | "exit" | "q" => {
            std::process::exit(0);
        }
        "poll" | "p" => {
            let system_code = parts.get(1).unwrap_or(&"FFFF");
            let brty = parts.get(2).unwrap_or(&"212F");
            let system_code = parse_u16_hex(system_code)?;

            let (felica, polling) = FelicaStandard::polling(driver, brty, system_code, 0x00, 0x00)?;

            println!("Found NFC-F target:");
            println!("  IDm: {}", hex_encode(felica.idm()).to_uppercase());
            println!("  PMm: {}", hex_encode(felica.pmm()).to_uppercase());
            if !polling.optional.is_empty() {
                println!("  RD:  {}", hex_encode(&polling.optional).to_uppercase());
            }
        }
        "system_code" | "sc" | "systemcode" => {
            let system_code = parts.get(1).unwrap_or(&"FFFF");
            let brty = parts.get(2).unwrap_or(&"212F");
            let system_code = parse_u16_hex(system_code)?;

            let (mut felica, _) = FelicaStandard::polling(driver, brty, system_code, 0x00, 0x00)?;
            let codes = felica.request_system_code()?;

            println!("System codes:");
            for code in &codes {
                println!("  0x{:04X}", code);
            }
        }
        "request_service" | "rs" => {
            if parts.len() < 2 {
                return Err("Usage: request_service <service_code1> [service_code2...]".into());
            }

            let (mut felica, _) = FelicaStandard::polling(driver, "212F", 0xFFFF, 0x00, 0x00)?;

            let codes: Vec<ServiceCode> = parts[1..]
                .iter()
                .filter_map(|s| parse_u16_hex(s).ok())
                .map(ServiceCode::new)
                .collect();

            if codes.is_empty() {
                return Err("No valid service codes".into());
            }

            let versions = felica.request_service(&codes)?;

            println!("Key versions:");
            for (code, version) in parts[1..].iter().zip(versions.iter()) {
                println!("  {}: 0x{:04X}", code, version);
            }
        }
        "read" | "r" => {
            if parts.len() < 3 {
                return Err("Usage: read <service_code> <block_number>".into());
            }

            let service_code = parse_u16_hex(parts[1])?;
            let block_number: u16 = parts[2].parse()?;

            let (mut felica, _) = FelicaStandard::polling(driver, "212F", 0xFFFF, 0x00, 0x00)?;

            let codes = vec![ServiceCode::new(service_code)];
            let blocks = vec![BlockListElement::new(block_number, 0, 0)];

            let data = felica.read_without_encryption(&codes, &blocks)?;

            println!("Block {} data:", block_number);
            for (i, block) in data.iter().enumerate() {
                println!(
                    "  Block {}: {}",
                    block_number + i as u16,
                    hex_encode(block).to_uppercase()
                );
            }
        }
        "search" | "ssc" => {
            if parts.len() < 2 {
                return Err("Usage: search <service_index>".into());
            }

            let service_index: u16 = parts[1].parse()?;

            let (mut felica, _) = FelicaStandard::polling(driver, "212F", 0xFFFF, 0x00, 0x00)?;
            let result = felica.search_service_code(service_index)?;

            match result {
                Some(nfc_rs::SearchServiceCodeResult::Service(code)) => {
                    println!("Index {}: Service 0x{:04X}", service_index, code.raw());
                    println!("  Number: {}", code.number());
                    println!("  Attributes: 0x{:02X}", code.attributes());
                    if let Some(desc) = code.attributes_description() {
                        println!("  Description: {}", desc);
                    }
                }
                Some(nfc_rs::SearchServiceCodeResult::Area {
                    area_code,
                    end_service_index,
                }) => {
                    println!("Index {}: Area 0x{:04X}", service_index, area_code);
                    println!("  End service index: 0x{:04X}", end_service_index);
                }
                None => {
                    println!("Index {}: No more entries", service_index);
                }
            }
        }
        "dump" => {
            let system_code = parts.get(1).unwrap_or(&"FFFF");
            let system_code = parse_u16_hex(system_code)?;

            println!("Polling for system code 0x{:04X}...", system_code);
            let (mut felica, _) = FelicaStandard::polling(driver, "212F", system_code, 0x00, 0x00)?;

            println!("IDm: {}", hex_encode(felica.idm()).to_uppercase());
            println!("PMm: {}", hex_encode(felica.pmm()).to_uppercase());
            println!();

            // Request system codes
            println!("System codes:");
            match felica.request_system_code() {
                Ok(codes) => {
                    for code in &codes {
                        println!("  0x{:04X}", code);
                    }
                }
                Err(e) => println!("  Error: {}", e),
            }
            println!();

            // Search for services and areas
            println!("Services and Areas:");
            let mut index = 0u16;
            while index <= 0xFF {
                // Need to re-poll for each search since the connection state may be lost
                let (mut felica, _) =
                    FelicaStandard::polling(driver, "212F", system_code, 0x00, 0x00)?;

                match felica.search_service_code(index) {
                    Ok(Some(nfc_rs::SearchServiceCodeResult::Service(code))) => {
                        println!(
                            "  [{:02X}] Service 0x{:04X} (attr: 0x{:02X})",
                            index,
                            code.raw(),
                            code.attributes()
                        );

                        // Try to read if it's a readable service
                        if code.attributes() & 0x01 == 0x01 {
                            let codes = vec![ServiceCode::new(code.raw())];
                            let blocks = vec![BlockListElement::new(0, 0, 0)];

                            // Re-poll and try to read
                            let (mut felica, _) =
                                FelicaStandard::polling(driver, "212F", system_code, 0x00, 0x00)?;
                            match felica.read_without_encryption(&codes, &blocks) {
                                Ok(data) => {
                                    for (i, block) in data.iter().enumerate() {
                                        println!(
                                            "        Block {}: {}",
                                            i,
                                            hex_encode(block).to_uppercase()
                                        );
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    Ok(Some(nfc_rs::SearchServiceCodeResult::Area {
                        area_code,
                        end_service_index,
                    })) => {
                        println!(
                            "  [{:02X}] Area 0x{:04X} (end: 0x{:04X})",
                            index, area_code, end_service_index
                        );
                    }
                    Ok(None) => break,
                    Err(e) => {
                        println!("  Error at index {}: {}", index, e);
                        break;
                    }
                }
                index += 1;
            }
        }
        _ => {
            println!(
                "Unknown command: {}. Type 'help' for available commands.",
                cmd
            );
        }
    }

    Ok(())
}

fn parse_u16_hex(s: &str) -> Result<u16, Box<dyn Error>> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(s, 16).map_err(|e| e.into())
}
