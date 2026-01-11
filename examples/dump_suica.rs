//! Suica Card Dump Utility
//!
//! This utility dumps information from Suica cards using FeliCa encryption.
//! Keys are loaded from a CSV file in the format: "system_code,node,version,key"
//!
//! # Usage
//!
//! Local reader:
//! ```bash
//! cargo run --example dump_suica -- --keys keys.csv
//! ```
//!
//! With station code lookup:
//! ```bash
//! cargo run --example dump_suica -- --keys keys.csv --station-codes station_codes.csv
//! ```
//!
//! Remote reader:
//! ```bash
//! cargo run --example dump_suica -- --keys keys.csv --station-codes station_codes.csv --remote 127.0.0.1:7878
//! ```

use csv::ReaderBuilder;
use encoding_rs::SHIFT_JIS;
use hex::encode;
use nfc_rs::felica_standard::{
    BlockListElement, FelicaDriver, FelicaStandard, FelicaStandardError, ServiceCode,
    generate_service_keys,
};
use nfc_rs::{ReaderPreference, RemoteDriver, open_reader};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Suica system code
const SUICA_SYSTEM_CODE: u16 = 0x0003;

/// Area node IDs for Suica
const AREA_NODE_IDS: &[u16] = &[0x0000, 0x0040, 0x0800, 0x0FC0, 0x1000];

/// Service node IDs for Suica
const SERVICE_NODE_IDS: &[u16] = &[
    0x0048, 0x0088, 0x0810, 0x08C8, 0x090C, 0x1008, 0x1048, 0x108C, 0x10C8,
];

/// Equipment type descriptions
fn equipment_type_to_str(equipment_type: u8) -> String {
    match equipment_type {
        0x00 => "未定義".to_string(),
        0x03 => "のりこし精算機".to_string(),
        0x04 => "携帯端末".to_string(),
        0x05 => "バス等車載機".to_string(),
        0x07 => "カード発売機".to_string(),
        0x08 => "自動券売機".to_string(),
        0x09 => "SMART ICOCA クイックチャージ機?".to_string(),
        0x12 => "自動券売機(東京モノレール)".to_string(),
        0x14 => "駅務機器(PASMO発行機?)".to_string(),
        0x15 => "定期券発売機".to_string(),
        0x16 => "自動改札機".to_string(),
        0x17 => "簡易改札機".to_string(),
        0x18 => "駅務機器(発行機?)".to_string(),
        0x19 => "窓口処理機(みどりの窓口)".to_string(),
        0x1A => "窓口処理機(有人改札)".to_string(),
        0x1B => "モバイルFeliCa".to_string(),
        0x1C => "入場券券売機".to_string(),
        0x1D => "他社乗換自動改札機".to_string(),
        0x1F => "入金機".to_string(),
        0x20 => "発行機?(モノレール)".to_string(),
        0x22 => "簡易改札機(ことでん)".to_string(),
        0x34 => "カード発売機(せたまる?)".to_string(),
        0x35 => "バス等車載機(せたまる車内入金機?)".to_string(),
        0x36 => "バス等車載機(車内簡易改札機)".to_string(),
        0x46 => "ビューアルッテ端末".to_string(),
        0xC7 | 0xC8 => "物販端末".to_string(),
        _ => format!("不明な機器種別 (0x{:02X})", equipment_type),
    }
}

/// Transaction type descriptions
fn transaction_type_to_str(transaction_type: u8) -> String {
    match transaction_type {
        0x00 => "未定義".to_string(),
        0x01 => "自動改札機出場".to_string(),
        0x02 => "SFチャージ".to_string(),
        0x03 => "きっぷ購入".to_string(),
        0x04 => "磁気券精算".to_string(),
        0x05 => "乗越精算".to_string(),
        0x06 => "窓口出場".to_string(),
        0x07 => "新規".to_string(),
        0x08 => "控除".to_string(),
        0x0D => "バス等均一運賃".to_string(),
        0x0F => "バス等".to_string(),
        0x11 => "再発行?".to_string(),
        0x13 => "料金出場".to_string(),
        0x14 => "オートチャージ".to_string(),
        0x1F => "バス等チャージ".to_string(),
        0x46 => "物販".to_string(),
        0x48 => "ポイントチャージ".to_string(),
        0x4B => "入場・物販".to_string(),
        _ => format!("不明な取引種別 (0x{:02X})", transaction_type),
    }
}

/// Pay type descriptions
fn pay_type_to_str(pay_type: u8) -> String {
    match pay_type {
        0x00 => "現金/なし".to_string(),
        0x02 => "VIEW".to_string(),
        0x0B => "PiTaPa".to_string(),
        0x0D => "オートチャージ対応PASMO".to_string(),
        0x3F => "モバイルSuica(VIEW決済以外)".to_string(),
        _ => format!("不明な支払種別 (0x{:02X})", pay_type),
    }
}

/// Gate instruction type descriptions
fn gate_instruction_type_to_str(gate_instruction_type: u8) -> String {
    match gate_instruction_type {
        0x00 => "未定義".to_string(),
        0x01 => "入場".to_string(),
        0x02 => "入場/出場".to_string(),
        0x03 => "定期入場/出場".to_string(),
        0x04 => "入場/定期出場".to_string(),
        0x0E => "窓口出場".to_string(),
        0x0F => "入場/出場(バス等)".to_string(),
        0x12 => "料金定期入場/料金出場".to_string(),
        0x17 => "入場/出場(乗継割引)".to_string(),
        0x21 => "入場/出場(バス等乗継割引)".to_string(),
        _ => format!("不明な改札処理種別 (0x{:02X})", gate_instruction_type),
    }
}

/// Gate in/out type descriptions
fn gate_in_out_type_to_str(gate_in_out_type: u8) -> String {
    match gate_in_out_type {
        0x00 => "精算出場".to_string(),
        0x01 => "精算出場(プリペイドカード併用?)".to_string(),
        0x20 => "出場".to_string(),
        0x21 => "駅務機器出場".to_string(),
        0x22 => "割引出場".to_string(),
        0x24 => "割引出場?".to_string(),
        0x40 => "定期出場".to_string(),
        0x80 => "均一区間入場?".to_string(),
        0xA0 => "入場".to_string(),
        0xA2 => "割引入場?".to_string(),
        0xC0 => "定期入場".to_string(),
        _ => format!("不明な改札入出場種別 (0x{:02X})", gate_in_out_type),
    }
}

/// Intermediate gate instruction type descriptions
fn intermediate_gate_instruction_type_to_str(gate_instruction_type: u8) -> String {
    match gate_instruction_type {
        0x00 => "未定義".to_string(),
        0x04 => "乗継割引?".to_string(),
        0x08 => "電車バス乗継割引?".to_string(),
        0x40 => "新幹線中間改札?".to_string(),
        _ => format!("不明な中間改札処理種別 (0x{:02X})", gate_instruction_type),
    }
}

/// Card type labels
fn card_type_to_str(card_type: u8) -> &'static str {
    match card_type {
        0 => "せたまる/IruCa",
        2 => "Suica/PiTaPa/TOICA/PASMO",
        3 => "ICOCA",
        _ => "不明",
    }
}

/// Issuer ID information (company name, identifier)
fn issuer_id_info(issuer_id: u16) -> Option<(&'static str, &'static str)> {
    match issuer_id {
        0x0102 => Some(("北海道旅客鉄道株式会社", "JH")),
        0x0103 => Some(("東日本旅客鉄道株式会社", "JE")),
        0x0104 => Some(("東海旅客鉄道株式会社", "JC")),
        0x0105 => Some(("西日本旅客鉄道株式会社", "JW")),
        0x0107 => Some(("九州旅客鉄道株式会社", "JK")),
        0x0252 => Some(("株式会社パスモ", "PB")),
        0x0387 => Some(("株式会社名古屋交通開発機構・株式会社エムアイシー", "TP")),
        0x05D5 => Some(("株式会社ニモカ", "NR")),
        0x05D7 => Some(("福岡市交通局", "FC")),
        _ => None,
    }
}

/// Issuer ID to string
fn issuer_id_to_str(issuer_id: u16) -> String {
    match issuer_id_info(issuer_id) {
        Some((company, identifier)) => format!("{:04X} ({} / {})", issuer_id, company, identifier),
        None => format!("{:04X}", issuer_id),
    }
}

/// Format IDi bytes to human-readable string
fn idi_bytes_to_str(idi_bytes: &[u8]) -> String {
    if idi_bytes.len() < 8 {
        return encode(idi_bytes).to_uppercase();
    }

    let issuer_id = u16::from_be_bytes([idi_bytes[0], idi_bytes[1]]);
    let remainder = encode(&idi_bytes[2..4]).to_uppercase();

    let head = match issuer_id_info(issuer_id) {
        Some((_, identifier)) => format!("{}{}", identifier, remainder),
        None => format!("{:04X}{}", issuer_id, remainder),
    };

    let v = u16::from_be_bytes([idi_bytes[4], idi_bytes[5]]);
    let year = (v >> 9) & 0x3F;
    let month = (v >> 5) & 0x0F;
    let day = v & 0x1F;
    let yy = year % 100;
    let date_part = format!("{:02}{:02}{:02}", yy, month, day);

    let tail_val = u16::from_be_bytes([idi_bytes[6], idi_bytes[7]]);
    let tail = format!("{:05}", tail_val);

    format!("{}{}{}", head, date_part, tail)
}

/// Format date from packed format
fn format_date(value: u16) -> String {
    let year = value >> 9;
    let month = (value >> 5) & 0x0F;
    let day = value & 0x1F;
    format!("{:02}-{:02}-{:02}", year, month, day)
}

/// Format time from packed format
fn format_time(value: u16) -> String {
    let hour = value >> 11;
    let minute = (value >> 5) & 0x3F;
    let second = (value & 0x1F) * 2;
    format!("{:02}:{:02}:{:02}", hour, minute, second)
}

/// Station information
#[derive(Debug, Clone)]
struct StationInfo {
    company_name: String,
    line_name: String,
    station_name: String,
}

/// Station code lookup with lazy loading and caching
/// Searches through the CSV file line by line to avoid loading the entire file
struct StationCodeLookup {
    csv_path: Option<String>,
    cache: RefCell<HashMap<(u8, u8), Option<StationInfo>>>,
}

impl StationCodeLookup {
    fn new(csv_path: Option<String>) -> Self {
        Self {
            csv_path,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Look up station info by line code and station order
    /// Returns None if not found or if no CSV file is configured
    fn lookup(&self, line_code: u8, station_order: u8) -> Option<StationInfo> {
        let key = (line_code, station_order);

        // Check cache first
        if let Some(cached) = self.cache.borrow().get(&key) {
            return cached.clone();
        }

        // No CSV file configured
        let csv_path = match &self.csv_path {
            Some(p) => p,
            None => {
                self.cache.borrow_mut().insert(key, None);
                return None;
            }
        };

        // Search through the file
        let result = self.search_in_file(csv_path, line_code, station_order);
        self.cache.borrow_mut().insert(key, result.clone());
        result
    }

    fn search_in_file(
        &self,
        csv_path: &str,
        line_code: u8,
        station_order: u8,
    ) -> Option<StationInfo> {
        let file = File::open(csv_path).ok()?;
        let reader = BufReader::new(file);

        let line_code_hex = format!("{:X}", line_code);
        let station_order_hex = format!("{:X}", station_order);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 6 {
                continue;
            }

            // CSV format: area_code, line_code, station_order, company, line, station, notes
            let csv_line_code = fields[1].trim().to_uppercase();
            let csv_station_order = fields[2].trim().to_uppercase();

            if csv_line_code == line_code_hex && csv_station_order == station_order_hex {
                return Some(StationInfo {
                    company_name: fields[3].to_string(),
                    line_name: fields[4].to_string(),
                    station_name: fields[5].to_string(),
                });
            }
        }

        None
    }

    /// Format station info as a string
    fn format_station(&self, line_code: u8, station_order: u8) -> String {
        match self.lookup(line_code, station_order) {
            Some(info) => format!(
                "{} {} {}",
                info.company_name, info.line_name, info.station_name
            ),
            None => format!(
                "不明 (線区コード: 0x{:02X}, 駅順コード: 0x{:02X})",
                line_code, station_order
            ),
        }
    }
}

// Thread-local station lookup instance
thread_local! {
    static STATION_LOOKUP: RefCell<Option<StationCodeLookup>> = const { RefCell::new(None) };
}

fn init_station_lookup(csv_path: Option<String>) {
    STATION_LOOKUP.with(|lookup| {
        *lookup.borrow_mut() = Some(StationCodeLookup::new(csv_path));
    });
}

fn format_station(line_code: u8, station_order: u8) -> String {
    STATION_LOOKUP.with(|lookup| {
        if let Some(ref lookup) = *lookup.borrow() {
            lookup.format_station(line_code, station_order)
        } else {
            format!("線区: 0x{:02X}, 駅順: 0x{:02X}", line_code, station_order)
        }
    })
}

/// CSV record for key data
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct KeyRecord {
    system_code: String,
    node: String,
    version: String,
    key: String,
}

/// Load keys from CSV file
/// CSV format: system_code,node,version,key (with header row)
fn load_keys_from_csv(path: &str) -> Result<HashMap<u16, [u8; 8]>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut csv_reader = ReaderBuilder::new()
        .has_headers(true)
        .trim(csv::Trim::All)
        .from_reader(file);

    let mut keys = HashMap::new();

    for (record_num, result) in csv_reader.deserialize().enumerate() {
        let record: KeyRecord = match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Warning: Failed to parse record {}: {}", record_num + 1, e);
                continue;
            }
        };

        let system_code = match u16::from_str_radix(&record.system_code, 16) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "Warning: Invalid system_code '{}' at record {}: {}",
                    record.system_code,
                    record_num + 1,
                    e
                );
                continue;
            }
        };

        if system_code != SUICA_SYSTEM_CODE {
            continue;
        }

        let node = match u16::from_str_radix(&record.node, 16) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "Warning: Invalid node '{}' at record {}: {}",
                    record.node,
                    record_num + 1,
                    e
                );
                continue;
            }
        };

        let key_bytes = match hex::decode(&record.key) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "Warning: Invalid key '{}' at record {}: {}",
                    record.key,
                    record_num + 1,
                    e
                );
                continue;
            }
        };

        if key_bytes.len() != 8 {
            eprintln!(
                "Warning: Invalid key length at record {} (expected 8 bytes, got {})",
                record_num + 1,
                key_bytes.len()
            );
            continue;
        }

        let mut key = [0u8; 8];
        key.copy_from_slice(&key_bytes);
        keys.insert(node, key);
    }

    Ok(keys)
}

/// Derive group and user service keys from hierarchical keys
fn derive_service_keys(
    keys: &HashMap<u16, [u8; 8]>,
    areas: &[u16],
    services: &[ServiceCode],
) -> Option<([u8; 8], [u8; 8])> {
    // Get system key (0xFFFF)
    let system_key = keys.get(&0xFFFF)?;

    // Collect area keys in order
    let mut area_keys = Vec::new();
    for &area in areas {
        if let Some(&key) = keys.get(&area) {
            area_keys.push(key);
        } else {
            return None;
        }
    }

    // Get service key
    let mut service_keys = Vec::new();
    for &service in services {
        if let Some(&key) = keys.get(&service.raw()) {
            service_keys.push(key);
        } else {
            return None;
        }
    }

    Some(generate_service_keys(system_key, &area_keys, &service_keys))
}

fn print_section(title: &str) {
    println!();
    println!("{}", title);
    println!("{}", "-".repeat(title.len()));
}

fn print_item(label: &str, value: impl std::fmt::Display) {
    println!("  - {}: {}", label, value);
}

fn print_usage() {
    eprintln!("Suica Card Dump Utility");
    eprintln!();
    eprintln!("Usage:");
    eprintln!(
        "  dump_suica --keys <keys.csv> [--station-codes <station_codes.csv>] [--remote <address:port>]"
    );
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --keys, -k <file>           Path to CSV file with keys (required)");
    eprintln!("  --station-codes, -s <file>  Path to station codes CSV file (optional)");
    eprintln!("  --remote, -r <addr>         Connect to remote reader server");
    eprintln!("                              (default: use local USB reader)");
    eprintln!("  --help, -h                  Show this help");
    eprintln!();
    eprintln!("CSV Format (with header row):");
    eprintln!("  system_code,node,version,key");
    eprintln!("  0003,FFFF,3,0123456789ABCDEF");
    eprintln!("  0003,0000,3,...");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse arguments
    let mut keys_path: Option<String> = None;
    let mut remote_addr: Option<String> = None;
    let mut station_codes_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--keys" | "-k" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --keys requires a file path argument");
                    print_usage();
                    std::process::exit(1);
                }
                keys_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--station-codes" | "-s" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --station-codes requires a file path argument");
                    print_usage();
                    std::process::exit(1);
                }
                station_codes_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--remote" | "-r" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --remote requires an address argument");
                    print_usage();
                    std::process::exit(1);
                }
                remote_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let keys_path = keys_path.unwrap_or_else(|| {
        eprintln!("Error: --keys argument is required");
        print_usage();
        std::process::exit(1);
    });

    // Initialize station lookup
    if let Some(ref path) = station_codes_path {
        println!("Station codes file: {}", path);
    }
    init_station_lookup(station_codes_path);

    // Load keys
    println!("Loading keys from {}...", keys_path);
    let keys = load_keys_from_csv(&keys_path)?;
    println!("Loaded {} keys", keys.len());

    if keys.is_empty() {
        eprintln!(
            "Error: No keys found for system code 0x{:04X}",
            SUICA_SYSTEM_CODE
        );
        std::process::exit(1);
    }

    // Run with appropriate driver
    if let Some(addr) = remote_addr {
        run_with_remote_driver(&addr, &keys)
    } else {
        run_with_local_driver(&keys)
    }
}

fn run_with_local_driver(keys: &HashMap<u16, [u8; 8]>) -> Result<(), Box<dyn Error>> {
    // Open local reader
    let preference = ReaderPreference::Auto;
    let mut reader = open_reader(preference).map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    println!(
        "Reader: {} - {}",
        reader.vendor_name().unwrap_or("Unknown"),
        reader.product_name().unwrap_or("Unknown")
    );

    // Poll for Suica card
    println!("Waiting for Suica card...");
    let (felica, _polling) =
        FelicaStandard::polling(reader.driver_mut(), "212F", SUICA_SYSTEM_CODE, 0x00, 0x00)?;

    let idm_hex = encode(felica.idm()).to_uppercase();
    let pmm_hex = encode(felica.pmm()).to_uppercase();

    print_section("カード識別");
    print_item("IDm", &idm_hex);
    print_item("PMm", &pmm_hex);

    // Prepare areas and services for authentication
    let areas: Vec<u16> = AREA_NODE_IDS.to_vec();
    let services: Vec<ServiceCode> = SERVICE_NODE_IDS
        .iter()
        .map(|&s| ServiceCode::new(s))
        .collect();

    let (group_service_key, user_service_key) = derive_service_keys(keys, &areas, &services)
        .ok_or_else(|| "Missing keys for authentication - check your keys.csv file")?;

    // Perform mutual authentication (need to re-poll)
    let (mut felica, _) =
        FelicaStandard::polling(reader.driver_mut(), "212F", SUICA_SYSTEM_CODE, 0x00, 0x00)?;

    let auth_result =
        felica.mutual_authentication(&areas, &services, &group_service_key, &user_service_key)?;

    let idi_str = idi_bytes_to_str(&auth_result.issue_id);
    let pmi_hex = encode(&auth_result.issue_parameter).to_uppercase();

    print_item("IDi", &idi_str);
    print_item("PMi", &pmi_hex);

    // Read encrypted blocks
    read_and_print_suica_data(&mut felica)?;

    Ok(())
}

fn run_with_remote_driver(addr: &str, keys: &HashMap<u16, [u8; 8]>) -> Result<(), Box<dyn Error>> {
    println!("Connecting to remote reader at {}...", addr);
    let mut driver = RemoteDriver::connect(addr)?;
    println!("Connected!");

    // Poll for Suica card
    println!("Waiting for Suica card...");
    let (felica, _polling) =
        FelicaStandard::polling(&mut driver, "212F", SUICA_SYSTEM_CODE, 0x00, 0x00)?;

    let idm_hex = encode(felica.idm()).to_uppercase();
    let pmm_hex = encode(felica.pmm()).to_uppercase();

    print_section("カード識別");
    print_item("IDm", &idm_hex);
    print_item("PMm", &pmm_hex);

    // Prepare areas and services for authentication
    let areas: Vec<u16> = AREA_NODE_IDS.to_vec();
    let services: Vec<ServiceCode> = SERVICE_NODE_IDS
        .iter()
        .map(|&s| ServiceCode::new(s))
        .collect();

    let (group_service_key, user_service_key) = derive_service_keys(keys, &areas, &services)
        .ok_or_else(|| "Missing keys for authentication - check your keys.csv file")?;

    // Perform mutual authentication (need to re-poll)
    let (mut felica, _) =
        FelicaStandard::polling(&mut driver, "212F", SUICA_SYSTEM_CODE, 0x00, 0x00)?;

    let auth_result =
        felica.mutual_authentication(&areas, &services, &group_service_key, &user_service_key)?;

    let idi_str = idi_bytes_to_str(&auth_result.issue_id);
    let pmi_hex = encode(&auth_result.issue_parameter).to_uppercase();

    print_item("IDi", &idi_str);
    print_item("PMi", &pmi_hex);

    // Read encrypted blocks
    read_and_print_suica_data(&mut felica)?;

    Ok(())
}

fn read_and_print_suica_data<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    // Read issue information (service index 0)
    print_issue_information(felica)?;

    // Read attribute information (service index 1)
    print_attribute_information(felica)?;

    // Read unknown information (service index 2)
    print_unknown_information(felica)?;

    // Read last topup information (service index 3)
    print_last_topup_information(felica)?;

    // Read transaction history (service index 4)
    print_transaction_history(felica)?;

    // Read commuter pass information (service index 6)
    print_commuter_pass_information(felica)?;

    // Read gate in/out information (service index 7)
    print_gate_in_out_information(felica)?;

    // Read SF gate entry information (service index 8)
    print_sf_gate_entry_information(felica)?;

    Ok(())
}

fn read_blocks<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    service_index: u8,
    block_count: usize,
) -> Result<Vec<[u8; 16]>, FelicaStandardError> {
    let mut blocks = Vec::with_capacity(block_count);

    for block_num in 0..block_count {
        let block_list = vec![BlockListElement::new(block_num as u16, service_index, 0)];
        match felica.read(&block_list) {
            Ok(read_blocks) => {
                if !read_blocks.is_empty() {
                    blocks.push(read_blocks[0]);
                }
            }
            Err(FelicaStandardError::Status { .. }) => {
                // No more blocks
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(blocks)
}

fn print_issue_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("発行情報");

    let blocks = read_blocks(felica, 0, 4)?;
    if blocks.len() < 4 {
        println!("  (データが不十分です)");
        return Ok(());
    }

    let owner_block = &blocks[0];
    let personal_block = &blocks[1];
    let secondary_idi_block = &blocks[2];
    let metadata_block = &blocks[3];

    // Owner name (Shift_JIS encoded)
    let name_bytes: Vec<u8> = owner_block
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect();
    let (name, _, _) = SHIFT_JIS.decode(&name_bytes);
    print_item("所有者名", name.trim());

    // Secondary IDi
    print_item("第二発行ID", idi_bytes_to_str(secondary_idi_block));

    // Phone number
    let phone = encode(&personal_block[0..8])
        .trim_end_matches('f')
        .to_string();
    print_item("所有者電話番号", phone);

    // Owner age
    let age = encode(&personal_block[8..9]);
    print_item("所有者年齢", age);

    // Owner date of birth
    let dob = u16::from_be_bytes([personal_block[9], personal_block[10]]);
    print_item("所有者生年月日", format_date(dob));

    // Deposit
    let deposit = u16::from_le_bytes([personal_block[12], personal_block[13]]);
    print_item("デポジット額", format!("{} 円", deposit));

    // Issuer ID
    let issuer_id = u16::from_be_bytes([metadata_block[0], metadata_block[1]]);
    print_item("発行者ID", issuer_id_to_str(issuer_id));

    // Equipment type
    let issued_by = metadata_block[2];
    print_item("発行機器", equipment_type_to_str(issued_by));

    // Issue station
    let issued_station_line = metadata_block[3];
    let issued_station_order = metadata_block[4];
    print_item(
        "発行駅",
        format_station(issued_station_line, issued_station_order),
    );

    // Issue date
    let issued_at = u16::from_be_bytes([metadata_block[7], metadata_block[8]]);
    print_item("発行日", format_date(issued_at));

    // Expiration date
    let expires_at = u16::from_be_bytes([metadata_block[14], metadata_block[15]]);
    print_item("有効期限", format_date(expires_at));

    Ok(())
}

fn print_attribute_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("属性情報");

    let blocks = read_blocks(felica, 1, 1)?;
    if blocks.is_empty() {
        println!("  (データが不十分です)");
        return Ok(());
    }

    let block = &blocks[0];

    let card_type = block[8] >> 4;
    print_item("カード種別", card_type_to_str(card_type));

    let region = block[8] & 0x0F;
    print_item("地域", region);

    let amount = u16::from_le_bytes([block[11], block[12]]);
    print_item("残高", format!("{} 円", amount));

    let transaction_number = u16::from_be_bytes([block[14], block[15]]);
    print_item("取引通番", transaction_number);

    Ok(())
}

fn print_transaction_history<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("取引履歴");

    let blocks = read_blocks(felica, 4, 20)?;
    if blocks.is_empty() {
        println!("  (履歴がありません)");
        return Ok(());
    }

    for (index, block) in blocks.iter().enumerate() {
        let recorded_by = block[0];
        if recorded_by == 0x00 {
            break;
        }

        let transaction_type = block[1] & 0x7F;
        let pay_type = block[2];
        let gate_instruction_type = block[3];
        let recorded_at = u16::from_be_bytes([block[4], block[5]]);

        println!("[{:02}] {}", index, format_date(recorded_at));
        print_item("機器", equipment_type_to_str(recorded_by));
        print_item("取引種別", transaction_type_to_str(transaction_type));
        print_item("支払種別", pay_type_to_str(pay_type));
        print_item(
            "改札処理",
            gate_instruction_type_to_str(gate_instruction_type),
        );

        if transaction_type == 0x46 {
            // 物販
            let time_value = u16::from_be_bytes([block[6], block[7]]);
            print_item("取引時刻", format_time(time_value));
        } else {
            let entry_station_line = block[6];
            let entry_station_order = block[7];
            let exit_station_line = block[8];
            let exit_station_order = block[9];
            print_item(
                "入場駅",
                format_station(entry_station_line, entry_station_order),
            );
            print_item(
                "出場駅",
                format_station(exit_station_line, exit_station_order),
            );
        }

        let amount = u16::from_le_bytes([block[10], block[11]]);
        let transaction_number = u16::from_be_bytes([block[13], block[14]]);
        print_item("残高", format!("{} 円", amount));
        print_item("取引通番", transaction_number);
        println!();
    }

    Ok(())
}

fn print_unknown_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("？？情報");

    let blocks = read_blocks(felica, 2, 1)?;
    if blocks.is_empty() {
        println!("  (データがありません)");
        return Ok(());
    }

    let block = &blocks[0];

    let amount = u16::from_le_bytes([block[0], block[1]]);
    print_item("不明な残高", format!("{} 円", amount));

    let unknown_date = u16::from_be_bytes([block[8], block[9]]);
    print_item("不明な日付", format_date(unknown_date));

    let transaction_number = u16::from_be_bytes([block[14], block[15]]);
    print_item("不明な取引通番", transaction_number);

    Ok(())
}

fn print_last_topup_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("最終チャージ情報");

    let blocks = read_blocks(felica, 3, 3)?;
    if blocks.is_empty() {
        println!("  (データがありません)");
        return Ok(());
    }

    let detail_block = &blocks[0];

    let topup_by = detail_block[0];
    print_item("チャージ機器", equipment_type_to_str(topup_by));

    let topup_station_line = detail_block[1];
    let topup_station_order = detail_block[2];
    print_item(
        "チャージ駅",
        format_station(topup_station_line, topup_station_order),
    );

    let topup_amount = u16::from_le_bytes([detail_block[5], detail_block[6]]);
    print_item("チャージ金額", format!("{} 円", topup_amount));

    Ok(())
}

fn print_commuter_pass_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("定期情報");

    let blocks = read_blocks(felica, 6, 3)?;
    if blocks.len() < 3 {
        println!("  (データが不十分です)");
        return Ok(());
    }

    let primary_block = &blocks[0];
    let supplemental_block = &blocks[2];

    let start_at = u16::from_be_bytes([primary_block[0], primary_block[1]]);
    print_item("開始日", format_date(start_at));

    let end_at = u16::from_be_bytes([primary_block[2], primary_block[3]]);
    print_item("終了日", format_date(end_at));

    let start_station_line = primary_block[8];
    let start_station_order = primary_block[9];
    print_item(
        "始点駅",
        format_station(start_station_line, start_station_order),
    );

    let end_station_line = primary_block[10];
    let end_station_order = primary_block[11];
    print_item(
        "終点駅",
        format_station(end_station_line, end_station_order),
    );

    let via1_station_line = primary_block[12];
    let via1_station_order = primary_block[13];
    print_item(
        "経由駅1",
        format_station(via1_station_line, via1_station_order),
    );

    let via2_station_line = primary_block[14];
    let via2_station_order = primary_block[15];
    print_item(
        "経由駅2",
        format_station(via2_station_line, via2_station_order),
    );

    let issued_at = u16::from_be_bytes([supplemental_block[5], supplemental_block[6]]);
    print_item("発行日", format_date(issued_at));

    Ok(())
}

fn print_gate_in_out_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("改札入出場情報");

    let blocks = read_blocks(felica, 7, 3)?;
    if blocks.is_empty() {
        println!("  (データがありません)");
        return Ok(());
    }

    for (index, block) in blocks.iter().enumerate() {
        let date = u16::from_be_bytes([block[6], block[7]]);
        let time_hex = encode(&block[8..10]);
        println!(
            "[{:02}] {} {}:{}",
            index,
            format_date(date),
            &time_hex[0..2],
            &time_hex[2..4]
        );

        let gate_in_out_type = block[0];
        print_item("改札入出場種別", gate_in_out_type_to_str(gate_in_out_type));

        let intermediate_gate_type = block[1];
        print_item(
            "中間改札処理種別",
            intermediate_gate_instruction_type_to_str(intermediate_gate_type),
        );

        let station_line = block[2];
        let station_order = block[3];
        print_item("入出場駅", format_station(station_line, station_order));

        let device_number = encode(&block[4..6]).to_uppercase();
        print_item("装置番号", device_number);

        let amount = u16::from_le_bytes([block[10], block[11]]);
        print_item("金額", format!("{} 円", amount));

        let commuter_pass_fee = u16::from_le_bytes([block[12], block[13]]);
        print_item("最寄定期区間までの運賃", commuter_pass_fee);

        let nearest_station_line = block[14];
        let nearest_station_order = block[15];
        print_item(
            "最寄定期区間の駅",
            format_station(nearest_station_line, nearest_station_order),
        );

        println!();
    }

    Ok(())
}

fn print_sf_gate_entry_information<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
) -> Result<(), FelicaStandardError> {
    print_section("SF改札入場情報");

    let blocks = read_blocks(felica, 8, 2)?;
    if blocks.len() < 2 {
        println!("  (データが不十分です)");
        return Ok(());
    }

    let first_block = &blocks[0];
    let second_block = &blocks[1];

    let entry_station_line = first_block[0];
    let entry_station_order = first_block[1];
    print_item(
        "入場駅",
        format_station(entry_station_line, entry_station_order),
    );

    let intermediate_date = u16::from_be_bytes([second_block[0], second_block[1]]);
    print_item(
        "料金収受対象中間改札入出場日付",
        format_date(intermediate_date),
    );

    let entry_time = encode(&second_block[2..4]);
    print_item(
        "中間改札入場時刻",
        format!("{}:{}", &entry_time[0..2], &entry_time[2..4]),
    );

    let intermediate_entry_station_line = second_block[4];
    let intermediate_entry_station_order = second_block[5];
    print_item(
        "中間改札入場駅",
        format_station(
            intermediate_entry_station_line,
            intermediate_entry_station_order,
        ),
    );

    print_item("不明値1", format!("0x{:02X}", second_block[6]));

    let exit_time = encode(&second_block[7..9]);
    print_item(
        "中間改札出場時刻",
        format!("{}:{}", &exit_time[0..2], &exit_time[2..4]),
    );

    let intermediate_exit_station_line = second_block[9];
    let intermediate_exit_station_order = second_block[10];
    print_item(
        "中間改札出場駅",
        format_station(
            intermediate_exit_station_line,
            intermediate_exit_station_order,
        ),
    );

    print_item("不明値2", format!("0x{:02X}", second_block[11]));

    Ok(())
}
