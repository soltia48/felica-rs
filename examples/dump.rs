//! NFC-F Card Dump Utility
//!
//! This utility dumps the structure and readable data from NFC-F cards.
//! It supports both local USB readers and remote readers via network.
//!
//! # Usage
//!
//! ```bash
//! # Local reader (auto-detect)
//! cargo run --example dump
//!
//! # Local reader with keys for authenticated services
//! cargo run --example dump -- --keys keys.jsonl
//!
//! # Remote reader
//! cargo run --example dump -- --remote 127.0.0.1:7878
//!
//! # Remote reader with keys for authenticated services
//! cargo run --example dump -- --keys keys.jsonl --remote 127.0.0.1:7878
//! ```

use hex::encode;
use nfc_rs::felica_standard::{
    BlockListElement, FelicaDriver, FelicaStandard, FelicaStandardError, SearchServiceCodeResult,
    ServiceCode, generate_service_keys,
};
use nfc_rs::{Reader, ReaderPreference, RemoteDriver, open_reader};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

const MAX_SERVICE_CODES_PER_REQUEST: usize = 0x20;
const BLOCKS_PER_READ_ATTEMPT: usize = 1;
const SYSTEM_SERVICE_CODE: u16 = 0xFFFF;
const ROOT_AREA_CODE: u16 = 0x0000;
const KEY_LENGTH_BYTES: usize = 8;

type NodeKeys = HashMap<u16, [u8; 8]>;
type IdmScopedKeys = HashMap<String, NodeKeys>;
type SystemKeys = HashMap<u16, IdmScopedKeys>;

#[derive(Debug, Serialize)]
struct DumpOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    reader: Option<ReaderInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteInfo>,
    systems: Vec<SystemSummary>,
}

#[derive(Debug, Serialize)]
struct ReaderInfo {
    vendor: String,
    product: String,
    chipset: String,
}

#[derive(Debug, Serialize)]
struct RemoteInfo {
    address: String,
}

#[derive(Debug, Serialize)]
struct SystemSummary {
    idm: String,
    pmm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    idi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pmi: Option<String>,
    system_code_hex: String,
    system_key: Option<KeyVersionSummary>,
    system_services: Vec<ServiceGroupSummary>,
    areas: Vec<AreaNode>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AreaNode {
    #[serde(skip_serializing)]
    area_code_raw: u16,
    area_code_hex: String,
    end_service_code_hex: String,
    key_version: Option<KeyVersionSummary>,
    children: Vec<AreaChild>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum AreaChild {
    Area(AreaNode),
    ServiceGroup(ServiceGroupSummary),
}

#[derive(Debug, Serialize)]
struct ServiceGroupSummary {
    number: u16,
    number_hex: String,
    services: Vec<ServiceSummary>,
    blocks: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ServiceSummary {
    #[serde(skip_serializing)]
    service_code_raw: u16,
    #[serde(skip_serializing)]
    attributes_raw: u8,
    code_hex: String,
    number: u16,
    attributes_hex: String,
    attributes_description: Option<String>,
    key_version: Option<KeyVersionSummary>,
}

#[derive(Debug, Serialize, Clone)]
struct KeyVersionSummary {
    aes_key_version_hex: Option<String>,
    des_key_version_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JsonlKeyRecord {
    system_code: String,
    node: String,
    algo: String,
    version: String,
    #[serde(default)]
    idm: Option<String>,
    key: String,
}

#[derive(Debug, Clone)]
struct AuthReadTarget {
    service_code_raw: u16,
    area_codes: Vec<u16>,
}

#[derive(Debug, Clone)]
struct MutualAuthSummary {
    idi: String,
    pmi: String,
}

#[derive(Debug)]
struct AuthReadResult {
    blocks: Vec<String>,
    auth_summary: MutualAuthSummary,
}

#[derive(Debug, Default)]
struct CliOptions {
    remote_addr: Option<String>,
    keys_path: Option<String>,
}

enum CliAction {
    Run(CliOptions),
    ShowHelp,
}

fn parse_hex_u16(value: &str) -> Result<u16, std::num::ParseIntError> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u16::from_str_radix(without_prefix, 16)
}

fn parse_idm_hex(value: &str) -> Result<Option<String>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let compact: String = without_prefix
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    let bytes = hex::decode(&compact).map_err(|err| err.to_string())?;
    if bytes.len() != KEY_LENGTH_BYTES {
        return Err(format!("expected 8 bytes, got {}", bytes.len()));
    }
    Ok(Some(hex::encode(bytes).to_uppercase()))
}

fn parse_hex_u16_key_field(record_num: usize, field: &str, value: &str) -> Option<u16> {
    match parse_hex_u16(value) {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            eprintln!(
                "Warning: Invalid {} '{}' at key record {}: {}",
                field, value, record_num, err
            );
            None
        }
    }
}

fn parse_idm_key_field(record_num: usize, value: &str) -> Option<Option<String>> {
    match parse_idm_hex(value) {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            eprintln!(
                "Warning: Invalid idm '{}' at key record {}: {}",
                value, record_num, err
            );
            None
        }
    }
}

fn parse_optional_idm_key_field(record_num: usize, value: Option<&str>) -> Option<Option<String>> {
    match value {
        Some(idm) => parse_idm_key_field(record_num, idm),
        None => Some(None),
    }
}

fn parse_key_bytes_field(record_num: usize, value: &str) -> Option<[u8; KEY_LENGTH_BYTES]> {
    let key_bytes = match hex::decode(value) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!(
                "Warning: Invalid key '{}' at key record {}: {}",
                value, record_num, err
            );
            return None;
        }
    };

    if key_bytes.len() != KEY_LENGTH_BYTES {
        eprintln!(
            "Warning: Invalid key length at key record {} (expected {} bytes, got {})",
            record_num,
            KEY_LENGTH_BYTES,
            key_bytes.len()
        );
        return None;
    }

    let mut key = [0u8; KEY_LENGTH_BYTES];
    key.copy_from_slice(&key_bytes);
    Some(key)
}

fn load_keys_from_jsonl(path: &str) -> Result<SystemKeys, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut keys_by_system: SystemKeys = HashMap::new();

    for (index, line_result) in reader.lines().enumerate() {
        let line_num = index + 1;
        let line = match line_result {
            Ok(line) => line,
            Err(err) => {
                eprintln!("Warning: Failed to read key line {}: {}", line_num, err);
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let record: JsonlKeyRecord = match serde_json::from_str(trimmed) {
            Ok(record) => record,
            Err(err) => {
                eprintln!(
                    "Warning: Failed to parse key JSONL line {}: {}",
                    line_num, err
                );
                continue;
            }
        };

        if !record.algo.eq_ignore_ascii_case("DES") {
            eprintln!(
                "Warning: Unsupported algo '{}' at key line {}; only DES is supported",
                record.algo, line_num
            );
            continue;
        }

        let Some(system_code) =
            parse_hex_u16_key_field(line_num, "system_code", &record.system_code)
        else {
            continue;
        };
        let Some(node_code) = parse_hex_u16_key_field(line_num, "node", &record.node) else {
            continue;
        };
        let Some(idm) = parse_optional_idm_key_field(line_num, record.idm.as_deref()) else {
            continue;
        };
        let Some(key) = parse_key_bytes_field(line_num, &record.key) else {
            continue;
        };

        keys_by_system
            .entry(system_code)
            .or_default()
            .entry(idm.unwrap_or_default())
            .or_default()
            .insert(node_code, key);
    }

    Ok(keys_by_system)
}

fn resolve_keys_for_card(
    key_store: &SystemKeys,
    system_code: u16,
    idm_hex: &str,
) -> Option<NodeKeys> {
    let idm_scoped = key_store.get(&system_code)?;
    let mut merged = NodeKeys::new();

    if let Some(common_keys) = idm_scoped.get("") {
        merged.extend(common_keys.iter().map(|(code, key)| (*code, *key)));
    }
    if let Some(card_keys) = idm_scoped.get(idm_hex) {
        merged.extend(card_keys.iter().map(|(code, key)| (*code, *key)));
    }

    if merged.is_empty() {
        None
    } else {
        Some(merged)
    }
}

fn print_usage() {
    eprintln!("NFC-F Card Dump Utility");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  dump [--keys <file>]                         Use local reader (auto-detect)");
    eprintln!("  dump [--keys <file>] --remote <address:port> Use remote reader");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --keys, -k <file>           Path to JSONL file with keys (optional)");
    eprintln!("  --remote, -r <addr>         Connect to remote reader server");
    eprintln!("  --help, -h                  Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  cargo run --example dump");
    eprintln!("  cargo run --example dump -- --keys keys.jsonl");
    eprintln!("  cargo run --example dump -- --remote 127.0.0.1:7878");
    eprintln!("  cargo run --example dump -- --keys keys.jsonl --remote 127.0.0.1:7878");
    eprintln!();
    eprintln!("JSONL Format (one JSON object per line):");
    eprintln!(
        "  {{\"system_code\":\"0003\",\"node\":\"FFFF\",\"algo\":\"DES\",\"version\":\"0003\",\"idm\":null,\"key\":\"0123456789ABCDEF\"}}"
    );
    eprintln!(
        "  {{\"system_code\":\"0003\",\"node\":\"090A\",\"algo\":\"DES\",\"version\":\"0003\",\"idm\":\"0123456789ABCDEF\",\"key\":\"0123456789ABCDEF\"}}"
    );
    eprintln!("  (idm null means shared key for all cards in the system)");
}

fn parse_cli_args(args: &[String]) -> Result<CliAction, String> {
    let mut options = CliOptions::default();
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--keys" | "-k" => {
                let Some(path) = args.get(index + 1) else {
                    return Err("--keys requires a file path argument".to_string());
                };
                options.keys_path = Some(path.clone());
                index += 2;
            }
            "--remote" | "-r" => {
                let Some(addr) = args.get(index + 1) else {
                    return Err("--remote requires an address argument".to_string());
                };
                options.remote_addr = Some(addr.clone());
                index += 2;
            }
            "--help" | "-h" => return Ok(CliAction::ShowHelp),
            unknown => return Err(format!("Unknown argument: {}", unknown)),
        }
    }

    Ok(CliAction::Run(options))
}

fn boxed_error<E>(err: E) -> Box<dyn Error>
where
    E: Error + 'static,
{
    Box::new(err)
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let options = match parse_cli_args(&args) {
        Ok(CliAction::Run(options)) => options,
        Ok(CliAction::ShowHelp) => {
            print_usage();
            return Ok(());
        }
        Err(message) => {
            eprintln!("Error: {}", message);
            print_usage();
            std::process::exit(1);
        }
    };

    let key_store = match options.keys_path.as_deref() {
        Some(path) => Some(load_keys_from_jsonl(path)?),
        None => None,
    };

    let output = if let Some(addr) = options.remote_addr.as_deref() {
        run_remote_dump(addr, key_store.as_ref())?
    } else {
        run_local_dump(key_store.as_ref())?
    };

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

fn run_local_dump(key_store: Option<&SystemKeys>) -> Result<DumpOutput, Box<dyn Error>> {
    let preference = ReaderPreference::Auto;
    let mut reader = open_reader(preference).map_err(boxed_error)?;

    let reader_info = build_reader_info(&reader);
    let system_codes = discover_system_codes(reader.driver_mut()).map_err(boxed_error)?;
    let systems = collect_system_summaries(reader.driver_mut(), &system_codes, key_store)
        .map_err(boxed_error)?;

    Ok(DumpOutput {
        reader: Some(reader_info),
        remote: None,
        systems,
    })
}

fn run_remote_dump(
    addr: &str,
    key_store: Option<&SystemKeys>,
) -> Result<DumpOutput, Box<dyn Error>> {
    let mut driver = RemoteDriver::connect(addr)?;

    let system_codes = discover_system_codes(&mut driver).map_err(boxed_error)?;
    let systems =
        collect_system_summaries(&mut driver, &system_codes, key_store).map_err(boxed_error)?;

    Ok(DumpOutput {
        reader: None,
        remote: Some(RemoteInfo {
            address: addr.to_string(),
        }),
        systems,
    })
}

fn build_reader_info(reader: &Reader) -> ReaderInfo {
    ReaderInfo {
        vendor: reader
            .vendor_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown Vendor".into()),
        product: reader
            .product_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown Device".into()),
        chipset: reader.chipset_name().to_string(),
    }
}

fn discover_system_codes<D: FelicaDriver + ?Sized>(
    driver: &mut D,
) -> Result<Vec<u16>, FelicaStandardError> {
    let (mut felica, _polling) = FelicaStandard::polling(driver, "212F", 0xFFFF, 0x00, 0x00)?;
    felica.request_system_code()
}

fn collect_system_summaries<D: FelicaDriver + ?Sized>(
    driver: &mut D,
    system_codes: &[u16],
    key_store: Option<&SystemKeys>,
) -> Result<Vec<SystemSummary>, FelicaStandardError> {
    let mut systems = Vec::with_capacity(system_codes.len());
    for &system_code in system_codes {
        systems.push(summarize_system(driver, system_code, key_store)?);
    }
    Ok(systems)
}

fn summarize_system<D: FelicaDriver + ?Sized>(
    driver: &mut D,
    system_code: u16,
    key_store: Option<&SystemKeys>,
) -> Result<SystemSummary, FelicaStandardError> {
    let (mut felica, _polling) = FelicaStandard::polling(driver, "212F", system_code, 0x00, 0x00)?;
    let idm = encode(felica.idm()).to_uppercase();
    let pmm = encode(felica.pmm()).to_uppercase();

    let mut seen_codes = HashSet::new();
    let mut key_request_codes = Vec::new();
    register_service_code(&mut key_request_codes, &mut seen_codes, SYSTEM_SERVICE_CODE);

    let (mut areas, mut system_services, mut warnings) =
        collect_system_areas(&mut felica, &mut key_request_codes, &mut seen_codes)?;

    let mut key_versions = fetch_key_versions(&mut felica, &key_request_codes, &mut warnings);

    let system_key = key_versions.remove(&SYSTEM_SERVICE_CODE);
    assign_system_key_versions(&mut system_services, &mut key_versions);
    for area in &mut areas {
        assign_area_key_versions(area, &mut key_versions);
    }

    if let Err(err) =
        read_plaintext_services(&mut felica, &mut areas, &mut system_services, &mut warnings)
    {
        warnings.push(format!(
            "Reading plaintext blocks failed for system 0x{:04X}: {}",
            system_code, err
        ));
    }

    let system_keys = key_store.and_then(|store| resolve_keys_for_card(store, system_code, &idm));
    let mut mutual_auth_summary = None;
    if let Some(keys) = system_keys.as_ref() {
        mutual_auth_summary = read_authenticated_services(
            &mut felica,
            &mut areas,
            &mut system_services,
            keys,
            &mut warnings,
        );
    } else if key_store.is_some() {
        warnings.push(format!(
            "No external keys available for system 0x{:04X} and IDm {}; skipping authenticated reads",
            system_code, idm
        ));
    }

    if !key_versions.is_empty() {
        let unknown_codes = key_versions
            .keys()
            .map(|code| hex_u16(*code))
            .collect::<Vec<_>>()
            .join(", ");
        warnings.push(format!(
            "Key versions returned for unknown codes: [{}]",
            unknown_codes
        ));
    }

    Ok(SystemSummary {
        idm,
        pmm,
        idi: mutual_auth_summary
            .as_ref()
            .map(|summary| summary.idi.clone()),
        pmi: mutual_auth_summary
            .as_ref()
            .map(|summary| summary.pmi.clone()),
        system_code_hex: hex_u16(system_code),
        system_key,
        system_services,
        areas,
        warnings,
    })
}

fn fetch_key_versions<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    key_request_codes: &[ServiceCode],
    warnings: &mut Vec<String>,
) -> HashMap<u16, KeyVersionSummary> {
    let mut key_versions = HashMap::new();
    for chunk in key_request_codes.chunks(MAX_SERVICE_CODES_PER_REQUEST) {
        match request_key_versions(felica, chunk) {
            Ok((summaries, warning)) => {
                store_key_versions(&mut key_versions, chunk, summaries);
                if let Some(message) = warning {
                    warnings.push(message);
                }
            }
            Err(err) => {
                warnings.push(format!("Request Service failed: {}", err));
            }
        }
    }
    key_versions
}

fn collect_system_areas<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    key_request_codes: &mut Vec<ServiceCode>,
    seen_codes: &mut HashSet<u16>,
) -> Result<(Vec<AreaNode>, Vec<ServiceGroupSummary>, Vec<String>), FelicaStandardError> {
    let mut areas = Vec::new();
    let mut system_services = Vec::new();
    let mut warnings = Vec::new();
    let mut index = 0u16;
    loop {
        match felica.search_service_code(index)? {
            None => break,
            Some(SearchServiceCodeResult::Area {
                area_code,
                end_service_code,
            }) => {
                let Some(child_index) = index.checked_add(1) else {
                    warnings.push(format!(
                        "Directory index overflow while descending into area 0x{:04X}",
                        area_code
                    ));
                    break;
                };
                let (area, next_index) = collect_area(
                    felica,
                    area_code,
                    end_service_code,
                    child_index,
                    key_request_codes,
                    seen_codes,
                    &mut warnings,
                )?;
                areas.push(area);
                if next_index <= index {
                    warnings.push(format!(
                        "Area traversal did not advance at directory index 0x{:04X}",
                        index
                    ));
                    break;
                }
                index = next_index;
            }
            Some(SearchServiceCodeResult::Service(service_code)) => {
                warnings.push(format!(
                    "Service 0x{:04X} at index 0x{:04X} has no parent area; treating as system-level service",
                    service_code.raw(),
                    index
                ));
                register_service_code(key_request_codes, seen_codes, service_code.raw());
                append_service_group(&mut system_services, build_service_summary(&service_code));
                let Some(next_index) = index.checked_add(1) else {
                    warnings.push(
                        "Directory index overflow while reading system-level services".into(),
                    );
                    break;
                };
                index = next_index;
            }
        }
    }
    Ok((areas, system_services, warnings))
}

fn collect_area<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    area_code: u16,
    end_service_code: u16,
    mut index: u16,
    key_request_codes: &mut Vec<ServiceCode>,
    seen_codes: &mut HashSet<u16>,
    warnings: &mut Vec<String>,
) -> Result<(AreaNode, u16), FelicaStandardError> {
    register_service_code(key_request_codes, seen_codes, area_code);

    let mut children = Vec::new();
    loop {
        match felica.search_service_code(index)? {
            Some(SearchServiceCodeResult::Service(service_code)) => {
                let service_code_raw = service_code.raw();
                if service_code_raw < area_code || service_code_raw > end_service_code {
                    break;
                }
                register_service_code(key_request_codes, seen_codes, service_code_raw);
                append_service_child(&mut children, build_service_summary(&service_code));
                let Some(next_index) = index.checked_add(1) else {
                    warnings.push(format!(
                        "Directory index overflow while traversing area 0x{:04X}",
                        area_code
                    ));
                    break;
                };
                index = next_index;
            }
            Some(SearchServiceCodeResult::Area {
                area_code: child_code,
                end_service_code: child_end,
            }) => {
                if child_end < child_code {
                    warnings.push(format!(
                        "Area 0x{:04X} end service code 0x{:04X} precedes start 0x{:04X}",
                        child_code, child_end, child_code
                    ));
                    break;
                }
                if child_code < area_code || child_end > end_service_code {
                    break;
                }
                let Some(child_index) = index.checked_add(1) else {
                    warnings.push(format!(
                        "Directory index overflow while descending into area 0x{:04X}",
                        child_code
                    ));
                    break;
                };
                let (child_area, next_index) = collect_area(
                    felica,
                    child_code,
                    child_end,
                    child_index,
                    key_request_codes,
                    seen_codes,
                    warnings,
                )?;
                children.push(AreaChild::Area(child_area));
                if next_index <= index {
                    warnings.push(format!(
                        "Child area traversal did not advance at directory index 0x{:04X}",
                        index
                    ));
                    break;
                }
                index = next_index;
            }
            None => {
                break;
            }
        }
    }

    Ok((
        AreaNode {
            area_code_raw: area_code,
            area_code_hex: hex_u16(area_code),
            end_service_code_hex: hex_u16(end_service_code),
            key_version: None,
            children,
        },
        index,
    ))
}

fn build_service_summary(service_code: &ServiceCode) -> ServiceSummary {
    let service_code_raw = service_code.raw();
    ServiceSummary {
        service_code_raw,
        attributes_raw: service_code.attributes(),
        code_hex: hex_u16(service_code_raw),
        number: service_code.number(),
        attributes_hex: hex_u8(service_code.attributes()),
        attributes_description: service_code
            .attributes_description()
            .map(|desc| desc.to_string()),
        key_version: None,
    }
}

fn new_service_group(summary: ServiceSummary) -> ServiceGroupSummary {
    let number = summary.number;
    ServiceGroupSummary {
        number,
        number_hex: hex_u16(number),
        services: vec![summary],
        blocks: None,
    }
}

fn find_child_group_mut(
    children: &mut [AreaChild],
    number: u16,
) -> Option<&mut ServiceGroupSummary> {
    children.iter_mut().find_map(|child| match child {
        AreaChild::ServiceGroup(group) if group.number == number => Some(group),
        _ => None,
    })
}

fn append_service_child(children: &mut Vec<AreaChild>, summary: ServiceSummary) {
    if let Some(group) = find_child_group_mut(children, summary.number) {
        group.services.push(summary);
    } else {
        children.push(AreaChild::ServiceGroup(new_service_group(summary)));
    }
}

fn append_service_group(groups: &mut Vec<ServiceGroupSummary>, summary: ServiceSummary) {
    if let Some(group) = groups
        .iter_mut()
        .find(|group| group.number == summary.number)
    {
        group.services.push(summary);
    } else {
        groups.push(new_service_group(summary));
    }
}

fn register_service_code(
    service_codes: &mut Vec<ServiceCode>,
    seen_codes: &mut HashSet<u16>,
    code: u16,
) {
    if seen_codes.insert(code) {
        service_codes.push(ServiceCode::new(code));
    }
}

fn store_key_versions(
    map: &mut HashMap<u16, KeyVersionSummary>,
    service_codes: &[ServiceCode],
    summaries: Vec<KeyVersionSummary>,
) {
    for (service_code, summary) in service_codes.iter().zip(summaries.into_iter()) {
        map.insert(service_code.raw(), summary);
    }
}

fn assign_area_key_versions(
    area: &mut AreaNode,
    key_versions: &mut HashMap<u16, KeyVersionSummary>,
) {
    if let Some(summary) = key_versions.remove(&area.area_code_raw) {
        area.key_version = Some(summary);
    }
    for child in &mut area.children {
        match child {
            AreaChild::Area(child_area) => assign_area_key_versions(child_area, key_versions),
            AreaChild::ServiceGroup(group) => assign_group_key_versions(group, key_versions),
        }
    }
}

fn assign_system_key_versions(
    system_services: &mut [ServiceGroupSummary],
    key_versions: &mut HashMap<u16, KeyVersionSummary>,
) {
    for group in system_services {
        assign_group_key_versions(group, key_versions);
    }
}

fn assign_group_key_versions(
    group: &mut ServiceGroupSummary,
    key_versions: &mut HashMap<u16, KeyVersionSummary>,
) {
    for service in &mut group.services {
        if let Some(summary) = key_versions.remove(&service.service_code_raw) {
            service.key_version = Some(summary);
        }
    }
}

fn read_plaintext_services<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    areas: &mut [AreaNode],
    system_services: &mut [ServiceGroupSummary],
    warnings: &mut Vec<String>,
) -> Result<(), FelicaStandardError> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    collect_plaintext_service_codes(areas, system_services, &mut targets, &mut seen);
    if targets.is_empty() {
        return Ok(());
    }

    let mut read_results: HashMap<u16, Vec<String>> = HashMap::new();
    for code in targets {
        match read_service_blocks(felica, code) {
            Ok(blocks) => store_read_result(&mut read_results, code, blocks),
            Err(err) => warnings.push(format!(
                "Read Without Encryption failed for service 0x{:04X}: {}",
                code, err
            )),
        }
    }

    assign_blocks(areas, system_services, &mut read_results);
    Ok(())
}

fn store_read_result(
    read_results: &mut HashMap<u16, Vec<String>>,
    service_code_raw: u16,
    blocks: Vec<String>,
) {
    if !blocks.is_empty() {
        read_results.insert(service_code_raw, blocks);
    }
}

fn read_authenticated_services<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    areas: &mut [AreaNode],
    system_services: &mut [ServiceGroupSummary],
    keys: &NodeKeys,
    warnings: &mut Vec<String>,
) -> Option<MutualAuthSummary> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    collect_authenticated_service_codes(areas, system_services, &mut targets, &mut seen);
    if targets.is_empty() {
        return None;
    }

    let mut read_results: HashMap<u16, Vec<String>> = HashMap::new();
    let mut mutual_auth_summary = None;
    for target in targets {
        match read_service_blocks_with_auth(felica, &target, keys) {
            Ok(result) => {
                if mutual_auth_summary.is_none() {
                    mutual_auth_summary = Some(result.auth_summary.clone());
                }
                store_read_result(&mut read_results, target.service_code_raw, result.blocks);
            }
            Err(err) => warnings.push(format!(
                "Authenticated Read failed for service {}: {}",
                hex_u16(target.service_code_raw),
                err
            )),
        }
    }

    assign_blocks(areas, system_services, &mut read_results);
    mutual_auth_summary
}

fn collect_authenticated_service_codes(
    areas: &[AreaNode],
    system_services: &[ServiceGroupSummary],
    targets: &mut Vec<AuthReadTarget>,
    seen: &mut HashSet<u16>,
) {
    for group in system_services {
        collect_group_authenticated_targets(group, &[], targets, seen);
    }

    for area in areas {
        let mut area_path = vec![area.area_code_raw];
        collect_authenticated_children(&area.children, &mut area_path, targets, seen);
    }
}

fn collect_authenticated_children(
    children: &[AreaChild],
    area_path: &mut Vec<u16>,
    targets: &mut Vec<AuthReadTarget>,
    seen: &mut HashSet<u16>,
) {
    for child in children {
        match child {
            AreaChild::Area(area) => {
                area_path.push(area.area_code_raw);
                collect_authenticated_children(&area.children, area_path, targets, seen);
                area_path.pop();
            }
            AreaChild::ServiceGroup(group) => {
                collect_group_authenticated_targets(group, area_path, targets, seen)
            }
        }
    }
}

fn collect_group_authenticated_targets(
    group: &ServiceGroupSummary,
    area_path: &[u16],
    targets: &mut Vec<AuthReadTarget>,
    seen: &mut HashSet<u16>,
) {
    if group.blocks.is_some() {
        return;
    }

    for service in &group.services {
        if service.attributes_raw & 0x01 == 0 && seen.insert(service.service_code_raw) {
            targets.push(AuthReadTarget {
                service_code_raw: service.service_code_raw,
                area_codes: area_path.to_vec(),
            });
        }
    }
}

fn derive_service_keys_for_auth(
    keys: &NodeKeys,
    area_codes: &[u16],
    service_code: ServiceCode,
) -> Result<([u8; 8], [u8; 8]), String> {
    let system_key = keys
        .get(&SYSTEM_SERVICE_CODE)
        .ok_or_else(|| "missing system key 0xFFFF".to_string())?;

    let mut area_keys = Vec::with_capacity(area_codes.len());
    for area_code in area_codes {
        let key = keys
            .get(area_code)
            .ok_or_else(|| format!("missing area key {}", hex_u16(*area_code)))?;
        area_keys.push(*key);
    }

    let service_key = keys
        .get(&service_code.raw())
        .ok_or_else(|| format!("missing service key {}", hex_u16(service_code.raw())))?;

    let service_keys = [*service_key];
    Ok(generate_service_keys(system_key, &area_keys, &service_keys))
}

fn normalize_area_path_for_auth(area_codes: &[u16]) -> Vec<u16> {
    let mut normalized = Vec::with_capacity(area_codes.len() + 1);
    normalized.push(ROOT_AREA_CODE);
    for &area_code in area_codes {
        if area_code != ROOT_AREA_CODE {
            normalized.push(area_code);
        }
    }
    normalized
}

fn append_blocks_hex<B: AsRef<[u8]>>(blocks_hex: &mut Vec<String>, blocks: Vec<B>) {
    for block in blocks {
        blocks_hex.push(hex::encode(block.as_ref()).to_uppercase());
    }
}

fn read_service_blocks_with_auth<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    target: &AuthReadTarget,
    keys: &NodeKeys,
) -> Result<AuthReadResult, String> {
    let service_code = ServiceCode::new(target.service_code_raw);
    let area_codes = normalize_area_path_for_auth(&target.area_codes);
    let (group_service_key, user_service_key) =
        derive_service_keys_for_auth(keys, &area_codes, service_code)?;

    let auth_result = felica
        .mutual_authentication(
            &area_codes,
            &[service_code],
            &group_service_key,
            &user_service_key,
        )
        .map_err(|err| format!("Mutual Authentication failed: {}", err))?;
    let auth_summary = MutualAuthSummary {
        idi: encode(&auth_result.issue_id).to_uppercase(),
        pmi: encode(&auth_result.issue_parameter).to_uppercase(),
    };

    let mut blocks_hex = Vec::new();
    let mut block_number: u16 = 0;
    loop {
        let block_list = [BlockListElement::new(block_number, 0, 0)];
        match felica.read(&block_list) {
            Ok(blocks) if blocks.is_empty() => break,
            Ok(blocks) => {
                append_blocks_hex(&mut blocks_hex, blocks);
                block_number = match block_number.checked_add(1) {
                    Some(next) => next,
                    None => break,
                };
            }
            Err(FelicaStandardError::Status { .. }) => break,
            Err(err) => {
                return Err(format!("Read failed at block {}: {}", block_number, err));
            }
        }
    }

    Ok(AuthReadResult {
        blocks: blocks_hex,
        auth_summary,
    })
}

fn collect_plaintext_service_codes(
    areas: &[AreaNode],
    system_services: &[ServiceGroupSummary],
    targets: &mut Vec<u16>,
    seen: &mut HashSet<u16>,
) {
    for area in areas {
        collect_plaintext_children(&area.children, targets, seen);
    }
    for group in system_services {
        collect_plaintext_service_group(group, targets, seen);
    }
}

fn collect_plaintext_children(
    children: &[AreaChild],
    targets: &mut Vec<u16>,
    seen: &mut HashSet<u16>,
) {
    for child in children {
        match child {
            AreaChild::Area(area) => collect_plaintext_children(&area.children, targets, seen),
            AreaChild::ServiceGroup(group) => collect_plaintext_service_group(group, targets, seen),
        }
    }
}

fn collect_plaintext_service_group(
    group: &ServiceGroupSummary,
    targets: &mut Vec<u16>,
    seen: &mut HashSet<u16>,
) {
    if let Some(service) = group
        .services
        .iter()
        .find(|service| service.attributes_raw & 0x01 == 0x01)
    {
        if seen.insert(service.service_code_raw) {
            targets.push(service.service_code_raw);
        }
    }
}

fn read_service_blocks<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    service_code_raw: u16,
) -> Result<Vec<String>, FelicaStandardError> {
    let service = ServiceCode::new(service_code_raw);
    let services = vec![service];
    let mut blocks_hex = Vec::new();
    let mut block_number: u16 = 0;

    loop {
        let mut block_list = Vec::with_capacity(BLOCKS_PER_READ_ATTEMPT);
        for offset in 0..BLOCKS_PER_READ_ATTEMPT {
            let number = block_number.wrapping_add(offset as u16);
            block_list.push(BlockListElement::new(number, 0, 0));
        }

        match felica.read_without_encryption(&services, &block_list) {
            Ok(blocks) if blocks.is_empty() => break,
            Ok(blocks) => {
                append_blocks_hex(&mut blocks_hex, blocks);
                match block_number.checked_add(block_list.len() as u16) {
                    Some(next) => block_number = next,
                    None => break,
                }
            }
            Err(FelicaStandardError::Status { .. }) => break,
            Err(err) => return Err(err),
        }
    }

    Ok(blocks_hex)
}

fn assign_blocks(
    areas: &mut [AreaNode],
    system_services: &mut [ServiceGroupSummary],
    results: &mut HashMap<u16, Vec<String>>,
) {
    for area in areas {
        assign_blocks_in_area(area, results);
    }
    for group in system_services {
        assign_blocks_in_group(group, results);
    }
}

fn assign_blocks_in_area(area: &mut AreaNode, results: &mut HashMap<u16, Vec<String>>) {
    for child in &mut area.children {
        match child {
            AreaChild::Area(child_area) => assign_blocks_in_area(child_area, results),
            AreaChild::ServiceGroup(group) => assign_blocks_in_group(group, results),
        }
    }
}

fn assign_blocks_in_group(
    group: &mut ServiceGroupSummary,
    results: &mut HashMap<u16, Vec<String>>,
) {
    if group.blocks.is_some() {
        return;
    }
    for service in &group.services {
        if let Some(blocks) = results.remove(&service.service_code_raw) {
            group.blocks = Some(blocks);
            break;
        }
    }
}

fn request_key_versions<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    service_codes: &[ServiceCode],
) -> Result<(Vec<KeyVersionSummary>, Option<String>), FelicaStandardError> {
    if service_codes.is_empty() {
        return Ok((Vec::new(), None));
    }

    match felica.request_service_v2(service_codes) {
        Ok(key_versions) => Ok((
            key_versions
                .into_iter()
                .map(|key_version| KeyVersionSummary {
                    aes_key_version_hex: hex_opt_u16(key_version.primary()),
                    des_key_version_hex: key_version.secondary().map(hex_u16),
                })
                .collect(),
            None,
        )),
        Err(err) => {
            let warning = format!("Request Service v2 failed: {}", err);
            let fallback_versions = felica.request_service(service_codes)?;
            Ok((
                fallback_versions
                    .into_iter()
                    .map(|key_version| KeyVersionSummary {
                        aes_key_version_hex: None,
                        des_key_version_hex: hex_opt_u16(Some(key_version)),
                    })
                    .collect(),
                Some(warning),
            ))
        }
    }
}

fn hex_u16(value: u16) -> String {
    format!("0x{:04X}", value)
}

fn hex_u8(value: u8) -> String {
    format!("0x{:02X}", value)
}

fn hex_opt_u16(value: Option<u16>) -> Option<String> {
    value.map(hex_u16)
}
