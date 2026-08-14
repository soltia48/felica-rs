//! NFC-F Card Dump Utility
//!
//! This utility dumps the structure and readable data from NFC-F cards.
//! It supports both local USB readers and remote readers via network.
//!
//! By default the card is rendered as a human-friendly tree. Pass `--json`
//! (or `--format json`) to emit the machine-readable JSON instead.
//!
//! # Usage
//!
//! ```bash
//! # Local reader (auto-detect), human-readable tree output
//! cargo run --example dump
//!
//! # Machine-readable JSON output
//! cargo run --example dump -- --json
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

use felica::felica_standard::{
    BlockListElement, FelicaDriver, FelicaStandard, FelicaStandardError, KeyStore,
    ResolvedNodeKeys, SearchServiceCodeResult, ServiceCode,
};
use felica::{Reader, ReaderPreference, RemoteDriver, open_reader};
use hex::encode;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::IsTerminal;
use std::time::Duration;

const MAX_SERVICE_CODES_PER_REQUEST: usize = 0x20;
const BLOCKS_PER_READ_ATTEMPT: usize = 1;
const SYSTEM_SERVICE_CODE: u16 = 0xFFFF;
/// How long to wait between polling attempts while no card is on the reader.
const POLL_RETRY_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Serialize)]
struct DumpOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    reader: Option<ReaderInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteInfo>,
    /// FeliCa bitrate the card was detected at ("212F" or "424F").
    data_rate: String,
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
    format: OutputFormat,
}

/// How the collected card structure is presented on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum OutputFormat {
    /// Colorized, indented tree meant for reading on a terminal.
    #[default]
    Human,
    /// Pretty-printed JSON meant for scripts and further processing.
    Json,
}

enum CliAction {
    Run(CliOptions),
    ShowHelp,
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
    eprintln!("  --format, -f <human|json>   Output format (default: human)");
    eprintln!("  --json                      Shorthand for --format json");
    eprintln!("  --human                     Shorthand for --format human");
    eprintln!("  --help, -h                  Show this help");
    eprintln!();
    eprintln!("Human output uses ANSI colors when stdout is a terminal; set NO_COLOR to disable.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  cargo run --example dump");
    eprintln!("  cargo run --example dump -- --json");
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
            "--format" | "-f" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--format requires a value (human|json)".to_string());
                };
                options.format = match value.to_ascii_lowercase().as_str() {
                    "human" | "text" | "pretty" => OutputFormat::Human,
                    "json" => OutputFormat::Json,
                    other => {
                        return Err(format!(
                            "Unknown format '{}' (expected human or json)",
                            other
                        ));
                    }
                };
                index += 2;
            }
            "--json" => {
                options.format = OutputFormat::Json;
                index += 1;
            }
            "--human" => {
                options.format = OutputFormat::Human;
                index += 1;
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
        Some(path) => {
            let loaded = KeyStore::from_jsonl_path(path)?;
            for warning in &loaded.warnings {
                eprintln!("Warning: key line {}: {}", warning.line, warning.message);
            }
            Some(loaded.store)
        }
        None => None,
    };

    let output = if let Some(addr) = options.remote_addr.as_deref() {
        run_remote_dump(addr, key_store.as_ref())?
    } else {
        run_local_dump(key_store.as_ref())?
    };

    match options.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Human => print_human(&output),
    }

    Ok(())
}

fn run_local_dump(key_store: Option<&KeyStore>) -> Result<DumpOutput, Box<dyn Error>> {
    let preference = ReaderPreference::Auto;
    let mut reader = open_reader(preference).map_err(boxed_error)?;

    let reader_info = build_reader_info(&reader);
    let (data_rate, system_codes) =
        discover_system_codes(reader.driver_mut()).map_err(boxed_error)?;
    let systems = collect_system_summaries(reader.driver_mut(), &system_codes, key_store)
        .map_err(boxed_error)?;

    Ok(DumpOutput {
        reader: Some(reader_info),
        remote: None,
        data_rate,
        systems,
    })
}

fn run_remote_dump(addr: &str, key_store: Option<&KeyStore>) -> Result<DumpOutput, Box<dyn Error>> {
    let mut driver = RemoteDriver::connect(addr)?;

    let (data_rate, system_codes) = discover_system_codes(&mut driver).map_err(boxed_error)?;
    let systems =
        collect_system_summaries(&mut driver, &system_codes, key_store).map_err(boxed_error)?;

    Ok(DumpOutput {
        reader: None,
        remote: Some(RemoteInfo {
            address: addr.to_string(),
        }),
        data_rate,
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
) -> Result<(String, Vec<u16>), FelicaStandardError> {
    // Keep polling until a card is placed on the reader.
    let mut announced = false;
    let (mut felica, _polling) = loop {
        match FelicaStandard::polling_multi(driver, &["212F", "424F"], 0xFFFF, 0x00, 0x00) {
            Ok(found) => break found,
            Err(_) => {
                if !announced {
                    // JSON goes to stdout, so status messages go to stderr.
                    eprintln!("Waiting for a card on the reader...");
                    announced = true;
                }
                std::thread::sleep(POLL_RETRY_INTERVAL);
            }
        }
    };
    let data_rate = felica.bitrate().to_string();
    let system_codes = felica.request_system_code()?;
    Ok((data_rate, system_codes))
}

fn collect_system_summaries<D: FelicaDriver + ?Sized>(
    driver: &mut D,
    system_codes: &[u16],
    key_store: Option<&KeyStore>,
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
    key_store: Option<&KeyStore>,
) -> Result<SystemSummary, FelicaStandardError> {
    let (mut felica, _polling) =
        FelicaStandard::polling_multi(driver, &["212F", "424F"], system_code, 0x00, 0x00)?;
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

    let system_keys = key_store.and_then(|store| store.resolve(system_code, felica.idm()));
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

// The tuple mirrors the three lists this walk accumulates; naming it would not help a reader of the example.
#[allow(clippy::type_complexity)]
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
        attributes_description: service_code.attributes_description(),
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
    for (service_code, summary) in service_codes.iter().zip(summaries) {
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
    keys: &ResolvedNodeKeys,
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

fn append_blocks_hex<B: AsRef<[u8]>>(blocks_hex: &mut Vec<String>, blocks: Vec<B>) {
    for block in blocks {
        blocks_hex.push(hex::encode(block.as_ref()).to_uppercase());
    }
}

fn read_service_blocks_with_auth<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<D>,
    target: &AuthReadTarget,
    keys: &ResolvedNodeKeys,
) -> Result<AuthReadResult, String> {
    let service_code = ServiceCode::new(target.service_code_raw);
    // Derive the right keys (DES group/user or AES-128 group key) from the node
    // being accessed and run the matching mutual authentication in one step.
    let auth_result = felica
        .authenticate_node(keys, &target.area_codes, &[service_code], None)
        .map_err(|err| format!("Mutual Authentication failed: {}", err))?;
    let auth_summary = MutualAuthSummary {
        idi: encode(auth_result.issue_id).to_uppercase(),
        pmi: encode(auth_result.issue_parameter).to_uppercase(),
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
        && seen.insert(service.service_code_raw)
    {
        targets.push(service.service_code_raw);
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

// ===========================================================================
// Human-readable rendering
//
// The card is a tree: System -> Areas (nested) -> Service groups -> Services,
// with optional block data hanging off a service group. We mirror that shape
// with box-drawing connectors, align the per-system metadata into a small
// key/value table, and print any read block data as a classic hex + ASCII
// dump so the bytes stay easy to scan.
// ===========================================================================

/// Width of the horizontal rules used for the banner and section separators.
const RULE_WIDTH: usize = 66;

/// Applies ANSI colors, but only when stdout is an interactive terminal and the
/// user has not opted out via the conventional `NO_COLOR` environment variable.
struct Painter {
    color: bool,
}

impl Painter {
    fn new() -> Self {
        let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
        Painter { color }
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }

    fn bold(&self, t: &str) -> String {
        self.wrap("1", t)
    }
    fn dim(&self, t: &str) -> String {
        self.wrap("2", t)
    }
    fn cyan(&self, t: &str) -> String {
        self.wrap("36", t)
    }
    fn bold_cyan(&self, t: &str) -> String {
        self.wrap("1;36", t)
    }
    fn green(&self, t: &str) -> String {
        self.wrap("32", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.wrap("33", t)
    }
    fn blue(&self, t: &str) -> String {
        self.wrap("1;34", t)
    }
    fn magenta(&self, t: &str) -> String {
        self.wrap("35", t)
    }
}

/// The two box-drawing fragments for a tree node: the branch drawn on the
/// node's own line, and the padding used to indent that node's descendants.
fn branch_parts(is_last: bool) -> (&'static str, &'static str) {
    if is_last {
        ("└─ ", "   ")
    } else {
        ("├─ ", "│  ")
    }
}

fn print_human(output: &DumpOutput) {
    let p = Painter::new();

    println!();
    println!("{}", p.bold_cyan(&"━".repeat(RULE_WIDTH)));
    println!("{}", p.bold_cyan("  FeliCa Card Dump"));
    println!("{}", p.bold_cyan(&"━".repeat(RULE_WIDTH)));

    if let Some(reader) = &output.reader {
        print_kv(
            &p,
            "Reader",
            &format!("{} {} ({})", reader.vendor, reader.product, reader.chipset),
        );
    }
    if let Some(remote) = &output.remote {
        print_kv(&p, "Remote", &remote.address);
    }
    print_kv(&p, "Data rate", &describe_data_rate(&output.data_rate));
    print_kv(&p, "Systems", &output.systems.len().to_string());

    if output.systems.is_empty() {
        println!();
        println!("  {}", p.dim("(no systems reported by the card)"));
        return;
    }

    for system in &output.systems {
        print_system(&p, system);
    }

    println!();
}

fn print_kv(p: &Painter, label: &str, value: &str) {
    println!("  {} {}", p.dim(&format!("{:<11}", label)), value);
}

fn print_system(p: &Painter, system: &SystemSummary) {
    println!();
    let title = match describe_system_code(&system.system_code_hex) {
        Some(name) => format!("System {}  —  {}", system.system_code_hex, name),
        None => format!("System {}", system.system_code_hex),
    };
    println!("{} {}", p.cyan("▐"), p.bold_cyan(&title));
    println!("{}", p.dim(&"─".repeat(RULE_WIDTH)));

    // --- Card identifiers ---------------------------------------------------
    print_kv(p, "IDm", &p.bold(&system.idm));
    print_kv(p, "PMm", &system.pmm);
    if let Some(idi) = &system.idi {
        print_kv(p, "IDi (issue)", idi);
    }
    if let Some(pmi) = &system.pmi {
        print_kv(p, "PMi (issue)", pmi);
    }
    if let Some(rendered) = system
        .system_key
        .as_ref()
        .and_then(|key| format_key_versions(p, key))
    {
        print_kv(p, "System key", &rendered);
    }

    // --- Structure tree -----------------------------------------------------
    let child_count = system.areas.len() + system.system_services.len();
    if child_count == 0 {
        println!();
        println!("  {}", p.dim("(no areas or services found)"));
    } else {
        println!();
        println!("  {}", p.bold("Structure"));
        let root_prefix = "  ";
        let mut index = 0;
        for area in &system.areas {
            index += 1;
            print_area_node(p, area, root_prefix, index == child_count);
        }
        for group in &system.system_services {
            index += 1;
            print_group_node(p, group, root_prefix, index == child_count);
        }
    }

    // --- Warnings -----------------------------------------------------------
    if !system.warnings.is_empty() {
        println!();
        println!(
            "  {}",
            p.yellow(&format!("Warnings ({})", system.warnings.len()))
        );
        for warning in &system.warnings {
            println!("  {} {}", p.yellow("!"), p.dim(warning));
        }
    }
}

fn print_area_node(p: &Painter, area: &AreaNode, prefix: &str, is_last: bool) {
    let (branch, cont) = branch_parts(is_last);
    println!("{}{}{}", prefix, p.dim(branch), area_label(p, area));

    let child_prefix = format!("{}{}", prefix, p.dim(cont));
    let count = area.children.len();
    for (i, child) in area.children.iter().enumerate() {
        let last = i + 1 == count;
        match child {
            AreaChild::Area(child_area) => print_area_node(p, child_area, &child_prefix, last),
            AreaChild::ServiceGroup(group) => print_group_node(p, group, &child_prefix, last),
        }
    }
}

fn area_label(p: &Painter, area: &AreaNode) -> String {
    let mut label = format!(
        "{} {} {}",
        p.blue("Area"),
        p.bold(&area.area_code_hex),
        p.dim(&format!("(max service {})", area.end_service_code_hex)),
    );
    append_key_label(p, &mut label, &area.key_version);
    label
}

fn print_group_node(p: &Painter, group: &ServiceGroupSummary, prefix: &str, is_last: bool) {
    let (branch, cont) = branch_parts(is_last);
    println!("{}{}{}", prefix, p.dim(branch), group_label(p, group));

    let child_prefix = format!("{}{}", prefix, p.dim(cont));
    let has_blocks = group
        .blocks
        .as_ref()
        .is_some_and(|blocks| !blocks.is_empty());
    let child_count = group.services.len() + usize::from(has_blocks);

    let mut index = 0;
    for service in &group.services {
        index += 1;
        print_service_line(p, service, &child_prefix, index == child_count);
    }
    if let Some(blocks) = group.blocks.as_ref().filter(|blocks| !blocks.is_empty()) {
        print_blocks(p, blocks, &child_prefix, true);
    }
}

fn group_label(p: &Painter, group: &ServiceGroupSummary) -> String {
    let count = group.services.len();
    format!(
        "{} {} {}",
        p.cyan("Service group"),
        p.bold(&group.number_hex),
        p.dim(&format!(
            "({} service{})",
            count,
            if count == 1 { "" } else { "s" }
        )),
    )
}

fn print_service_line(p: &Painter, service: &ServiceSummary, prefix: &str, is_last: bool) {
    let (branch, _) = branch_parts(is_last);
    println!("{}{}{}", prefix, p.dim(branch), service_label(p, service));
}

fn service_label(p: &Painter, service: &ServiceSummary) -> String {
    // Attribute bit 0 clear => authentication (mutual auth) is required to read.
    let access = if service.attributes_raw & 0x01 == 0 {
        p.yellow("auth")
    } else {
        p.green("open")
    };
    let description = service
        .attributes_description
        .as_deref()
        .unwrap_or("unknown attribute");
    let mut label = format!(
        "{} {} [{}] {}",
        p.cyan("Service"),
        p.bold(&service.code_hex),
        access,
        p.dim(description),
    );
    append_key_label(p, &mut label, &service.key_version);
    label
}

/// Appends the rendered key versions (if any) to a node label, prefixed with
/// spacing so it reads as a trailing annotation.
fn append_key_label(p: &Painter, label: &mut String, key: &Option<KeyVersionSummary>) {
    if let Some(rendered) = key.as_ref().and_then(|key| format_key_versions(p, key)) {
        label.push_str(&format!("  {}", rendered));
    }
}

/// Renders the AES/DES key versions, or `None` when neither is present.
fn format_key_versions(p: &Painter, key: &KeyVersionSummary) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(aes) = &key.aes_key_version_hex {
        parts.push(format!("AES {}", aes));
    }
    if let Some(des) = &key.des_key_version_hex {
        parts.push(format!("DES {}", des));
    }
    if parts.is_empty() {
        None
    } else {
        Some(p.magenta(&format!("key[{}]", parts.join(" "))))
    }
}

fn print_blocks(p: &Painter, blocks: &[String], prefix: &str, is_last: bool) {
    let (branch, cont) = branch_parts(is_last);
    println!(
        "{}{}{}",
        prefix,
        p.dim(branch),
        p.bold(&format!(
            "data ({} block{})",
            blocks.len(),
            if blocks.len() == 1 { "" } else { "s" }
        )),
    );

    let data_prefix = format!("{}{}", prefix, p.dim(cont));
    for (block_index, block_hex) in blocks.iter().enumerate() {
        println!("{}{}", data_prefix, hexdump_line(p, block_index, block_hex));
    }
}

/// Formats one 16-byte block as `NNN | hex bytes | ASCII`, tolerating blocks
/// that decode to fewer than 16 bytes.
fn hexdump_line(p: &Painter, block_index: usize, block_hex: &str) -> String {
    let bytes = hex::decode(block_hex).unwrap_or_default();

    let mut hex_cols = String::new();
    for column in 0..16 {
        if column == 8 {
            hex_cols.push(' ');
        }
        match bytes.get(column) {
            Some(byte) => hex_cols.push_str(&format!("{:02X} ", byte)),
            None => hex_cols.push_str("   "),
        }
    }

    let ascii: String = bytes
        .iter()
        .map(|&byte| {
            if (0x20..=0x7E).contains(&byte) {
                byte as char
            } else {
                '.'
            }
        })
        .collect();

    format!(
        "{} {} {}{} {}",
        p.dim(&format!("{:>3}", block_index)),
        p.dim("│"),
        hex_cols,
        p.dim("│"),
        p.green(&ascii),
    )
}

fn describe_data_rate(data_rate: &str) -> String {
    match data_rate {
        "212F" => "212F (212 kbps)".to_string(),
        "424F" => "424F (424 kbps)".to_string(),
        other => other.to_string(),
    }
}

/// Best-effort friendly names for a few widely deployed FeliCa system codes.
fn describe_system_code(system_code_hex: &str) -> Option<&'static str> {
    match system_code_hex {
        "0x0003" => Some("交通系IC (Suica / PASMO / ICOCA など)"),
        "0xFE00" => Some("共通領域 (Edy / nanaco / WAON / QUICPay など)"),
        "0x88B4" => Some("FeliCa Lite-S"),
        "0x957A" => Some("FeliCa Plug / NFC Dynamic Tag"),
        _ => None,
    }
}
