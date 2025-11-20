use hex::encode;
use nfc_rs::felica_standard::{
    BlockListElement, FelicaDriver, FelicaStandard, FelicaStandardError, SearchServiceCodeResult,
    ServiceCode,
};
use nfc_rs::{Reader, ReaderPreference, open_reader};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;

const MAX_SERVICE_CODES_PER_REQUEST: usize = 0x20;
const BLOCKS_PER_READ_ATTEMPT: usize = 1;
const SYSTEM_SERVICE_CODE: u16 = 0xFFFF;

#[derive(Debug, Serialize)]
struct DumpOutput {
    reader: ReaderInfo,
    systems: Vec<SystemSummary>,
}

#[derive(Debug, Serialize)]
struct ReaderInfo {
    vendor: String,
    product: String,
    chipset: String,
}

#[derive(Debug, Serialize)]
struct SystemSummary {
    idm: String,
    pmm: String,
    system_code_hex: String,
    system_key: Option<KeyVersionSummary>,
    areas: Vec<AreaNode>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AreaNode {
    #[serde(skip_serializing)]
    area_code_raw: u16,
    area_code_hex: String,
    end_service_index_hex: String,
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
    read_without_encryption_blocks: Option<Vec<String>>,
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

fn main() -> Result<(), Box<dyn Error>> {
    let preference = ReaderPreference::Auto;
    let mut reader = open_reader(preference).map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    let reader_info = build_reader_info(&reader);
    let system_codes =
        discover_system_codes(&mut reader).map_err(|err| -> Box<dyn Error> { Box::new(err) })?;
    let systems = collect_system_summaries(&mut reader, &system_codes)
        .map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    let output = DumpOutput {
        reader: reader_info,
        systems,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
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

fn discover_system_codes(reader: &mut Reader) -> Result<Vec<u16>, FelicaStandardError> {
    let (mut felica, _polling) =
        FelicaStandard::polling(reader.driver_mut(), "212F", 0xFFFF, 0x00, 0x00)?;
    felica.request_system_code()
}

fn collect_system_summaries(
    reader: &mut Reader,
    system_codes: &[u16],
) -> Result<Vec<SystemSummary>, FelicaStandardError> {
    let mut systems = Vec::with_capacity(system_codes.len());
    for &system_code in system_codes {
        systems.push(summarize_system(reader, system_code)?);
    }
    Ok(systems)
}

fn summarize_system(
    reader: &mut Reader,
    system_code: u16,
) -> Result<SystemSummary, FelicaStandardError> {
    let (mut felica, _polling) =
        FelicaStandard::polling(reader.driver_mut(), "212F", system_code, 0x00, 0x00)?;
    let idm = encode(felica.idm()).to_uppercase();
    let pmm = encode(felica.pmm()).to_uppercase();

    let mut seen_codes = HashSet::new();
    let mut key_request_codes = Vec::new();
    register_service_code(&mut key_request_codes, &mut seen_codes, SYSTEM_SERVICE_CODE);

    let (mut areas, mut warnings) =
        collect_system_areas(&mut felica, &mut key_request_codes, &mut seen_codes)?;

    let mut key_versions = fetch_key_versions(&mut felica, &key_request_codes, &mut warnings);

    let system_key = key_versions.remove(&SYSTEM_SERVICE_CODE);
    for area in &mut areas {
        assign_area_key_versions(area, &mut key_versions);
    }

    if let Err(err) = read_plaintext_services(&mut felica, &mut areas, &mut warnings) {
        warnings.push(format!(
            "Reading plaintext blocks failed for system 0x{:04X}: {}",
            system_code, err
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
        system_code_hex: hex_u16(system_code),
        system_key,
        areas,
        warnings,
    })
}

fn fetch_key_versions<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<'_, D>,
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
    felica: &mut FelicaStandard<'_, D>,
    key_request_codes: &mut Vec<ServiceCode>,
    seen_codes: &mut HashSet<u16>,
) -> Result<(Vec<AreaNode>, Vec<String>), FelicaStandardError> {
    let mut areas = Vec::new();
    let mut warnings = Vec::new();
    let mut index = 0x00u16;
    while index <= 0x00FF {
        match felica.search_service_code(index)? {
            None => break,
            Some(SearchServiceCodeResult::Area {
                area_code,
                end_service_index,
            }) => {
                let (area, next_index) = collect_area(
                    felica,
                    area_code,
                    end_service_index,
                    index.saturating_add(1),
                    key_request_codes,
                    seen_codes,
                    &mut warnings,
                )?;
                areas.push(area);
                index = next_index;
            }
            Some(SearchServiceCodeResult::Service(service_code)) => {
                warnings.push(format!(
                    "Service 0x{:04X} at index 0x{:02X} has no parent area",
                    service_code.raw(),
                    index
                ));
                register_service_code(key_request_codes, seen_codes, service_code.raw());
                index = index.saturating_add(1);
            }
        }
    }
    Ok((areas, warnings))
}

fn collect_area<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<'_, D>,
    area_code: u16,
    end_service_index: u16,
    mut index: u16,
    key_request_codes: &mut Vec<ServiceCode>,
    seen_codes: &mut HashSet<u16>,
    warnings: &mut Vec<String>,
) -> Result<(AreaNode, u16), FelicaStandardError> {
    register_service_code(key_request_codes, seen_codes, area_code);

    let mut children = Vec::new();
    while index <= end_service_index {
        match felica.search_service_code(index)? {
            Some(SearchServiceCodeResult::Service(service_code)) => {
                register_service_code(key_request_codes, seen_codes, service_code.raw());
                append_service_child(
                    &mut children,
                    ServiceSummary {
                        service_code_raw: service_code.raw(),
                        attributes_raw: service_code.attributes(),
                        code_hex: hex_u16(service_code.raw()),
                        number: service_code.number(),
                        attributes_hex: hex_u8(service_code.attributes()),
                        attributes_description: service_code
                            .attributes_description()
                            .map(|desc| desc.to_string()),
                        key_version: None,
                    },
                );
                index = index.saturating_add(1);
            }
            Some(SearchServiceCodeResult::Area {
                area_code: child_code,
                end_service_index: child_end,
            }) => {
                if child_end < index {
                    warnings.push(format!(
                        "Area 0x{:04X} end index 0x{:02X} precedes start 0x{:02X}",
                        child_code, child_end, index
                    ));
                    break;
                }
                let (child_area, next_index) = collect_area(
                    felica,
                    child_code,
                    child_end,
                    index.saturating_add(1),
                    key_request_codes,
                    seen_codes,
                    warnings,
                )?;
                children.push(AreaChild::Area(child_area));
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
            end_service_index_hex: hex_u16(end_service_index),
            key_version: None,
            children,
        },
        end_service_index.saturating_add(1),
    ))
}

fn append_service_child(children: &mut Vec<AreaChild>, summary: ServiceSummary) {
    if let Some(group) = children.iter_mut().find_map(|child| match child {
        AreaChild::ServiceGroup(group) if group.number == summary.number => Some(group),
        _ => None,
    }) {
        group.services.push(summary);
    } else {
        let number = summary.number;
        children.push(AreaChild::ServiceGroup(ServiceGroupSummary {
            number,
            number_hex: hex_u16(number),
            services: vec![summary],
            read_without_encryption_blocks: None,
        }));
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
    felica: &mut FelicaStandard<'_, D>,
    areas: &mut [AreaNode],
    warnings: &mut Vec<String>,
) -> Result<(), FelicaStandardError> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    collect_plaintext_service_codes(areas, &mut targets, &mut seen);
    if targets.is_empty() {
        return Ok(());
    }

    let mut read_results: HashMap<u16, Vec<String>> = HashMap::new();
    for code in targets {
        match read_service_blocks(felica, code) {
            Ok(blocks) => {
                if !blocks.is_empty() {
                    read_results.insert(code, blocks);
                }
            }
            Err(err) => warnings.push(format!(
                "Read Without Encryption failed for service 0x{:04X}: {}",
                code, err
            )),
        }
    }

    assign_read_blocks(areas, &mut read_results);
    Ok(())
}

fn collect_plaintext_service_codes(
    areas: &[AreaNode],
    targets: &mut Vec<u16>,
    seen: &mut HashSet<u16>,
) {
    for area in areas {
        collect_plaintext_children(&area.children, targets, seen);
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
    felica: &mut FelicaStandard<'_, D>,
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
                for block in blocks {
                    blocks_hex.push(hex::encode(block).to_uppercase());
                }
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

fn assign_read_blocks(areas: &mut [AreaNode], results: &mut HashMap<u16, Vec<String>>) {
    for area in areas {
        assign_read_blocks_in_area(area, results);
    }
}

fn assign_read_blocks_in_area(area: &mut AreaNode, results: &mut HashMap<u16, Vec<String>>) {
    for child in &mut area.children {
        match child {
            AreaChild::Area(child_area) => assign_read_blocks_in_area(child_area, results),
            AreaChild::ServiceGroup(group) => assign_read_blocks_in_group(group, results),
        }
    }
}

fn assign_read_blocks_in_group(
    group: &mut ServiceGroupSummary,
    results: &mut HashMap<u16, Vec<String>>,
) {
    if group.read_without_encryption_blocks.is_some() {
        return;
    }
    for service in &group.services {
        if let Some(blocks) = results.remove(&service.service_code_raw) {
            group.read_without_encryption_blocks = Some(blocks);
            break;
        }
    }
}

fn request_key_versions<D: FelicaDriver + ?Sized>(
    felica: &mut FelicaStandard<'_, D>,
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
                    aes_key_version_hex: hex_opt_u16(Some(key_version.primary())),
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
