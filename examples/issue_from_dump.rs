//! Issue a FeliCa Standard system onto a blank card, replicating the structure
//! recorded in a `dump --json` output.
//!
//! The tool reads a dump JSON (the layout source), picks one system out of it,
//! and replays that system's area/service tree onto the card currently on the
//! reader using the DES issuance commands (Register Issue ID / Register Area /
//! Register Service / Change System Block). Node keys come from a JSONL key
//! store; the blank card's factory key (system `FFFF`, node `0000`) is used as
//! the registration package key.
//!
//! It plans first and prints the whole sequence. Nothing is written to the card
//! unless `--commit` is passed, because issuance cannot be undone.
//!
//! # Usage
//!
//! ```bash
//! # Plan only (default)
//! cargo run --example issue_from_dump -- --layout suica.log --keys keys.jsonl \
//!     --system 0003 --issue-id 0011223344556677 --issue-parameter 8899AABBCCDDEEFF
//!
//! # Actually issue, then restore the block data present in the layout
//! cargo run --example issue_from_dump -- --layout suica.log --keys keys.jsonl \
//!     --system 0003 --issue-id 0011223344556677 --issue-parameter 8899AABBCCDDEEFF \
//!     --commit --write-data
//! ```
//!
//! # Sizes
//!
//! A dump only knows a service's block count when it could actually read it, so
//! services that are key-protected on the source card have no size recorded.
//! `--default-size` covers those, and `--size 0048=4` overrides an individual
//! service group. An area is registered with the total block count of its
//! subtree.

use felica::felica_standard::{
    BlockListElement, ChangeKeyParameters, FelicaStandard, KeyStore, NodeKey, ResolvedNodeKeys,
    ServiceCode, ServiceKind,
};
use felica::{ReaderPreference, open_reader};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;

const BLOCK_SIZE: usize = 16;
const DES_KEY_LEN: usize = 8;
/// Key version a keyless service is registered with (§3.4: a service that needs
/// no key carries no key version).
const NO_KEY_VERSION: u16 = 0xFFFF;
/// System code of an unissued card, and the key store scope holding its factory
/// package key.
const BLANK_SYSTEM_CODE: u16 = 0xFFFF;
/// Node code that denotes the system itself, whose key is the root of the chain.
const SYSTEM_NODE_CODE: u16 = 0xFFFF;

// ---------------------------------------------------------------- plan model

#[derive(Debug)]
struct PlannedArea {
    code: u16,
    end_service_code: u16,
    /// Total blocks of everything registered below this area.
    size: u16,
    key_version: u16,
    key: [u8; DES_KEY_LEN],
    /// Key of the enclosing area, which seals this node's registration package.
    package_key: [u8; DES_KEY_LEN],
    /// Depth in the tree, for display only.
    depth: usize,
}

#[derive(Debug)]
struct PlannedService {
    code: u16,
    size: u16,
    key_version: u16,
    key: [u8; DES_KEY_LEN],
    /// Area codes from the root inward, used to authenticate when writing data.
    area_path: Vec<u16>,
    /// Block data recovered from the layout dump, if any. Only the service that
    /// will carry the restore write holds it; its overlap aliases address the
    /// same blocks.
    blocks: Vec<[u8; BLOCK_SIZE]>,
    /// Whether the size came from real read data or from the default.
    size_is_known: bool,
    /// A cyclic service is restored by appending oldest record first.
    is_cyclic: bool,
    /// Key of the enclosing area, which seals this node's registration package.
    package_key: [u8; DES_KEY_LEN],
}

#[derive(Debug)]
enum Step {
    Area(PlannedArea),
    Service(PlannedService),
}

struct Plan {
    system_code: u16,
    root_key_version: u16,
    root_key: [u8; DES_KEY_LEN],
    steps: Vec<Step>,
    /// Nodes that needed a key but had none in the key store.
    missing_keys: Vec<u16>,
    /// Nodes that exist only under AES on the source card and were given their
    /// AES key version under DES here.
    converted_from_aes: Vec<u16>,
}

// ------------------------------------------------------------------ CLI

struct Options {
    layout_path: String,
    keys_path: String,
    system_code: u16,
    issue_id: [u8; DES_KEY_LEN],
    issue_parameter: [u8; DES_KEY_LEN],
    default_size: u16,
    size_overrides: HashMap<u16, u16>,
    /// How an area's block count parameter is derived.
    area_size: AreaSize,
    /// How the issuance is split into card sessions.
    phase: Phase,
    commit: bool,
    /// Reset the system with Register Issue ID, commit that, and stop.
    reset_only: bool,
    /// Commit each registration on its own instead of once at the end.
    commit_each: bool,
    /// Skip registration entirely and only restore block data.
    data_only: bool,
    /// Replace the card's system key with the target system's own key.
    change_system_key: bool,
    /// Which key to use as the "parent" of the system node, which has none.
    system_parent_key: SystemParentKey,
    write_data: bool,
    allow_missing_keys: bool,
}

/// What to pass as an area's block count in its registration package. The
/// spec's meaning is "blocks allocated to this area", but cards differ on
/// whether an area owns its subtree's blocks or leaves them to the services, so
/// this is selectable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AreaSize {
    /// Total blocks of everything below the area.
    Subtree,
    /// Zero: only services draw blocks from the pool.
    Zero,
}

/// The system node sits at the root of the key hierarchy, so it has no parent
/// key to chain its key change through. Which value the card expects there is a
/// property of the product, so it is selectable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SystemParentKey {
    /// The system key being replaced acts as its own parent.
    Old,
    /// The replacement key acts as the parent.
    New,
    /// An all-zero key.
    Zero,
}

/// How the registration sequence is split across sessions. A card may not let a
/// system that Register Issue ID has only just created be filled from the same
/// session, so the sequence can be re-anchored on the new system.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Everything in the blank system's session.
    Single,
    /// Register Issue ID, then re-activate on the new system and register there.
    Repoll,
    /// Register Issue ID, commit it, then re-activate on the new system.
    CommitFirst,
    /// The system already exists: skip Register Issue ID and register the rest
    /// of the tree into it.
    Continue,
    /// The system already exists: re-run Register Issue ID against it, which
    /// resets it, then register the tree from scratch.
    Reissue,
}

fn parse_hex8(label: &str, text: &str) -> Result<[u8; DES_KEY_LEN], String> {
    let bytes = hex::decode(text).map_err(|err| format!("{label}: {err}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly 8 bytes (16 hex characters)"))
}

fn parse_args() -> Result<Options, String> {
    let mut layout_path = None;
    let mut keys_path = None;
    let mut system_code = None;
    let mut issue_id = None;
    let mut issue_parameter = None;
    let mut default_size = 1u16;
    let mut area_size = AreaSize::Subtree;
    let mut phase = Phase::Single;
    let mut size_overrides = HashMap::new();
    let mut commit = false;
    let mut reset_only = false;
    let mut commit_each = false;
    let mut data_only = false;
    let mut change_system_key = false;
    let mut system_parent_key = SystemParentKey::Old;
    let mut write_data = false;
    let mut allow_missing_keys = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].clone();
        let arg = arg.as_str();
        // Takes the value that follows `arg`, advancing past it.
        macro_rules! value {
            () => {{
                index += 1;
                args.get(index)
                    .cloned()
                    .ok_or_else(|| format!("{arg} requires a value"))?
            }};
        }
        match arg {
            "--layout" => layout_path = Some(value!()),
            "--keys" => keys_path = Some(value!()),
            "--system" => {
                let text = value!();
                system_code = Some(
                    u16::from_str_radix(text.trim_start_matches("0x"), 16)
                        .map_err(|err| format!("--system: {err}"))?,
                );
            }
            "--issue-id" => issue_id = Some(parse_hex8("--issue-id", &value!())?),
            "--issue-parameter" => {
                issue_parameter = Some(parse_hex8("--issue-parameter", &value!())?)
            }
            "--default-size" => {
                default_size = value!()
                    .parse()
                    .map_err(|err| format!("--default-size: {err}"))?
            }
            "--size" => {
                let text = value!();
                let (code, size) = text
                    .split_once('=')
                    .ok_or_else(|| "--size expects CODE=BLOCKS".to_string())?;
                let code = u16::from_str_radix(code.trim_start_matches("0x"), 16)
                    .map_err(|err| format!("--size code: {err}"))?;
                let size: u16 = size
                    .parse()
                    .map_err(|err| format!("--size blocks: {err}"))?;
                size_overrides.insert(code, size);
            }
            "--area-size" => {
                area_size = match value!().as_str() {
                    "subtree" => AreaSize::Subtree,
                    "zero" => AreaSize::Zero,
                    other => {
                        return Err(format!("--area-size expects subtree or zero, got {other}"));
                    }
                }
            }
            "--phase" => {
                phase = match value!().as_str() {
                    "single" => Phase::Single,
                    "repoll" => Phase::Repoll,
                    "commit-first" => Phase::CommitFirst,
                    "continue" => Phase::Continue,
                    "reissue" => Phase::Reissue,
                    other => {
                        return Err(format!(
                            "--phase expects single, repoll, commit-first, continue or reissue, got {other}"
                        ));
                    }
                }
            }
            "--commit" => commit = true,
            "--reset-only" => reset_only = true,
            "--commit-each" => commit_each = true,
            "--data-only" => data_only = true,
            "--change-system-key" => change_system_key = true,
            "--system-parent-key" => {
                system_parent_key = match value!().as_str() {
                    "old" => SystemParentKey::Old,
                    "new" => SystemParentKey::New,
                    "zero" => SystemParentKey::Zero,
                    other => {
                        return Err(format!(
                            "--system-parent-key expects old, new or zero, got {other}"
                        ));
                    }
                }
            }
            "--write-data" => write_data = true,
            "--allow-missing-keys" => allow_missing_keys = true,
            other => return Err(format!("unknown argument {other}")),
        }
        index += 1;
    }

    Ok(Options {
        layout_path: layout_path.ok_or("--layout is required")?,
        keys_path: keys_path.ok_or("--keys is required")?,
        system_code: system_code.ok_or("--system is required")?,
        issue_id: issue_id.ok_or("--issue-id is required")?,
        issue_parameter: issue_parameter.ok_or("--issue-parameter is required")?,
        default_size,
        size_overrides,
        area_size,
        phase,
        commit,
        reset_only,
        commit_each,
        data_only,
        change_system_key,
        system_parent_key,
        write_data,
        allow_missing_keys,
    })
}

// ------------------------------------------------------------------ planning

fn hex_field(value: &Value, key: &str) -> Option<u16> {
    let text = value.get(key)?.as_str()?;
    u16::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

fn des_key_version(value: &Value) -> Option<u16> {
    let versions = value.get("key_version")?;
    let text = versions.get("des_key_version_hex")?.as_str()?;
    u16::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

fn aes_key_version(value: &Value) -> Option<u16> {
    let versions = value.get("key_version")?;
    let text = versions.get("aes_key_version_hex")?.as_str()?;
    u16::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

/// The key version to register a node with.
///
/// A node that exists only under AES on the source card has no DES key version
/// to copy. The blank card is DES-only, so the AES version is reused as the DES
/// one and the node is reported as converted.
fn key_version_for(node: &Value, converted: &mut Vec<u16>, code: u16) -> u16 {
    if let Some(version) = des_key_version(node) {
        return version;
    }
    match aes_key_version(node) {
        Some(version) => {
            converted.push(code);
            version
        }
        None => NO_KEY_VERSION,
    }
}

fn lookup_key(keys: &ResolvedNodeKeys, node: u16, missing: &mut Vec<u16>) -> [u8; DES_KEY_LEN] {
    match keys.get(node) {
        Some(NodeKey::Des(key)) => *key,
        // An AES key cannot be provisioned through the DES issuance commands, so
        // it counts as missing just like an absent one.
        Some(NodeKey::Aes128(_)) | None => {
            missing.push(node);
            [0u8; DES_KEY_LEN]
        }
    }
}

/// Loads the raw DES node keys for one system straight out of the JSONL store.
///
/// [`KeyStore`] resolves keys but does not hand back the node map, and the
/// restore pass needs to rebuild that map with the card's own system key in
/// place of the source card's.
fn load_des_nodes(path: &str, system_code: u16) -> Result<HashMap<u16, NodeKey>, Box<dyn Error>> {
    let mut nodes = HashMap::new();
    for line in std::fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: Value = serde_json::from_str(line)?;
        let field =
            |name: &str| -> Option<String> { record.get(name)?.as_str().map(str::to_owned) };
        let (Some(system), Some(node), Some(algo), Some(key)) = (
            field("system_code"),
            field("node"),
            field("algo"),
            field("key"),
        ) else {
            continue;
        };
        if !algo.eq_ignore_ascii_case("DES") {
            continue;
        }
        if u16::from_str_radix(&system, 16).ok() != Some(system_code) {
            continue;
        }
        let (Ok(node), Ok(key)) = (u16::from_str_radix(&node, 16), hex::decode(&key)) else {
            continue;
        };
        if let Ok(key) = <[u8; DES_KEY_LEN]>::try_from(key.as_slice()) {
            nodes.insert(node, NodeKey::Des(key));
        }
    }
    Ok(nodes)
}

/// Blocks recorded for one service group in the dump, if the dump could read it.
fn group_blocks(group: &Value) -> Vec<[u8; BLOCK_SIZE]> {
    let Some(entries) = group.get("blocks").and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|text| hex::decode(text).ok())
        .filter_map(|bytes| <[u8; BLOCK_SIZE]>::try_from(bytes.as_slice()).ok())
        .collect()
}

/// Walks one area of the dump tree, appending its registration steps.
///
/// Returns the total block count of the subtree, which is what the area itself
/// is registered with.
// Each parameter is a distinct piece of the issuing plan; bundling them would hide what the example does.
#[allow(clippy::too_many_arguments)]
fn plan_area(
    area: &Value,
    parent_key: [u8; DES_KEY_LEN],
    parent_path: &[u16],
    depth: usize,
    options: &Options,
    keys: &ResolvedNodeKeys,
    steps: &mut Vec<Step>,
    missing: &mut Vec<u16>,
    converted: &mut Vec<u16>,
) -> Result<u16, String> {
    let area_code = hex_field(area, "area_code_hex")
        .ok_or_else(|| "area is missing area_code_hex".to_string())?;
    let end_service_code = hex_field(area, "end_service_code_hex")
        .ok_or_else(|| "area is missing end_service_code_hex".to_string())?;
    let key_version = key_version_for(area, converted, area_code);
    let area_key = lookup_key(keys, area_code, missing);

    let mut path = parent_path.to_vec();
    path.push(area_code);

    // Reserve this area's slot; its size is only known once the subtree is
    // planned, so the step is patched below.
    let area_index = steps.len();
    steps.push(Step::Area(PlannedArea {
        code: area_code,
        end_service_code,
        size: 0,
        key_version,
        key: area_key,
        package_key: parent_key,
        depth,
    }));

    let mut subtree_blocks = 0u16;
    let empty = Vec::new();
    let children = area
        .get("children")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    for child in children {
        let kind = child
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = child
            .get("value")
            .ok_or_else(|| "tree child is missing value".to_string())?;

        match kind {
            "area" => {
                let child_cost = plan_area(
                    value,
                    area_key,
                    &path,
                    depth + 1,
                    options,
                    keys,
                    steps,
                    missing,
                    converted,
                )?;
                // The child area needs one management block of its own on top of
                // whatever its subtree costs.
                subtree_blocks = subtree_blocks.saturating_add(child_cost).saturating_add(1);
            }
            "service_group" => {
                let services = value
                    .get("services")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "service group is missing services".to_string())?;
                let blocks = group_blocks(value);

                // Overlapping services share one block store (§3.4.6), so the
                // group has a single size. A group the dump could read tells us
                // that size exactly; anything else falls back to the default.
                //
                // The dump may have read the group through a read-only alias, so
                // the restore write has to go through whichever alias in the
                // group actually allows writing.
                let write_target = services
                    .iter()
                    .filter_map(|service| hex_field(service, "code_hex"))
                    .find(|code| {
                        ServiceCode::new(*code)
                            .attribute()
                            .is_some_and(|attribute| attribute.allows_write())
                    });
                let override_size = services.iter().find_map(|service| {
                    hex_field(service, "code_hex")
                        .and_then(|code| options.size_overrides.get(&code))
                });
                let (size, size_is_known) = match (override_size, blocks.len()) {
                    (Some(size), _) => (*size, true),
                    (None, 0) => (options.default_size, false),
                    (None, count) => (count as u16, true),
                };
                // A group costs its shared data blocks plus one management block
                // for every service code that addresses them: registering the
                // overlap alias 0x0009 after 0x0008 consumes exactly one block.
                subtree_blocks = subtree_blocks
                    .saturating_add(size)
                    .saturating_add(services.len() as u16);

                for service in services {
                    let code = hex_field(service, "code_hex")
                        .ok_or_else(|| "service is missing code_hex".to_string())?;
                    let service_code = ServiceCode::new(code);
                    let (key_version, key) = if service_code.requires_key() {
                        (
                            key_version_for(service, converted, code),
                            lookup_key(keys, code, missing),
                        )
                    } else {
                        (NO_KEY_VERSION, [0u8; DES_KEY_LEN])
                    };

                    steps.push(Step::Service(PlannedService {
                        code,
                        size,
                        key_version,
                        key,
                        area_path: path.clone(),
                        blocks: if Some(code) == write_target {
                            blocks.clone()
                        } else {
                            Vec::new()
                        },
                        size_is_known,
                        is_cyclic: service_code.kind() == Some(ServiceKind::Cyclic),
                        package_key: area_key,
                    }));
                }
            }
            other => return Err(format!("unknown tree child kind {other}")),
        }
    }

    if let Step::Area(planned) = &mut steps[area_index] {
        planned.size = subtree_blocks;
    }

    Ok(subtree_blocks)
}

fn build_plan(
    layout: &Value,
    options: &Options,
    keys: &ResolvedNodeKeys,
) -> Result<Plan, Box<dyn Error>> {
    let systems = layout
        .get("systems")
        .and_then(Value::as_array)
        .ok_or("layout has no systems array")?;

    let wanted = format!("0x{:04X}", options.system_code);
    let system = systems
        .iter()
        .find(|system| {
            system
                .get("system_code_hex")
                .and_then(Value::as_str)
                .map(|text| text.eq_ignore_ascii_case(&wanted))
                .unwrap_or(false)
        })
        .ok_or_else(|| format!("layout has no system {wanted}"))?;

    let areas = system
        .get("areas")
        .and_then(Value::as_array)
        .ok_or("system has no areas")?;
    let root = areas.first().ok_or("system has no root area")?;

    let mut missing = Vec::new();
    let mut converted = Vec::new();
    let mut steps = Vec::new();
    plan_area(
        root,
        [0u8; DES_KEY_LEN],
        &[],
        0,
        options,
        keys,
        &mut steps,
        &mut missing,
        &mut converted,
    )?;

    // Register Issue ID creates the system and the root area in one step, so the
    // root is not registered again.
    let root_step = match steps.remove(0) {
        Step::Area(area) => area,
        Step::Service(_) => return Err("root of the tree is not an area".into()),
    };
    if root_step.code != 0x0000 {
        return Err(format!("root area is 0x{:04X}, expected 0x0000", root_step.code).into());
    }

    Ok(Plan {
        system_code: options.system_code,
        root_key_version: root_step.key_version,
        root_key: root_step.key,
        steps,
        missing_keys: missing,
        converted_from_aes: converted,
    })
}

fn print_plan(plan: &Plan, options: &Options) {
    let mut area_count = 0;
    let mut service_count = 0;
    let mut total_blocks = 0u32;
    let mut unknown_sizes = Vec::new();
    let mut data_blocks = 0usize;
    let mut seen_numbers = std::collections::HashSet::new();

    println!(
        "Register Issue ID  system=0x{:04X}  area0 keyver=0x{:04X}  issue_id={}  issue_param={}",
        plan.system_code,
        plan.root_key_version,
        hex::encode_upper(options.issue_id),
        hex::encode_upper(options.issue_parameter),
    );

    for step in &plan.steps {
        match step {
            Step::Area(area) => {
                area_count += 1;
                println!(
                    "{}Register Area     0x{:04X}..0x{:04X}  size={:4}  keyver=0x{:04X}",
                    "  ".repeat(area.depth),
                    area.code,
                    area.end_service_code,
                    area.size,
                    area.key_version
                );
            }
            Step::Service(service) => {
                service_count += 1;
                data_blocks += service.blocks.len();
                // Overlap aliases share one block store, so a group's blocks are
                // counted once, against the first code seen for that number.
                if seen_numbers.insert(ServiceCode::new(service.code).number()) {
                    total_blocks += service.size as u32;
                    if !service.size_is_known {
                        unknown_sizes.push(service.code);
                    }
                }
                println!(
                    "  Register Service  0x{:04X}         size={:4}{}  keyver=0x{:04X}{}",
                    service.code,
                    service.size,
                    if service.size_is_known { " " } else { "?" },
                    service.key_version,
                    if service.blocks.is_empty() {
                        String::new()
                    } else {
                        format!("  data={} blocks", service.blocks.len())
                    }
                );
            }
        }
    }
    println!("Change System Block");

    println!();
    println!(
        "areas={} services={} planned blocks={} (data recovered for {} blocks)",
        area_count, service_count, total_blocks, data_blocks
    );
    if !unknown_sizes.is_empty() {
        // Report one code per overlap group rather than every alias.
        let groups = unknown_sizes.len();
        println!(
            "sizes assumed ({} blocks each) for {} service groups: the source dump could not read them",
            options.default_size, groups
        );
    }
    if !plan.converted_from_aes.is_empty() {
        let codes: Vec<String> = plan
            .converted_from_aes
            .iter()
            .map(|code| format!("{:04X}", code))
            .collect();
        println!(
            "AES-only on the source card, registered under DES here ({} nodes): {}",
            codes.len(),
            codes.join(" ")
        );
    }
    if !plan.missing_keys.is_empty() {
        let mut codes: Vec<String> = plan
            .missing_keys
            .iter()
            .map(|code| format!("{:04X}", code))
            .collect();
        codes.dedup();
        println!(
            "missing DES keys for {} nodes: {}",
            codes.len(),
            codes.join(" ")
        );
    }
}

// ------------------------------------------------------------------ execution

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let options = match parse_args() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("Error: {message}");
            eprintln!("See the module docs at the top of examples/issue_from_dump.rs for usage.");
            std::process::exit(1);
        }
    };

    let layout: Value = serde_json::from_str(&std::fs::read_to_string(&options.layout_path)?)?;

    let loaded = KeyStore::from_jsonl_path(&options.keys_path)?;
    for warning in &loaded.warnings {
        eprintln!("Warning: key line {}: {}", warning.line, warning.message);
    }
    let store = loaded.store;

    // Target-system keys are shared (not IDm-scoped) in the store, so any IDm
    // resolves them.
    let target_keys = store
        .resolve(options.system_code, &[0u8; 8])
        .ok_or_else(|| format!("no keys for system 0x{:04X}", options.system_code))?;

    let plan = build_plan(&layout, &options, &target_keys)?;
    print_plan(&plan, &options);

    if !plan.missing_keys.is_empty() && !options.allow_missing_keys {
        return Err(
            "refusing to continue: nodes above have no DES key (pass --allow-missing-keys to register them with an all-zero key)".into(),
        );
    }

    if !options.commit {
        println!();
        println!("Dry run: nothing was written. Re-run with --commit to issue.");
        return Ok(());
    }

    // The blank card's factory key doubles as the registration package key.
    let package_keys = store
        .resolve(BLANK_SYSTEM_CODE, &[0u8; 8])
        .ok_or("no keys for the blank system 0xFFFF (need the factory package key)")?;
    let package_key = match package_keys.get(0x0000) {
        Some(NodeKey::Des(key)) => *key,
        _ => return Err("system 0xFFFF node 0x0000 has no DES key".into()),
    };

    // Register Issue ID replaces the blank system with the target one, but it
    // leaves the card's own system key (and so the key that opens a session on
    // the new system) untouched at its factory value.
    let session_keys = {
        let mut nodes = HashMap::new();
        if let Some(NodeKey::Des(key)) = package_keys.get(BLANK_SYSTEM_CODE) {
            nodes.insert(BLANK_SYSTEM_CODE, NodeKey::Des(*key));
        }
        nodes.insert(0x0000, NodeKey::Des(plan.root_key));
        ResolvedNodeKeys::from_map(nodes)
    };

    let mut reader = open_reader(ReaderPreference::Auto)?;

    let mut felica = if matches!(options.phase, Phase::Continue | Phase::Reissue) {
        let (mut felica, _) = FelicaStandard::polling_multi(
            reader.driver_mut(),
            &["212F", "424F"],
            plan.system_code,
            0x00,
            0x00,
        )?;
        println!();
        println!(
            "Card {} already carries system 0x{:04X}",
            hex::encode_upper(felica.idm()),
            plan.system_code
        );
        felica.authenticate_node(&session_keys, &[0x0000], &[ServiceCode::new(0x0000)], None)?;
        println!("Mutual authentication with the issued system: ok");

        if options.phase == Phase::Reissue {
            // Re-running Register Issue ID against an issued system resets it,
            // which is the only way to clear nodes a previous run committed.
            let remaining = felica.register_issue_id(
                plan.system_code,
                plan.root_key_version,
                &plan.root_key,
                &options.issue_id,
                &options.issue_parameter,
                &plan.root_key,
            )?;
            println!(
                "Register Issue ID (reset)  system=0x{:04X}  -> {} blocks remaining",
                plan.system_code, remaining
            );
            if options.reset_only {
                felica.change_system_block()?;
                println!("Change System Block: reset committed");
                return Ok(());
            }
        }
        felica
    } else {
        let (mut felica, _) = FelicaStandard::polling_multi(
            reader.driver_mut(),
            &["212F", "424F"],
            BLANK_SYSTEM_CODE,
            0x00,
            0x00,
        )?;
        println!();
        println!("Card {} on the reader", hex::encode_upper(felica.idm()));

        // The registration commands are secure commands, so they only run inside
        // a session. A blank card has nothing but its root node, so the session
        // is opened against area 0x0000 / service 0x0000 with the factory key.
        felica.authenticate_node(&package_keys, &[0x0000], &[ServiceCode::new(0x0000)], None)?;
        println!("Mutual authentication with the blank system: ok");

        let remaining = felica.register_issue_id(
            plan.system_code,
            plan.root_key_version,
            &plan.root_key,
            &options.issue_id,
            &options.issue_parameter,
            &package_key,
        )?;
        println!(
            "Register Issue ID  system=0x{:04X}  -> {} blocks remaining",
            plan.system_code, remaining
        );

        if options.phase == Phase::CommitFirst {
            felica.change_system_block()?;
            println!(
                "Change System Block: system 0x{:04X} committed",
                plan.system_code
            );
        }

        if options.phase == Phase::Single {
            felica
        } else {
            // Re-anchor on the freshly created system: activate it and open a
            // session with its own root key before registering into it.
            let (mut felica, _) = FelicaStandard::polling_multi(
                reader.driver_mut(),
                &["212F", "424F"],
                plan.system_code,
                0x00,
                0x00,
            )?;
            println!(
                "Re-activated on system 0x{:04X} as {}",
                plan.system_code,
                hex::encode_upper(felica.idm())
            );
            felica.authenticate_node(
                &session_keys,
                &[0x0000],
                &[ServiceCode::new(0x0000)],
                None,
            )?;
            println!("Mutual authentication with the new system: ok");
            felica
        }
    };

    for step in plan.steps.iter().filter(|_| !options.data_only) {
        match step {
            Step::Area(area) => {
                let size = match options.area_size {
                    AreaSize::Subtree => area.size,
                    AreaSize::Zero => 0,
                };
                felica.register_area(
                    area.code,
                    (area.code, area.end_service_code),
                    size,
                    area.key_version,
                    &area.key,
                    &area.package_key,
                )?;
                if options.commit_each {
                    felica.change_system_block()?;
                }
                println!("Register Area     0x{:04X}  size={}", area.code, size);
            }
            Step::Service(service) => {
                let remaining = felica.register_service(
                    service.code,
                    service.size,
                    service.key_version,
                    &service.key,
                    &service.package_key,
                )?;
                if options.commit_each {
                    felica.change_system_block()?;
                }
                println!(
                    "Register Service  0x{:04X}  size={}  -> {} blocks remaining",
                    service.code, service.size, remaining
                );
            }
        }
    }

    if !options.commit_each && !options.data_only {
        felica.change_system_block()?;
    }
    if !options.data_only {
        println!("System 0x{:04X} is now issued", plan.system_code);
    }

    // Register Issue ID leaves the card's system key at its factory value, so
    // the issued system does not yet answer to the source system's key chain.
    // Changing it last makes the card readable with the unmodified key store.
    if options.change_system_key {
        let old_key = match package_keys.get(BLANK_SYSTEM_CODE) {
            Some(NodeKey::Des(key)) => *key,
            _ => return Err("system 0xFFFF node 0xFFFF has no DES key".into()),
        };
        let new_key = match target_keys.get(BLANK_SYSTEM_CODE) {
            Some(NodeKey::Des(key)) => *key,
            _ => {
                return Err(format!(
                    "system 0x{:04X} node 0xFFFF has no DES key",
                    options.system_code
                )
                .into());
            }
        };
        let parent_key = match options.system_parent_key {
            SystemParentKey::Old => old_key,
            SystemParentKey::New => new_key,
            SystemParentKey::Zero => [0u8; DES_KEY_LEN],
        };

        // The key change addresses its node by position in the session's node
        // list, so the system node has to be one of the nodes authenticated
        // against. It goes in the service list, which accepts the system node.
        felica.clear_authenticated_context();
        felica.authenticate_node(
            &session_keys,
            &[0x0000],
            &[ServiceCode::new(SYSTEM_NODE_CODE)],
            None,
        )?;
        felica.change_keys(&[ChangeKeyParameters::new(
            SYSTEM_NODE_CODE,
            parent_key,
            new_key,
            old_key,
            plan.root_key_version,
        )])?;
        felica.clear_authenticated_context();
        println!(
            "Change Key: system key -> version 0x{:04X}",
            plan.root_key_version
        );
    }

    if !options.write_data {
        return Ok(());
    }

    // Keep using the session that is already activated on the target system: a
    // second Polling while the card is still selected is not answered, and the
    // per-service authentication below re-keys the session anyway.
    felica.clear_authenticated_context();

    // Register Issue ID left the card's system key at its factory value, so the
    // session key chain is the factory system key followed by the target
    // system's own area and service keys.
    let restore_keys = {
        let mut nodes = load_des_nodes(&options.keys_path, options.system_code)?;
        if let Some(NodeKey::Des(key)) = package_keys.get(BLANK_SYSTEM_CODE) {
            nodes.insert(BLANK_SYSTEM_CODE, NodeKey::Des(*key));
        }
        ResolvedNodeKeys::from_map(nodes)
    };

    println!();
    println!(
        "Restoring block data as {}",
        hex::encode_upper(felica.idm())
    );

    for step in &plan.steps {
        let Step::Service(service) = step else {
            continue;
        };
        if service.blocks.is_empty() {
            continue;
        }
        let service_code = ServiceCode::new(service.code);

        felica.authenticate_node(&restore_keys, &service.area_path, &[service_code], None)?;
        if service.is_cyclic {
            // A cyclic write always appends at block 0 and pushes the rest down,
            // and a cyclic read returns newest first, so replaying the dump in
            // reverse reproduces the original order.
            for block in service.blocks.iter().rev() {
                felica.write(&[BlockListElement::new(0, 0, 0)], block)?;
            }
        } else {
            for (number, block) in service.blocks.iter().enumerate() {
                felica.write(&[BlockListElement::new(number as u16, 0, 0)], block)?;
            }
        }
        // Read the blocks straight back inside the same session: the dump tool
        // cannot authenticate against this card (its system key is still the
        // factory one), so this is the only chance to confirm the write landed.
        // A secure read is capped at 14 blocks per command, so long services are
        // read back in chunks.
        const MAX_SECURE_READ: usize = 14;
        let mut read_back = Vec::with_capacity(service.blocks.len());
        for chunk in (0..service.blocks.len())
            .collect::<Vec<_>>()
            .chunks(MAX_SECURE_READ)
        {
            let list: Vec<_> = chunk
                .iter()
                .map(|number| BlockListElement::new(*number as u16, 0, 0))
                .collect();
            // Read-back is a check, not part of the restore: a service the card
            // will not read back (a cyclic one, say) must not abort the pass.
            match felica.read(&list) {
                Ok(blocks) => read_back.extend(blocks),
                Err(err) => {
                    read_back.clear();
                    println!("    read-back unavailable: {err}");
                    break;
                }
            }
        }
        felica.clear_authenticated_context();

        let matches = read_back == service.blocks;
        println!(
            "Wrote {} blocks to service 0x{:04X}  [{}]",
            service.blocks.len(),
            service.code,
            if matches {
                "verified"
            } else if read_back.is_empty() {
                "written, not read back"
            } else {
                "MISMATCH"
            }
        );
        if !matches && !read_back.is_empty() {
            for (number, (want, got)) in service.blocks.iter().zip(&read_back).enumerate() {
                if want != got {
                    println!(
                        "    block {number}: expected {} got {}",
                        hex::encode_upper(want),
                        hex::encode_upper(got)
                    );
                }
            }
        }
    }

    Ok(())
}
