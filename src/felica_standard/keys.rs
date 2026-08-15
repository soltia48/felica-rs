//! JSONL-backed key store and node-aware authentication-key derivation.
//!
//! FeliCa Standard secure messaging needs the caller to feed the right derived
//! keys into [`FelicaStandard::mutual_authentication`] (DES) or
//! [`FelicaStandard::mutual_authentication_v2`] (AES-128). The raw key-chaining
//! primitives live in [`super::secure`] ([`generate_service_keys_des`] /
//! [`generate_group_key_v2_aes128`]); this module supplies the middle layer:
//!
//! - [`KeyStore`] loads per-`(system_code, IDm, node)` key material from a JSONL
//!   file (the format used by the `dump` example), supporting both DES (8-byte)
//!   and AES-128 (16-byte) keys.
//! - [`KeyStore::resolve`] flattens the shared and card-specific keys for one
//!   card into [`ResolvedNodeKeys`].
//! - [`ResolvedNodeKeys::derive_auth_keys`] turns "the node I want to access"
//!   (an area path plus an optional service) into the [`DerivedAuthKeys`] the
//!   authentication commands expect, picking the scheme from the node's own key.
//!
//! [`FelicaStandard`]: super::FelicaStandard
//! [`FelicaStandard::mutual_authentication`]: super::FelicaStandard::mutual_authentication
//! [`FelicaStandard::mutual_authentication_v2`]: super::FelicaStandard::mutual_authentication_v2

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redact::Redacted;
use super::secure::{generate_group_key_v2_aes128, generate_service_keys_des};
use super::types::ServiceCode;

/// Node code of the system key (`0xFFFF`), the root of the DES key hierarchy.
const SYSTEM_SERVICE_CODE: u16 = 0xFFFF;

const DES_KEY_LEN: usize = 8;
const AES_KEY_LEN: usize = 16;

/// Key material for a single node, tagged by secure-messaging scheme.
/// Not `Copy`: see [`SecureSessionCredentials`] — an implicit copy would escape
/// [`Drop`] and never be cleared.
///
/// [`SecureSessionCredentials`]: super::SecureSessionCredentials
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum NodeKey {
    /// DES/3DES key (8 bytes).
    Des([u8; DES_KEY_LEN]),
    /// FeliCa Standard v2 AES-128 node key (16 bytes).
    Aes128([u8; AES_KEY_LEN]),
}

impl NodeKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            NodeKey::Des(_) => Algorithm::Des,
            NodeKey::Aes128(_) => Algorithm::Aes128,
        }
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The scheme and key length are the useful part; the bytes are the secret.
        // `KeyStore` and `ResolvedNodeKeys` derive `Debug` over `NodeKey`, so
        // redacting here covers a whole key store too.
        let (label, len) = match self {
            NodeKey::Des(key) => ("NodeKey::Des", key.len()),
            NodeKey::Aes128(key) => ("NodeKey::Aes128", key.len()),
        };
        f.debug_tuple(label).field(&Redacted(len)).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Des,
    Aes128,
}

/// Errors from loading a key store or deriving authentication keys.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The key file could not be opened or read.
    #[error("failed to read key file: {0}")]
    Io(#[from] std::io::Error),
    /// A node required for the derivation has no key in the store.
    #[error("missing key for node {node:#06X}")]
    MissingKey { node: u16 },
    /// The nodes in the chain do not all use the same scheme.
    #[error("cannot mix DES and AES-128 keys in one authentication chain")]
    MixedAlgorithm,
    /// Neither an area path nor a service was supplied.
    #[error("no node to authenticate: area path and service are both empty")]
    EmptyChain,
    /// DES authentication was requested with an empty area path.
    #[error("DES authentication requires at least one area")]
    DesRequiresArea,
    /// DES authentication was requested with no key-contributing service —
    /// either the list is empty, or every entry is an authentication-free
    /// service, which folds no key into the chain.
    #[error("DES authentication requires at least one key-contributing service")]
    DesRequiresService,
    /// An `individual_key` was supplied for a DES node, which has no such key.
    #[error("individual_key applies only to AES-128 nodes")]
    IndividualKeyNotApplicable,
}

/// A warning for one JSONL line that was skipped during loading.
///
/// Loading never fails on a malformed line — the line is skipped and recorded
/// here so the caller can surface it however it likes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecordWarning {
    /// 1-based line number in the source.
    pub line: usize,
    /// Human-readable reason the line was skipped.
    pub message: String,
}

/// Result of loading a [`KeyStore`]: the store plus any per-line warnings.
#[derive(Debug)]
pub struct KeyStoreLoad {
    pub store: KeyStore,
    pub warnings: Vec<KeyRecordWarning>,
}

/// One JSONL record. `version` is retained for format compatibility but unused.
#[derive(Deserialize)]
struct JsonlKeyRecord {
    system_code: String,
    node: String,
    algo: String,
    #[allow(dead_code)]
    version: String,
    #[serde(default)]
    idm: Option<String>,
    key: String,
}

type NodeKeys = HashMap<u16, NodeKey>;
/// `IDm hex ("" = shared across all cards) -> node -> key`.
type IdmScopedKeys = HashMap<String, NodeKeys>;

/// A collection of node keys indexed by `system_code`, then IDm, then node.
///
/// Records with a null `idm` are stored under the shared key (`""`) and apply to
/// every card in the system; records with an IDm apply only to that card and
/// override the shared entry for the same node (see [`Self::resolve`]).
#[derive(Debug, Default)]
pub struct KeyStore {
    by_system: HashMap<u16, IdmScopedKeys>,
}

impl KeyStore {
    /// Load keys from a JSONL file. Only I/O failures are fatal; malformed lines
    /// are skipped and reported in [`KeyStoreLoad::warnings`].
    pub fn from_jsonl_path<P: AsRef<Path>>(path: P) -> Result<KeyStoreLoad, KeyError> {
        let file = File::open(path)?;
        Ok(Self::from_jsonl_reader(BufReader::new(file)))
    }

    /// Load keys from an in-memory string. See [`Self::from_jsonl_reader`].
    pub fn from_jsonl_str(contents: &str) -> KeyStoreLoad {
        Self::from_jsonl_reader(contents.as_bytes())
    }

    /// Load keys from any buffered reader, collecting per-line warnings instead
    /// of failing on malformed input.
    pub fn from_jsonl_reader<R: BufRead>(reader: R) -> KeyStoreLoad {
        let mut store = KeyStore::default();
        let mut warnings = Vec::new();

        for (index, line_result) in reader.lines().enumerate() {
            let line_num = index + 1;
            let line = match line_result {
                Ok(line) => line,
                Err(err) => {
                    warnings.push(warn(line_num, format!("failed to read line: {err}")));
                    continue;
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match parse_record(trimmed) {
                Ok((system_code, idm_key, node, node_key)) => {
                    store
                        .by_system
                        .entry(system_code)
                        .or_default()
                        .entry(idm_key)
                        .or_default()
                        .insert(node, node_key);
                }
                Err(message) => warnings.push(warn(line_num, message)),
            }
        }

        KeyStoreLoad { store, warnings }
    }

    /// Total number of node keys stored for a system, summed across every IDm
    /// scope (a node present in both a shared and a card-specific scope counts
    /// twice). Useful as a quick "did I load any keys for this system?" check.
    pub fn key_count(&self, system_code: u16) -> usize {
        self.by_system
            .get(&system_code)
            .map(|idm_scoped| idm_scoped.values().map(|nodes| nodes.len()).sum())
            .unwrap_or(0)
    }

    /// Merge the shared and card-specific keys for one `(system_code, IDm)` into
    /// a flat [`ResolvedNodeKeys`]. Card-specific keys override shared keys for
    /// the same node. Returns `None` when the system has no keys for this card.
    pub fn resolve(&self, system_code: u16, idm: &[u8]) -> Option<ResolvedNodeKeys> {
        let idm_scoped = self.by_system.get(&system_code)?;
        let idm_hex = hex::encode_upper(idm);

        // Each resolved key is its own zeroizing copy, cleared when the
        // `ResolvedNodeKeys` it belongs to is dropped.
        let mut merged = NodeKeys::new();
        if let Some(shared) = idm_scoped.get("") {
            merged.extend(shared.iter().map(|(code, key)| (*code, key.clone())));
        }
        if let Some(card) = idm_scoped.get(&idm_hex) {
            merged.extend(card.iter().map(|(code, key)| (*code, key.clone())));
        }

        if merged.is_empty() {
            None
        } else {
            Some(ResolvedNodeKeys { keys: merged })
        }
    }
}

/// The node keys for one card, flattened and ready for key derivation.
#[derive(Clone, Debug, Default)]
pub struct ResolvedNodeKeys {
    keys: NodeKeys,
}

impl ResolvedNodeKeys {
    /// Look up the raw key for a single node.
    pub fn get(&self, node: u16) -> Option<&NodeKey> {
        self.keys.get(&node)
    }

    /// Build one from an explicit node map (mainly for callers that source keys
    /// from somewhere other than a [`KeyStore`]).
    pub fn from_map(keys: HashMap<u16, NodeKey>) -> Self {
        Self { keys }
    }

    /// Derive the authentication keys for the node(s) being accessed.
    ///
    /// `area_path` lists the area codes from the outermost area inward;
    /// `services` are the target services (several when one session spans
    /// overlapping services). The scheme is chosen from the target node's own
    /// key (deepest service, else deepest area). All keys in the chain must share
    /// that scheme, otherwise [`KeyError::MixedAlgorithm`].
    ///
    /// - **DES** yields [`DerivedAuthKeys::Des`], chaining the system key
    ///   (`0xFFFF`), the `area_path` keys, and the service keys via
    ///   [`generate_service_keys_des`]. `area_path` is used verbatim (the root
    ///   area `0x0000` is *not* injected — include it yourself if the card needs
    ///   it). `area_path` must be non-empty, otherwise
    ///   [`KeyError::DesRequiresArea`].
    ///
    ///   Only the **key-contributing** entries of `services` advance the chain.
    ///   A service code list may name areas and the system node as well as
    ///   services, and the card applies the key of each of those; what it
    ///   applies no key for is an authentication-free service
    ///   ([`ServiceCode::is_key_free_service`]), which holds a key without
    ///   contributing one. Such entries are skipped here, so their keys need not
    ///   be in the store — but they are kept in the returned `services` list,
    ///   because the card still has to receive the list as the caller gave it.
    ///   At least one entry must contribute, otherwise
    ///   [`KeyError::DesRequiresService`]; a list of nothing but key-free
    ///   services would leave the user service key equal to the group service
    ///   key.
    ///
    ///   [`EmulatedSystem`] applies the same rule on the card side, so the two
    ///   agree on what a given request derives.
    ///
    ///   [`EmulatedSystem`]: super::EmulatedSystem
    /// - **AES-128** yields [`DerivedAuthKeys::Aes128`], chaining the area and
    ///   service keys (no system key) via [`generate_group_key_v2_aes128`]. The
    ///   combined node list (`area_path ++ services`) must be non-empty, though
    ///   either list may be empty on its own, otherwise [`KeyError::EmptyChain`].
    ///   `individual_key` supplies the v2 individual key — it is derived
    ///   out-of-spec per card, so it is never computed here; pass `Some(k)` to
    ///   set it manually, or `None` for all-zero (`h = group_key`). Supplying it
    ///   for a DES node is [`KeyError::IndividualKeyNotApplicable`].
    pub fn derive_auth_keys(
        &self,
        area_path: &[u16],
        services: &[ServiceCode],
        individual_key: Option<[u8; AES_KEY_LEN]>,
    ) -> Result<DerivedAuthKeys, KeyError> {
        match self.chain_algorithm(area_path, services)? {
            Algorithm::Des => {
                if individual_key.is_some() {
                    return Err(KeyError::IndividualKeyNotApplicable);
                }
                self.derive_des(area_path, services)
            }
            Algorithm::Aes128 => self.derive_aes128(
                area_path,
                services,
                individual_key.unwrap_or([0u8; AES_KEY_LEN]),
            ),
        }
    }

    /// Pick the scheme from the target node (deepest service, else deepest area).
    ///
    /// A key-free service is passed over where a key-contributing one is
    /// available: [`derive_des`] no longer consults its key, so requiring the
    /// store to hold one just to name the scheme would reject a request the
    /// derivation itself can serve. The fallback keeps a list of nothing but
    /// key-free services resolving as it did before, so the error it produces
    /// still comes from the derivation rather than from here.
    ///
    /// [`derive_des`]: Self::derive_des
    fn chain_algorithm(
        &self,
        area_path: &[u16],
        services: &[ServiceCode],
    ) -> Result<Algorithm, KeyError> {
        let target = services
            .iter()
            .rev()
            .find(|s| !s.is_key_free_service())
            .or_else(|| services.last())
            .map(|s| s.raw())
            .or_else(|| area_path.last().copied())
            .ok_or(KeyError::EmptyChain)?;
        Ok(self
            .keys
            .get(&target)
            .ok_or(KeyError::MissingKey { node: target })?
            .algorithm())
    }

    fn derive_des(
        &self,
        area_path: &[u16],
        services: &[ServiceCode],
    ) -> Result<DerivedAuthKeys, KeyError> {
        if area_path.is_empty() {
            return Err(KeyError::DesRequiresArea);
        }
        if !services.iter().any(|s| !s.is_key_free_service()) {
            return Err(KeyError::DesRequiresService);
        }

        let system_key = self.require_des(SYSTEM_SERVICE_CODE)?;
        let mut area_keys = Vec::with_capacity(area_path.len());
        for &area in area_path {
            area_keys.push(self.require_des(area)?);
        }
        let mut service_keys = Vec::with_capacity(services.len());
        for service in services {
            if service.is_key_free_service() {
                continue;
            }
            service_keys.push(self.require_des(service.raw())?);
        }

        let (group_service_key, user_service_key) =
            generate_service_keys_des(&system_key, &area_keys, &service_keys);
        Ok(DerivedAuthKeys::Des {
            areas: area_path.to_vec(),
            services: services.to_vec(),
            group_service_key,
            user_service_key,
        })
    }

    fn derive_aes128(
        &self,
        area_path: &[u16],
        services: &[ServiceCode],
        individual_key: [u8; AES_KEY_LEN],
    ) -> Result<DerivedAuthKeys, KeyError> {
        let mut nodes = Vec::with_capacity(area_path.len() + services.len());
        let mut chain = Vec::with_capacity(area_path.len() + services.len());
        for &area in area_path {
            chain.push(self.require_aes(area)?);
            nodes.push(area);
        }
        for service in services {
            chain.push(self.require_aes(service.raw())?);
            nodes.push(service.raw());
        }
        if nodes.is_empty() {
            return Err(KeyError::EmptyChain);
        }

        let group_key = generate_group_key_v2_aes128(&chain);
        Ok(DerivedAuthKeys::Aes128 {
            nodes,
            group_key,
            individual_key,
        })
    }

    fn require_des(&self, node: u16) -> Result<[u8; DES_KEY_LEN], KeyError> {
        match self.keys.get(&node) {
            Some(NodeKey::Des(key)) => Ok(*key),
            Some(NodeKey::Aes128(_)) => Err(KeyError::MixedAlgorithm),
            None => Err(KeyError::MissingKey { node }),
        }
    }

    fn require_aes(&self, node: u16) -> Result<[u8; AES_KEY_LEN], KeyError> {
        match self.keys.get(&node) {
            Some(NodeKey::Aes128(key)) => Ok(*key),
            Some(NodeKey::Des(_)) => Err(KeyError::MixedAlgorithm),
            None => Err(KeyError::MissingKey { node }),
        }
    }
}

/// Authentication keys derived for a target node, with the node list the
/// matching authentication command expects.
///
/// Bundling the node list keeps the key-chain order and the codes sent to the
/// card in lockstep — both come from a single derivation.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum DerivedAuthKeys {
    /// DES/3DES keys for [`FelicaStandard::mutual_authentication`].
    ///
    /// [`FelicaStandard::mutual_authentication`]: super::FelicaStandard::mutual_authentication
    Des {
        /// Area codes to pass as `areas` (`area_path` verbatim; always non-empty).
        #[zeroize(skip)]
        areas: Vec<u16>,
        /// Services to pass as `services` (always non-empty for DES).
        #[zeroize(skip)]
        services: Vec<ServiceCode>,
        group_service_key: [u8; DES_KEY_LEN],
        user_service_key: [u8; DES_KEY_LEN],
    },
    /// AES-128 keys for [`FelicaStandard::mutual_authentication_v2`].
    ///
    /// [`FelicaStandard::mutual_authentication_v2`]: super::FelicaStandard::mutual_authentication_v2
    Aes128 {
        /// Node codes to pass as `nodes`.
        #[zeroize(skip)]
        nodes: Vec<u16>,
        group_key: [u8; AES_KEY_LEN],
        individual_key: [u8; AES_KEY_LEN],
    },
}

// The node codes travel to the card in the clear and are what a caller needs to
// see; the derived keys are the secret.
impl fmt::Debug for DerivedAuthKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerivedAuthKeys::Des {
                areas,
                services,
                group_service_key,
                user_service_key,
            } => f
                .debug_struct("DerivedAuthKeys::Des")
                .field("areas", areas)
                .field("services", services)
                .field("group_service_key", &Redacted(group_service_key.len()))
                .field("user_service_key", &Redacted(user_service_key.len()))
                .finish(),
            DerivedAuthKeys::Aes128 {
                nodes,
                group_key,
                individual_key,
            } => f
                .debug_struct("DerivedAuthKeys::Aes128")
                .field("nodes", nodes)
                .field("group_key", &Redacted(group_key.len()))
                .field("individual_key", &Redacted(individual_key.len()))
                .finish(),
        }
    }
}

fn warn(line: usize, message: String) -> KeyRecordWarning {
    KeyRecordWarning { line, message }
}

fn parse_record(line: &str) -> Result<(u16, String, u16, NodeKey), String> {
    let record: JsonlKeyRecord =
        serde_json::from_str(line).map_err(|err| format!("failed to parse JSON: {err}"))?;

    let system_code = parse_hex_u16(&record.system_code)
        .map_err(|err| format!("invalid system_code '{}': {err}", record.system_code))?;
    let node = parse_hex_u16(&record.node)
        .map_err(|err| format!("invalid node '{}': {err}", record.node))?;
    let idm_key = match record.idm.as_deref() {
        Some(idm) => parse_idm_hex(idm)?,
        None => String::new(),
    };
    let node_key = parse_node_key(&record.algo, &record.key)?;

    Ok((system_code, idm_key, node, node_key))
}

fn parse_node_key(algo: &str, value: &str) -> Result<NodeKey, String> {
    // The decoded key lands on the heap, which is reused far more eagerly than the
    // stack, so the buffer is cleared once the key has been copied out of it.
    let mut bytes = hex::decode(value).map_err(|err| format!("invalid key '{value}': {err}"))?;
    let result = parse_node_key_bytes(algo, &bytes);
    bytes.zeroize();
    result
}

fn parse_node_key_bytes(algo: &str, bytes: &[u8]) -> Result<NodeKey, String> {
    if algo.eq_ignore_ascii_case("DES") {
        let key: [u8; DES_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| format!("DES key must be {DES_KEY_LEN} bytes, got {}", bytes.len()))?;
        Ok(NodeKey::Des(key))
    } else if algo.eq_ignore_ascii_case("AES") {
        let key: [u8; AES_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| format!("AES key must be {AES_KEY_LEN} bytes, got {}", bytes.len()))?;
        Ok(NodeKey::Aes128(key))
    } else {
        Err(format!("unsupported algo '{algo}'; expected DES or AES"))
    }
}

fn parse_hex_u16(value: &str) -> Result<u16, std::num::ParseIntError> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u16::from_str_radix(without_prefix, 16)
}

/// Validate an IDm string (plain 8-byte hex) and normalize it to uppercase.
fn parse_idm_hex(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("idm is empty".to_string());
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("idm must be plain hex".to_string());
    }
    let bytes = hex::decode(value).map_err(|err| err.to_string())?;
    if bytes.len() != super::IDM_LEN {
        return Err(format!(
            "idm must be {} bytes, got {}",
            super::IDM_LEN,
            bytes.len()
        ));
    }
    Ok(hex::encode_upper(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDM: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

    fn sample_jsonl() -> String {
        [
            // shared DES keys for system 0x0003
            r#"{"system_code":"0003","node":"FFFF","algo":"DES","version":"0000","idm":null,"key":"00112233445566FF"}"#,
            r#"{"system_code":"0003","node":"0000","algo":"des","version":"0000","idm":null,"key":"1011223344556600"}"#,
            // card-specific DES keys for the same system + IDm
            r#"{"system_code":"0003","node":"1020","algo":"DES","version":"0000","idm":"0123456789ABCDEF","key":"2011223344556620"}"#,
            r#"{"system_code":"0003","node":"1022","algo":"DES","version":"0000","idm":"0123456789ABCDEF","key":"3011223344556622"}"#,
            // shared entry that a card-specific entry overrides
            r#"{"system_code":"0003","node":"1020","algo":"DES","version":"0000","idm":null,"key":"FFFFFFFFFFFFFFFF"}"#,
            // AES keys for system 0x0018
            r#"{"system_code":"0018","node":"100A","algo":"AES","version":"0000","idm":null,"key":"000102030405060708090A0B0C0D0E0F"}"#,
            r#"{"system_code":"0018","node":"100C","algo":"AES","version":"0000","idm":null,"key":"101112131415161718191A1B1C1D1E1F"}"#,
            // malformed lines (skipped with warnings)
            "not json at all",
            r#"{"system_code":"0003","node":"ZZZZ","algo":"DES","version":"0000","idm":null,"key":"0011223344556677"}"#,
            r#"{"system_code":"0003","node":"2000","algo":"DES","version":"0000","idm":null,"key":"00112233"}"#,
            r#"{"system_code":"0003","node":"2002","algo":"RSA","version":"0000","idm":null,"key":"0011223344556677"}"#,
            "",
        ]
        .join("\n")
    }

    #[test]
    fn loads_valid_records_and_reports_bad_lines() {
        let loaded = KeyStore::from_jsonl_str(&sample_jsonl());

        // Four malformed lines (bad JSON, bad node, short key, unknown algo).
        assert_eq!(loaded.warnings.len(), 4);
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.message.contains("parse JSON"))
        );
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.message.contains("invalid node"))
        );
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.message.contains("DES key must be"))
        );
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.message.contains("unsupported algo"))
        );

        let resolved = loaded.store.resolve(0x0003, &IDM).expect("keys for card");
        assert_eq!(
            resolved.get(0xFFFF),
            Some(&NodeKey::Des([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xFF
            ]))
        );
    }

    #[test]
    fn resolve_overrides_shared_with_card_specific() {
        let loaded = KeyStore::from_jsonl_str(&sample_jsonl());
        let resolved = loaded.store.resolve(0x0003, &IDM).unwrap();

        // node 0x1020 exists as both a shared (FFFF…) and a card-specific key;
        // the card-specific one wins.
        assert_eq!(
            resolved.get(0x1020),
            Some(&NodeKey::Des([
                0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x20
            ]))
        );
        // A different IDm only sees the shared key.
        let other = loaded.store.resolve(0x0003, &[0u8; 8]).unwrap();
        assert_eq!(other.get(0x1020), Some(&NodeKey::Des([0xFF; 8])));
        assert_eq!(other.get(0x1022), None);
    }

    #[test]
    fn resolve_returns_none_for_unknown_system() {
        let loaded = KeyStore::from_jsonl_str(&sample_jsonl());
        assert!(loaded.store.resolve(0xFEFE, &IDM).is_none());
    }

    #[test]
    fn derive_des_matches_primitive() {
        let loaded = KeyStore::from_jsonl_str(&sample_jsonl());
        let resolved = loaded.store.resolve(0x0003, &IDM).unwrap();

        // area_path is used verbatim, including the root area we pass explicitly.
        let derived = resolved
            .derive_auth_keys(&[0x0000, 0x1020], &[ServiceCode::new(0x1022)], None)
            .unwrap();

        let system_key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xFF];
        let root_key = [0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00];
        let area_key = [0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x20];
        let service_key = [0x30, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x22];
        let (group, user) =
            generate_service_keys_des(&system_key, &[root_key, area_key], &[service_key]);

        match &derived {
            DerivedAuthKeys::Des {
                areas,
                services,
                group_service_key,
                user_service_key,
            } => {
                assert_eq!(areas, &vec![0x0000, 0x1020]);
                assert_eq!(services, &vec![ServiceCode::new(0x1022)]);
                assert_eq!(group_service_key, &group);
                assert_eq!(user_service_key, &user);
            }
            other => panic!("expected DES keys, got {other:?}"),
        }
    }

    /// The card folds no key in for an authentication-free service, wherever it
    /// sits in the list and however many appear, so the derivation must skip
    /// them too. Naming one must therefore leave the derived keys untouched —
    /// the behaviour [`EmulatedSystem`] implements on the card side.
    ///
    /// [`EmulatedSystem`]: crate::felica_standard::EmulatedSystem
    #[test]
    fn derive_des_skips_authentication_free_services() {
        const SYSTEM: [u8; 8] = [0xFF; 8];
        const AREA: [u8; 8] = [0xA0; 8];
        const KEYED: [u8; 8] = [0x50; 8];

        let area = 0x1000u16; // attribute 000000b — an area, always contributing
        let keyed = ServiceCode::new(0x1008); // 001000b — authentication required
        let key_free = ServiceCode::new(0x1009); // 001001b — authentication free
        assert!(!keyed.is_key_free_service());
        assert!(key_free.is_key_free_service());

        // The key-free service's key is deliberately absent: the derivation must
        // not ask for it, and `chain_algorithm` must not pick it as the node it
        // reads the scheme from. Either slip would surface here as `MissingKey`.
        let resolved = ResolvedNodeKeys::from_map(HashMap::from([
            (SYSTEM_SERVICE_CODE, NodeKey::Des(SYSTEM)),
            (area, NodeKey::Des(AREA)),
            (keyed.raw(), NodeKey::Des(KEYED)),
        ]));
        let (group, user) = generate_service_keys_des(&SYSTEM, &[AREA], &[KEYED]);

        for services in [
            vec![keyed],
            vec![keyed, key_free],
            vec![keyed, key_free, key_free],
        ] {
            let derived = resolved
                .derive_auth_keys(&[area], &services, None)
                .unwrap_or_else(|err| panic!("{services:04X?} should derive, got {err}"));
            match &derived {
                DerivedAuthKeys::Des {
                    services: listed,
                    group_service_key,
                    user_service_key,
                    ..
                } => {
                    assert_eq!(group_service_key, &group, "{services:04X?}");
                    assert_eq!(user_service_key, &user, "{services:04X?}");
                    // The list still travels to the card as the caller gave it;
                    // only the key chain skips the key-free entries.
                    assert_eq!(listed, &services, "{services:04X?}");
                }
                other => panic!("expected DES keys, got {other:?}"),
            }
        }
    }

    #[test]
    fn derive_des_rejects_a_service_list_that_contributes_no_key() {
        let area = 0x1000u16;
        let key_free = ServiceCode::new(0x1009);
        let resolved = ResolvedNodeKeys::from_map(HashMap::from([
            (SYSTEM_SERVICE_CODE, NodeKey::Des([0xFF; 8])),
            (area, NodeKey::Des([0xA0; 8])),
            (key_free.raw(), NodeKey::Des([0x50; 8])),
        ]));

        for services in [vec![], vec![key_free], vec![key_free, key_free]] {
            assert!(
                matches!(
                    resolved.derive_auth_keys(&[area], &services, None),
                    Err(KeyError::DesRequiresService)
                ),
                "{services:04X?} should be refused"
            );
        }
    }

    #[test]
    fn derive_aes_matches_primitive_and_honors_individual_key() {
        let loaded = KeyStore::from_jsonl_str(&sample_jsonl());
        let resolved = loaded.store.resolve(0x0018, &IDM).unwrap();

        let area_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let service_key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        let expected_group = generate_group_key_v2_aes128(&[area_key, service_key]);

        // Default individual key is all-zero.
        let derived = resolved
            .derive_auth_keys(&[0x100A], &[ServiceCode::new(0x100C)], None)
            .unwrap();
        match &derived {
            DerivedAuthKeys::Aes128 {
                nodes,
                group_key,
                individual_key,
            } => {
                assert_eq!(nodes, &vec![0x100A, 0x100C]);
                assert_eq!(group_key, &expected_group);
                assert_eq!(individual_key, &[0u8; 16]);
            }
            other => panic!("expected AES keys, got {other:?}"),
        }

        // A manually supplied individual key is passed through verbatim.
        let manual = [0xABu8; 16];
        let derived = resolved
            .derive_auth_keys(&[0x100A], &[ServiceCode::new(0x100C)], Some(manual))
            .unwrap();
        match derived {
            DerivedAuthKeys::Aes128 { individual_key, .. } => assert_eq!(individual_key, manual),
            other => panic!("expected AES keys, got {other:?}"),
        }
    }

    #[test]
    fn derive_errors() {
        let loaded = KeyStore::from_jsonl_str(&sample_jsonl());

        // Missing system key 0xFFFF for a card that has none.
        let des = loaded.store.resolve(0x0003, &[0u8; 8]).unwrap();
        // node 0x1022 (service) is card-specific, absent for this IDm → MissingKey.
        assert!(matches!(
            des.derive_auth_keys(&[0x1020], &[ServiceCode::new(0x1022)], None),
            Err(KeyError::MissingKey { .. })
        ));

        // individual_key on a DES node is rejected.
        let des_card = loaded.store.resolve(0x0003, &IDM).unwrap();
        assert!(matches!(
            des_card.derive_auth_keys(&[0x1020], &[ServiceCode::new(0x1022)], Some([0u8; 16])),
            Err(KeyError::IndividualKeyNotApplicable)
        ));

        // A DES service whose area chain hits an AES area key.
        let mixed = ResolvedNodeKeys::from_map(HashMap::from([
            (SYSTEM_SERVICE_CODE, NodeKey::Des([1u8; 8])),
            (0x1000, NodeKey::Aes128([3u8; 16])), // area carries an AES key
            (0x1002, NodeKey::Des([4u8; 8])),     // DES service selects the DES chain
        ]));
        assert!(matches!(
            mixed.derive_auth_keys(&[0x1000], &[ServiceCode::new(0x1002)], None),
            Err(KeyError::MixedAlgorithm)
        ));

        // DES requires a non-empty area path even when a service is supplied.
        let des_service = ResolvedNodeKeys::from_map(HashMap::from([
            (SYSTEM_SERVICE_CODE, NodeKey::Des([1u8; 8])),
            (0x1002, NodeKey::Des([4u8; 8])),
        ]));
        assert!(matches!(
            des_service.derive_auth_keys(&[], &[ServiceCode::new(0x1002)], None),
            Err(KeyError::DesRequiresArea)
        ));

        // DES requires a non-empty service list even when an area is supplied.
        let des_area = ResolvedNodeKeys::from_map(HashMap::from([
            (SYSTEM_SERVICE_CODE, NodeKey::Des([1u8; 8])),
            (0x1000, NodeKey::Des([2u8; 8])),
        ]));
        assert!(matches!(
            des_area.derive_auth_keys(&[0x1000], &[], None),
            Err(KeyError::DesRequiresService)
        ));

        // AES allows an empty service list as long as the node list is non-empty.
        let aes_area =
            ResolvedNodeKeys::from_map(HashMap::from([(0x1000, NodeKey::Aes128([5u8; 16]))]));
        assert!(matches!(
            aes_area.derive_auth_keys(&[0x1000], &[], None),
            Ok(DerivedAuthKeys::Aes128 { .. })
        ));

        // Empty chain (no area, no service).
        let empty =
            ResolvedNodeKeys::from_map(HashMap::from([(0x1000, NodeKey::Aes128([3u8; 16]))]));
        assert!(matches!(
            empty.derive_auth_keys(&[], &[], None),
            Err(KeyError::EmptyChain)
        ));
    }

    /// A key store or a derivation result must not print key bytes.
    #[test]
    fn debug_output_never_contains_key_material() {
        let store = KeyStore::from_jsonl_str(
            r#"{"system_code":"0003","node":"FFFF","algo":"DES","version":"0000","idm":null,"key":"DEADBEEFDEADBEEF"}
{"system_code":"0003","node":"1000","algo":"AES","version":"0000","idm":null,"key":"A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"}"#,
        )
        .store;

        let text = format!("{store:?}");
        assert!(!text.to_lowercase().contains("deadbeef"), "leaked: {text}");
        assert!(!text.contains("161"), "leaked a key byte: {text}");
        assert!(text.contains("<8 bytes redacted>"), "unexpected: {text}");
        assert!(text.contains("<16 bytes redacted>"), "unexpected: {text}");
        // The node codes are not secret and stay visible.
        assert!(
            text.contains("65535") || text.contains("4096"),
            "unexpected: {text}"
        );

        let resolved = store.resolve(0x0003, &[0x01; 8]).expect("resolved");
        let text = format!("{:?}", resolved.get(0xFFFF).expect("system key"));
        assert_eq!(text, "NodeKey::Des(<8 bytes redacted>)");

        let derived = DerivedAuthKeys::Des {
            areas: vec![0x1000],
            services: vec![ServiceCode::new(0x1008)],
            group_service_key: [0xDE; 8],
            user_service_key: [0xAD; 8],
        };
        let text = format!("{derived:?}");
        assert!(!text.contains("222"), "leaked a key byte: {text}");
        assert_eq!(text.matches("<8 bytes redacted>").count(), 2);
        assert!(text.contains("4096"), "node codes stay visible: {text}");
    }
}
