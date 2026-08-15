//! FeliCa Standard secure messaging.
//!
//! The protocol supports two mutually exclusive secure-messaging schemes,
//! captured by [`SecureSessionScheme`]:
//!
//! - **DES/3DES** ([`des`]) — the original FeliCa Standard secure messaging.
//! - **v2 AES-128** ([`v2_aes`]) — the FeliCa Standard v2 scheme.
//!
//! This module holds the scheme-agnostic session abstractions — the
//! authenticated-session state ([`AuthenticatedContext`]) and the per-command
//! dispatcher ([`SecureCommandContext`]) that routes each operation to the
//! scheme selected at authentication time. The low-level ciphers live in
//! [`primitives`].

mod des;
mod primitives;
#[cfg(test)]
mod test_util;
mod v2_aes;

use crate::felica_standard::redact::Redacted;
use crate::felica_standard::{
    BLOCK_SIZE, DES_BLOCK_SIZE, DES_MAC_SIZE, FelicaStandardError, MAX_PACKET_LEN,
    V2_AES128_MAC_SIZE,
};
use des::{calculate_command_mac_des, decrypt_secure_response_des};
use primitives::{encrypt_des_cbc_zero_iv, pad_to_des_block_size};
use std::fmt;
use v2_aes::{decrypt_secure_response_v2_aes128, encrypt_secure_request_v2_aes128};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export each scheme's public and crate-internal surface so the rest of the
// crate keeps referring to it through the `secure::` path.
pub use des::{Authentication2Response, generate_service_keys_des};
pub(crate) use des::{
    AuthenticationContext, build_authentication2_payload, build_secure_response_frame_des,
    check_packet_mac_des, encrypt_authentication2_payload, generate_registration_package_des,
};
pub(crate) use primitives::{ct_eq, decrypt_des_cbc_zero_iv, encrypt_des_block};
pub(crate) use v2_aes::AuthenticationContextV2Aes128;
#[cfg(test)]
pub(crate) use v2_aes::build_secure_response_frame_v2_aes128;
pub use v2_aes::{Authentication2V2Response, generate_group_key_v2_aes128};

const TRANSACTION_NUMBER_SIZE: usize = 2;
const TRANSACTION_ID_SIZE: usize = 6;
const DES_SECURE_HEADER_SIZE: usize = TRANSACTION_NUMBER_SIZE + TRANSACTION_ID_SIZE;

/// Rounds `len` up to whole DES blocks the way PKCS#7 padding does — always
/// appending between one and [`DES_BLOCK_SIZE`] bytes, so an already-aligned
/// length grows by a full block.
const fn padded_to_des_block_size(len: usize) -> usize {
    (len / DES_BLOCK_SIZE + 1) * DES_BLOCK_SIZE
}

/// Fixed part of a `Read`/`Read v2` response payload: both status flags and the
/// block count, ahead of the block data itself.
const SECURE_READ_RESPONSE_OVERHEAD: usize = 1 + 1 + 1;

/// Most blocks a single DES `Read` can return.
///
/// A secure read is bounded by its response, not its command: the request stays
/// small however many blocks it names, so an over-long one would be sent and then
/// be unanswerable. The response frame is
///
/// ```text
/// LEN(1) + response code(1) + E( txn(2) + txid(6) + SF1(1) + SF2(1) + n(1) + 16n ) + MAC(8)
/// ```
///
/// where `E(..)` is PKCS#7-padded to whole DES blocks, against the
/// [`MAX_PACKET_LEN`] ceiling of §2.2. The manual leaves the per-product maximum
/// open (§4.4.5), but no product can exceed this.
///
/// [`MAX_PACKET_LEN`]: crate::felica_standard::MAX_PACKET_LEN
pub(crate) const MAX_SECURE_READ_BLOCK_COUNT: usize = {
    let mut blocks = 0;
    while 2
        + padded_to_des_block_size(
            DES_SECURE_HEADER_SIZE + SECURE_READ_RESPONSE_OVERHEAD + (blocks + 1) * BLOCK_SIZE,
        )
        + DES_MAC_SIZE
        <= MAX_PACKET_LEN
    {
        blocks += 1;
    }
    blocks
};

/// Most blocks a single AES-128 `Read v2` can return.
///
/// The v2 scheme encrypts with an OFB stream rather than a block cipher, so its
/// response frame carries no padding:
///
/// ```text
/// LEN(1) + response code(1) + counter(2) + SF1(1) + SF2(1) + n(1) + 16n + MAC(8)
/// ```
///
/// which leaves room for one more block than the DES scheme.
pub(crate) const MAX_SECURE_READ_V2_BLOCK_COUNT: usize = (MAX_PACKET_LEN
    - (2 + TRANSACTION_NUMBER_SIZE + SECURE_READ_RESPONSE_OVERHEAD + V2_AES128_MAC_SIZE))
    / BLOCK_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureSessionScheme {
    /// FeliCa Standard secure messaging (DES/3DES).
    Des,
    /// FeliCa Standard v2 secure messaging (AES).
    Aes128,
}

/// Not `Copy`: an implicit bitwise copy is invisible to [`Drop`], so the keys
/// could be duplicated without any of the duplicates ever being cleared. Every
/// copy has to be an explicit `clone()` that zeroizes when it goes out of scope.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum SecureSessionCredentials {
    Des([u8; 8]),
    Aes128 {
        encryption_key: [u8; 16],
        mac_key: [u8; 16],
        challenge_3c: [u8; 4],
    },
}

impl SecureSessionCredentials {
    pub fn scheme(&self) -> SecureSessionScheme {
        match self {
            Self::Des(_) => SecureSessionScheme::Des,
            Self::Aes128 { .. } => SecureSessionScheme::Aes128,
        }
    }
}

// The session keys must not reach a log; `challenge_3c` is carried in the clear
// in the Authentication1 v2 response, so it stays visible for debugging.
impl fmt::Debug for SecureSessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Des(key) => f
                .debug_tuple("SecureSessionCredentials::Des")
                .field(&Redacted(key.len()))
                .finish(),
            Self::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => f
                .debug_struct("SecureSessionCredentials::Aes128")
                .field("encryption_key", &Redacted(encryption_key.len()))
                .field("mac_key", &Redacted(mac_key.len()))
                .field("challenge_3c", challenge_3c)
                .finish(),
        }
    }
}

impl fmt::Debug for SecureSessionCredentialsRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Des(key) => f
                .debug_tuple("SecureSessionCredentialsRef::Des")
                .field(&Redacted(key.len()))
                .finish(),
            Self::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => f
                .debug_struct("SecureSessionCredentialsRef::Aes128")
                .field("encryption_key", &Redacted(encryption_key.len()))
                .field("mac_key", &Redacted(mac_key.len()))
                .field("challenge_3c", challenge_3c)
                .finish(),
        }
    }
}

// The transaction number and ID are known to both parties and useful to see; the
// credentials are not, and they are what `SecureSessionCredentials` redacts.
impl fmt::Debug for AuthenticatedContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedContext")
            .field("transaction_number", &self.transaction_number)
            .field("transaction_id", &self.transaction_id)
            .field("credentials", &self.credentials)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecureSessionCredentialsRef<'a> {
    Des(&'a [u8; 8]),
    Aes128 {
        encryption_key: &'a [u8; 16],
        mac_key: &'a [u8; 16],
        challenge_3c: &'a [u8; 4],
    },
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatedContext {
    transaction_number: u16,
    transaction_id: [u8; 6],
    credentials: SecureSessionCredentials,
    /// The service list this session was opened against, in Authentication1
    /// order. Node codes are structure, not secrets, so they are not zeroized
    /// with the session keys.
    #[zeroize(skip)]
    nodes: Vec<u16>,
}

impl AuthenticatedContext {
    pub fn new(
        transaction_number: u16,
        transaction_id: [u8; 6],
        credentials: SecureSessionCredentials,
    ) -> Self {
        Self {
            transaction_number,
            transaction_id,
            credentials,
            nodes: Vec::new(),
        }
    }

    /// Records the session's addressable node list.
    ///
    /// A block list element names its target by position in this list (§4.4.5,
    /// "サービスコードリスト順番"), so anything that has to identify a node of
    /// the live session — reading a block, or [`change_keys`] naming the node
    /// whose key it replaces — depends on the order being preserved.
    ///
    /// For DES this is the **service** list of Authentication1: the area list
    /// scopes the key chain and is not addressable. For v2 it is the node list.
    ///
    /// A context built by hand (a relay that holds the keys, say) should pass
    /// the same list it authenticated with; leaving it empty only means node
    /// lookups fail with [`InvalidParameter`], never that a wrong node is used.
    ///
    /// [`change_keys`]: crate::felica_standard::FelicaStandard::change_keys
    /// [`InvalidParameter`]: FelicaStandardError::InvalidParameter
    pub fn with_nodes(mut self, nodes: Vec<u16>) -> Self {
        self.nodes = nodes;
        self
    }

    /// The addressable nodes of this session, in Authentication1 order.
    pub fn nodes(&self) -> &[u16] {
        &self.nodes
    }

    /// Position of `node` in the session's node list, which is what a block list
    /// element's "service code list order" field selects (§4.4.5, figure 4-8).
    pub fn node_index(&self, node: u16) -> Option<usize> {
        self.nodes.iter().position(|listed| *listed == node)
    }

    pub fn scheme(&self) -> SecureSessionScheme {
        self.credentials.scheme()
    }

    #[cfg(test)]
    pub(crate) fn ensure_scheme(
        &self,
        expected: SecureSessionScheme,
    ) -> Result<(), FelicaStandardError> {
        if self.scheme() != expected {
            let label = match expected {
                SecureSessionScheme::Des => "DES",
                SecureSessionScheme::Aes128 => "AES",
            };
            return Err(FelicaStandardError::SecureSession(format!(
                "authenticated secure session scheme is not {label}"
            )));
        }
        Ok(())
    }

    pub fn transaction_number(&self) -> u16 {
        self.transaction_number
    }

    pub fn transaction_id(&self) -> &[u8; 6] {
        &self.transaction_id
    }

    pub fn credentials(&self) -> SecureSessionCredentialsRef<'_> {
        match &self.credentials {
            SecureSessionCredentials::Des(key) => SecureSessionCredentialsRef::Des(key),
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => SecureSessionCredentialsRef::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            },
        }
    }

    pub fn increment_transaction_number(&mut self) -> Result<u16, FelicaStandardError> {
        if self.transaction_number == u16::MAX {
            return Err(FelicaStandardError::SecureSession(
                "transaction number overflow during secure session".into(),
            ));
        }
        self.transaction_number += 1;
        Ok(self.transaction_number)
    }

    pub fn set_transaction_number(&mut self, value: u16) {
        self.transaction_number = value;
    }
}

pub(crate) struct DecryptedSecureResponse {
    pub(crate) transaction_number: u16,
    pub(crate) payload: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecureCommandContext {
    transaction_number: u16,
    transaction_id: [u8; 6],
    credentials: SecureSessionCredentials,
}

impl SecureCommandContext {
    pub(crate) fn capture(context: &mut AuthenticatedContext) -> Result<Self, FelicaStandardError> {
        let transaction_number = context.increment_transaction_number()?;
        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(context.transaction_id());
        let credentials = context.credentials.clone();
        Ok(Self {
            transaction_number,
            transaction_id,
            credentials,
        })
    }

    pub(crate) fn build_payload_des(&self, command_payload: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(DES_SECURE_HEADER_SIZE + command_payload.len());
        payload.extend_from_slice(&self.transaction_number.to_le_bytes());
        payload.extend_from_slice(&self.transaction_id);
        payload.extend_from_slice(command_payload);
        payload
    }

    pub(crate) fn build_secure_payload(&self, command_payload: &[u8]) -> Vec<u8> {
        match self.credentials.scheme() {
            SecureSessionScheme::Des => self.build_payload_des(command_payload),
            SecureSessionScheme::Aes128 => command_payload.to_vec(),
        }
    }

    fn transaction_counter_bytes(&self) -> [u8; 2] {
        self.transaction_number.to_le_bytes()
    }

    pub(crate) fn encrypt_command(
        &self,
        command_code: u8,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        match &self.credentials {
            SecureSessionCredentials::Des(key) => {
                let padded_payload = pad_to_des_block_size(payload);
                let mac = calculate_command_mac_des(command_code, &padded_payload)
                    .map_err(FelicaStandardError::Protocol)?;
                let mut command_data = padded_payload;
                command_data.extend_from_slice(&mac);
                encrypt_des_cbc_zero_iv(&command_data, key).map_err(FelicaStandardError::Protocol)
            }
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => encrypt_secure_request_v2_aes128(
                command_code,
                self.transaction_counter_bytes(),
                &self.transaction_id,
                challenge_3c,
                encryption_key,
                mac_key,
                &payload,
            )
            .map_err(FelicaStandardError::Protocol),
        }
    }

    pub(crate) fn decrypt_response(
        &self,
        response_code: u8,
        data: &[u8],
    ) -> Result<DecryptedSecureResponse, FelicaStandardError> {
        match &self.credentials {
            SecureSessionCredentials::Des(key) => {
                decrypt_secure_response_des(response_code, &self.transaction_id, key, data)
            }
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => decrypt_secure_response_v2_aes128(
                response_code,
                &self.transaction_id,
                challenge_3c,
                encryption_key,
                mac_key,
                data,
            )
            .map_err(FelicaStandardError::Protocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::{assert_protocol_error_contains, assert_secure_session_error_contains};
    use super::*;

    #[test]
    fn authenticated_context_increment_and_overflow() {
        let mut context = AuthenticatedContext::new(
            u16::MAX - 1,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Des([7, 8, 9, 10, 11, 12, 13, 14]),
        );
        assert_eq!(context.scheme(), SecureSessionScheme::Des);
        assert_eq!(context.increment_transaction_number().unwrap(), u16::MAX);
        assert_secure_session_error_contains(
            context.increment_transaction_number(),
            "transaction number overflow",
        );
    }

    #[test]
    fn secure_command_context_capture_and_build_payload() {
        let mut context = AuthenticatedContext::new(
            0x0020,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Des([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]),
        );

        let captured = SecureCommandContext::capture(&mut context).unwrap();
        assert_eq!(context.transaction_number(), 0x0021u16);
        assert_eq!(captured.transaction_number, 0x0021);
        assert_eq!(captured.transaction_id, [1, 2, 3, 4, 5, 6]);
        assert_eq!(
            captured.credentials,
            SecureSessionCredentials::Des([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7])
        );

        let payload = captured.build_payload_des(&[0x55, 0x66, 0x77]);
        assert_eq!(&payload[0..2], &0x0021u16.to_le_bytes());
        assert_eq!(&payload[2..8], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&payload[8..], &[0x55, 0x66, 0x77]);
    }

    #[test]
    fn secure_command_encrypt_and_decrypt_round_trip() {
        let mut context = AuthenticatedContext::new(
            0,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Des([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]),
        );
        let captured = SecureCommandContext::capture(&mut context).unwrap();
        let payload = captured.build_payload_des(&[0xAA, 0xBB, 0xCC]);

        let encrypted = captured.encrypt_command(0x42, payload).unwrap();
        let decrypted = captured.decrypt_response(0x42, &encrypted).unwrap();
        assert_eq!(decrypted.transaction_number, captured.transaction_number);
        assert_eq!(
            decrypted.payload,
            vec![0xAA, 0xBB, 0xCC, 0x05, 0x05, 0x05, 0x05, 0x05]
        );
    }

    #[test]
    fn secure_command_encrypt_rejects_too_long_payload() {
        let mut context = AuthenticatedContext::new(
            0,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Des([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]),
        );
        let captured = SecureCommandContext::capture(&mut context).unwrap();
        let payload = vec![0xAB; 248];
        assert_protocol_error_contains(
            captured.encrypt_command(0x42, payload),
            "exceeds maximum frame length",
        );
    }

    #[test]
    fn authenticated_context_v2_holds_key() {
        let encryption_key = [0x55u8; 16];
        let mac_key = [0x77u8; 16];
        let challenge_3c = [0x01, 0x02, 0x03, 0x04];
        let context = AuthenticatedContext::new(
            7,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            },
        );
        assert_eq!(context.scheme(), SecureSessionScheme::Aes128);
        assert_eq!(
            context.credentials(),
            SecureSessionCredentialsRef::Aes128 {
                encryption_key: &encryption_key,
                mac_key: &mac_key,
                challenge_3c: &challenge_3c,
            }
        );
        assert!(context.ensure_scheme(SecureSessionScheme::Aes128).is_ok());
        assert!(context.ensure_scheme(SecureSessionScheme::Des).is_err());
    }

    /// Key material must never reach a log or a panic message, so the types that
    /// carry it redact their secret fields rather than deriving `Debug`.
    #[test]
    fn debug_output_never_contains_key_material() {
        let des_key = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
        let encryption_key = [0xA1u8; 16];
        let mac_key = [0xB2u8; 16];
        let challenge_3c = [0x01, 0x02, 0x03, 0x04];

        // `{:?}` on a byte array renders decimals, so 0xDE would appear as 222.
        let des = SecureSessionCredentials::Des(des_key);
        let text = format!("{des:?}");
        assert!(!text.contains("222"), "DES key byte leaked: {text}");
        assert!(!text.contains("190"), "DES key byte leaked: {text}");
        assert_eq!(text, "SecureSessionCredentials::Des(<8 bytes redacted>)");

        let aes = SecureSessionCredentials::Aes128 {
            encryption_key,
            mac_key,
            challenge_3c,
        };
        let text = format!("{aes:?}");
        assert!(!text.contains("161"), "AES key byte leaked: {text}");
        assert_eq!(text.matches("<16 bytes redacted>").count(), 2);
        // challenge_3c travels in the clear in the Authentication1 v2 response, so
        // it stays visible for debugging.
        assert!(text.contains("challenge_3c"), "unexpected: {text}");

        let context = AuthenticatedContext::new(7, [1, 2, 3, 4, 5, 6], des);
        let text = format!("{context:?}");
        assert!(text.contains("transaction_number: 7"), "unexpected: {text}");
        assert!(text.contains("<8 bytes redacted>"), "unexpected: {text}");
        assert!(!text.contains("222"), "session key leaked: {text}");

        let text = format!("{:?}", context.credentials());
        assert!(text.contains("<8 bytes redacted>"), "unexpected: {text}");
        assert!(!text.contains("222"), "session key leaked via ref: {text}");
    }

    /// Key material must not outlive the type that holds it. `Zeroize` is what
    /// clears it, and `ZeroizeOnDrop` is what guarantees the clear actually runs
    /// when the value goes out of scope.
    #[test]
    fn credentials_are_cleared_when_zeroized() {
        let mut des = SecureSessionCredentials::Des([0xAB; 8]);
        des.zeroize();
        assert_eq!(des, SecureSessionCredentials::Des([0x00; 8]));

        let mut aes = SecureSessionCredentials::Aes128 {
            encryption_key: [0xCD; 16],
            mac_key: [0xEF; 16],
            challenge_3c: [0x01, 0x02, 0x03, 0x04],
        };
        aes.zeroize();
        assert_eq!(
            aes,
            SecureSessionCredentials::Aes128 {
                encryption_key: [0x00; 16],
                mac_key: [0x00; 16],
                challenge_3c: [0x00; 4],
            }
        );

        let mut context =
            AuthenticatedContext::new(9, [1, 2, 3, 4, 5, 6], SecureSessionCredentials::Des([7; 8]));
        context.zeroize();
        assert_eq!(context.transaction_number(), 0);
        assert_eq!(
            context.credentials(),
            SecureSessionCredentialsRef::Des(&[0; 8])
        );
    }

    /// `Copy` would let the compiler duplicate key material without `Drop` ever
    /// seeing the duplicate, so these types must not be `Copy`. A static assertion
    /// is the only way to keep a future `#[derive(Copy)]` from slipping back in.
    #[test]
    fn key_bearing_types_are_not_copy() {
        fn assert_not_copy<T: Clone>() {}
        // `ZeroizeOnDrop` is only implementable for a non-`Copy` type, since `Copy`
        // and `Drop` are mutually exclusive; requiring the bound below therefore
        // pins the property.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_not_copy::<SecureSessionCredentials>();
        assert_zeroize_on_drop::<SecureSessionCredentials>();
        assert_zeroize_on_drop::<AuthenticatedContext>();
        assert_zeroize_on_drop::<crate::felica_standard::NodeKey>();
        assert_zeroize_on_drop::<crate::felica_standard::DerivedAuthKeys>();
        assert_zeroize_on_drop::<crate::felica_standard::ChangeKeyParameters>();
        assert_zeroize_on_drop::<crate::felica_standard::EmulatedSystem>();
        assert_zeroize_on_drop::<crate::felica_standard::EmulatedArea>();
        assert_zeroize_on_drop::<crate::felica_standard::EmulatedService>();
    }

    /// `ZeroizeOnDrop` is only useful if the clear is observable after the value
    /// dies. Reading the bytes back through a raw pointer is the only way to check
    /// that from inside the language: the storage is deliberately kept alive in a
    /// `MaybeUninit` so the read stays in-bounds after the value is dropped.
    #[test]
    fn dropping_a_session_context_overwrites_the_key_in_place() {
        use std::mem::MaybeUninit;

        const KEY: [u8; 8] = [0x5A; 8];

        let mut slot: MaybeUninit<AuthenticatedContext> = MaybeUninit::new(
            AuthenticatedContext::new(1, [1, 2, 3, 4, 5, 6], SecureSessionCredentials::Des(KEY)),
        );
        let base = slot.as_ptr().cast::<u8>();
        let size = size_of::<AuthenticatedContext>();

        // SAFETY: `slot` is initialised, and the read stays within its allocation.
        let before = unsafe { std::slice::from_raw_parts(base, size) }.to_vec();
        assert!(
            before.windows(KEY.len()).any(|window| window == KEY),
            "the key should be present while the context is alive"
        );

        // SAFETY: `slot` is initialised and is not read as a value afterwards.
        unsafe { slot.assume_init_drop() };

        // SAFETY: the backing storage is still owned by `slot`, so this reads
        // memory this test allocated; the value it held is gone by design.
        let after = unsafe { std::slice::from_raw_parts(base, size) };
        assert!(
            !after.windows(KEY.len()).any(|window| window == KEY),
            "dropping the context must have overwritten the key, found {after:02X?}"
        );
    }
}
