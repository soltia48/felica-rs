//! FeliCa Standard v2 secure messaging over AES-128.
//!
//! Covers the AES mutual-authentication context, the AES-OFB encryption with
//! AES-CMAC authentication used for secure requests/responses, and the AES node
//! key (group key) derivation.

use super::DecryptedSecureResponse;
use super::TRANSACTION_NUMBER_SIZE;
use super::primitives::{
    ct_eq, decrypt_aes128_block_internal, encrypt_aes128_block_internal, xor_block,
};
use crate::felica_standard::{
    AUTHENTICATION2_V2_RESPONSE_CODE, FelicaStandardError, V2_AES128_BLOCK_SIZE,
    V2_AES128_MAC_SIZE, frame_with_length_prefix,
};
use aes::Aes128;
use cmac::{Cmac, Mac};
use des::cipher::{KeyInit, KeyIvInit, StreamCipher};
use ofb::Ofb;

const V2_AES128_IV_MARKER: u8 = 0x01;
const V2_AES128_AUTH_CONTEXT_SUFFIX: [u8; 2] = [0x01, 0x00];
const V2_AES128_NODE_KEY_INIT: [u8; V2_AES128_BLOCK_SIZE] = [
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
];
const V2_AES128_DERIVE_ENCRYPTION_KEY_INPUT: [u8; V2_AES128_BLOCK_SIZE] = [
    0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];
const V2_AES128_DERIVE_MAC_KEY_INPUT: [u8; V2_AES128_BLOCK_SIZE] = [
    0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2V2Response {
    pub(crate) encrypted_payload: Vec<u8>,
}

impl Authentication2V2Response {
    pub fn scheme(&self) -> super::SecureSessionScheme {
        super::SecureSessionScheme::Aes128
    }

    pub fn decrypt_payload(
        &self,
        transaction_id: &[u8; 6],
        challenge_3c: &[u8; 4],
        encryption_key: &[u8; V2_AES128_BLOCK_SIZE],
        mac_key: &[u8; V2_AES128_BLOCK_SIZE],
    ) -> Result<(u16, Vec<u8>), FelicaStandardError> {
        let decrypted = decrypt_secure_response_v2_aes128(
            AUTHENTICATION2_V2_RESPONSE_CODE,
            transaction_id,
            challenge_3c,
            encryption_key,
            mac_key,
            &self.encrypted_payload,
        )
        .map_err(FelicaStandardError::SecureSession)?;
        Ok((decrypted.transaction_number, decrypted.payload))
    }
}

pub(crate) struct AuthenticationContextV2Aes128 {
    alpha: [u8; V2_AES128_BLOCK_SIZE],
    beta: [u8; V2_AES128_BLOCK_SIZE],
}

impl AuthenticationContextV2Aes128 {
    pub(crate) fn new(
        idm: &[u8; 8],
        group_key: &[u8; V2_AES128_BLOCK_SIZE],
        individual_key: &[u8; V2_AES128_BLOCK_SIZE],
    ) -> Self {
        let h = xor_block(group_key, individual_key);
        let alpha = encrypt_aes128_block_internal(
            &build_authentication_context_block_v2_aes128([0x01, 0x02], idm),
            &h,
        );
        let beta = encrypt_aes128_block_internal(
            &build_authentication_context_block_v2_aes128([0x02, 0x02], idm),
            &h,
        );
        Self { alpha, beta }
    }

    fn beta_with_challenge_3c(&self, challenge_3c: &[u8; 4]) -> [u8; V2_AES128_BLOCK_SIZE] {
        let mut beta_mask = [0u8; V2_AES128_BLOCK_SIZE];
        beta_mask[..4].copy_from_slice(challenge_3c);
        xor_block(&self.beta, &beta_mask)
    }

    pub(crate) fn encrypt_challenge1a(&self, random_1: &[u8; V2_AES128_BLOCK_SIZE]) -> [u8; 16] {
        encrypt_aes128_block_internal(random_1, &self.alpha)
    }

    pub(crate) fn encrypt_challenge1b(
        &self,
        random_1: &[u8; V2_AES128_BLOCK_SIZE],
        challenge_3c: &[u8; 4],
    ) -> [u8; 16] {
        let beta = self.beta_with_challenge_3c(challenge_3c);
        encrypt_aes128_block_internal(random_1, &beta)
    }

    pub(crate) fn verify_challenge1b(
        &self,
        random_1: &[u8; V2_AES128_BLOCK_SIZE],
        challenge_1b: &[u8; V2_AES128_BLOCK_SIZE],
        challenge_3c: &[u8; 4],
    ) -> bool {
        ct_eq(
            &self.encrypt_challenge1b(random_1, challenge_3c),
            challenge_1b,
        )
    }

    #[cfg(test)]
    pub(crate) fn encrypt_challenge2a(
        &self,
        random_2: &[u8; V2_AES128_BLOCK_SIZE],
        challenge_3c: &[u8; 4],
    ) -> [u8; 16] {
        let beta = self.beta_with_challenge_3c(challenge_3c);
        encrypt_aes128_block_internal(random_2, &beta)
    }

    pub(crate) fn decrypt_challenge2a(
        &self,
        challenge_2a: &[u8; V2_AES128_BLOCK_SIZE],
        challenge_3c: &[u8; 4],
    ) -> [u8; 16] {
        let beta = self.beta_with_challenge_3c(challenge_3c);
        decrypt_aes128_block_internal(challenge_2a, &beta)
    }

    pub(crate) fn encrypt_challenge2b(&self, random_2: &[u8; V2_AES128_BLOCK_SIZE]) -> [u8; 16] {
        encrypt_aes128_block_internal(random_2, &self.alpha)
    }

    pub(crate) fn derive_secure_session_keys(
        &self,
        random_2: &[u8; V2_AES128_BLOCK_SIZE],
    ) -> ([u8; V2_AES128_BLOCK_SIZE], [u8; V2_AES128_BLOCK_SIZE]) {
        let encryption_key =
            encrypt_aes128_block_internal(&V2_AES128_DERIVE_ENCRYPTION_KEY_INPUT, random_2);
        let mac_key = encrypt_aes128_block_internal(&V2_AES128_DERIVE_MAC_KEY_INPUT, random_2);
        (encryption_key, mac_key)
    }
}

fn build_authentication_context_block_v2_aes128(
    prefix: [u8; 2],
    idm: &[u8; 8],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let mut block = [0u8; V2_AES128_BLOCK_SIZE];
    block[..2].copy_from_slice(&prefix);
    block[6..14].copy_from_slice(idm);
    block[14..16].copy_from_slice(&V2_AES128_AUTH_CONTEXT_SUFFIX);
    block
}

fn ceil_to_multiple(value: usize, block_size: usize) -> usize {
    value.div_ceil(block_size) * block_size
}

fn build_initial_vector_v2_aes128(
    frame_length: u8,
    code: u8,
    counter_bytes: [u8; 2],
    transaction_id: &[u8; 6],
    challenge_3c: &[u8; 4],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let mut iv = [0u8; V2_AES128_BLOCK_SIZE];
    iv[0] = V2_AES128_IV_MARKER;
    iv[1] = frame_length;
    iv[2] = code;
    iv[3..5].copy_from_slice(&counter_bytes);
    iv[5..11].copy_from_slice(transaction_id);
    iv[11..14].copy_from_slice(&challenge_3c[1..4]);
    iv
}

fn checked_frame_length_u8(frame_length: usize, context: &str) -> Result<u8, String> {
    if frame_length > u8::MAX as usize {
        return Err(context.into());
    }
    Ok(frame_length as u8)
}

fn calculate_mac_v2_aes128(
    iv: &[u8; V2_AES128_BLOCK_SIZE],
    payload: &[u8],
    mac_key: &[u8; V2_AES128_BLOCK_SIZE],
) -> [u8; V2_AES128_MAC_SIZE] {
    let mut b0 = [0u8; V2_AES128_BLOCK_SIZE];
    b0[0] = 0x19;
    b0[1..14].copy_from_slice(&iv[1..14]);
    b0[14..16].copy_from_slice(&(payload.len() as u16).to_be_bytes());

    let mut cmac = <Cmac<Aes128> as KeyInit>::new_from_slice(mac_key)
        .expect("AES-128 CMAC key length is fixed to 16 bytes");
    cmac.update(&b0);
    cmac.update(payload);
    let full = cmac.finalize().into_bytes();
    let mut mac = [0u8; V2_AES128_MAC_SIZE];
    mac.copy_from_slice(&full[..V2_AES128_MAC_SIZE]);
    mac
}

fn crypt_payload_and_mac_v2_aes128(
    encryption_key: &[u8; V2_AES128_BLOCK_SIZE],
    iv: &[u8; V2_AES128_BLOCK_SIZE],
    payload: &[u8],
    mac: &[u8; V2_AES128_MAC_SIZE],
) -> Result<(Vec<u8>, [u8; V2_AES128_MAC_SIZE]), String> {
    let mut stream = Ofb::<Aes128>::new_from_slices(encryption_key, iv)
        .map_err(|_| "failed to initialize AES-128 OFB stream".to_string())?;

    let mut payload_out = payload.to_vec();
    stream.apply_keystream(&mut payload_out);
    let aligned = ceil_to_multiple(payload.len(), V2_AES128_BLOCK_SIZE);
    if aligned > payload.len() {
        let mut skip = vec![0u8; aligned - payload.len()];
        stream.apply_keystream(&mut skip);
    }

    let mut mac_out = *mac;
    stream.apply_keystream(&mut mac_out);
    Ok((payload_out, mac_out))
}

pub(super) fn encrypt_secure_request_v2_aes128(
    command_code: u8,
    counter_bytes: [u8; 2],
    transaction_id: &[u8; 6],
    challenge_3c: &[u8; 4],
    encryption_key: &[u8; V2_AES128_BLOCK_SIZE],
    mac_key: &[u8; V2_AES128_BLOCK_SIZE],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let frame_length = checked_frame_length_u8(
        1usize + 1 + TRANSACTION_NUMBER_SIZE + payload.len() + V2_AES128_MAC_SIZE,
        "secure command payload exceeds maximum frame length",
    )?;
    let iv = build_initial_vector_v2_aes128(
        frame_length,
        command_code,
        counter_bytes,
        transaction_id,
        challenge_3c,
    );
    let mac = calculate_mac_v2_aes128(&iv, payload, mac_key);
    let (cipher_payload, cipher_mac) =
        crypt_payload_and_mac_v2_aes128(encryption_key, &iv, payload, &mac)?;
    let mut out = Vec::with_capacity(2 + cipher_payload.len() + V2_AES128_MAC_SIZE);
    out.extend_from_slice(&counter_bytes);
    out.extend_from_slice(&cipher_payload);
    out.extend_from_slice(&cipher_mac);
    Ok(out)
}

pub(super) fn decrypt_secure_response_v2_aes128(
    response_code: u8,
    transaction_id: &[u8; 6],
    challenge_3c: &[u8; 4],
    encryption_key: &[u8; V2_AES128_BLOCK_SIZE],
    mac_key: &[u8; V2_AES128_BLOCK_SIZE],
    data: &[u8],
) -> Result<DecryptedSecureResponse, String> {
    if data.len() < TRANSACTION_NUMBER_SIZE + V2_AES128_MAC_SIZE {
        return Err("secure response too short for AES v2 framing".into());
    }
    let mut counter_bytes = [0u8; 2];
    counter_bytes.copy_from_slice(&data[..2]);
    let transaction_number = u16::from_le_bytes(counter_bytes);
    let cipher_payload = &data[2..data.len() - V2_AES128_MAC_SIZE];
    let mut cipher_mac = [0u8; V2_AES128_MAC_SIZE];
    cipher_mac.copy_from_slice(&data[data.len() - V2_AES128_MAC_SIZE..]);

    let frame_length = checked_frame_length_u8(
        TRANSACTION_NUMBER_SIZE + data.len(),
        "secure response exceeds maximum frame length",
    )?;
    let iv = build_initial_vector_v2_aes128(
        frame_length,
        response_code,
        counter_bytes,
        transaction_id,
        challenge_3c,
    );
    let (payload, mac_plain) =
        crypt_payload_and_mac_v2_aes128(encryption_key, &iv, cipher_payload, &cipher_mac)?;
    // The recomputed tag is secret-derived and this verifies attacker-supplied
    // frames, so compare in constant time (no early-out timing oracle).
    if ct_eq(&mac_plain, &calculate_mac_v2_aes128(&iv, &payload, mac_key)) {
        return Ok(DecryptedSecureResponse {
            transaction_number,
            payload,
        });
    }
    Err("secure response MAC verification failed for AES v2".into())
}

#[allow(dead_code)]
pub(crate) fn build_secure_response_frame_v2_aes128(
    response_code: u8,
    transaction_number: u16,
    transaction_id: &[u8; 6],
    challenge_3c: &[u8; 4],
    encryption_key: &[u8; V2_AES128_BLOCK_SIZE],
    mac_key: &[u8; V2_AES128_BLOCK_SIZE],
    response_payload: &[u8],
) -> Option<Vec<u8>> {
    let frame_length = checked_frame_length_u8(
        1usize + 1 + TRANSACTION_NUMBER_SIZE + response_payload.len() + V2_AES128_MAC_SIZE,
        "secure response exceeds maximum frame length",
    )
    .ok()?;
    let counter_bytes = transaction_number.to_le_bytes();
    let iv = build_initial_vector_v2_aes128(
        frame_length,
        response_code,
        counter_bytes,
        transaction_id,
        challenge_3c,
    );
    let mac = calculate_mac_v2_aes128(&iv, response_payload, mac_key);
    let (cipher_payload, cipher_mac) =
        crypt_payload_and_mac_v2_aes128(encryption_key, &iv, response_payload, &mac).ok()?;
    let mut frame_payload = Vec::with_capacity(1 + 2 + cipher_payload.len() + V2_AES128_MAC_SIZE);
    frame_payload.push(response_code);
    frame_payload.extend_from_slice(&counter_bytes);
    frame_payload.extend_from_slice(&cipher_payload);
    frame_payload.extend_from_slice(&cipher_mac);
    Some(frame_with_length_prefix(&frame_payload))
}

pub fn generate_group_key_v2_aes128(
    node_keys: &[[u8; V2_AES128_BLOCK_SIZE]],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let mut current_key = V2_AES128_NODE_KEY_INIT;
    for key in node_keys {
        current_key = encrypt_aes128_block_internal(&current_key, key);
    }
    current_key
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_secure_session_error_contains, bytes_from_hex};
    use super::*;

    #[test]
    fn authentication_context_v2_challenge_round_trip() {
        let idm = [1, 2, 3, 4, 5, 6, 7, 8];
        let group_key = [0x11u8; V2_AES128_BLOCK_SIZE];
        let individual_key = [0x22u8; V2_AES128_BLOCK_SIZE];
        let random_1 = [0x33u8; V2_AES128_BLOCK_SIZE];
        let random_2 = [0x44u8; V2_AES128_BLOCK_SIZE];
        let challenge_3c = [0xAA, 0xBB, 0xCC, 0xDD];

        let context = AuthenticationContextV2Aes128::new(&idm, &group_key, &individual_key);
        let challenge_1a = context.encrypt_challenge1a(&random_1);
        assert_eq!(
            decrypt_aes128_block_internal(&challenge_1a, &context.alpha),
            random_1
        );

        let challenge_1b = context.encrypt_challenge1b(&random_1, &challenge_3c);
        assert!(context.verify_challenge1b(&random_1, &challenge_1b, &challenge_3c));

        let challenge_2a = context.encrypt_challenge2a(&random_2, &challenge_3c);
        assert_eq!(
            context.decrypt_challenge2a(&challenge_2a, &challenge_3c),
            random_2
        );

        let challenge_2b = context.encrypt_challenge2b(&random_2);
        assert_eq!(
            decrypt_aes128_block_internal(&challenge_2b, &context.alpha),
            random_2
        );
    }

    #[test]
    fn authentication2_v2_response_decrypts_with_derived_keys() {
        let idm = [1, 2, 3, 4, 5, 6, 7, 8];
        let group_key = [0x10u8; V2_AES128_BLOCK_SIZE];
        let individual_key = [0x20u8; V2_AES128_BLOCK_SIZE];
        let random_1 = [0x30u8; V2_AES128_BLOCK_SIZE];
        let random_2 = [0x40u8; V2_AES128_BLOCK_SIZE];
        let challenge_3c = [0x10, 0x11, 0x12, 0x13];
        let context = AuthenticationContextV2Aes128::new(&idm, &group_key, &individual_key);
        let (encryption_key, mac_key) = context.derive_secure_session_keys(&random_2);

        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&random_1[2..8]);
        let payload = bytes_from_hex("00112233445566778899aabbccddeeff");
        let frame = build_secure_response_frame_v2_aes128(
            AUTHENTICATION2_V2_RESPONSE_CODE,
            0,
            &transaction_id,
            &challenge_3c,
            &encryption_key,
            &mac_key,
            &payload,
        )
        .expect("failed to build authentication2 v2 response frame");
        let response = Authentication2V2Response {
            encrypted_payload: frame[2..].to_vec(),
        };

        let (transaction_number, decrypted_payload) = response
            .decrypt_payload(&transaction_id, &challenge_3c, &encryption_key, &mac_key)
            .expect("failed to decrypt authentication2 v2 payload");
        assert_eq!(transaction_number, 0);
        assert_eq!(decrypted_payload, payload);

        let mut wrong_tx_id = transaction_id;
        wrong_tx_id[0] ^= 0xFF;
        assert_secure_session_error_contains(
            response.decrypt_payload(&wrong_tx_id, &challenge_3c, &encryption_key, &mac_key),
            "MAC verification failed",
        );

        let mut wrong_challenge_3c = challenge_3c;
        wrong_challenge_3c[1] ^= 0xFF;
        assert_secure_session_error_contains(
            response.decrypt_payload(
                &transaction_id,
                &wrong_challenge_3c,
                &encryption_key,
                &mac_key,
            ),
            "MAC verification failed",
        );
    }

    #[test]
    fn secure_v2_encrypt_matches_reference_vector() {
        let payload = bytes_from_hex(
            "0000000100000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let tx_id = [0x5E, 0xC8, 0xB5, 0x97, 0x17, 0x04];
        let challenge_3c = [0x00u8; 4];
        let expected = bytes_from_hex(
            "41cfae0d2f92b2259287e05646e140e5924ee27f79cb69a2047da5f9353eed59e35fbc90a5d731d25a0fcdbdd6802174",
        );
        let encoded = encrypt_secure_request_v2_aes128(
            0x48,
            [0x41, 0xCF],
            &tx_id,
            &challenge_3c,
            &[0u8; V2_AES128_BLOCK_SIZE],
            &[0u8; V2_AES128_BLOCK_SIZE],
            &payload,
        )
        .expect("AES v2 encode should succeed");
        assert_eq!(encoded, expected);
    }

    #[test]
    fn secure_v2_decrypt_matches_reference_vector() {
        let encrypted = bytes_from_hex(
            "41cfae0d2f92b2259287e05646e140e5924ee27f79cb69a2047da5f9353eed59e35fbc90a5d731d25a0fcdbdd6802174",
        );
        let tx_id = [0x5E, 0xC8, 0xB5, 0x97, 0x17, 0x04];
        let challenge_3c = [0x00u8; 4];
        let decoded = decrypt_secure_response_v2_aes128(
            0x48,
            &tx_id,
            &challenge_3c,
            &[0u8; V2_AES128_BLOCK_SIZE],
            &[0u8; V2_AES128_BLOCK_SIZE],
            &encrypted,
        )
        .unwrap();
        assert_eq!(decoded.transaction_number, u16::from_le_bytes([0x41, 0xCF]));
        assert_eq!(
            decoded.payload,
            bytes_from_hex(
                "0000000100000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
        );
    }

    #[test]
    fn build_secure_response_frame_v2_round_trip() {
        let response_code = 0x15;
        let tx_number = 3u16;
        let tx_id = [1, 2, 3, 4, 5, 6];
        let challenge_3c = [0x00u8; 4];
        let encryption_key = [0x10u8; V2_AES128_BLOCK_SIZE];
        let mac_key = [0x20u8; V2_AES128_BLOCK_SIZE];
        let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        let frame = build_secure_response_frame_v2_aes128(
            response_code,
            tx_number,
            &tx_id,
            &challenge_3c,
            &encryption_key,
            &mac_key,
            &payload,
        )
        .expect("failed to build secure response frame v2");
        assert_eq!(frame[0] as usize, frame.len());
        assert_eq!(frame[1], response_code);

        let decoded = decrypt_secure_response_v2_aes128(
            response_code,
            &tx_id,
            &challenge_3c,
            &encryption_key,
            &mac_key,
            &frame[2..],
        )
        .unwrap();
        assert_eq!(decoded.transaction_number, tx_number);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn authentication2_v2_response_reports_v2_scheme() {
        let response = Authentication2V2Response {
            encrypted_payload: vec![0xAA; 8],
        };
        assert_eq!(response.scheme(), super::super::SecureSessionScheme::Aes128);
    }

    #[test]
    fn generate_service_key_aes_reproduces_card_vectors() {
        // Per-node AES key on the sample card: the node code repeated 8 times.
        fn code_key(code: u16) -> [u8; V2_AES128_BLOCK_SIZE] {
            let tag = code.to_be_bytes();
            let mut key = [0u8; V2_AES128_BLOCK_SIZE];
            for chunk in key.chunks_exact_mut(2) {
                chunk.copy_from_slice(&tag);
            }
            key
        }

        // Node 0x1008 carries a weak (all-zero) AES key on this card.
        let weak_1008 = [0u8; V2_AES128_BLOCK_SIZE];

        // All vectors below were confirmed live via mutual_authentication_v2.
        let cases: &[(&[[u8; V2_AES128_BLOCK_SIZE]], &str)] = &[
            (&[weak_1008], "3925042E238282F085BCEE62593C2385"),
            (
                &[weak_1008, code_key(0x100C)],
                "586A2E06EE16AA2C6AE5B6CDFF6A5039",
            ),
            (&[code_key(0x100C)], "651049AE89581DDC3F302EA4E4A0F911"),
            (
                &[code_key(0x100C), code_key(0x1012)],
                "5E86F6C0574EBAD952FAD9142E1AA6BB",
            ),
            // 3xxx services use (code + 1) repeated.
            (&[code_key(0x3111)], "94459E3640EDBCE4746D83EECE80C065"),
        ];
        for (service_keys, expected) in cases {
            assert_eq!(
                generate_group_key_v2_aes128(service_keys).to_vec(),
                bytes_from_hex(expected),
            );
        }
    }
}
