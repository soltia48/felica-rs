//! FeliCa Standard secure messaging over DES/3DES.
//!
//! Covers the DES authentication context (mutual authentication key schedule),
//! the command/response MACs, the encrypted request/response framing, and the
//! DES service-key derivation used by issuers.

use super::DecryptedSecureResponse;
use super::primitives::{
    decrypt_3des_block, decrypt_des_block, decrypt_des_cbc_zero_iv, encrypt_3des_block,
    encrypt_des_block, encrypt_des_cbc_zero_iv, pad_to_des_block_size, xor_blocks,
};
use super::{DES_SECURE_HEADER_SIZE, TRANSACTION_ID_SIZE, TRANSACTION_NUMBER_SIZE};
use crate::felica_standard::{
    DES_BLOCK_SIZE, DES_MAC_SIZE, FelicaStandardError, frame_with_length_prefix,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2Response {
    pub(crate) encrypted_payload: Vec<u8>,
}

impl Authentication2Response {
    pub fn scheme(&self) -> super::SecureSessionScheme {
        super::SecureSessionScheme::Des
    }

    pub fn decrypt_payload(&self, session_key: &[u8; 8]) -> Result<Vec<u8>, FelicaStandardError> {
        let plaintext = decrypt_des_cbc_zero_iv(&self.encrypted_payload, session_key)
            .map_err(FelicaStandardError::SecureSession)?;
        if !check_packet_mac_des(&plaintext, 0x13) {
            return Err(FelicaStandardError::SecureSession(
                "authentication2 response MAC verification failed".into(),
            ));
        }
        if plaintext.len() < DES_MAC_SIZE {
            return Err(FelicaStandardError::Protocol(
                "authentication2 response payload too short".into(),
            ));
        }
        let payload = &plaintext[..plaintext.len() - DES_MAC_SIZE];
        Ok(payload.to_vec())
    }
}

pub(crate) fn build_authentication2_payload(
    transaction_number: u16,
    transaction_id: &[u8; 6],
    idi: &[u8; 8],
    pmi: &[u8; 8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(TRANSACTION_NUMBER_SIZE + TRANSACTION_ID_SIZE + 8 + 8);
    payload.extend_from_slice(&transaction_number.to_le_bytes());
    payload.extend_from_slice(transaction_id);
    payload.extend_from_slice(idi);
    payload.extend_from_slice(pmi);
    payload
}

pub(crate) fn encrypt_authentication2_payload(
    payload: &[u8],
    session_key: &[u8; 8],
) -> Option<Vec<u8>> {
    let mut padded = pad_to_des_block_size(payload.to_vec());
    let mac = calculate_command_mac_des(0x13, &padded).ok()?;
    padded.extend_from_slice(&mac);
    encrypt_des_cbc_zero_iv(&padded, session_key).ok()
}

pub(crate) struct SecureResponseHeader {
    pub(crate) transaction_number: u16,
    pub(crate) transaction_id: [u8; 6],
}

impl SecureResponseHeader {
    fn new(transaction_number: u16, transaction_id: [u8; 6]) -> Self {
        Self {
            transaction_number,
            transaction_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn apply(
        &self,
        context: &mut super::AuthenticatedContext,
    ) -> Result<(), FelicaStandardError> {
        if self.transaction_number <= context.transaction_number() {
            return Err(FelicaStandardError::SecureSession(
                "secure response transaction number did not advance".into(),
            ));
        }
        if self.transaction_id != *context.transaction_id() {
            return Err(FelicaStandardError::SecureSession(
                "secure response transaction ID mismatch".into(),
            ));
        }
        context.set_transaction_number(self.transaction_number);
        Ok(())
    }
}

pub(crate) struct SecureResponse<'a> {
    pub(crate) header: SecureResponseHeader,
    pub(crate) payload: &'a [u8],
}

impl<'a> SecureResponse<'a> {
    pub(crate) fn parse(data: &'a [u8], response_code: u8) -> Result<Self, FelicaStandardError> {
        if data.len() < DES_BLOCK_SIZE * 2 {
            return Err(FelicaStandardError::Protocol(
                "secure response shorter than minimum encrypted payload".into(),
            ));
        }
        if !check_packet_mac_des(data, response_code) {
            return Err(FelicaStandardError::SecureSession(
                "secure response MAC verification failed".into(),
            ));
        }
        let transaction_number = u16::from_le_bytes([data[0], data[1]]);
        let mut transaction_id = [0u8; TRANSACTION_ID_SIZE];
        transaction_id.copy_from_slice(&data[TRANSACTION_NUMBER_SIZE..DES_SECURE_HEADER_SIZE]);
        let header = SecureResponseHeader::new(transaction_number, transaction_id);
        Ok(Self {
            header,
            payload: &data[DES_SECURE_HEADER_SIZE..],
        })
    }
}

pub(super) fn decrypt_secure_response_des(
    response_code: u8,
    expected_transaction_id: &[u8; 6],
    key: &[u8; 8],
    encrypted_data: &[u8],
) -> Result<DecryptedSecureResponse, FelicaStandardError> {
    let plaintext =
        decrypt_des_cbc_zero_iv(encrypted_data, key).map_err(FelicaStandardError::Protocol)?;
    let parsed = SecureResponse::parse(&plaintext, response_code)?;
    if parsed.header.transaction_id != *expected_transaction_id {
        return Err(FelicaStandardError::SecureSession(
            "secure response transaction ID mismatch".into(),
        ));
    }
    let payload = strip_des_response_mac(parsed.payload)?;
    Ok(DecryptedSecureResponse {
        transaction_number: parsed.header.transaction_number,
        payload,
    })
}

fn strip_des_response_mac(payload_with_mac: &[u8]) -> Result<Vec<u8>, FelicaStandardError> {
    if payload_with_mac.len() < DES_MAC_SIZE {
        return Err(FelicaStandardError::Protocol(
            "secure response payload shorter than MAC".into(),
        ));
    }
    let payload = payload_with_mac[..payload_with_mac.len() - DES_MAC_SIZE].to_vec();
    Ok(payload)
}

pub(crate) fn calculate_command_mac_des(
    command_code: u8,
    payload: &[u8],
) -> Result<[u8; DES_BLOCK_SIZE], String> {
    if !payload.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err("secure command payload must be multiple of 8 bytes".into());
    }
    let total_length = 2 + payload.len() + DES_MAC_SIZE;
    if total_length > u8::MAX as usize {
        return Err("secure command payload exceeds maximum frame length".into());
    }
    let mut mac = [0u8; DES_BLOCK_SIZE];
    mac[0] = total_length as u8;
    mac[1] = command_code;
    for chunk in payload.chunks(DES_BLOCK_SIZE) {
        let mut block = [0u8; DES_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        mac = encrypt_des_block(&mac, &block);
    }
    Ok(mac)
}

pub(crate) fn check_packet_mac_des(data: &[u8], expected_response_code: u8) -> bool {
    if !data.len().is_multiple_of(DES_BLOCK_SIZE) || data.len() < DES_BLOCK_SIZE + DES_MAC_SIZE {
        return false;
    }
    let (payload, mac) = data.split_at(data.len() - DES_MAC_SIZE);
    if payload.is_empty() {
        return false;
    }
    let mut x = [0u8; DES_MAC_SIZE];
    x.copy_from_slice(mac);
    let mut current = x;
    for block in payload.chunks(DES_BLOCK_SIZE).rev() {
        let mut block_arr = [0u8; DES_BLOCK_SIZE];
        block_arr.copy_from_slice(block);
        current = decrypt_des_block(&current, &block_arr);
    }
    current[0] == (data.len() as u8 + 2) && current[1] == expected_response_code
}

pub(crate) fn build_secure_response_frame_des(
    response_code: u8,
    transaction_number: u16,
    transaction_id: &[u8; 6],
    encryption_key: &[u8; 8],
    response_payload: &[u8],
) -> Option<Vec<u8>> {
    let mut payload = Vec::with_capacity(8 + response_payload.len());
    payload.extend_from_slice(&transaction_number.to_le_bytes());
    payload.extend_from_slice(transaction_id);
    payload.extend_from_slice(response_payload);
    let mut padded = pad_to_des_block_size(payload);
    let mac = calculate_command_mac_des(response_code, &padded).ok()?;
    padded.extend_from_slice(&mac);
    let encrypted = encrypt_des_cbc_zero_iv(&padded, encryption_key).ok()?;
    let mut frame_payload = Vec::with_capacity(1 + encrypted.len());
    frame_payload.push(response_code);
    frame_payload.extend_from_slice(&encrypted);
    Some(frame_with_length_prefix(&frame_payload))
}

pub fn generate_service_keys_des(
    system_key: &[u8; 8],
    area_keys: &[[u8; 8]],
    service_keys: &[[u8; 8]],
) -> ([u8; 8], [u8; 8]) {
    let mut current_key = *system_key;
    for key in area_keys {
        current_key = encrypt_des_block(&current_key, key);
    }
    let group_service_key = current_key;
    for key in service_keys {
        current_key = encrypt_des_block(&current_key, key);
    }
    let user_service_key = current_key;
    (group_service_key, user_service_key)
}

pub(crate) fn generate_registration_package_des(
    package_plain: &[u8],
    package_key: &[u8; DES_BLOCK_SIZE],
) -> Result<Vec<u8>, FelicaStandardError> {
    if package_plain.is_empty() || !package_plain.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err(FelicaStandardError::InvalidParameter(
            "registration package must be multiple of 8 bytes".into(),
        ));
    }

    let mut mac_key = [0u8; DES_BLOCK_SIZE];
    for (dst, src) in mac_key.iter_mut().zip(package_key.iter()) {
        *dst = *src ^ 0xFF;
    }

    let encrypted_plain =
        encrypt_des_cbc_zero_iv(package_plain, &mac_key).map_err(FelicaStandardError::Protocol)?;
    if encrypted_plain.len() < DES_BLOCK_SIZE {
        return Err(FelicaStandardError::Protocol(
            "registration package MAC calculation failed".into(),
        ));
    }

    let mac = &encrypted_plain[encrypted_plain.len() - DES_BLOCK_SIZE..];
    let mut package_with_mac = Vec::with_capacity(package_plain.len() + DES_BLOCK_SIZE);
    package_with_mac.extend_from_slice(package_plain);
    package_with_mac.extend_from_slice(mac);

    encrypt_des_cbc_zero_iv(&package_with_mac, package_key).map_err(FelicaStandardError::Protocol)
}

pub(crate) struct AuthenticationContext {
    l: [u8; 8],
    alpha: [u8; 8],
    beta: [u8; 8],
}

impl AuthenticationContext {
    pub(crate) fn new(
        idm: &[u8; 8],
        group_service_key: &[u8; 8],
        user_service_key: &[u8; 8],
    ) -> Self {
        let l = xor_blocks(group_service_key, idm);
        let alpha = encrypt_des_block(user_service_key, &l);
        let beta = encrypt_des_block(&l, &alpha);
        Self { l, alpha, beta }
    }

    pub(crate) fn decrypt_challenge1a(&self, challenge_1a: &[u8; 8]) -> [u8; 8] {
        decrypt_3des_block(challenge_1a, &self.alpha, &self.l)
    }

    pub(crate) fn encrypt_challenge1a(&self, random_1: &[u8; 8]) -> [u8; 8] {
        encrypt_3des_block(random_1, &self.alpha, &self.l)
    }

    pub(crate) fn encrypt_challenge1b(&self, random_1: &[u8; 8]) -> [u8; 8] {
        encrypt_3des_block(random_1, &self.l, &self.beta)
    }

    pub(crate) fn encrypt_challenge2a(&self, random_2: &[u8; 8]) -> [u8; 8] {
        encrypt_3des_block(random_2, &self.l, &self.beta)
    }

    pub(crate) fn verify_challenge1b(&self, random_1: &[u8; 8], challenge_1b: &[u8; 8]) -> bool {
        self.encrypt_challenge1b(random_1) == *challenge_1b
    }

    pub(crate) fn decrypt_challenge2a(&self, challenge_2a: &[u8; 8]) -> [u8; 8] {
        decrypt_3des_block(challenge_2a, &self.l, &self.beta)
    }

    pub(crate) fn encrypt_challenge2b(&self, random_2: &[u8; 8]) -> [u8; 8] {
        encrypt_3des_block(random_2, &self.alpha, &self.l)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::assert_secure_session_error_contains;
    use super::super::{AuthenticatedContext, SecureSessionCredentials, SecureSessionScheme};
    use super::*;

    #[test]
    fn build_authentication2_payload_layout() {
        let tx_number = 0x3412;
        let tx_id = [1, 2, 3, 4, 5, 6];
        let idi = [0x11; 8];
        let pmi = [0x22; 8];

        let payload = build_authentication2_payload(tx_number, &tx_id, &idi, &pmi);
        assert_eq!(payload.len(), 24);
        assert_eq!(&payload[0..2], &tx_number.to_le_bytes());
        assert_eq!(&payload[2..8], &tx_id);
        assert_eq!(&payload[8..16], &idi);
        assert_eq!(&payload[16..24], &pmi);
    }

    #[test]
    fn calculate_command_mac_rejects_bad_inputs() {
        assert!(
            calculate_command_mac_des(0x10, &[1, 2, 3])
                .unwrap_err()
                .contains("multiple of 8")
        );
        assert!(
            calculate_command_mac_des(0x10, &[0xAA; 248])
                .unwrap_err()
                .contains("exceeds maximum frame length")
        );
    }

    #[test]
    fn build_secure_response_frame_and_parse_round_trip() {
        let response_code = 0x33;
        let tx_number = 0x2211;
        let tx_id = [1, 2, 3, 4, 5, 6];
        let key = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let response_payload = [0xAA, 0xBB, 0xCC];

        let frame = build_secure_response_frame_des(
            response_code,
            tx_number,
            &tx_id,
            &key,
            &response_payload,
        )
        .expect("failed to build secure response frame");
        assert_eq!(frame[0] as usize, frame.len());
        assert_eq!(frame[1], response_code);

        let decrypted = decrypt_des_cbc_zero_iv(&frame[2..], &key).unwrap();
        assert!(check_packet_mac_des(&decrypted, response_code));

        let parsed = SecureResponse::parse(&decrypted, response_code).unwrap();
        assert_eq!(parsed.header.transaction_number, tx_number);
        assert_eq!(parsed.header.transaction_id, tx_id);
        assert_eq!(&parsed.payload[..response_payload.len()], &response_payload);

        let tampered = decrypted[..decrypted.len() - 1].to_vec();
        assert!(!check_packet_mac_des(&tampered, response_code));
        assert_secure_session_error_contains(
            SecureResponse::parse(&decrypted, response_code.wrapping_add(1)),
            "MAC verification failed",
        );
    }

    #[test]
    fn secure_response_header_apply_validates_and_updates_context() {
        let mut context = AuthenticatedContext::new(
            10,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Des([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]),
        );
        let header_ok = SecureResponseHeader::new(11, [1, 2, 3, 4, 5, 6]);
        header_ok.apply(&mut context).unwrap();
        assert_eq!(context.transaction_number(), 11);

        let header_stale = SecureResponseHeader::new(11, [1, 2, 3, 4, 5, 6]);
        assert_secure_session_error_contains(header_stale.apply(&mut context), "did not advance");

        let header_bad_id = SecureResponseHeader::new(12, [9, 9, 9, 9, 9, 9]);
        assert_secure_session_error_contains(header_bad_id.apply(&mut context), "ID mismatch");
    }

    #[test]
    fn authentication2_response_decrypt_success_and_failures() {
        let key = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let raw_payload = vec![0x01, 0x02, 0x03];
        let expected_payload = pad_to_des_block_size(raw_payload.clone());
        let encrypted = encrypt_authentication2_payload(&raw_payload, &key)
            .expect("failed to encrypt authentication2 payload");

        let response = Authentication2Response {
            encrypted_payload: encrypted.clone(),
        };
        assert_eq!(response.scheme(), SecureSessionScheme::Des);
        let decrypted = response.decrypt_payload(&key).unwrap();
        assert_eq!(decrypted, expected_payload);

        let mut tampered = encrypted.clone();
        tampered[0] ^= 0xFF;
        let tampered_response = Authentication2Response {
            encrypted_payload: tampered,
        };
        assert_secure_session_error_contains(
            tampered_response.decrypt_payload(&key),
            "MAC verification failed",
        );

        let malformed = Authentication2Response {
            encrypted_payload: vec![0x01, 0x02, 0x03],
        };
        assert_secure_session_error_contains(
            malformed.decrypt_payload(&key),
            "multiple of 8 bytes",
        );
    }
}
