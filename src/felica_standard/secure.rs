use super::{DES_BLOCK_SIZE, FelicaStandardError, frame_with_length_prefix};
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use des::{Des, TdesEde3};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2Response {
    pub(crate) encrypted_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2V2Response {
    pub(crate) encrypted_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedContext {
    transaction_number: u16,
    transaction_id: [u8; 6],
    transaction_key: [u8; 8],
}

impl AuthenticatedContext {
    pub fn new(transaction_number: u16, transaction_id: [u8; 6], transaction_key: [u8; 8]) -> Self {
        Self {
            transaction_number,
            transaction_id,
            transaction_key,
        }
    }

    pub fn transaction_number(&self) -> u16 {
        self.transaction_number
    }

    pub fn transaction_id(&self) -> &[u8; 6] {
        &self.transaction_id
    }

    pub fn transaction_key(&self) -> &[u8; 8] {
        &self.transaction_key
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

pub(crate) fn build_authentication2_payload(
    transaction_number: u16,
    transaction_id: &[u8; 6],
    idi: &[u8; 8],
    pmi: &[u8; 8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(24);
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
    let mac = calculate_command_mac(0x13, &padded).ok()?;
    padded.extend_from_slice(&mac);
    encrypt_des_cbc_zero_iv(&padded, session_key).ok()
}

pub(crate) struct SecureCommandContext {
    transaction_number: u16,
    transaction_id: [u8; 6],
    transaction_key: [u8; 8],
}

impl SecureCommandContext {
    pub(crate) fn capture(context: &mut AuthenticatedContext) -> Result<Self, FelicaStandardError> {
        let transaction_number = context.increment_transaction_number()?;
        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(context.transaction_id());
        let mut transaction_key = [0u8; 8];
        transaction_key.copy_from_slice(context.transaction_key());
        Ok(Self {
            transaction_number,
            transaction_id,
            transaction_key,
        })
    }

    pub(crate) fn build_payload(&self, command_payload: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(8 + command_payload.len());
        payload.extend_from_slice(&self.transaction_number.to_le_bytes());
        payload.extend_from_slice(&self.transaction_id);
        payload.extend_from_slice(command_payload);
        payload
    }

    pub(crate) fn encrypt_request(
        &self,
        command_code: u8,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        let padded_payload = pad_to_des_block_size(payload);
        let mac = calculate_command_mac(command_code, &padded_payload)
            .map_err(FelicaStandardError::Protocol)?;
        let mut command_data = padded_payload;
        command_data.extend_from_slice(&mac);
        encrypt_des_cbc_zero_iv(&command_data, &self.transaction_key)
            .map_err(FelicaStandardError::Protocol)
    }

    pub(crate) fn decrypt_response(&self, data: &[u8]) -> Result<Vec<u8>, FelicaStandardError> {
        decrypt_des_cbc_zero_iv(data, &self.transaction_key).map_err(FelicaStandardError::Protocol)
    }
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

    pub(crate) fn apply(
        &self,
        context: &mut AuthenticatedContext,
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
        if !check_packet_mac(data, response_code) {
            return Err(FelicaStandardError::SecureSession(
                "secure response MAC verification failed".into(),
            ));
        }
        if data.len() < 8 {
            return Err(FelicaStandardError::Protocol(
                "secure response shorter than transaction header".into(),
            ));
        }
        let transaction_number = u16::from_le_bytes([data[0], data[1]]);
        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&data[2..8]);
        let header = SecureResponseHeader::new(transaction_number, transaction_id);
        Ok(Self {
            header,
            payload: &data[8..],
        })
    }
}

impl Authentication2Response {
    pub fn decrypt_payload(&self, session_key: &[u8; 8]) -> Result<Vec<u8>, FelicaStandardError> {
        let plaintext = decrypt_des_cbc_zero_iv(&self.encrypted_payload, session_key)
            .map_err(FelicaStandardError::SecureSession)?;
        if !check_packet_mac(&plaintext, 0x13) {
            return Err(FelicaStandardError::SecureSession(
                "authentication2 response MAC verification failed".into(),
            ));
        }
        if plaintext.len() < 8 {
            return Err(FelicaStandardError::Protocol(
                "authentication2 response payload too short".into(),
            ));
        }
        let payload = &plaintext[..plaintext.len() - 8];
        Ok(payload.to_vec())
    }
}

fn xor_blocks(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn des_cipher(key: &[u8; 8]) -> Des {
    Des::new(GenericArray::from_slice(key))
}

pub(crate) fn encrypt_des_block(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    let cipher = des_cipher(key);
    let mut block = GenericArray::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

pub(crate) fn decrypt_des_block(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    let cipher = des_cipher(key);
    let mut block = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

fn encrypt_3des_block(data: &[u8; 8], key1: &[u8; 8], key2: &[u8; 8]) -> [u8; 8] {
    let mut triple_key = [0u8; 24];
    triple_key[..8].copy_from_slice(key1);
    triple_key[8..16].copy_from_slice(key2);
    triple_key[16..24].copy_from_slice(key1);
    let cipher = TdesEde3::new(GenericArray::from_slice(&triple_key));
    let mut block = GenericArray::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

fn decrypt_3des_block(data: &[u8; 8], key1: &[u8; 8], key2: &[u8; 8]) -> [u8; 8] {
    let mut triple_key = [0u8; 24];
    triple_key[..8].copy_from_slice(key1);
    triple_key[8..16].copy_from_slice(key2);
    triple_key[16..24].copy_from_slice(key1);
    let cipher = TdesEde3::new(GenericArray::from_slice(&triple_key));
    let mut block = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

pub(crate) fn encrypt_des_cbc_zero_iv(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err("secure command payload length must be multiple of 8 bytes".into());
    }
    let cipher = des_cipher(key);
    let mut prev_block = [0u8; DES_BLOCK_SIZE];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(DES_BLOCK_SIZE) {
        let mut block = [0u8; DES_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        for i in 0..DES_BLOCK_SIZE {
            block[i] ^= prev_block[i];
        }
        let mut block_array = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut block_array);
        out.extend_from_slice(&block_array);
        prev_block.copy_from_slice(&block_array);
    }
    Ok(out)
}

pub(crate) fn decrypt_des_cbc_zero_iv(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err("authentication2 response length must be multiple of 8 bytes".into());
    }
    let cipher = des_cipher(key);
    let mut prev_block = [0u8; 8];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(DES_BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        let mut plain = [0u8; 8];
        for i in 0..DES_BLOCK_SIZE {
            plain[i] = block[i] ^ prev_block[i];
        }
        out.extend_from_slice(&plain);
        prev_block.copy_from_slice(chunk);
    }
    Ok(out)
}

fn pad_to_des_block_size(mut data: Vec<u8>) -> Vec<u8> {
    let remainder = data.len() % DES_BLOCK_SIZE;
    if remainder != 0 {
        let pad_len = (DES_BLOCK_SIZE - remainder) as u8;
        for _ in 0..pad_len {
            data.push(pad_len);
        }
    }
    data
}

pub(crate) fn strip_secure_padding(data: &mut Vec<u8>) {
    let Some(&pad_len) = data.last() else {
        return;
    };
    if pad_len == 0 || pad_len as usize >= DES_BLOCK_SIZE {
        return;
    }
    let pad_len = pad_len as usize;
    if pad_len <= data.len()
        && data[data.len() - pad_len..]
            .iter()
            .all(|&b| b == pad_len as u8)
    {
        data.truncate(data.len() - pad_len);
    }
}

pub fn generate_service_keys(
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

pub(crate) fn calculate_command_mac(
    command_code: u8,
    payload: &[u8],
) -> Result<[u8; DES_BLOCK_SIZE], String> {
    if !payload.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err("secure command payload must be multiple of 8 bytes".into());
    }
    let total_length = 2 + payload.len() + DES_BLOCK_SIZE;
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

pub(crate) fn check_packet_mac(data: &[u8], expected_response_code: u8) -> bool {
    if !data.len().is_multiple_of(DES_BLOCK_SIZE) || data.len() < 16 {
        return false;
    }
    let (payload, mac) = data.split_at(data.len() - 8);
    if payload.is_empty() {
        return false;
    }
    let mut x = [0u8; 8];
    x.copy_from_slice(mac);
    let mut current = x;
    for block in payload.chunks(DES_BLOCK_SIZE).rev() {
        let mut block_arr = [0u8; 8];
        block_arr.copy_from_slice(block);
        current = decrypt_des_block(&current, &block_arr);
    }
    current[0] == (data.len() as u8 + 2) && current[1] == expected_response_code
}

pub(crate) fn build_secure_response_frame(
    response_code: u8,
    transaction_number: u16,
    transaction_id: &[u8; 6],
    transaction_key: &[u8; 8],
    response_payload: &[u8],
) -> Option<Vec<u8>> {
    let mut payload = Vec::with_capacity(8 + response_payload.len());
    payload.extend_from_slice(&transaction_number.to_le_bytes());
    payload.extend_from_slice(transaction_id);
    payload.extend_from_slice(response_payload);
    let mut padded = pad_to_des_block_size(payload);
    let mac = calculate_command_mac(response_code, &padded).ok()?;
    padded.extend_from_slice(&mac);
    let encrypted = encrypt_des_cbc_zero_iv(&padded, transaction_key).ok()?;
    let mut frame_payload = Vec::with_capacity(1 + encrypted.len());
    frame_payload.push(response_code);
    frame_payload.extend_from_slice(&encrypted);
    Some(frame_with_length_prefix(&frame_payload))
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
    use super::*;

    fn assert_protocol_error_contains<T>(result: Result<T, FelicaStandardError>, expected: &str) {
        match result {
            Err(FelicaStandardError::Protocol(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected protocol error message: {message}"
                );
            }
            Err(other) => panic!("expected protocol error, got {other}"),
            Ok(_) => panic!("expected protocol error, got Ok"),
        }
    }

    fn assert_secure_session_error_contains<T>(
        result: Result<T, FelicaStandardError>,
        expected: &str,
    ) {
        match result {
            Err(FelicaStandardError::SecureSession(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected secure-session error message: {message}"
                );
            }
            Err(other) => panic!("expected secure-session error, got {other}"),
            Ok(_) => panic!("expected secure-session error, got Ok"),
        }
    }

    #[test]
    fn authenticated_context_increment_and_overflow() {
        let mut context = AuthenticatedContext::new(
            u16::MAX - 1,
            [1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12, 13, 14],
        );
        assert_eq!(context.increment_transaction_number().unwrap(), u16::MAX);
        assert_secure_session_error_contains(
            context.increment_transaction_number(),
            "transaction number overflow",
        );
    }

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
    fn secure_command_context_capture_and_build_payload() {
        let mut context = AuthenticatedContext::new(
            0x0020,
            [1, 2, 3, 4, 5, 6],
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7],
        );

        let captured = SecureCommandContext::capture(&mut context).unwrap();
        assert_eq!(context.transaction_number(), 0x0021u16);
        assert_eq!(captured.transaction_number, 0x0021);
        assert_eq!(captured.transaction_id, [1, 2, 3, 4, 5, 6]);
        assert_eq!(
            captured.transaction_key,
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]
        );

        let payload = captured.build_payload(&[0x55, 0x66, 0x77]);
        assert_eq!(&payload[0..2], &0x0021u16.to_le_bytes());
        assert_eq!(&payload[2..8], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&payload[8..], &[0x55, 0x66, 0x77]);
    }

    #[test]
    fn secure_command_encrypt_and_decrypt_round_trip() {
        let mut context = AuthenticatedContext::new(
            0,
            [1, 2, 3, 4, 5, 6],
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
        );
        let captured = SecureCommandContext::capture(&mut context).unwrap();
        let payload = captured.build_payload(&[0xAA, 0xBB, 0xCC]);
        let padded_payload = pad_to_des_block_size(payload.clone());

        let encrypted = captured.encrypt_request(0x42, payload).unwrap();
        let decrypted = captured.decrypt_response(&encrypted).unwrap();
        assert!(check_packet_mac(&decrypted, 0x42));
        assert_eq!(
            &decrypted[..padded_payload.len()],
            padded_payload.as_slice()
        );
    }

    #[test]
    fn secure_command_encrypt_rejects_too_long_payload() {
        let mut context = AuthenticatedContext::new(
            0,
            [1, 2, 3, 4, 5, 6],
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
        );
        let captured = SecureCommandContext::capture(&mut context).unwrap();
        let payload = vec![0xAB; 248];
        assert_protocol_error_contains(
            captured.encrypt_request(0x42, payload),
            "exceeds maximum frame length",
        );
    }

    #[test]
    fn encrypt_and_decrypt_des_cbc_round_trip() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let data = [0x10u8; 16];
        let encrypted = encrypt_des_cbc_zero_iv(&data, &key).unwrap();
        let decrypted = decrypt_des_cbc_zero_iv(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn des_cbc_rejects_non_aligned_payload() {
        let key = [0u8; 8];
        assert!(
            encrypt_des_cbc_zero_iv(&[1, 2, 3], &key)
                .unwrap_err()
                .contains("multiple of 8")
        );
        assert!(
            decrypt_des_cbc_zero_iv(&[1, 2, 3], &key)
                .unwrap_err()
                .contains("multiple of 8")
        );
    }

    #[test]
    fn strip_secure_padding_only_when_valid() {
        let mut valid = vec![1, 2, 3, 2, 2];
        strip_secure_padding(&mut valid);
        assert_eq!(valid, vec![1, 2, 3]);

        let mut invalid_value = vec![1, 2, 3, 1, 2];
        strip_secure_padding(&mut invalid_value);
        assert_eq!(invalid_value, vec![1, 2, 3, 1, 2]);

        let mut invalid_len = vec![1, 2, 3, 8];
        strip_secure_padding(&mut invalid_len);
        assert_eq!(invalid_len, vec![1, 2, 3, 8]);
    }

    #[test]
    fn calculate_command_mac_rejects_bad_inputs() {
        assert!(
            calculate_command_mac(0x10, &[1, 2, 3])
                .unwrap_err()
                .contains("multiple of 8")
        );
        assert!(
            calculate_command_mac(0x10, &[0xAA; 248])
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

        let frame =
            build_secure_response_frame(response_code, tx_number, &tx_id, &key, &response_payload)
                .expect("failed to build secure response frame");
        assert_eq!(frame[0] as usize, frame.len());
        assert_eq!(frame[1], response_code);

        let decrypted = decrypt_des_cbc_zero_iv(&frame[2..], &key).unwrap();
        assert!(check_packet_mac(&decrypted, response_code));

        let parsed = SecureResponse::parse(&decrypted, response_code).unwrap();
        assert_eq!(parsed.header.transaction_number, tx_number);
        assert_eq!(parsed.header.transaction_id, tx_id);
        assert_eq!(&parsed.payload[..response_payload.len()], &response_payload);

        let tampered = decrypted[..decrypted.len() - 1].to_vec();
        assert!(!check_packet_mac(&tampered, response_code));
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
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
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
