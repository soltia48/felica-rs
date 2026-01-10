use super::{DES_BLOCK_SIZE, FelicaStandardError};
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use des::{Des, TdesEde3};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2Response {
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

fn decrypt_des_cbc_zero_iv(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, String> {
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

fn calculate_command_mac(command_code: u8, payload: &[u8]) -> Result<[u8; DES_BLOCK_SIZE], String> {
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

fn check_packet_mac(data: &[u8], expected_response_code: u8) -> bool {
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

    pub(crate) fn encrypt_challenge1(&self, random_1: &[u8; 8]) -> [u8; 8] {
        encrypt_3des_block(random_1, &self.alpha, &self.l)
    }

    pub(crate) fn verify_challenge1(&self, random_1: &[u8; 8], challenge_1b: &[u8; 8]) -> bool {
        encrypt_3des_block(random_1, &self.l, &self.beta) == *challenge_1b
    }

    pub(crate) fn decrypt_challenge2(&self, challenge_2a: &[u8; 8]) -> [u8; 8] {
        decrypt_3des_block(challenge_2a, &self.l, &self.beta)
    }

    pub(crate) fn encrypt_challenge2(&self, random_2: &[u8; 8]) -> [u8; 8] {
        encrypt_3des_block(random_2, &self.alpha, &self.l)
    }
}
