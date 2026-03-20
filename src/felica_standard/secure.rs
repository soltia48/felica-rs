use super::{
    AUTHENTICATION2_V2_RESPONSE_CODE, DES_BLOCK_SIZE, DES_MAC_SIZE, FelicaStandardError,
    V2_AES128_BLOCK_SIZE, V2_AES128_MAC_SIZE, frame_with_length_prefix,
};
use aes::Aes128;
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cmac::{Cmac, Mac};
use des::cipher::{
    BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher,
    block_padding::NoPadding, generic_array::GenericArray,
};
use des::{Des, TdesEde3};
use ofb::Ofb;

const TRANSACTION_NUMBER_SIZE: usize = 2;
const TRANSACTION_ID_SIZE: usize = 6;
const DES_SECURE_HEADER_SIZE: usize = TRANSACTION_NUMBER_SIZE + TRANSACTION_ID_SIZE;
const AES128_V2_IV_MARKER: u8 = 0x01;
const AES128_V2_AUTH_CONTEXT_SUFFIX: [u8; 2] = [0x01, 0x00];
const AES128_V2_DERIVE_ENCRYPTION_KEY_INPUT: [u8; V2_AES128_BLOCK_SIZE] = [
    0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];
const AES128_V2_DERIVE_MAC_KEY_INPUT: [u8; V2_AES128_BLOCK_SIZE] = [
    0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureSessionScheme {
    /// FeliCa Standard secure messaging (DES/3DES).
    Des,
    /// FeliCa Standard v2 secure messaging (AES).
    Aes128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2Response {
    pub(crate) encrypted_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication2V2Response {
    pub(crate) encrypted_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureSessionCredentials {
    Des([u8; 8]),
    Aes128 {
        encryption_key: [u8; 16],
        mac_key: [u8; 16],
        challenge_3c: [u8; 4],
    },
}

impl SecureSessionCredentials {
    pub fn scheme(self) -> SecureSessionScheme {
        match self {
            Self::Des(_) => SecureSessionScheme::Des,
            Self::Aes128 { .. } => SecureSessionScheme::Aes128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureSessionCredentialsRef<'a> {
    Des(&'a [u8; 8]),
    Aes128 {
        encryption_key: &'a [u8; 16],
        mac_key: &'a [u8; 16],
        challenge_3c: &'a [u8; 4],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedContext {
    transaction_number: u16,
    transaction_id: [u8; 6],
    credentials: SecureSessionCredentials,
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
        }
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
        let credentials = context.credentials;
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
        match self.credentials {
            SecureSessionCredentials::Des(key) => {
                let padded_payload = pad_to_des_block_size(payload);
                let mac = calculate_command_mac_des(command_code, &padded_payload)
                    .map_err(FelicaStandardError::Protocol)?;
                let mut command_data = padded_payload;
                command_data.extend_from_slice(&mac);
                encrypt_des_cbc_zero_iv(&command_data, &key).map_err(FelicaStandardError::Protocol)
            }
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => encrypt_secure_request_v2_aes128(
                command_code,
                self.transaction_counter_bytes(),
                &self.transaction_id,
                &challenge_3c,
                &encryption_key,
                &mac_key,
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
        match self.credentials {
            SecureSessionCredentials::Des(key) => {
                decrypt_secure_response_des(response_code, &self.transaction_id, &key, data)
            }
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            } => decrypt_secure_response_v2_aes128(
                response_code,
                &self.transaction_id,
                &challenge_3c,
                &encryption_key,
                &mac_key,
                data,
            )
            .map_err(FelicaStandardError::Protocol),
        }
    }
}

pub(crate) struct DecryptedSecureResponse {
    pub(crate) transaction_number: u16,
    pub(crate) payload: Vec<u8>,
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

impl Authentication2Response {
    pub fn scheme(&self) -> SecureSessionScheme {
        SecureSessionScheme::Des
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

impl Authentication2V2Response {
    pub fn scheme(&self) -> SecureSessionScheme {
        SecureSessionScheme::Aes128
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
        self.encrypt_challenge1b(random_1, challenge_3c) == *challenge_1b
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
            encrypt_aes128_block_internal(&AES128_V2_DERIVE_ENCRYPTION_KEY_INPUT, random_2);
        let mac_key = encrypt_aes128_block_internal(&AES128_V2_DERIVE_MAC_KEY_INPUT, random_2);
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
    block[14..16].copy_from_slice(&AES128_V2_AUTH_CONTEXT_SUFFIX);
    block
}

fn decrypt_secure_response_des(
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

fn xor_block<const BLOCK_SIZE: usize>(
    a: &[u8; BLOCK_SIZE],
    b: &[u8; BLOCK_SIZE],
) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn pad_to_block_size_pkcs7(mut data: Vec<u8>, block_size: usize) -> Vec<u8> {
    let remainder = data.len() % block_size;
    if remainder != 0 {
        let pad_len = (block_size - remainder) as u8;
        for _ in 0..pad_len {
            data.push(pad_len);
        }
    }
    data
}

fn strip_padding_pkcs7(data: &mut Vec<u8>, block_size: usize) {
    let Some(&pad_len) = data.last() else {
        return;
    };
    if pad_len == 0 || pad_len as usize >= block_size {
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

fn xor_blocks(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    xor_block(a, b)
}

fn des_cipher(key: &[u8; 8]) -> Des {
    Des::new(GenericArray::from_slice(key))
}

fn encrypt_des_block_internal(data: &[u8; DES_BLOCK_SIZE], key: &[u8; DES_BLOCK_SIZE]) -> [u8; 8] {
    let cipher = des_cipher(key);
    let mut block_array = GenericArray::clone_from_slice(data);
    cipher.encrypt_block(&mut block_array);
    let mut out = [0u8; DES_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

fn decrypt_des_block_internal(data: &[u8; DES_BLOCK_SIZE], key: &[u8; DES_BLOCK_SIZE]) -> [u8; 8] {
    let cipher = des_cipher(key);
    let mut block_array = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block_array);
    let mut out = [0u8; DES_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

fn encrypt_aes128_block_internal(
    data: &[u8; V2_AES128_BLOCK_SIZE],
    key: &[u8; V2_AES128_BLOCK_SIZE],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block_array = GenericArray::clone_from_slice(data);
    cipher.encrypt_block(&mut block_array);
    let mut out = [0u8; V2_AES128_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

fn decrypt_aes128_block_internal(
    data: &[u8; V2_AES128_BLOCK_SIZE],
    key: &[u8; V2_AES128_BLOCK_SIZE],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block_array = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block_array);
    let mut out = [0u8; V2_AES128_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

pub(crate) fn encrypt_des_block(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    encrypt_des_block_internal(data, key)
}

pub(crate) fn decrypt_des_block(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    decrypt_des_block_internal(data, key)
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
    let iv = [0u8; DES_BLOCK_SIZE];
    let mut out = vec![0u8; data.len()];
    let encrypted_len = CbcEncryptor::<Des>::new_from_slices(key, &iv)
        .map_err(|_| "failed to initialize DES-CBC encryptor".to_string())?
        .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
        .map_err(|_| "secure command payload length must be multiple of 8 bytes".to_string())?
        .len();
    out.truncate(encrypted_len);
    Ok(out)
}

pub(crate) fn decrypt_des_cbc_zero_iv(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err("authentication2 response length must be multiple of 8 bytes".into());
    }
    let iv = [0u8; DES_BLOCK_SIZE];
    let mut out = vec![0u8; data.len()];
    let decrypted_len = CbcDecryptor::<Des>::new_from_slices(key, &iv)
        .map_err(|_| "failed to initialize DES-CBC decryptor".to_string())?
        .decrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
        .map_err(|_| "authentication2 response length must be multiple of 8 bytes".to_string())?
        .len();
    out.truncate(decrypted_len);
    Ok(out)
}

fn pad_to_des_block_size(data: Vec<u8>) -> Vec<u8> {
    pad_to_block_size_pkcs7(data, DES_BLOCK_SIZE)
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
    iv[0] = AES128_V2_IV_MARKER;
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

    let mut cmac = <Cmac<Aes128> as Mac>::new_from_slice(mac_key)
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

fn encrypt_secure_request_v2_aes128(
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

fn decrypt_secure_response_v2_aes128(
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
    if mac_plain == calculate_mac_v2_aes128(&iv, &payload, mac_key) {
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

    fn bytes_from_hex(input: &str) -> Vec<u8> {
        let mut cleaned = String::with_capacity(input.len());
        for ch in input.chars() {
            if !ch.is_ascii_whitespace() {
                cleaned.push(ch);
            }
        }
        let mut out = Vec::with_capacity(cleaned.len() / 2);
        for i in (0..cleaned.len()).step_by(2) {
            let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
                .expect("invalid hex literal in test vector");
            out.push(byte);
        }
        out
    }

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
    fn authenticated_context_v2_holds_key() {
        let encryption_key = [0x55u8; V2_AES128_BLOCK_SIZE];
        let mac_key = [0x77u8; V2_AES128_BLOCK_SIZE];
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

    #[test]
    fn authentication2_v2_response_reports_v2_scheme() {
        let response = Authentication2V2Response {
            encrypted_payload: vec![0xAA; 8],
        };
        assert_eq!(response.scheme(), SecureSessionScheme::Aes128);
    }
}
