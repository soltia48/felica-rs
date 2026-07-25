//! Scheme-neutral cryptographic building blocks shared by the DES/3DES and v2
//! AES-128 secure-messaging layers.
//!
//! These are the lowest-level primitives — single-block ciphers, CBC helpers,
//! XOR, and PKCS#7 padding. They carry no protocol framing; the per-scheme
//! modules ([`super::des`], [`super::aes_v2`]) build the message formats on top
//! of them.

use crate::felica_standard::{DES_BLOCK_SIZE, V2_AES128_BLOCK_SIZE};
use aes::Aes128;
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use des::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
    block_padding::NoPadding,
};
use des::{Des, TdesEde3};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Constant-time equality for secret-derived byte strings (MAC tags, challenge
/// responses). Unequal lengths compare `false`; equal-length inputs are compared
/// in time independent of where they first differ, so the comparison leaks no
/// timing oracle to an attacker who can submit forged MACs / challenges.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub(super) fn xor_block<const BLOCK_SIZE: usize>(
    a: &[u8; BLOCK_SIZE],
    b: &[u8; BLOCK_SIZE],
) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub(super) fn xor_blocks(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    xor_block(a, b)
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

pub(super) fn pad_to_des_block_size(data: Vec<u8>) -> Vec<u8> {
    pad_to_block_size_pkcs7(data, DES_BLOCK_SIZE)
}

fn des_cipher(key: &[u8; 8]) -> Des {
    Des::new(key.into())
}

fn encrypt_des_block_internal(data: &[u8; DES_BLOCK_SIZE], key: &[u8; DES_BLOCK_SIZE]) -> [u8; 8] {
    let cipher = des_cipher(key);
    let mut block_array = (*data).into();
    cipher.encrypt_block(&mut block_array);
    let mut out = [0u8; DES_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

fn decrypt_des_block_internal(data: &[u8; DES_BLOCK_SIZE], key: &[u8; DES_BLOCK_SIZE]) -> [u8; 8] {
    let cipher = des_cipher(key);
    let mut block_array = (*data).into();
    cipher.decrypt_block(&mut block_array);
    let mut out = [0u8; DES_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

pub(super) fn encrypt_aes128_block_internal(
    data: &[u8; V2_AES128_BLOCK_SIZE],
    key: &[u8; V2_AES128_BLOCK_SIZE],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let cipher = Aes128::new(key.into());
    let mut block_array = (*data).into();
    cipher.encrypt_block(&mut block_array);
    let mut out = [0u8; V2_AES128_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

pub(super) fn decrypt_aes128_block_internal(
    data: &[u8; V2_AES128_BLOCK_SIZE],
    key: &[u8; V2_AES128_BLOCK_SIZE],
) -> [u8; V2_AES128_BLOCK_SIZE] {
    let cipher = Aes128::new(key.into());
    let mut block_array = (*data).into();
    cipher.decrypt_block(&mut block_array);
    let mut out = [0u8; V2_AES128_BLOCK_SIZE];
    out.copy_from_slice(&block_array);
    out
}

pub(crate) fn encrypt_des_block(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    encrypt_des_block_internal(data, key)
}

pub(super) fn decrypt_des_block(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    decrypt_des_block_internal(data, key)
}

pub(super) fn encrypt_3des_block(data: &[u8; 8], key1: &[u8; 8], key2: &[u8; 8]) -> [u8; 8] {
    let mut triple_key = [0u8; 24];
    triple_key[..8].copy_from_slice(key1);
    triple_key[8..16].copy_from_slice(key2);
    triple_key[16..24].copy_from_slice(key1);
    let cipher = TdesEde3::new((&triple_key).into());
    // The K1|K2|K1 buffer exists nowhere else, so clear it as soon as the cipher
    // has taken the key. The cipher's own expanded schedule is cleared by the
    // `des` crate, which is built with its `zeroize` feature.
    triple_key.zeroize();
    let mut block = (*data).into();
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

pub(super) fn decrypt_3des_block(data: &[u8; 8], key1: &[u8; 8], key2: &[u8; 8]) -> [u8; 8] {
    let mut triple_key = [0u8; 24];
    triple_key[..8].copy_from_slice(key1);
    triple_key[8..16].copy_from_slice(key2);
    triple_key[16..24].copy_from_slice(key1);
    let cipher = TdesEde3::new((&triple_key).into());
    // The K1|K2|K1 buffer exists nowhere else, so clear it as soon as the cipher
    // has taken the key. The cipher's own expanded schedule is cleared by the
    // `des` crate, which is built with its `zeroize` feature.
    triple_key.zeroize();
    let mut block = (*data).into();
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

pub(super) fn encrypt_des_cbc_zero_iv(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(DES_BLOCK_SIZE) {
        return Err("secure command payload length must be multiple of 8 bytes".into());
    }
    let iv = [0u8; DES_BLOCK_SIZE];
    let mut out = vec![0u8; data.len()];
    let encrypted_len = CbcEncryptor::<Des>::new_from_slices(key, &iv)
        .map_err(|_| "failed to initialize DES-CBC encryptor".to_string())?
        .encrypt_padded_b2b::<NoPadding>(data, &mut out)
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
        .decrypt_padded_b2b::<NoPadding>(data, &mut out)
        .map_err(|_| "authentication2 response length must be multiple of 8 bytes".to_string())?
        .len();
    out.truncate(decrypted_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
