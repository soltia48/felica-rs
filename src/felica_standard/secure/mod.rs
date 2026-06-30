//! FeliCa Standard secure messaging.
//!
//! The protocol supports two mutually exclusive secure-messaging schemes,
//! captured by [`SecureSessionScheme`]:
//!
//! - **DES/3DES** ([`des`]) — the original FeliCa Standard secure messaging.
//! - **v2 AES-128** ([`aes_v2`]) — the FeliCa Standard v2 scheme.
//!
//! This module holds the scheme-agnostic session abstractions — the
//! authenticated-session state ([`AuthenticatedContext`]) and the per-command
//! dispatcher ([`SecureCommandContext`]) that routes each operation to the
//! scheme selected at authentication time. The low-level ciphers live in
//! [`primitives`].

mod aes_v2;
mod des;
mod primitives;
#[cfg(test)]
mod test_util;

use crate::felica_standard::FelicaStandardError;
use aes_v2::{decrypt_secure_response_v2_aes128, encrypt_secure_request_v2_aes128};
use des::{calculate_command_mac_des, decrypt_secure_response_des};
use primitives::{encrypt_des_cbc_zero_iv, pad_to_des_block_size};

// Re-export each scheme's public and crate-internal surface so the rest of the
// crate keeps referring to it through the `secure::` path.
pub(crate) use aes_v2::AuthenticationContextV2Aes128;
#[cfg(test)]
pub(crate) use aes_v2::build_secure_response_frame_v2_aes128;
pub use aes_v2::{Authentication2V2Response, generate_group_key_v2_aes128};
pub use des::{Authentication2Response, generate_service_keys_des};
pub(crate) use des::{
    AuthenticationContext, build_authentication2_payload, build_secure_response_frame_des,
    check_packet_mac_des, encrypt_authentication2_payload, generate_registration_package_des,
};
pub(crate) use primitives::{decrypt_des_cbc_zero_iv, encrypt_des_block};

const TRANSACTION_NUMBER_SIZE: usize = 2;
const TRANSACTION_ID_SIZE: usize = 6;
const DES_SECURE_HEADER_SIZE: usize = TRANSACTION_NUMBER_SIZE + TRANSACTION_ID_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureSessionScheme {
    /// FeliCa Standard secure messaging (DES/3DES).
    Des,
    /// FeliCa Standard v2 secure messaging (AES).
    Aes128,
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

pub(crate) struct DecryptedSecureResponse {
    pub(crate) transaction_number: u16,
    pub(crate) payload: Vec<u8>,
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
}
