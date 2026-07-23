/// CRC-16 polynomial used by NFC-A and NFC-B protocols.
const CRC_POLYNOMIAL: u16 = 0x8408;

/// Initial CRC value for NFC-A (Type A).
const CRC_A_INIT: u16 = 0x6363;

/// Initial CRC value for NFC-B (Type B).
const CRC_B_INIT: u16 = 0xFFFF;

/// Calculates CRC-16 using the ISO/IEC 14443 polynomial.
fn calculate_crc(data: &[u8], size: usize, mut reg: u16) -> u16 {
    for &octet in data.iter().take(size) {
        for pos in 0..8 {
            let bit = (reg ^ (u16::from(octet >> pos) & 1)) & 1;
            reg >>= 1;
            if bit != 0 {
                reg ^= CRC_POLYNOMIAL;
            }
        }
    }
    reg
}

/// Appends CRC bytes (low byte first) to the data vector.
#[inline]
fn append_crc(data: &mut Vec<u8>, crc: u16) {
    data.push((crc & 0x00FF) as u8);
    data.push((crc >> 8) as u8);
}

/// Verifies CRC bytes at the end of data match the expected CRC.
#[inline]
fn verify_crc(data: &[u8], crc: u16) -> bool {
    if data.len() < 2 {
        return false;
    }
    let expected_low = (crc & 0x00FF) as u8;
    let expected_high = (crc >> 8) as u8;
    data[data.len() - 2] == expected_low && data[data.len() - 1] == expected_high
}

/// Adds NFC-A CRC to the data and returns the extended vector.
pub fn add_crc_a(mut data: Vec<u8>) -> Vec<u8> {
    let crc = calculate_crc(&data, data.len(), CRC_A_INIT);
    append_crc(&mut data, crc);
    data
}

/// Checks if the NFC-A CRC at the end of data is valid.
pub fn check_crc_a(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let crc = calculate_crc(data, data.len() - 2, CRC_A_INIT);
    verify_crc(data, crc)
}

/// Adds NFC-B CRC to the data and returns the extended vector.
pub fn add_crc_b(mut data: Vec<u8>) -> Vec<u8> {
    let crc = !calculate_crc(&data, data.len(), CRC_B_INIT);
    append_crc(&mut data, crc);
    data
}

/// Checks if the NFC-B CRC at the end of data is valid.
pub fn check_crc_b(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let crc = !calculate_crc(data, data.len() - 2, CRC_B_INIT);
    verify_crc(data, crc)
}

#[cfg(test)]
mod tests {
    use super::{add_crc_a, add_crc_b, check_crc_a, check_crc_b};

    #[test]
    fn add_and_check_crc_a_round_trip() {
        let payload = vec![0x93, 0x20, 0x01, 0x02];
        let framed = add_crc_a(payload.clone());
        assert_eq!(framed.len(), payload.len() + 2);
        assert!(check_crc_a(&framed));
    }

    #[test]
    fn check_crc_a_rejects_modified_payload() {
        let mut framed = add_crc_a(vec![0x12, 0x34, 0x56, 0x78]);
        framed[1] ^= 0xFF;
        assert!(!check_crc_a(&framed));
    }

    #[test]
    fn add_and_check_crc_b_round_trip() {
        let payload = vec![0x05, 0x00, 0x08, 0x39, 0x73];
        let framed = add_crc_b(payload.clone());
        assert_eq!(framed.len(), payload.len() + 2);
        assert!(check_crc_b(&framed));
    }

    #[test]
    fn check_crc_b_rejects_short_input() {
        assert!(!check_crc_b(&[]));
        assert!(!check_crc_b(&[0x00]));
    }
}
