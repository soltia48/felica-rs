fn calculate_crc(data: &[u8], size: usize, mut reg: u16) -> u16 {
    for &octet in data.iter().take(size) {
        for pos in 0..8 {
            let bit = (reg ^ (((octet >> pos) & 1) as u16)) & 1;
            reg >>= 1;
            if bit != 0 {
                reg ^= 0x8408;
            }
        }
    }
    reg
}

pub fn add_crc_a(mut data: Vec<u8>) -> Vec<u8> {
    let crc = calculate_crc(&data, data.len(), 0x6363);
    data.push((crc & 0x00FF) as u8);
    data.push((crc >> 8) as u8);
    data
}

pub fn check_crc_a(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let crc = calculate_crc(data, data.len() - 2, 0x6363);
    let low = (crc & 0x00FF) as u8;
    let high = (crc >> 8) as u8;
    data[data.len() - 2] == low && data[data.len() - 1] == high
}

pub fn add_crc_b(mut data: Vec<u8>) -> Vec<u8> {
    let crc = !calculate_crc(&data, data.len(), 0xFFFF) & 0xFFFF;
    data.push((crc & 0x00FF) as u8);
    data.push((crc >> 8) as u8);
    data
}

pub fn check_crc_b(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let crc = !calculate_crc(data, data.len() - 2, 0xFFFF) & 0xFFFF;
    let low = (crc & 0x00FF) as u8;
    let high = (crc >> 8) as u8;
    data[data.len() - 2] == low && data[data.len() - 1] == high
}
