use hex::encode;
use nfc_rs::felica_standard::RequestServiceV2KeyVersion;
use nfc_rs::{BlockListElement, FelicaStandard, ServiceCode, open_port100_device};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut device = open_port100_device()?;
    println!(
        "Connected to {} {}",
        device.vendor_name().unwrap_or("Unknown Vendor"),
        device.product_name().unwrap_or("Unknown Device")
    );

    let (mut felica, _polling) = FelicaStandard::polling(&mut device, "212F", 0xFFFF, 0x00, 0x00)?;

    println!("IDm: {}", encode(felica.idm()).to_uppercase());
    println!("PMm: {}", encode(felica.pmm()).to_uppercase());

    let mode = felica.request_response()?;
    println!("Current mode: {}", mode);

    // let key_versions = felica.request_service(&[ServiceCode::new(0x0088)])?;
    // if let Some(key_version) = key_versions.first() {
    //     println!("Key Version 0: {}", key_version);
    // } else {
    //     println!("No key versions returned");
    // }

    let service_code = ServiceCode::new(0x090C);
    let key_versions_v2 = felica.request_service_v2(&[service_code])?;
    match key_versions_v2.first() {
        Some(RequestServiceV2KeyVersion::Single(version)) => {
            println!(
                "Request Service V2 for {:04X}: key_version={}",
                service_code.raw(),
                version
            );
        }
        Some(RequestServiceV2KeyVersion::Dual { aes, des }) => {
            println!(
                "Request Service V2 for {:04X}: aes={} des={}",
                service_code.raw(),
                aes,
                des
            );
        }
        None => println!("Request Service V2 returned no key versions"),
    }

    // let service_code = ServiceCode::new(0x008B);
    // let block = BlockListElement::new(0, 0, 0);
    // let blocks = felica.read_without_encryption(&[service_code], &[block])?;
    // if let Some(block_data) = blocks.first() {
    //     println!(
    //         "Read Without Encryption block 0 data: {}",
    //         encode(block_data).to_uppercase()
    //     );
    // } else {
    //     println!("No data returned from service");
    // }

    // for service_index in 0u16..255u16 {
    //     match felica.search_service_code(service_index)? {
    //         Some(SearchServiceCodeResult::Service(code)) => {
    //             println!(
    //                 "Service index {service_index:04X} -> service code {:04X}",
    //                 code.raw()
    //             );
    //         }
    //         Some(SearchServiceCodeResult::Area {
    //             area_code,
    //             end_service_index,
    //         }) => {
    //             println!(
    //                 "Service index {service_index:04X} -> area {:04X}..{:04X}",
    //                 area_code, end_service_index
    //             );
    //         }
    //         None => {
    //             println!("Service index {service_index:04X}: not found");
    //             break;
    //         }
    //     }
    // }

    // let block_info = felica.request_block_information(&[service_code.raw()])?;
    // println!(
    //     "Block information for node {:04X}: {:?}",
    //     service_code.raw(),
    //     block_info
    // );

    let group_service_key = [0xE7, 0x81, 0x6C, 0xA2, 0x12, 0x3F, 0x5F, 0xA0];
    let user_service_key = [0x4B, 0xB1, 0x81, 0xC3, 0xD2, 0xE7, 0xF9, 0x5A];
    match felica.mutual_authentication(
        &[0x0000, 0x0040, 0x0800],
        &[ServiceCode(0x0088), ServiceCode(0x090C)],
        &group_service_key,
        &user_service_key,
    ) {
        Ok(session) => {
            println!(
                "Mutual authentication succeeded: issue_id={}, issue_parameter={}",
                encode(session.issue_id).to_uppercase(),
                encode(session.issue_parameter).to_uppercase()
            );

            // Secure Read example: service index 0, block number 0, random read mode.
            let block_descriptor = BlockListElement::new(0x0000, 0, 0);
            let blocks = felica.read(&[block_descriptor])?;
            if let Some(block_data) = blocks.first() {
                println!("Read block 0 data: {}", encode(block_data).to_uppercase());
            } else {
                println!("No data returned from service");
            }
        }
        Err(err) => {
            println!("Mutual authentication failed: {err}");
        }
    }

    Ok(())
}
