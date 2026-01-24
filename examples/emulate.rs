//! FeliCa Standard emulator using the Port-100 (RC-S380) driver.
//!
//! Usage:
//!   cargo run --example emulate

use log::{debug, info};
use nfc_rs::felica_standard::{
    EmulatedArea, EmulatedService, EmulatedSystem, FelicaStandardEmulator,
};
use nfc_rs::{LocalTarget, ServiceCode, open_port100_device};
use std::error::Error;
use std::io;

const COMMAND_TIMEOUT_MS: u16 = 1000;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut device = open_port100_device()?;

    let idm_a: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let pmm_a: [u8; 8] = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let idm_b: [u8; 8] = [0x11, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let pmm_b: [u8; 8] = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let mut system_a = EmulatedSystem::new(0x0123, idm_a, pmm_a)?;
    let mut area_a = EmulatedArea::new(0x0008, 0x000F)?;
    area_a.add_service(EmulatedService::new(ServiceCode::new(0x0009), 16))?;
    // Same service number (0x0000) with a different attribute shares blocks.
    area_a.add_service(EmulatedService::with_key_version(
        ServiceCode::new(0x000B),
        0x0001,
        16,
    ))?;
    system_a.add_area(area_a)?;
    // Same service number (0x0000) as 0x0009/0x000B, so keep block count aligned.
    system_a.add_service(EmulatedService::new(ServiceCode::new(0x0011), 16))?;
    // Authentication-required service (LSB = 0) with its own key.
    let mut auth_service = EmulatedService::with_key_version(ServiceCode::new(0x0048), 0x0000, 8);
    auth_service.set_key([0x00; 8]);
    system_a.add_service(auth_service)?;

    let mut system_b = EmulatedSystem::new(0x4567, idm_b, pmm_b)?;
    let mut area_b = EmulatedArea::new(0x0100, 0x010F)?;
    area_b.add_service(EmulatedService::new(ServiceCode::new(0x0109), 12))?;
    system_b.add_area(area_b)?;

    let mut emulator = FelicaStandardEmulator::new();
    emulator.add_system(system_a);
    emulator.add_system(system_b);

    let mut target = LocalTarget::new("212F")?;

    info!("waiting for NFC-F initiator...");
    if let Some(code) = emulator.active_system_code() {
        info!("active system code: 0x{:04X}", code);
    }

    loop {
        let sensf_res = emulator
            .sensf_res()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no system configured"))?;
        target.data.sensf_res = Some(sensf_res);

        let local = match device.listen_type_f(&target, 1.0)? {
            Some(local) => local,
            None => continue,
        };

        let Some(first_payload) = local.data.tt3_cmd else {
            continue;
        };

        let mut next_frame = Some(frame_with_length_prefix(&first_payload));

        while let Some(frame) = next_frame {
            let response = match emulator.handle_frame(&frame) {
                Some(response) => response,
                None => {
                    debug!("no response for command, ending session");
                    break;
                }
            };

            next_frame = device.send_response_receive_command(&response, COMMAND_TIMEOUT_MS)?;
        }
    }
}

fn frame_with_length_prefix(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 1);
    frame.push((payload.len() + 1) as u8);
    frame.extend_from_slice(payload);
    frame
}
