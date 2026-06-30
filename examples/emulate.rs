//! FeliCa Standard emulator using the Port-100 (RC-S380) driver.
//!
//! Usage:
//!   cargo run --example emulate

use log::{debug, info};
use nfc_rs::felica_standard::{
    EmulatedArea, EmulatedService, EmulatedSystem, FelicaStandardEmulator,
};
use nfc_rs::{LocalTarget, ServiceCode, open_port100};
use std::error::Error;

const COMMAND_TIMEOUT_MS: u16 = 1000;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut device = open_port100()?;

    let idm_a: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let pmm_a: [u8; 8] = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let idm_b: [u8; 8] = [0x11, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let pmm_b: [u8; 8] = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let mut system_a = EmulatedSystem::new(0x0123, idm_a, pmm_a)?;
    system_a.add_service(EmulatedService::new(ServiceCode::new(0x0048), 12))?;

    let mut area_a = EmulatedArea::new(0x1000, 0x1FFF)?;
    area_a.add_service(EmulatedService::new(ServiceCode::new(0x1009), 8))?;
    area_a.add_service(EmulatedService::new(ServiceCode::new(0x100B), 8))?;
    system_a.add_area(area_a)?;

    let mut system_b = EmulatedSystem::new(0x4567, idm_b, pmm_b)?;
    let mut area_b = EmulatedArea::new(0x1000, 0x1FFF)?;
    area_b.add_service(EmulatedService::new(ServiceCode::new(0x1009), 12))?;
    system_b.add_area(area_b)?;

    let mut emulator = FelicaStandardEmulator::new();
    emulator.add_system(system_a);
    emulator.add_system(system_b);

    let target = LocalTarget::new("212F")?;

    info!("waiting for NFC-F initiator...");
    if let Some(code) = emulator.active_system_code() {
        info!("active system code: 0x{:04X}", code);
    }

    loop {
        let local = match device.listen_type_f(&target, 1.0, |req| {
            emulator.polling_response(req.system_code, req.request_code)
        })? {
            Some(local) => local,
            None => continue,
        };

        let Some(first_frame) = local.data.tt3_cmd else {
            continue;
        };

        let mut next_frame = Some(first_frame);

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
