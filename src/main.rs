use hex::encode;
use nfc_rs::driver::errors::DriverError;
use nfc_rs::felica_standard::{
    FelicaDriver, FelicaStandard, FelicaStandardError, RequestServiceV2KeyVersion,
};
use nfc_rs::{
    BlockListElement, Port400Device, ServiceCode, UsbTransport, open_port100_device,
    open_port400_device,
};
use std::env;
use std::error::Error;

type Port100Device = nfc_rs::Device<UsbTransport>;
type Port400UsbDevice = Port400Device<UsbTransport>;

fn main() -> Result<(), Box<dyn Error>> {
    let preference = reader_preference();
    let mut reader = open_reader(preference).map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    println!(
        "Connected to {} {} ({})",
        reader.vendor_name().unwrap_or("Unknown Vendor"),
        reader.product_name().unwrap_or("Unknown Device"),
        reader.chipset_name()
    );

    run_session(reader.as_driver_mut()).map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    Ok(())
}

fn run_session(device: &mut dyn FelicaDriver) -> Result<(), FelicaStandardError> {
    let (mut felica, _polling) = FelicaStandard::polling(device, "212F", 0xFFFF, 0x00, 0x00)?;

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

fn reader_preference() -> ReaderPreference {
    match env::var("NFC_DRIVER").ok().as_deref() {
        Some(value) if value.eq_ignore_ascii_case("port400") => ReaderPreference::ForcePort400,
        Some(value) if value.eq_ignore_ascii_case("port100") => ReaderPreference::ForcePort100,
        _ => ReaderPreference::Auto,
    }
}

fn open_reader(preference: ReaderPreference) -> Result<Reader, DriverError> {
    match preference {
        ReaderPreference::ForcePort100 => open_port100_device().map(Reader::Port100),
        ReaderPreference::ForcePort400 => open_port400_device().map(Reader::Port400),
        ReaderPreference::Auto => match open_port100_device() {
            Ok(device) => Ok(Reader::Port100(device)),
            Err(err100) => match open_port400_device() {
                Ok(device) => Ok(Reader::Port400(device)),
                Err(err400) => Err(DriverError::Other(format!(
                    "failed to open Port-100 ({err100}) and Port-400 ({err400})"
                ))),
            },
        },
    }
}

enum ReaderPreference {
    Auto,
    ForcePort100,
    ForcePort400,
}

enum Reader {
    Port100(Port100Device),
    Port400(Port400UsbDevice),
}

impl Reader {
    fn vendor_name(&self) -> Option<&str> {
        match self {
            Reader::Port100(device) => device.vendor_name(),
            Reader::Port400(device) => device.vendor_name(),
        }
    }

    fn product_name(&self) -> Option<&str> {
        match self {
            Reader::Port100(device) => device.product_name(),
            Reader::Port400(device) => device.product_name(),
        }
    }

    fn chipset_name(&self) -> &str {
        match self {
            Reader::Port100(device) => device.chipset_name(),
            Reader::Port400(device) => device.chipset_name(),
        }
    }

    fn as_driver_mut(&mut self) -> &mut dyn FelicaDriver {
        match self {
            Reader::Port100(device) => device,
            Reader::Port400(device) => device,
        }
    }
}
