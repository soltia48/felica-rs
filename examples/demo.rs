use hex::encode;
use nfc_rs::felica_standard::FelicaStandard;
use nfc_rs::{ReaderPreference, open_reader};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let preference = ReaderPreference::Auto;
    let mut reader = open_reader(preference).map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    println!(
        "Connected to {} {} ({})",
        reader.vendor_name().unwrap_or("Unknown Vendor"),
        reader.product_name().unwrap_or("Unknown Device"),
        reader.chipset_name()
    );

    let (mut felica, _polling) =
        FelicaStandard::polling(reader.driver_mut(), "212F", 0xFFFF, 0x00, 0x00)?;

    println!("IDm: {}", encode(felica.idm()).to_uppercase());
    println!("PMm: {}", encode(felica.pmm()).to_uppercase());

    let mode = felica.request_response()?;
    println!("Current mode: {}", mode);

    Ok(())
}
