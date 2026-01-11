use crate::driver::errors::DriverError;
use crate::driver::port100::{Device as Port100Driver, open_port100_device};
use crate::driver::port400::{Device as Port400Driver, open_port400_device};
use crate::driver::rcs956::{Device as Rcs956Driver, open_rcs956_device};
use crate::felica_standard::FelicaDriver;
use crate::transport::usb::UsbTransport;

pub type Port100Device = Port100Driver<UsbTransport>;
pub type Port400UsbDevice = Port400Driver<UsbTransport>;
pub type Rcs956Device = Rcs956Driver<UsbTransport>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderPreference {
    Auto,
    ForcePort100,
    ForcePort400,
    ForceRcs956,
}

pub enum Reader {
    Port100(Port100Device),
    Port400(Port400UsbDevice),
    Rcs956(Rcs956Device),
}

impl Reader {
    pub fn vendor_name(&self) -> Option<&str> {
        match self {
            Reader::Port100(device) => device.vendor_name(),
            Reader::Port400(device) => device.vendor_name(),
            Reader::Rcs956(device) => device.vendor_name(),
        }
    }

    pub fn product_name(&self) -> Option<&str> {
        match self {
            Reader::Port100(device) => device.product_name(),
            Reader::Port400(device) => device.product_name(),
            Reader::Rcs956(device) => device.product_name(),
        }
    }

    pub fn chipset_name(&self) -> &str {
        match self {
            Reader::Port100(device) => device.chipset_name(),
            Reader::Port400(device) => device.chipset_name(),
            Reader::Rcs956(device) => device.chipset_name(),
        }
    }

    pub fn driver_mut(&mut self) -> &mut dyn FelicaDriver {
        match self {
            Reader::Port100(device) => device,
            Reader::Port400(device) => device,
            Reader::Rcs956(device) => device,
        }
    }
}

pub fn open_reader(preference: ReaderPreference) -> Result<Reader, DriverError> {
    match preference {
        ReaderPreference::ForcePort100 => open_port100_device().map(Reader::from),
        ReaderPreference::ForcePort400 => open_port400_device().map(Reader::from),
        ReaderPreference::ForceRcs956 => open_rcs956_device().map(Reader::from),
        ReaderPreference::Auto => match open_port100_device() {
            Ok(device) => Ok(Reader::from(device)),
            Err(err100) => match open_port400_device() {
                Ok(device) => Ok(Reader::from(device)),
                Err(err400) => match open_rcs956_device() {
                    Ok(device) => Ok(Reader::from(device)),
                    Err(err956) => Err(DriverError::Other(format!(
                        "failed to open Port-100 ({err100}), Port-400 ({err400}), and RC-S956 ({err956})"
                    ))),
                },
            },
        },
    }
}

impl From<Port100Device> for Reader {
    fn from(device: Port100Device) -> Self {
        Reader::Port100(device)
    }
}

impl From<Port400UsbDevice> for Reader {
    fn from(device: Port400UsbDevice) -> Self {
        Reader::Port400(device)
    }
}

impl From<Rcs956Device> for Reader {
    fn from(device: Rcs956Device) -> Self {
        Reader::Rcs956(device)
    }
}
