//! High-level reader facade.
//!
//! [`Reader`] is a thin, driver-agnostic wrapper around any device that
//! implements [`ReaderDevice`]. Opening a reader returns one of these so callers
//! can poll FeliCa cards without caring which Sony chipset is attached, while
//! still being able to [`Reader::downcast_mut`] back to the concrete driver for
//! device-specific features (emulation, ISO-DEP, …).

use crate::driver::common::ReaderDevice;
use crate::driver::errors::{DriverError, Result};
use crate::driver::port100::{Device as Port100Driver, open_port100};
use crate::driver::port400::{Device as Port400Driver, open_port400};
use crate::driver::rcs320::{Device as Rcs320Driver, Rcs320Transport, open_rcs320};
use crate::driver::rcs956::{Device as Rcs956Driver, open_rcs956};
use crate::felica_standard::FelicaDriver;
use crate::transport::usb::UsbTransport;

/// Concrete Port-100 device over USB (downcast target for [`Reader::downcast_mut`]).
pub type Port100Device = Port100Driver<UsbTransport>;
/// Concrete Port-400 device over USB.
pub type Port400Device = Port400Driver<UsbTransport>;
/// Concrete RC-S320 device.
pub type Rcs320Device = Rcs320Driver<Rcs320Transport>;
/// Concrete RC-S956 device over USB.
pub type Rcs956Device = Rcs956Driver<UsbTransport>;

/// Which reader [`open_reader`] should attach to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderPreference {
    /// Try every supported reader in turn.
    Auto,
    /// Only the NFC Port-100 (RC-S380).
    ForcePort100,
    /// Only the NFC Port-400.
    ForcePort400,
    /// Only the RC-S320.
    ForceRcs320,
    /// Only the RC-S956 (RC-S330/RC-S360/RC-S370).
    ForceRcs956,
}

/// A driver-agnostic handle to an attached NFC reader.
pub struct Reader {
    device: Box<dyn ReaderDevice>,
}

impl Reader {
    /// Wraps a concrete reader driver in the facade.
    pub fn new(device: impl ReaderDevice) -> Self {
        Self {
            device: Box::new(device),
        }
    }

    /// Returns the USB vendor / manufacturer name, if known.
    pub fn vendor_name(&self) -> Option<&str> {
        self.device.vendor_name()
    }

    /// Returns the USB product name, if known.
    pub fn product_name(&self) -> Option<&str> {
        self.device.product_name()
    }

    /// Returns the chipset name (with firmware version where available).
    pub fn chipset_name(&self) -> &str {
        self.device.chipset_name()
    }

    /// Releases the device and turns off the RF field.
    pub fn close(&mut self) -> Result<()> {
        self.device.close()
    }

    /// Borrows the underlying FeliCa driver for protocol operations.
    pub fn driver_mut(&mut self) -> &mut dyn FelicaDriver {
        &mut *self.device
    }

    /// Attempts to borrow the concrete driver (e.g. [`Port100Device`]) to reach
    /// device-specific features not exposed by the facade.
    pub fn downcast_mut<D: ReaderDevice>(&mut self) -> Option<&mut D> {
        self.device.as_any_mut().downcast_mut::<D>()
    }
}

impl<D: ReaderDevice> From<D> for Reader {
    fn from(device: D) -> Self {
        Self::new(device)
    }
}

/// Opens an NFC reader according to `preference`.
pub fn open_reader(preference: ReaderPreference) -> Result<Reader> {
    match preference {
        ReaderPreference::ForcePort100 => open_port100().map(Reader::new),
        ReaderPreference::ForcePort400 => open_port400().map(Reader::new),
        ReaderPreference::ForceRcs320 => open_rcs320().map(Reader::new),
        ReaderPreference::ForceRcs956 => open_rcs956().map(Reader::new),
        ReaderPreference::Auto => open_first_available(),
    }
}

/// One reader [`ReaderPreference::Auto`] knows how to attach to.
struct SupportedReader {
    /// How a failure to open this reader is reported.
    name: &'static str,
    /// Attaches to the reader.
    open: fn() -> Result<Reader>,
}

/// The readers [`ReaderPreference::Auto`] tries, in the order it tries them.
const AUTO_PROBE_ORDER: [SupportedReader; 4] = [
    SupportedReader {
        name: "Port-100",
        open: || open_port100().map(Reader::new),
    },
    SupportedReader {
        name: "Port-400",
        open: || open_port400().map(Reader::new),
    },
    SupportedReader {
        name: "RC-S956",
        open: || open_rcs956().map(Reader::new),
    },
    SupportedReader {
        name: "RC-S320",
        open: || open_rcs320().map(Reader::new),
    },
];

fn open_first_available() -> Result<Reader> {
    let mut failures = Vec::with_capacity(AUTO_PROBE_ORDER.len());
    for candidate in AUTO_PROBE_ORDER {
        match (candidate.open)() {
            Ok(reader) => return Ok(reader),
            // Every reader is tried before giving up, and the report names them
            // all: which one is actually attached is not knowable from here.
            Err(err) => failures.push(format!("{} ({err})", candidate.name)),
        }
    }
    Err(DriverError::Other(format!(
        "failed to open {}",
        failures.join(", ")
    )))
}
