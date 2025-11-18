pub mod usb;

use std::time::Duration;

pub trait Transport {
    fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    fn read(&mut self, timeout: Duration) -> std::io::Result<Vec<u8>>;
    fn close(&mut self) -> std::io::Result<()>;

    fn manufacturer_name(&self) -> Option<&str> {
        None
    }

    fn product_name(&self) -> Option<&str> {
        None
    }
}
