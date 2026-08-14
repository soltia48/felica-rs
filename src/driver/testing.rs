//! Test doubles shared by the driver tests.
//!
//! Every chipset driver is exercised the same way: a fake [`Transport`] replays
//! a scripted sequence of reads, the test inspects what was written, and error
//! assertions look for a substring in a [`DriverError::Other`]. Those pieces
//! live here rather than being spelled out again in each driver's test module.

use crate::driver::errors::{DriverError, Result};
use crate::transport::Transport;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;
use std::time::Duration;

/// What a [`DummyTransport`] answers once its scripted reads are used up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum WhenExhausted {
    /// An empty read, which a deadline-driven reader keeps polling through.
    #[default]
    Empty,
    /// A timeout error, which fails the read straight away.
    Timeout,
}

/// A shared handle on everything a [`DummyTransport`] was asked to write.
///
/// The handle can be cloned before the transport is moved into a chipset or
/// device, which is how a test still reads the frames afterwards.
#[derive(Clone, Default)]
pub(crate) struct WriteLog(Rc<RefCell<Vec<Vec<u8>>>>);

impl WriteLog {
    /// Number of frames written so far.
    pub(crate) fn len(&self) -> usize {
        self.0.borrow().len()
    }

    /// Every frame written so far, in order.
    pub(crate) fn frames(&self) -> Vec<Vec<u8>> {
        self.0.borrow().clone()
    }

    /// The `index`th frame written.
    ///
    /// # Panics
    ///
    /// Panics if fewer than `index + 1` frames were written.
    pub(crate) fn frame(&self, index: usize) -> Vec<u8> {
        self.0
            .borrow()
            .get(index)
            .unwrap_or_else(|| panic!("expected at least {} written frames", index + 1))
            .clone()
    }

    /// The most recent frame written.
    ///
    /// # Panics
    ///
    /// Panics if nothing was written.
    pub(crate) fn last(&self) -> Vec<u8> {
        self.0
            .borrow()
            .last()
            .expect("expected at least one written frame")
            .clone()
    }

    fn push(&self, frame: Vec<u8>) {
        self.0.borrow_mut().push(frame);
    }
}

/// A [`Transport`] that replays scripted reads and records every write.
#[derive(Default)]
pub(crate) struct DummyTransport {
    reads: VecDeque<io::Result<Vec<u8>>>,
    writes: WriteLog,
    when_exhausted: WhenExhausted,
    manufacturer: Option<String>,
    product: Option<String>,
}

impl DummyTransport {
    /// A transport that answers reads with `reads`, in order.
    pub(crate) fn with_reads(reads: Vec<io::Result<Vec<u8>>>) -> Self {
        Self {
            reads: reads.into(),
            ..Self::default()
        }
    }

    /// Reports `manufacturer` and `product` as the USB metadata.
    pub(crate) fn with_metadata(mut self, manufacturer: &str, product: &str) -> Self {
        self.manufacturer = Some(manufacturer.to_string());
        self.product = Some(product.to_string());
        self
    }

    /// Fails reads with a timeout once the scripted reads run out, instead of
    /// answering with empty ones.
    pub(crate) fn timing_out_when_exhausted(mut self) -> Self {
        self.when_exhausted = WhenExhausted::Timeout;
        self
    }

    /// Returns a handle on the frames this transport is asked to write.
    ///
    /// The handle stays valid after the transport is moved elsewhere.
    pub(crate) fn writes(&self) -> WriteLog {
        self.writes.clone()
    }
}

impl Transport for DummyTransport {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.writes.push(data.to_vec());
        Ok(())
    }

    fn read(&mut self, _timeout: Duration) -> io::Result<Vec<u8>> {
        match self.reads.pop_front() {
            Some(chunk) => chunk,
            None => match self.when_exhausted {
                WhenExhausted::Empty => Ok(Vec::new()),
                WhenExhausted::Timeout => {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "no more reads"))
                }
            },
        }
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn manufacturer_name(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }

    fn product_name(&self) -> Option<&str> {
        self.product.as_deref()
    }
}

/// Asserts that `result` failed with a [`DriverError::Other`] whose message
/// contains `expected`.
#[track_caller]
pub(crate) fn assert_driver_error_contains<T>(result: Result<T>, expected: &str) {
    match result {
        Err(DriverError::Other(message)) => assert!(
            message.contains(expected),
            "unexpected DriverError::Other message: {message}"
        ),
        Err(other) => panic!("expected DriverError::Other, got {other}"),
        Ok(_) => panic!("expected DriverError::Other, got Ok"),
    }
}
