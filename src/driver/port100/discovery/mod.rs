//! Target discovery and card emulation for the NFC Port-100.
//!
//! The reader plays two roles, and this module is split along that line:
//!
//! - [`initiator`] polls for cards — the `detect_*` methods.
//! - [`target`] makes the reader look like one — the `listen_*` methods and the
//!   DEP activation that follows.
//!
//! What both sides share — configuring the RF for a role, running a step until
//! a deadline, and the one-exchange wrappers around the chipset — stays here.

mod initiator;
mod target;

use crate::clf::errors::UnsupportedTargetError;
use crate::driver::errors::{ChipsetError, DriverError, Result};
use crate::driver::port100::device::Device;
use crate::transport::Transport;
use log::debug;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SensfRequest {
    pub system_code: u16,
    pub request_code: u8,
    pub time_slots: u8,
    pub raw: Vec<u8>,
}

impl SensfRequest {
    fn from_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() < 6 || frame.get(1) != Some(&0x00) {
            return None;
        }
        Some(Self {
            system_code: u16::from_be_bytes([frame[2], frame[3]]),
            request_code: frame[4],
            time_slots: frame[5],
            raw: frame.to_vec(),
        })
    }
}

impl<T: Transport> Device<T> {
    fn configure_initiator_for_poll(&mut self, bitrate: &str, params: &[(&str, u8)]) -> Result<()> {
        self.chipset.set_initiator_rf(bitrate, None)?;
        self.chipset.apply_initiator_defaults()?;
        if !params.is_empty() {
            self.chipset.configure_initiator(params)?;
        }
        Ok(())
    }

    fn configure_target_for_listen(&mut self, bitrate: &str) -> Result<()> {
        self.chipset.set_target_rf(bitrate)?;
        self.chipset.apply_target_defaults()?;
        self.chipset.configure_target(&[("rf_off_error", 0)])
    }

    fn run_timeout_loop<R, F>(&mut self, timeout: f32, mut step: F) -> Result<Option<R>>
    where
        F: FnMut(&mut Self, u16, Instant) -> Result<Option<R>>,
    {
        let Some(mut window) = TimeoutWindow::new(timeout) else {
            return Ok(None);
        };
        while window.active() {
            if let Some(outcome) = step(self, window.remaining(), window.deadline())? {
                return Ok(Some(outcome));
            }
            window.refresh();
        }
        Ok(None)
    }

    fn target_exchange_default(
        &mut self,
        mdaa: bool,
        nfca_params: &[u8],
        nfcf_params: &[u8],
        timeout: u16,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.chipset.target_exchange_rf(
            0,
            0xFFFF,
            mdaa,
            nfca_params,
            nfcf_params,
            false,
            false,
            timeout,
            payload,
        )
    }

    fn initiator_exchange_optional(
        &mut self,
        payload: &[u8],
        timeout: u16,
        context: &str,
        log_timeouts: bool,
    ) -> Result<Option<Vec<u8>>> {
        match self.chipset.initiator_exchange_rf(payload, timeout) {
            Ok(data) => Ok(Some(data)),
            Err(DriverError::Chipset(ChipsetError::Fault(fault))) => {
                let is_timeout = fault.matches("RECEIVE_TIMEOUT_ERROR");
                if log_timeouts || !is_timeout {
                    debug!("{}: {}", context, fault);
                }
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }
}

fn ensure_supported_bitrate(bitrate: &str, allowed: &[&str], error_prefix: &str) -> Result<()> {
    if allowed.contains(&bitrate) {
        Ok(())
    } else {
        Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            format!("{error_prefix}{bitrate}"),
        )))
    }
}

struct TimeoutWindow {
    deadline: Instant,
    remaining_ms: u16,
}

impl TimeoutWindow {
    fn new(timeout: f32) -> Option<Self> {
        let remaining_ms = clamp_timeout(timeout);
        if remaining_ms == 0 {
            return None;
        }
        Some(Self {
            deadline: Instant::now() + Duration::from_secs_f32(timeout.max(0.0)),
            remaining_ms,
        })
    }

    fn refresh(&mut self) {
        self.remaining_ms = self
            .deadline
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining.as_millis().min(u16::MAX as u128) as u16)
            .unwrap_or(0);
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn remaining(&self) -> u16 {
        self.remaining_ms
    }

    fn active(&self) -> bool {
        self.remaining_ms > 0
    }
}

fn clamp_timeout(timeout: f32) -> u16 {
    if timeout <= 0.0 {
        0
    } else {
        let ms = (timeout * 1000.0).round() as i32;
        ms.clamp(1, 0xFFFF) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_supported_bitrate_accepts_allowed_values_and_rejects_others() {
        assert!(ensure_supported_bitrate("106A", &["106A", "212F"], "unsupported ").is_ok());
        match ensure_supported_bitrate("424A", &["106A", "212F"], "unsupported ") {
            Err(DriverError::UnsupportedTarget(err)) => {
                assert_eq!(err.0, "unsupported 424A");
            }
            Err(other) => panic!("expected UnsupportedTarget error, got {other}"),
            Ok(_) => panic!("expected error for unsupported bitrate"),
        }
    }

    #[test]
    fn timeout_window_and_clamp_timeout_cover_edge_cases() {
        assert_eq!(clamp_timeout(-1.0), 0);
        assert_eq!(clamp_timeout(0.0), 0);
        assert_eq!(clamp_timeout(0.0006), 1);
        assert_eq!(clamp_timeout(1.5), 1500);
        assert_eq!(clamp_timeout(100_000.0), 0xFFFF);

        assert!(TimeoutWindow::new(0.0).is_none());
        let mut window = TimeoutWindow::new(0.05).expect("positive timeout should create window");
        assert!(window.active());
        assert!(window.remaining() > 0);
        let _ = window.deadline();
        window.deadline = Instant::now();
        window.refresh();
        assert!(!window.active());
        assert_eq!(window.remaining(), 0);
    }
}
