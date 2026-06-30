//! Buffered transport-read primitives shared by the SOF-based chipset drivers
//! (Port-100, RC-S320, RC-S956).
//!
//! These readers buffer raw bytes from the transport in a [`VecDeque`] and pull
//! exact-length slices out of it while honouring a deadline. The deadline and
//! buffer bookkeeping are identical across drivers, so they live here as the
//! single source of truth.

use crate::transport::Transport;
use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

/// Returns the time left until `deadline`, or `None` once it has elapsed.
pub(crate) fn remaining_until(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| d.as_nanos() != 0)
}

/// The canonical timeout error returned when no data arrives before the
/// deadline.
pub(crate) fn timeout_error() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "timeout while waiting for data")
}

/// Moves buffered bytes into `out` until it holds `len` bytes or the buffer is
/// exhausted.
pub(crate) fn take_from_buffer(buffer: &mut VecDeque<u8>, out: &mut Vec<u8>, len: usize) {
    while out.len() < len {
        match buffer.pop_front() {
            Some(byte) => out.push(byte),
            None => break,
        }
    }
}

/// How long [`recover_after_error`] spends draining stale input.
const BUFFER_CLEAR_TIMEOUT: Duration = Duration::from_millis(50);

/// Recovers a chipset after a failed exchange: re-sends `ack`, optionally drains
/// pending input, and clears the read buffer.
pub(crate) fn recover_after_error<T: Transport>(
    transport: &mut T,
    buffer: &mut VecDeque<u8>,
    ack: &[u8],
    drain_buffer: bool,
) {
    if let Err(err) = transport.write(ack) {
        log::warn!("failed to send recovery ACK: {err}");
    }
    if drain_buffer {
        drain_input(transport, buffer, BUFFER_CLEAR_TIMEOUT);
    }
    buffer.clear();
}

/// Clears the buffer and discards any pending transport input for up to
/// `timeout`, stopping on the first empty read or timeout.
pub(crate) fn drain_input<T: Transport>(
    transport: &mut T,
    buffer: &mut VecDeque<u8>,
    timeout: Duration,
) {
    buffer.clear();
    let deadline = Instant::now() + timeout;
    while let Some(remaining) = remaining_until(deadline) {
        match transport.read(remaining) {
            Ok(bytes) if bytes.is_empty() => break,
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::TimedOut => break,
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_until_and_timeout_error_behave_as_expected() {
        assert!(remaining_until(Instant::now() - Duration::from_secs(1)).is_none());
        assert!(remaining_until(Instant::now() + Duration::from_secs(60)).is_some());
        assert_eq!(timeout_error().kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn take_from_buffer_consumes_only_requested_bytes() {
        let mut buffer: VecDeque<u8> = [1, 2, 3, 4].into_iter().collect();
        let mut out = Vec::new();
        take_from_buffer(&mut buffer, &mut out, 3);
        assert_eq!(out, vec![1, 2, 3]);
        assert_eq!(buffer.into_iter().collect::<Vec<_>>(), vec![4]);
    }
}
