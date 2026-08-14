//! Buffered transport-read primitives shared by every chipset driver.
//!
//! A USB transport hands back whole packets, but a driver reads a frame header
//! and then its body, so the bytes it did not ask for have to be kept. All of
//! them do this the same way: buffer the surplus in a [`VecDeque`], pull
//! exact-length slices out of it, and give up at a deadline. The SOF-framed
//! drivers (Port-100, RC-S320, RC-S956) additionally share one recovery
//! sequence after a failed exchange. Both live here as the single source of
//! truth; the Port-400's CCID transport uses the read side.

use crate::driver::errors::{DriverError, Result};
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

/// Reads exactly `len` bytes, topping `buffer` up from `transport` until they
/// have all arrived or `deadline` passes.
///
/// Whatever the transport hands back beyond `len` stays in `buffer` for the next
/// read, which is what lets a driver read a frame header and then its body out
/// of a transport that delivers whole packets.
pub(crate) fn read_exact<T: Transport>(
    transport: &mut T,
    buffer: &mut VecDeque<u8>,
    len: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        take_from_buffer(buffer, &mut out, len);
        if out.len() == len {
            break;
        }
        let remaining =
            remaining_until(deadline).ok_or_else(|| DriverError::Io(timeout_error()))?;
        match transport.read(remaining) {
            Ok(chunk) => buffer.extend(chunk),
            // A transport timeout and an elapsed deadline are the same failure
            // to the caller, so both are reported as the canonical one.
            Err(err) if err.kind() == ErrorKind::TimedOut => {
                return Err(DriverError::Io(timeout_error()));
            }
            Err(err) => return Err(DriverError::Io(err)),
        }
    }
    Ok(out)
}

/// Passes `result` through, recovering the chipset first if it failed.
///
/// Recovery is [`recover_after_error`]: the chipset is left able to accept the
/// next command rather than holding a half-finished exchange.
pub(crate) fn recover_on_error<T: Transport, R>(
    result: Result<R>,
    transport: &mut T,
    buffer: &mut VecDeque<u8>,
    ack: &[u8],
    drain_buffer: bool,
) -> Result<R> {
    if result.is_err() {
        recover_after_error(transport, buffer, ack, drain_buffer);
    }
    result
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
