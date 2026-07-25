//! `Debug` formatting for the types that carry key material.
//!
//! Session keys, node keys and the derived authentication keys all end up in
//! types that are otherwise worth being [`Debug`] — a caller wants to see which
//! nodes a derivation covered, or what transaction a session is on. A derived
//! `Debug` would print the key bytes alongside that, and a single
//! `log::debug!("{:?}", ..)` while troubleshooting is enough to put live keys
//! into an application log. Those types therefore write their secret fields
//! through [`Redacted`] instead of deriving the impl.

use std::fmt;

/// Stands in for a secret byte string in a `Debug` impl, printing only how long
/// it was.
pub(crate) struct Redacted(pub(crate) usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes redacted>", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_reports_only_the_length() {
        assert_eq!(format!("{:?}", Redacted(8)), "<8 bytes redacted>");
        assert_eq!(format!("{:?}", Redacted(16)), "<16 bytes redacted>");
    }
}
