//! Block-level write semantics for the emulated card: the purse arithmetic of
//! §3.4.4/§3.4.4.1 and the ring behaviour of the cyclic service in §3.4.3.
//!
//! These are the rules that make a purse or cyclic service behave differently
//! from a plain random service. They live apart from [`super::system`] because
//! they are pure functions over block bytes, which is also how they are tested.

use super::structure::LimitPurseProperty;
use crate::felica_standard::{BLOCK_SIZE, ServiceAttribute};

/// Status flag 2 `01h`: a decrement went below the floor, or a cashback overflowed
/// four bytes (§4.5.2, table 4-11).
const SF2_PURSE_RESULT_OUT_OF_RANGE: u8 = 0x01;

/// Status flag 2 `02h`: the requested cashback exceeds the stored cashback data.
const SF2_CASHBACK_EXCEEDS_STORED: u8 = 0x02;

/// Status flag 2 `03h`: a limit purse write would leave the purse outside its
/// upper/lower limits.
const SF2_LIMIT_PURSE_OUT_OF_RANGE: u8 = 0x03;

/// Status flag 2 `A5h`: the command's parameters do not satisfy the success
/// requirements (§4.5.2, table 4-12).
const SF2_ACCESS_NOT_PERMITTED: u8 = 0xA5;

/// Status flag 2 `AFh`: more blocks were written to one cyclic service in a single
/// command than the service owns.
const SF2_CYCLIC_WRITE_OVERFLOW: u8 = 0xAF;

/// Purse data: D0-D3, little endian (§3.4.4, figure 3-15).
const PURSE_DATA: std::ops::Range<usize> = 0..4;

/// Cashback data: D4-D7, little endian (figure 3-15).
const CASHBACK_DATA: std::ops::Range<usize> = 4..8;

/// Execution ID: D12-D15 (figures 3-15, 3-16, 3-17).
const EXECUTION_ID: std::ops::Range<usize> = 12..16;

/// Largest value a four-byte purse field can hold when it is *not* a limit purse
/// service, i.e. when the field is a plain unsigned number (§4.5.2: a cashback
/// result may not become "4 バイトを超える数字").
const PURSE_MAX_UNSIGNED: i64 = u32::MAX as i64;

type Block = [u8; BLOCK_SIZE];

/// Which purse operation a write performs, decided by the service attribute and
/// the block list element's access mode (table 3-6, §4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PurseOperation {
    /// Direct access: the block is written as supplied, with no arithmetic.
    Direct,
    /// Decrement: subtract the command's value from the stored purse data and
    /// record what was subtracted in the cashback data.
    Decrement,
    /// Cashback: add the command's value back to the purse data, bounded by the
    /// cashback data, then clear the cashback data.
    Cashback,
}

impl PurseOperation {
    /// Resolves the operation for a purse service, or reports the status flag 2
    /// value for a combination the card would refuse.
    ///
    /// Access mode `001b` selects cashback and `000b` everything else (§4.2.1);
    /// §4.4.6 requires that `001b` only ever addresses a service whose attribute
    /// is purse cashback/decrement.
    pub(super) fn resolve(attribute: ServiceAttribute, access_mode: u8) -> Result<Self, u8> {
        match (attribute, access_mode) {
            (ServiceAttribute::PurseDirect, 0b000) => Ok(PurseOperation::Direct),
            (ServiceAttribute::PurseDecrement, 0b000) => Ok(PurseOperation::Decrement),
            (ServiceAttribute::PurseCashback, 0b000) => Ok(PurseOperation::Decrement),
            (ServiceAttribute::PurseCashback, 0b001) => Ok(PurseOperation::Cashback),
            // Cashback access to a service that does not offer the cashback
            // function fails the §4.4.6 success requirement for access mode 001b.
            (_, 0b001) => Err(SF2_ACCESS_NOT_PERMITTED),
            _ => Err(SF2_ACCESS_NOT_PERMITTED),
        }
    }
}

/// Reads a little-endian four-byte purse field.
///
/// A limit purse service treats purse data as a two's-complement number
/// (§3.4.4.1); an ordinary purse service treats it as unsigned (§3.4.4: "ブロック
/// データの一部を正の数値とみなして").
fn read_value(bytes: &[u8], signed: bool) -> i64 {
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if signed {
        i64::from(raw as i32)
    } else {
        i64::from(raw)
    }
}

fn write_value(target: &mut [u8], value: i64) {
    let raw = (value as u32).to_le_bytes();
    target.copy_from_slice(&raw);
}

/// Applies one purse write to `stored`, returning the block to store.
///
/// `Ok(None)` means the write completed successfully but left the block
/// untouched: §3.4.4 suppresses the update when the command repeats the stored
/// execution ID, so that a command re-sent after a communication failure does
/// not decrement twice. `Err(sf2)` carries the status flag 2 value to report.
pub(super) fn apply_purse_write(
    stored: &Block,
    command: &Block,
    operation: PurseOperation,
    limit: Option<LimitPurseProperty>,
) -> Result<Option<Block>, u8> {
    let signed = limit.is_some();
    let (floor, ceiling) = match limit {
        Some(limit) => (i64::from(limit.lower_limit), i64::from(limit.upper_limit)),
        None => (0, PURSE_MAX_UNSIGNED),
    };
    // A limit purse write that falls outside the limits is 03h, whereas the same
    // overflow on an ordinary purse is 01h (§4.5.2, table 4-11).
    let out_of_range = if limit.is_some() {
        SF2_LIMIT_PURSE_OUT_OF_RANGE
    } else {
        SF2_PURSE_RESULT_OUT_OF_RANGE
    };

    // Table 3-7: the execution ID is compared for the cashback/decrement
    // attributes and ignored for direct access.
    if operation != PurseOperation::Direct && command[EXECUTION_ID] == stored[EXECUTION_ID] {
        return Ok(None);
    }

    let stored_purse = read_value(&stored[PURSE_DATA], signed);
    let stored_cashback = read_value(&stored[CASHBACK_DATA], signed);
    let mut updated = *command;

    match operation {
        PurseOperation::Direct => {
            // Direct access performs no arithmetic, so the whole block is stored
            // as supplied — but §4.4.6 still requires the command not to inflate
            // the purse or the cashback field.
            let new_purse = read_value(&command[PURSE_DATA], signed);
            let new_cashback = read_value(&command[CASHBACK_DATA], signed);
            if new_purse > stored_purse || new_cashback > stored_cashback {
                return Err(SF2_ACCESS_NOT_PERMITTED);
            }
            if stored_purse + new_cashback > PURSE_MAX_UNSIGNED {
                return Err(SF2_ACCESS_NOT_PERMITTED);
            }
            if new_purse < floor || new_purse > ceiling {
                return Err(out_of_range);
            }
        }
        PurseOperation::Decrement => {
            // Figure 3-16: D0-D3 hold the value to subtract, D4-D11 are ignored.
            let amount = read_value(&command[PURSE_DATA], signed);
            let result = stored_purse - amount;
            if result < floor {
                return Err(out_of_range);
            }
            if result > ceiling {
                return Err(out_of_range);
            }
            write_value(&mut updated[PURSE_DATA], result);
            // §3.4.4: what was subtracted is recorded as the cashback data, which
            // is what bounds a later cashback.
            write_value(&mut updated[CASHBACK_DATA], amount);
            updated[8..12].copy_from_slice(&stored[8..12]);
        }
        PurseOperation::Cashback => {
            // Figure 3-17: D0-D3 hold the value to add back, D4-D11 are ignored.
            let amount = read_value(&command[PURSE_DATA], signed);
            if amount > stored_cashback {
                return Err(SF2_CASHBACK_EXCEEDS_STORED);
            }
            let result = stored_purse + amount;
            if result > ceiling {
                return Err(out_of_range);
            }
            if result < floor {
                return Err(out_of_range);
            }
            write_value(&mut updated[PURSE_DATA], result);
            // §3.4.4: a completed cashback resets the cashback data to 0.
            write_value(&mut updated[CASHBACK_DATA], 0);
            updated[8..12].copy_from_slice(&stored[8..12]);
        }
    }

    Ok(Some(updated))
}

/// The outcome of writing a run of blocks to one cyclic service.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CyclicWrite {
    /// The ring after the write, newest generation first.
    Updated(Vec<Block>),
    /// The command repeated the newest generations byte for byte. §3.4.3 has the
    /// card complete normally without touching the ring, so that a log entry is
    /// not duplicated by an accidental repeat.
    Unchanged,
}

/// Pushes `command_blocks` onto a cyclic service's ring.
///
/// `stored` is ordered newest generation first, which is how block number 0
/// addresses the newest entry (§3.4.3). `command_blocks` follows the block list
/// order, so its first element is the newest of the run.
///
/// Writing more blocks to one cyclic service in a single command than the service
/// owns is `AFh` (§4.5.2, table 4-12: 同時サイクリックライト過多).
pub(super) fn apply_cyclic_write(
    stored: &[Block],
    command_blocks: &[Block],
) -> Result<CyclicWrite, u8> {
    if command_blocks.len() > stored.len() {
        return Err(SF2_CYCLIC_WRITE_OVERFLOW);
    }

    // §3.4.3: consecutive writes to one cyclic service are compared as a single
    // unit, so a multi-block log entry that exactly repeats the previous one is
    // recognised as a repeat rather than appended again.
    if stored[..command_blocks.len()] == *command_blocks {
        return Ok(CyclicWrite::Unchanged);
    }

    let mut updated = Vec::with_capacity(stored.len());
    updated.extend_from_slice(command_blocks);
    updated.extend_from_slice(&stored[..stored.len() - command_blocks.len()]);
    Ok(CyclicWrite::Updated(updated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn purse_block(purse: u32, cashback: u32, user: [u8; 4], execution_id: [u8; 4]) -> Block {
        let mut block = [0u8; BLOCK_SIZE];
        block[PURSE_DATA].copy_from_slice(&purse.to_le_bytes());
        block[CASHBACK_DATA].copy_from_slice(&cashback.to_le_bytes());
        block[8..12].copy_from_slice(&user);
        block[EXECUTION_ID].copy_from_slice(&execution_id);
        block
    }

    fn purse_of(block: &Block) -> u32 {
        u32::from_le_bytes(block[PURSE_DATA].try_into().unwrap())
    }

    fn cashback_of(block: &Block) -> u32 {
        u32::from_le_bytes(block[CASHBACK_DATA].try_into().unwrap())
    }

    /// Table 3-6 pairs each purse attribute with the functions it offers, and
    /// §4.2.1 assigns access mode 001b to cashback alone.
    #[test]
    fn purse_operation_follows_the_attribute_and_access_mode() {
        use ServiceAttribute::*;
        assert_eq!(
            PurseOperation::resolve(PurseDirect, 0b000),
            Ok(PurseOperation::Direct)
        );
        assert_eq!(
            PurseOperation::resolve(PurseDecrement, 0b000),
            Ok(PurseOperation::Decrement)
        );
        assert_eq!(
            PurseOperation::resolve(PurseCashback, 0b000),
            Ok(PurseOperation::Decrement)
        );
        assert_eq!(
            PurseOperation::resolve(PurseCashback, 0b001),
            Ok(PurseOperation::Cashback)
        );

        // Cashback access needs the cashback/decrement attribute.
        assert_eq!(
            PurseOperation::resolve(PurseDirect, 0b001),
            Err(SF2_ACCESS_NOT_PERMITTED)
        );
        assert_eq!(
            PurseOperation::resolve(PurseDecrement, 0b001),
            Err(SF2_ACCESS_NOT_PERMITTED)
        );
    }

    /// §3.4.4: a decrement subtracts from the purse and records what it took in
    /// the cashback data.
    #[test]
    fn decrement_subtracts_and_records_the_cashback_amount() {
        let stored = purse_block(1_000, 0, [0xAA; 4], [0x00; 4]);
        let command = purse_block(120, 0, [0x00; 4], [0x01, 0x02, 0x03, 0x04]);

        let updated = apply_purse_write(&stored, &command, PurseOperation::Decrement, None)
            .expect("a decrement within range succeeds")
            .expect("the block is updated");
        assert_eq!(purse_of(&updated), 880);
        assert_eq!(cashback_of(&updated), 120);
        assert_eq!(&updated[EXECUTION_ID], &[0x01, 0x02, 0x03, 0x04]);
        // D8-D11 are "don't care" in the command block (figure 3-16), so the
        // stored user data survives.
        assert_eq!(&updated[8..12], &[0xAA; 4]);
    }

    /// §4.5.2, table 4-11: 01h is "パースのデクリメント時に計算結果がゼロ未満になります".
    #[test]
    fn decrement_below_zero_is_status_flag_2_01h() {
        let stored = purse_block(100, 0, [0; 4], [0x00; 4]);
        let command = purse_block(101, 0, [0; 4], [0x01; 4]);
        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Decrement, None),
            Err(SF2_PURSE_RESULT_OUT_OF_RANGE)
        );
    }

    /// §3.4.4: a cashback is bounded by the cashback data and clears it.
    #[test]
    fn cashback_adds_back_and_clears_the_cashback_data() {
        let stored = purse_block(880, 120, [0xAA; 4], [0x00; 4]);
        let command = purse_block(120, 0, [0; 4], [0x09; 4]);

        let updated = apply_purse_write(&stored, &command, PurseOperation::Cashback, None)
            .expect("a cashback within the stored amount succeeds")
            .expect("the block is updated");
        assert_eq!(purse_of(&updated), 1_000);
        assert_eq!(cashback_of(&updated), 0);
        assert_eq!(&updated[8..12], &[0xAA; 4]);
    }

    /// Table 4-11: 02h is "パースのキャッシュバック時に、指定されたデータがキャッシュ
    /// バックデータの値を超えています".
    #[test]
    fn cashback_beyond_the_stored_amount_is_status_flag_2_02h() {
        let stored = purse_block(880, 120, [0; 4], [0x00; 4]);
        let command = purse_block(121, 0, [0; 4], [0x09; 4]);
        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Cashback, None),
            Err(SF2_CASHBACK_EXCEEDS_STORED)
        );
    }

    /// Table 4-11: 01h also covers "パースのキャッシュバック時に計算結果が、4 バイトを
    /// 超える数字になります".
    #[test]
    fn cashback_overflowing_four_bytes_is_status_flag_2_01h() {
        let stored = purse_block(u32::MAX - 5, 10, [0; 4], [0x00; 4]);
        let command = purse_block(10, 0, [0; 4], [0x09; 4]);
        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Cashback, None),
            Err(SF2_PURSE_RESULT_OUT_OF_RANGE)
        );
    }

    /// §3.4.4: repeating the stored execution ID completes normally but performs
    /// no arithmetic, so a re-sent fare deduction does not charge twice.
    #[test]
    fn a_repeated_execution_id_suppresses_the_update() {
        let stored = purse_block(880, 120, [0; 4], [0x07; 4]);
        let command = purse_block(120, 0, [0; 4], [0x07; 4]);

        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Decrement, None),
            Ok(None)
        );
        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Cashback, None),
            Ok(None)
        );

        // Table 3-7 marks direct access as "実行 ID ×", so it writes regardless.
        let direct = purse_block(500, 0, [0; 4], [0x07; 4]);
        assert!(
            apply_purse_write(&stored, &direct, PurseOperation::Direct, None)
                .expect("direct access within range succeeds")
                .is_some()
        );
    }

    /// §4.4.6: a direct-access write may not raise the purse data or the cashback
    /// data, which fails the success requirements and so reports A5h.
    #[test]
    fn direct_access_cannot_raise_the_stored_values() {
        let stored = purse_block(500, 20, [0; 4], [0x00; 4]);

        assert_eq!(
            apply_purse_write(
                &stored,
                &purse_block(501, 20, [0; 4], [0x01; 4]),
                PurseOperation::Direct,
                None
            ),
            Err(SF2_ACCESS_NOT_PERMITTED)
        );
        assert_eq!(
            apply_purse_write(
                &stored,
                &purse_block(500, 21, [0; 4], [0x01; 4]),
                PurseOperation::Direct,
                None
            ),
            Err(SF2_ACCESS_NOT_PERMITTED)
        );

        let updated = apply_purse_write(
            &stored,
            &purse_block(400, 10, [0xBB; 4], [0x01; 4]),
            PurseOperation::Direct,
            None,
        )
        .expect("lowering both fields is allowed")
        .expect("the block is updated");
        assert_eq!(purse_of(&updated), 400);
        assert_eq!(cashback_of(&updated), 10);
        // Direct access stores the command block whole, user data included.
        assert_eq!(&updated[8..12], &[0xBB; 4]);
    }

    /// §3.4.4.1: a limit purse treats purse data as two's complement and confines
    /// it to the configured limits; table 4-11 reports a breach as 03h.
    #[test]
    fn limit_purse_bounds_results_by_its_limits_and_reports_03h() {
        let limit = Some(LimitPurseProperty {
            upper_limit: 1_000,
            lower_limit: -200,
            generation_number: 3,
        });
        let stored = purse_block(0, 0, [0; 4], [0x00; 4]);

        // A decrement may run negative, down to the lower limit.
        let command = purse_block(200u32, 0, [0; 4], [0x01; 4]);
        let updated = apply_purse_write(&stored, &command, PurseOperation::Decrement, limit)
            .expect("reaching the lower limit exactly is allowed")
            .expect("the block is updated");
        assert_eq!(
            i32::from_le_bytes(updated[PURSE_DATA].try_into().unwrap()),
            -200
        );

        // One more than the lower limit allows is out of range.
        let command = purse_block(201u32, 0, [0; 4], [0x01; 4]);
        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Decrement, limit),
            Err(SF2_LIMIT_PURSE_OUT_OF_RANGE)
        );

        // A cashback may not carry the purse above the upper limit.
        let stored = purse_block(900, 200, [0; 4], [0x00; 4]);
        let command = purse_block(101, 0, [0; 4], [0x01; 4]);
        assert_eq!(
            apply_purse_write(&stored, &command, PurseOperation::Cashback, limit),
            Err(SF2_LIMIT_PURSE_OUT_OF_RANGE)
        );
        let command = purse_block(100, 0, [0; 4], [0x01; 4]);
        assert!(
            apply_purse_write(&stored, &command, PurseOperation::Cashback, limit)
                .expect("reaching the upper limit exactly is allowed")
                .is_some()
        );
    }

    /// §3.4.3: a write lands on the newest slot and pushes the ring down, so the
    /// oldest generation falls off the end.
    #[test]
    fn cyclic_write_pushes_the_ring_and_drops_the_oldest_generation() {
        let stored = [[0x11; BLOCK_SIZE], [0x22; BLOCK_SIZE], [0x33; BLOCK_SIZE]];
        let command = [[0xAA; BLOCK_SIZE]];

        let CyclicWrite::Updated(updated) =
            apply_cyclic_write(&stored, &command).expect("one block fits")
        else {
            panic!("expected the ring to be updated");
        };
        assert_eq!(
            updated,
            vec![[0xAA; BLOCK_SIZE], [0x11; BLOCK_SIZE], [0x22; BLOCK_SIZE]]
        );
    }

    /// §3.4.3: consecutive blocks written to one cyclic service are compared as a
    /// single unit, and an exact repeat leaves the ring alone.
    #[test]
    fn cyclic_write_treats_a_consecutive_run_as_one_unit() {
        let stored = [
            [0x11; BLOCK_SIZE],
            [0x22; BLOCK_SIZE],
            [0x33; BLOCK_SIZE],
            [0x44; BLOCK_SIZE],
        ];

        // Repeating the two newest generations is recognised as a repeat.
        assert_eq!(
            apply_cyclic_write(&stored, &[[0x11; BLOCK_SIZE], [0x22; BLOCK_SIZE]]),
            Ok(CyclicWrite::Unchanged)
        );
        // Repeating them out of order is a genuinely new entry.
        let CyclicWrite::Updated(updated) =
            apply_cyclic_write(&stored, &[[0x22; BLOCK_SIZE], [0x11; BLOCK_SIZE]])
                .expect("two blocks fit")
        else {
            panic!("expected the ring to be updated");
        };
        assert_eq!(
            updated,
            vec![
                [0x22; BLOCK_SIZE],
                [0x11; BLOCK_SIZE],
                [0x11; BLOCK_SIZE],
                [0x22; BLOCK_SIZE]
            ]
        );
    }

    /// Table 4-12: AFh is 同時サイクリックライト過多 — more simultaneous writes to one
    /// cyclic service than it has blocks.
    #[test]
    fn cyclic_write_longer_than_the_ring_is_status_flag_2_afh() {
        let stored = [[0x11; BLOCK_SIZE], [0x22; BLOCK_SIZE]];
        let command = [[0xAA; BLOCK_SIZE], [0xBB; BLOCK_SIZE], [0xCC; BLOCK_SIZE]];
        assert_eq!(
            apply_cyclic_write(&stored, &command),
            Err(SF2_CYCLIC_WRITE_OVERFLOW)
        );
    }
}
