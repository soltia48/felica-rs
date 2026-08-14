//! Reads the bitrates a FeliCa card advertises and then checks whether the link
//! really works at each of them.
//!
//! Polling with request code `02h` makes the card report its communication
//! performance: which of 212/424 kbps it supports and whether it can detect the
//! reader's bitrate by itself. That is only a claim, so every bitrate is then
//! activated for real and exercised with a run of Request Response commands.
//!
//! Whether the faster link actually came up is read back from the reader
//! (`link=`), not inferred from the timings: a Request Response round trip is
//! only ~20 bytes on the air, so the measured milliseconds are dominated by the
//! USB round trip and barely move between 212 and 424 kbps.
//!
//! The Port-400 negotiates no faster than the RF speed its frontend is set to,
//! and that setting persists in the reader across sessions, so it is printed
//! too: a Type-F frontend left at 212 kbps keeps the link at 212 kbps however
//! much the card advertises.
//!
//! ```bash
//! cargo run --example probe_bitrate
//! cargo run --example probe_bitrate -- 50   # exchanges per bitrate
//! # force the reader's Type-F frontend speed while probing (codes 1: 106,
//! # 2: 212, 3: 424, 4: 848), restored on exit:
//! PROBE_TYPE_F_RF_SPEED=3,3 cargo run --example probe_bitrate
//! ```

use felica::felica_standard::{FelicaStandard, FelicaStandardError};
use felica::{Port100Device, Port400Device, Reader, ReaderPreference, open_reader};
use hex::encode;
use std::error::Error;
use std::time::Instant;

/// Bitrates FeliCa defines, slowest first. A card always powers up at 212 kbps.
const BITRATES: [&str; 2] = ["212F", "424F"];

/// Bits of the communication performance byte a card returns for request
/// code `02h`.
const PERFORMANCE_212F: u8 = 0x01;
const PERFORMANCE_424F: u8 = 0x02;
const PERFORMANCE_AUTO_DETECT: u8 = 0x80;

const REQUEST_CODE_NONE: u8 = 0x00;
const REQUEST_CODE_COMMUNICATION_PERFORMANCE: u8 = 0x02;
const SYSTEM_CODE_ANY: u16 = 0xFFFF;
const TIME_SLOT_1: u8 = 0x00;

const DEFAULT_EXCHANGES: usize = 20;

/// Protocol slots the Port-400 keeps a frontend RF speed for.
const RF_SPEED_PROTOCOLS: [(u8, &str); 3] = [(0, "Type A"), (1, "Type B"), (2, "Type F")];
const TYPE_F_PROTOCOL: u8 = 2;

/// Round trip times of the Request Response run at one bitrate.
struct Timings {
    mode: u8,
    samples: Vec<f64>,
}

impl Timings {
    fn mean(&self) -> f64 {
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }

    fn median(&self) -> f64 {
        self.samples[self.samples.len() / 2]
    }

    fn min(&self) -> f64 {
        self.samples[0]
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let exchanges: usize = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_EXCHANGES)
        .max(1);

    let mut reader = open_reader(ReaderPreference::Auto)?;
    println!("reader: {}", reader.chipset_name());

    let performance = read_communication_performance(&mut reader)?;
    let supported = describe_performance(performance);

    print_rf_speed_settings(&mut reader);
    let restore_rf_speed = apply_type_f_rf_speed_override(&mut reader)?;

    println!();
    println!("bitrate  advertised  result");
    for bitrate in BITRATES {
        let advertised = match performance {
            Some(byte) => yes_no(supports(byte, bitrate)),
            None => "unknown",
        };
        match probe_bitrate(&mut reader, bitrate, exchanges) {
            Ok(timings) => println!(
                "{bitrate:<8} {advertised:<11} ok  link={} mode={:02X} n={} mean={:.3} ms median={:.3} ms min={:.3} ms",
                describe_link(&mut reader),
                timings.mode,
                timings.samples.len(),
                timings.mean(),
                timings.median(),
                timings.min(),
            ),
            Err(err) => println!("{bitrate:<8} {advertised:<11} failed: {err}"),
        }
    }

    if let Some(summary) = supported {
        println!();
        println!("card reports: {summary}");
    }

    if let (Some((rw_to_card, card_to_rw)), Some(device)) =
        (restore_rf_speed, reader.downcast_mut::<Port400Device>())
    {
        match device.set_rf_speed(TYPE_F_PROTOCOL, rw_to_card, card_to_rw) {
            Ok(()) => println!("restored Type-F rf speed to {rw_to_card},{card_to_rw}"),
            Err(err) => println!("restoring Type-F rf speed failed: {err}"),
        }
    }
    reader.close()?;
    Ok(())
}

/// Applies `PROBE_TYPE_F_RF_SPEED` if it is set, returning the setting to restore.
///
/// The reader stores this across sessions, so a probe that changes it has to put
/// the previous value back — the same save and restore the vendor library
/// performs around a fixed-speed session.
fn apply_type_f_rf_speed_override(reader: &mut Reader) -> Result<Option<(u8, u8)>, Box<dyn Error>> {
    let Ok(spec) = std::env::var("PROBE_TYPE_F_RF_SPEED") else {
        return Ok(None);
    };
    let Some(device) = reader.downcast_mut::<Port400Device>() else {
        println!("PROBE_TYPE_F_RF_SPEED needs a Port-400 reader; ignoring it");
        return Ok(None);
    };
    let codes: Vec<u8> = spec.split(',').filter_map(|v| v.parse().ok()).collect();
    let [rw_to_card, card_to_rw] = codes[..] else {
        return Err(format!("PROBE_TYPE_F_RF_SPEED must be two numbers, got {spec:?}").into());
    };
    let previous = device.get_rf_speed(TYPE_F_PROTOCOL)?;
    let restore = match previous[..] {
        [before_rw, before_cr, ..] => Some((before_rw, before_cr)),
        _ => None,
    };
    device.set_rf_speed(TYPE_F_PROTOCOL, rw_to_card, card_to_rw)?;
    println!("set Type-F rf speed to {rw_to_card},{card_to_rw}");
    Ok(restore)
}

/// Speed of the current link, as the reader itself sees it.
///
/// The Port-400 negotiates the speed inside the reader and reports what it
/// settled on, which is what tells a link that really moved to 424 kbps apart
/// from one that fell back to 212 kbps. The Port-100 has no such query because
/// the host drives the RF: the card answered at the speed the RF was set to, or
/// the detection above would have failed, so the configured speed is the answer.
fn describe_link(reader: &mut Reader) -> String {
    if let Some(device) = reader.downcast_mut::<Port400Device>() {
        return match device.card_baudrate() {
            Ok(Some(kbps)) => format!("{kbps}kbps"),
            Ok(None) => "unknown".to_string(),
            Err(err) => format!("unreadable ({err})"),
        };
    }
    if let Some(device) = reader.downcast_mut::<Port100Device>() {
        return match device.initiator_bitrate() {
            Some((send, recv)) if send == recv => format!("{send} (rf)"),
            Some((send, recv)) => format!("{send}/{recv} (rf)"),
            None => "unknown".to_string(),
        };
    }
    "n/a".to_string()
}

/// Prints the frontend RF speeds the reader has stored.
fn print_rf_speed_settings(reader: &mut Reader) {
    let Some(device) = reader.downcast_mut::<Port400Device>() else {
        return;
    };
    println!();
    for (protocol, name) in RF_SPEED_PROTOCOLS {
        match device.get_rf_speed(protocol) {
            Ok(setting) => println!("reader rf speed[{protocol}] ({name}): {}", encode(&setting)),
            Err(err) => println!("reader rf speed[{protocol}] ({name}): {err}"),
        }
    }
}

/// Polls the card at 212 kbps asking for its communication performance.
///
/// Returns the performance bitmap, or `None` when the card answered without the
/// optional request data.
fn read_communication_performance(reader: &mut Reader) -> Result<Option<u8>, FelicaStandardError> {
    let (tag, polling) = FelicaStandard::polling(
        reader.driver_mut(),
        BITRATES[0],
        SYSTEM_CODE_ANY,
        REQUEST_CODE_COMMUNICATION_PERFORMANCE,
        TIME_SLOT_1,
    )?;
    println!("IDm: {}", encode(tag.idm()));
    println!("PMm: {}", encode(tag.pmm()));

    // The request data is two bytes; the second one carries the bitrate bits.
    match polling.optional.as_slice() {
        [_, performance] => {
            println!("communication performance: {}", encode(&polling.optional));
            Ok(Some(*performance))
        }
        [] => {
            println!("communication performance: not reported by this card");
            Ok(None)
        }
        other => {
            println!(
                "communication performance: unexpected request data {}",
                encode(other)
            );
            Ok(None)
        }
    }
}

/// Whether the card claims support for `bitrate`.
///
/// 424 kbps additionally needs the automatic detection bit: the reader raises
/// its speed without telling the card, so a card that cannot detect the incoming
/// bitrate would stop answering. This is the same condition the vendor library
/// applies before switching a FeliCa link up.
fn supports(performance: u8, bitrate: &str) -> bool {
    match bitrate {
        "212F" => performance & PERFORMANCE_212F != 0,
        "424F" => performance & PERFORMANCE_424F != 0 && performance & PERFORMANCE_AUTO_DETECT != 0,
        _ => false,
    }
}

fn describe_performance(performance: Option<u8>) -> Option<String> {
    let performance = performance?;
    let mut parts = Vec::new();
    if performance & PERFORMANCE_212F != 0 {
        parts.push("212 kbps");
    }
    if performance & PERFORMANCE_424F != 0 {
        parts.push("424 kbps");
    }
    if performance & PERFORMANCE_AUTO_DETECT != 0 {
        parts.push("automatic bitrate detection");
    }
    if parts.is_empty() {
        parts.push("no known capability bit");
    }
    Some(format!("{} ({performance:02X})", parts.join(", ")))
}

/// Activates the card at `bitrate` and exchanges Request Response commands to
/// confirm the link carries data, not just the polling frame.
fn probe_bitrate(
    reader: &mut Reader,
    bitrate: &str,
    exchanges: usize,
) -> Result<Timings, FelicaStandardError> {
    let (mut tag, _) = FelicaStandard::polling(
        reader.driver_mut(),
        bitrate,
        SYSTEM_CODE_ANY,
        REQUEST_CODE_NONE,
        TIME_SLOT_1,
    )?;
    let mut samples = Vec::with_capacity(exchanges);
    let mut mode = 0;
    for _ in 0..exchanges {
        let start = Instant::now();
        mode = tag.request_response()?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    Ok(Timings { mode, samples })
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
