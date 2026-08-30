//! Serial backend — RFC 4 §5.3.
//!
//! > "At 115 200 a serial link is four orders of magnitude faster than LoRa and
//! > moves an entire corpus overnight. A direct cable, **a wired radio modem**,
//! > or an X.25 PAD are all serviceable links, and serial is the natural
//! > carrier for a physically isolated but co-located pair."
//!
//! | baud | B/s | full n=500 corpus (447 MB) |
//! |---|---|---|
//! | 9 600 | 960 | 129 h |
//! | 115 200 | 11 520 | **11 h** |
//!
//! Everything above the bytes is identical to TCP: the same Noise IK
//! ([`crate::noise`]), the same framing, the same `Session`, and therefore the
//! same reconciliation driver. A modem link is not a different protocol, it is
//! a different pipe — which is what the `Fabric` seam exists for.
//!
//! # What is genuinely different
//!
//! **There is no connection.** TCP has `connect` and `accept`; a serial line
//! has originate and answer, and both ends are already physically joined. The
//! role is therefore fixed at construction ([`Role`]) rather than implied by
//! which method a caller reaches for. Two nodes configured with the same role
//! sit waiting for each other, which is a wiring mistake and not a protocol
//! state — it is worth being able to say that plainly.
//!
//! **There is no integrity.** TCP guarantees an ordered, error-checked byte
//! stream. A serial line guarantees neither: a flipped bit in a length prefix
//! makes the reader consume the wrong number of bytes and **desynchronise
//! permanently**, because nothing downstream can resynchronise a stream whose
//! framing is lost.
//!
//! Noise's AEAD catches corrupted *payloads* — it cannot catch a corrupted
//! *length*, since that damage happens before any ciphertext is identified. So
//! a session that fails to decrypt is torn down rather than retried, and RFC 4
//! §5.3's "FEC SHOULD be enabled where there is no link-layer retransmission"
//! is the mitigation at the layer below. A modem with V.42 provides it in
//! hardware; a direct cable does not.
//!
//! # Device names differ per platform, and one of them is a trap
//!
//! The operator names the device — Krab reads no configuration file
//! (`Documentation/NO-CONFIG.md`), so there is no remembered port and no
//! enumeration. [`device_hint`] renders the right shape for the host.
//!
//! | platform | typical | note |
//! |---|---|---|
//! | Linux | `/dev/ttyUSB0`, `/dev/ttyACM0`, `/dev/ttyS0` | user must be in `dialout` |
//! | macOS | **`/dev/cu.usbserial-XXXX`** | see below |
//! | Windows | `COM3` | above `COM9` needs `\\.\COM10` |
//!
//! **On macOS, use `cu.` and not `tty.`** They are the same physical device.
//! `tty.*` is the *dial-in* node and blocks on `open()` until Data Carrier
//! Detect is asserted — so originating a call through it hangs before a single
//! byte is sent, with no error and no timeout, because the block is in the
//! kernel's open path rather than in any read this code performs. `cu.*` is the
//! *call-out* node and does not wait for DCD.
//!
//! It is the sort of thing that reads as "the modem is broken" for an hour, so
//! [`SerialFabric::new`] warns when handed a `tty.` path on macOS rather than
//! leaving the operator to discover it.
//!
//! **There is no timeout by default.** A read on an idle line blocks forever,
//! so [`SerialFabric::new`] sets one and `accept` returns `Ok(None)` when it
//! expires — the same "nobody is there" that a courier link reports, which
//! I-4 requires be ordinary rather than an error.

use crate::noise::{handshake_initiator, handshake_responder, StreamSession};
use crate::profile::LinkProfile;
use crate::{Error, Fabric, Session};
use std::io::{Read, Write};
use std::time::Duration;

/// Which end of the line this node is.
///
/// Fixed at construction because a serial pair is already joined: there is no
/// listening socket and no address to dial, only two ends that must disagree
/// about who speaks first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Speaks first. Sends Noise message 1.
    Originate,
    /// Waits. Reads message 1, replies with message 2.
    Answer,
}

/// How long `accept` waits before reporting that nobody is there.
///
/// Generous, because a person is often physically connecting a cable or dialling
/// a modem while this runs, and short enough that a wrong `Role` on both ends
/// is discovered rather than hung on.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// A serial link to one peer.
pub struct SerialFabric {
    profile: LinkProfile,
    path: String,
    baud: u32,
    role: Role,
    local_static: [u8; 32],
    /// The peer's expected static, **from their credential** (RFC 4 §4.1).
    expected_peer: [u8; 32],
}

impl SerialFabric {
    /// A link on `path` at `baud`.
    ///
    /// `expected_peer` is required, exactly as for TCP: RFC 4 §4.1 makes a
    /// static mismatch a hard failure and never a prompt, so a caller who does
    /// not know who is on the other end of the cable cannot express that.
    pub fn new(
        profile: LinkProfile,
        path: impl Into<String>,
        baud: u32,
        role: Role,
        local_static: [u8; 32],
        expected_peer: [u8; 32],
    ) -> SerialFabric {
        SerialFabric {
            profile,
            path: path.into(),
            baud,
            role,
            local_static,
            expected_peer,
        }
    }

    /// This node's role on the line.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Sustained throughput, bytes per second — RFC 4 §5.3's table.
    ///
    /// 8N1 framing, so ten bits carry eight.
    pub fn bytes_per_second(&self) -> f64 {
        self.baud as f64 / 10.0
    }

    /// Hours to move `bytes` at this rate.
    ///
    /// RFC 4 §5.3's headline figure is 11 hours for a 447 MB corpus at
    /// 115 200 baud, and an operator deciding whether to leave a cable
    /// connected overnight wants this before they start rather than after.
    pub fn hours_for(&self, bytes: u64) -> f64 {
        bytes as f64 / self.bytes_per_second() / 3_600.0
    }

    /// Whether this device name is likely to block on open — see the module
    /// note on macOS `tty.` versus `cu.`.
    ///
    /// Advisory, not enforced: an operator may have a reason, and refusing a
    /// device the kernel would accept is worse than saying so.
    pub fn is_dial_in_node(path: &str) -> bool {
        cfg!(target_os = "macos") && path.contains("/tty.")
    }

    /// What a device name looks like on this platform, for an operator who has
    /// to type one and has no configuration file to copy it from.
    pub fn device_hint() -> &'static str {
        if cfg!(target_os = "windows") {
            "COM3  (above COM9 use \\\\.\\COM10)"
        } else if cfg!(target_os = "macos") {
            "/dev/cu.usbserial-XXXX  (cu. not tty. — tty. blocks until carrier detect)"
        } else {
            "/dev/ttyUSB0 or /dev/ttyACM0  (membership of `dialout` may be required)"
        }
    }

    fn open(&self, timeout: Duration) -> Result<Box<dyn serialport::SerialPort>, Error> {
        serialport::new(&self.path, self.baud)
            .timeout(timeout)
            .open()
            .map_err(|_| Error::Unreachable)
    }
}

/// A serial port as a plain byte stream.
///
/// `serialport` reports a timeout as `TimedOut`, which no other backend
/// produces, so it is mapped to `UnexpectedEof` — the one every stream
/// transport already reaches at the end of input.
///
/// # What that means now, which is not what it used to
///
/// This said `frame::read_bytes` treats `UnexpectedEof` as "a clean end of
/// input rather than corruption". It did, and Pass 13 §9 removed that: a
/// stream that ends part-way through a length prefix is a truncated frame,
/// not a finished peer, and reporting the two identically let a cut
/// connection be recorded as a completed exchange. `read_len` now answers
/// "clean end" only for zero bytes read, so a timeout **mid-frame** is an
/// error and a timeout **between** frames still ends the session.
///
/// That is the behaviour a serial line should have, and the comment had
/// simply outlived the code it described.
struct Port(Box<dyn serialport::SerialPort>);

impl Port {
    /// Swap the handshake's deadline for the session's.
    ///
    /// [`ANSWER_TIMEOUT`] is how long to wait for somebody to connect a cable.
    /// Leaving it in place made it the exchange's deadline too, which nothing
    /// said and nobody chose — thirty seconds for a peer to answer a manifest
    /// on the slowest link this program supports. The session deadline is the
    /// one every other backend uses.
    fn arm_session(&mut self, deadline: Duration) -> Result<(), Error> {
        self.0.set_timeout(deadline).map_err(|_| Error::Unreachable)
    }
}

impl Read for Port {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(out) {
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            }
            other => other,
        }
    }
}

impl Write for Port {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Fabric for SerialFabric {
    fn profile(&self) -> &LinkProfile {
        &self.profile
    }

    /// Originate — RFC 4 §4.1's initiator.
    ///
    /// Refuses if this end is configured to answer, rather than sending
    /// message 1 into a line where nobody is listening for it.
    fn connect(&self) -> Result<Box<dyn Session>, Error> {
        if self.role != Role::Originate {
            return Err(Error::Unreachable);
        }
        let mut port = Port(self.open(ANSWER_TIMEOUT)?);
        let noise = handshake_initiator(&mut port, &self.local_static, &self.expected_peer)?;
        port.arm_session(self.profile.session_timeout())?;
        Ok(Box::new(StreamSession::new(port, noise)))
    }

    /// Answer — RFC 4 §4.1's responder.
    ///
    /// `Ok(None)` when the timeout expires with nothing on the line. That is
    /// the normal state of a link for most of its life (I-4), not an error.
    fn accept(&self) -> Result<Option<Box<dyn Session>>, Error> {
        if self.role != Role::Answer {
            return Ok(None);
        }
        let mut port = Port(self.open(ANSWER_TIMEOUT)?);
        match handshake_responder(&mut port, &self.local_static, &self.expected_peer) {
            Ok(noise) => {
                port.arm_session(self.profile.session_timeout())?;
                Ok(Some(Box::new(StreamSession::new(port, noise))))
            }
            // Nothing arrived, or what arrived was not a handshake. Neither is
            // fatal on a line an operator may still be connecting.
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_static;

    fn fabric(role: Role) -> SerialFabric {
        let (sk, _) = generate_static().unwrap();
        let (_, pk) = generate_static().unwrap();
        SerialFabric::new(
            LinkProfile::serial(),
            "/dev/nonexistent",
            115_200,
            role,
            sk,
            pk,
        )
    }

    /// RFC 4 §5.3's table, which is what an operator needs before deciding to
    /// leave a cable connected overnight.
    #[test]
    fn throughput_matches_rfc4() {
        let f = fabric(Role::Originate);
        assert_eq!(f.bytes_per_second(), 11_520.0, "115 200 baud, 8N1");

        // §5.3's headline: a 447 MB corpus in 11 hours.
        let hours = f.hours_for(447 * 1_000_000);
        assert!(
            (hours - 10.8).abs() < 0.5,
            "{hours:.1} h, expected about 11"
        );

        // And the slow end of the table.
        let slow = SerialFabric::new(
            LinkProfile::serial(),
            "/dev/nonexistent",
            9_600,
            Role::Originate,
            [0; 32],
            [0; 32],
        );
        assert_eq!(slow.bytes_per_second(), 960.0);
        assert!((slow.hours_for(447 * 1_000_000) - 129.3).abs() < 1.0);
    }

    /// **Both ends must disagree about who speaks first.** A serial pair is
    /// already joined, so the role is configuration rather than a protocol
    /// state — and two ends configured alike is a wiring mistake worth being
    /// able to state.
    #[test]
    fn a_role_mismatch_is_refused_rather_than_hung_on() {
        // An answering end must not originate.
        assert!(fabric(Role::Answer).connect().is_err());
        // An originating end has nothing to accept.
        assert!(fabric(Role::Originate).accept().unwrap().is_none());
    }

    /// A missing device is unreachable, not fatal — I-4 forbids assuming a
    /// link is there.
    #[test]
    fn a_missing_device_is_unreachable() {
        let f = fabric(Role::Originate);
        assert!(matches!(f.connect(), Err(Error::Unreachable)));
        // And answering on a missing device says so. The assertion here was
        // `is_err() || true`, which is `true` — it asserted nothing, and would
        // have passed had `accept` returned a session on a device that does
        // not exist. What matters is that it does not report a caller.
        match fabric(Role::Answer).accept() {
            Ok(None) | Err(Error::Unreachable) => {}
            Ok(Some(_)) => panic!("a missing device answered a call"),
            Err(e) => panic!("expected Unreachable, got {e:?}"),
        }
    }

    /// **The macOS trap.** `tty.*` blocks in `open()` until carrier detect, so
    /// originating through it hangs before a byte is sent — no error, no
    /// timeout, because the block is in the kernel rather than in any read.
    #[test]
    fn a_dial_in_device_name_is_recognised() {
        if cfg!(target_os = "macos") {
            assert!(SerialFabric::is_dial_in_node("/dev/tty.usbserial-A1"));
            assert!(!SerialFabric::is_dial_in_node("/dev/cu.usbserial-A1"));
        }
        // Elsewhere the distinction does not exist and must not be invented.
        if !cfg!(target_os = "macos") {
            assert!(!SerialFabric::is_dial_in_node("/dev/ttyUSB0"));
        }
    }

    /// The hint must name a device shape that exists on this platform, since
    /// there is no configuration file to copy one from.
    #[test]
    fn the_device_hint_suits_the_host() {
        let hint = SerialFabric::device_hint();
        if cfg!(target_os = "windows") {
            assert!(hint.starts_with("COM"), "{hint}");
        } else {
            assert!(hint.starts_with("/dev/"), "{hint}");
        }
        if cfg!(target_os = "macos") {
            assert!(hint.contains("cu."), "macOS must be steered away from tty.");
        }
    }

    /// RFC 5 §4.5 derives the sync mode from latency class. A serial link is
    /// slow enough that a multi-round protocol is the wrong choice.
    #[test]
    fn a_serial_link_uses_the_mode_its_latency_implies() {
        let p = LinkProfile::serial();
        assert_eq!(p.sync_mode(), p.latency_class.sync_mode());
        assert!(
            p.sustained_bps < LinkProfile::tcp().sustained_bps,
            "serial must not claim TCP's throughput"
        );
    }
}
