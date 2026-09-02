//! TCP backend: Noise IK over a length-delimited byte stream — RFC 4 §4.1.
//!
//! | message | size | contents |
//! |---|---|---|
//! | 1, initiator → responder | 96 B | `e, es, s, ss` |
//! | 2, responder → initiator | 48 B | `e, ee, se` |
//! | **total** | **144 B** | 1-RTT, mutual auth, initiator hidden from a passive observer |
//!
//! IK is the right pattern because **the initiator already knows the
//! responder's static key — that is what the credential is.** There is no
//! discovery step, no certificate, and no second identity system.
//!
//! # The check that must never become a prompt
//!
//! > "Both parties MUST verify that the peer's presented static key matches
//! > the credential. A mismatch is a hard failure, **never a TOFU prompt** —
//! > the credential *is* the trust decision and it was made out of band."
//!
//! RFC 4 §4.1. This is the requirement most likely to be softened later,
//! because a mismatch looks like a bug to a user and "trust this key?" looks
//! like a fix. It is not: the fingerprint comparison at RFC 3 §11 step 2 is the
//! only thing that ever established who the peer is, and a prompt at connect
//! time asks someone to redo that decision with none of the information.
//!
//! [`TcpFabric::connect`] therefore takes the expected static key as a
//! **required constructor argument**, and there is no variant that omits it.
//! A caller who does not know who they are connecting to cannot express that.
//!
//! The handshake itself lives in [`crate::noise`], shared with every other
//! stream transport so there is one copy of the static-key check rather than
//! one per carrier.
//!
//! # Entropy is not an argument here, and that is a real difference
//!
//! `krab-crypto` takes randomness as a parameter so every key derivation is
//! reproducible under test and the OS is named in exactly one file. Noise
//! draws its ephemeral inside `write_message`, so that posture does not carry
//! across this boundary: `snow` reaches for `getrandom` directly.
//!
//! It is stated rather than worked around. A custom `snow` resolver could
//! inject an RNG, but it would mean reimplementing the resolver's primitive
//! selection to change one thing — and a bespoke crypto resolver is a larger
//! risk than a second entropy call site.
//!
//! The consequence: a handshake is not replayable from a seed, so the
//! handshake tests use real sockets rather than fixed vectors. The *sizes* are
//! pinned instead, which is what RFC 4 §4.1 actually specifies.
//!
//! # Sessions are held open
//!
//! RFC 4 §4.1: at 144 bytes and SF10's 0.83 B/s, a handshake is roughly three
//! minutes of LoRa airtime. Constrained links "MUST hold sessions open across
//! reconciliation cycles rather than reconnecting". Nothing here closes a
//! session on idle.

pub use crate::noise::{generate_static, NOISE_PARAMS};

use crate::backend::listener;
use crate::noise::{handshake_initiator, handshake_responder, StreamSession};
use crate::profile::LinkProfile;
use crate::{Error, Fabric, Session};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;

/// A TCP link to one peer.
pub struct TcpFabric {
    profile: LinkProfile,
    addr: String,
    /// This node's Noise static private key.
    local_static: [u8; 32],
    /// The peer's expected static public key, **from their credential**.
    ///
    /// Required, not optional — RFC 4 §4.1 makes a mismatch a hard failure and
    /// never a TOFU prompt, so a caller who does not know who they are
    /// connecting to cannot express that.
    expected_peer: [u8; 32],
    listener: Mutex<Option<TcpListener>>,
}

impl TcpFabric {
    /// A link toward `addr`, expecting `expected_peer`'s static key.
    pub fn new(
        profile: LinkProfile,
        addr: impl Into<String>,
        local_static: [u8; 32],
        expected_peer: [u8; 32],
    ) -> TcpFabric {
        TcpFabric {
            profile,
            addr: addr.into(),
            local_static,
            expected_peer,
            listener: Mutex::new(None),
        }
    }

    /// Listen for inbound sessions on `addr`.
    pub fn listen(&self, addr: impl ToSocketAddrs) -> Result<u16, Error> {
        let l = TcpListener::bind(addr)?;
        let port = l.local_addr()?.port();
        l.set_nonblocking(true)?;
        *self.listener.lock().map_err(|_| Error::Frame)? = Some(l);
        Ok(port)
    }
}

impl Fabric for TcpFabric {
    fn profile(&self) -> &LinkProfile {
        &self.profile
    }

    /// Dial, handshake, and hand back a session.
    ///
    /// # Every step has a deadline, and none of them did
    ///
    /// `TcpStream::connect` blocks for the operating system's connect
    /// timeout — on Linux about two minutes — and the handshake that follows
    /// had no read timeout at all, so a socket that accepts and says nothing
    /// blocked here indefinitely. **This runs on the interface thread**:
    /// `connect <peer> tcp <addr>` is typed at the command line, and while it
    /// blocks, `event::poll` is not being called. Nothing reaches the key
    /// handler — including `Binding::Lock` and `Binding::PanicWipe`, which had
    /// just been made to fire on one press and could not be pressed at all.
    ///
    /// It needs no credential either: the block is inside
    /// `handshake_initiator`, before `check_peer` has anything to check.
    ///
    /// Every sibling path in this crate already did this — `bootstrap_connect`,
    /// `Listener::accept`, the serial backend — which is what made the gap
    /// hard to see by reading.
    fn connect(&self) -> Result<Box<dyn Session>, Error> {
        // `connect_timeout` needs a resolved address; `connect` does its own
        // resolution. Resolving first also bounds the DNS step, which is the
        // other half of "the operator typed a hostname and the interface
        // stopped".
        let addr = self
            .addr
            .to_socket_addrs()?
            .next()
            .ok_or(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
        let mut stream = TcpStream::connect_timeout(
            &addr,
            std::time::Duration::from_secs(listener::CONNECT_TIMEOUT_S),
        )?;
        listener::arm_handshake(&stream)?;
        let noise = handshake_initiator(
            &mut stream,
            &self.local_static,
            &self.expected_peer,
            std::time::Duration::from_secs(listener::HANDSHAKE_TOTAL_S),
        )?;
        listener::arm_session_for(&stream, self.profile.session_timeout())?;
        Ok(Box::new(StreamSession::new(stream, noise)))
    }

    fn accept(&self) -> Result<Option<Box<dyn Session>>, Error> {
        let guard = self.listener.lock().map_err(|_| Error::Frame)?;
        let Some(listener) = guard.as_ref() else {
            return Ok(None);
        };
        let mut stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        listener::arm_handshake(&stream)?;
        let noise = handshake_responder(
            &mut stream,
            &self.local_static,
            &self.expected_peer,
            std::time::Duration::from_secs(listener::HANDSHAKE_TOTAL_S),
        )?;
        listener::arm_session_for(&stream, self.profile.session_timeout())?;
        Ok(Some(Box::new(StreamSession::new(stream, noise))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_proto::control::Control;

    // The handshake itself, its sizes, and both halves of RFC 4 §4.1's
    // static-key check are tested in `crate::noise`, which every stream
    // transport shares. What is TCP-specific is sockets: listening, accepting,
    // and an address that is not there.

    /// A session over real sockets, both directions.
    #[test]
    fn a_session_establishes_and_carries_control_messages() {
        let (a_sk, a_pk) = generate_static().unwrap();
        let (b_sk, b_pk) = generate_static().unwrap();

        let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, a_pk);
        let port = responder.listen("127.0.0.1:0").unwrap();
        let initiator = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, b_pk);

        let handle = std::thread::spawn(move || {
            for _ in 0..300 {
                if let Ok(Some(mut s)) = responder.accept() {
                    let got = s.recv().unwrap();
                    s.send(&Control::Done).unwrap();
                    return got;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            None
        });

        let mut client = initiator.connect().expect("handshake completes");
        client.send(&Control::Done).unwrap();
        assert!(matches!(client.recv().unwrap(), Some(Control::Done)));
        assert!(matches!(handle.join().unwrap(), Some(Control::Done)));
    }

    /// A link to nowhere fails rather than hanging — I-4 forbids assuming
    /// reachability, so this must be an ordinary error.
    #[test]
    fn an_unreachable_peer_is_an_error() {
        let (a_sk, _) = generate_static().unwrap();
        let (_, b_pk) = generate_static().unwrap();
        // Port 1 on loopback: reserved, nothing listening.
        let f = TcpFabric::new(LinkProfile::tcp(), "127.0.0.1:1", a_sk, b_pk);
        assert!(f.connect().is_err());
    }

    /// `accept` on a fabric that never listened is not an error — it is the
    /// normal state of an outbound-only link.
    #[test]
    fn accept_without_listening_yields_nothing() {
        let (a_sk, _) = generate_static().unwrap();
        let (_, b_pk) = generate_static().unwrap();
        let f = TcpFabric::new(LinkProfile::tcp(), "127.0.0.1:1", a_sk, b_pk);
        assert!(f.accept().unwrap().is_none());
    }
}
