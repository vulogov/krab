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

use crate::frame;
use crate::profile::LinkProfile;
use crate::{Error, Fabric, Session};
use krab_proto::control::Control;
use snow::{Builder, TransportState};
use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;

/// RFC 4 §4.1's pattern, with RFC 1 §6.1's primitives.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Generate a Noise static keypair for RFC 4 §4.1's IK handshake.
///
/// Lives here rather than in `krab-crypto` because it is a *link* key and this
/// crate owns link-layer cryptography — see
/// `Documentation/CRYPTO-BOUNDARIES.md`. Entropy comes from `snow`'s generator,
/// which is the same OS source and is not injectable; the module note above
/// explains why that boundary is not crossed.
pub fn generate_static() -> Result<([u8; 32], [u8; 32]), Error> {
    let params = NOISE_PARAMS.parse().map_err(|_| Error::Frame)?;
    let kp = Builder::new(params)
        .generate_keypair()
        .map_err(|_| Error::Frame)?;
    Ok((
        kp.private.try_into().map_err(|_| Error::Frame)?,
        kp.public.try_into().map_err(|_| Error::Frame)?,
    ))
}

/// An established Noise session over TCP.
pub struct TcpSession {
    stream: TcpStream,
    noise: TransportState,
    /// Scratch for the Noise ciphertext, sized to `frame::MAX_FRAME`.
    buf: Vec<u8>,
}

impl TcpSession {
    /// The peer's static key, as presented and verified during the handshake.
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.noise
            .get_remote_static()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
    }
}

impl Session for TcpSession {
    fn send(&mut self, msg: &Control) -> Result<(), Error> {
        let plain = msg.write();
        self.buf.resize(plain.len() + 16, 0);
        let n = self
            .noise
            .write_message(&plain, &mut self.buf)
            .map_err(|_| Error::Frame)?;
        frame::write_bytes(&mut self.stream, &self.buf[..n])?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Control>, Error> {
        let Some(ct) = frame::read_bytes(&mut self.stream)? else {
            // The peer said nothing more. Distinct from unreachable, and only
            // the first is normal.
            return Ok(None);
        };
        self.buf.resize(ct.len(), 0);
        let n = self
            .noise
            .read_message(&ct, &mut self.buf)
            .map_err(|_| Error::Frame)?;
        Control::parse(&self.buf[..n])
            .map(Some)
            .map_err(|_| Error::Frame)
    }

    fn close(&mut self) -> Result<(), Error> {
        let _ = self.stream.flush();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

/// A TCP link to one peer.
pub struct TcpFabric {
    profile: LinkProfile,
    addr: String,
    /// This node's Noise static private key.
    local_static: [u8; 32],
    /// The peer's expected static public key, **from their credential**.
    ///
    /// Required, not optional. See the module note on why there is no variant
    /// that omits it.
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

    /// Verify the presented static against the credential — RFC 4 §4.1.
    ///
    /// Constant-time, because the comparison is against a value an attacker
    /// may be trying to guess a prefix of.
    fn check_peer(&self, presented: Option<&[u8]>) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        let Some(k) = presented else {
            return Err(Error::Frame);
        };
        if k.len() != 32 || !bool::from(k.ct_eq(&self.expected_peer)) {
            // A hard failure. Never a prompt.
            return Err(Error::Frame);
        }
        Ok(())
    }
}

impl Fabric for TcpFabric {
    fn profile(&self) -> &LinkProfile {
        &self.profile
    }

    fn connect(&self) -> Result<Box<dyn Session>, Error> {
        let mut hs = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Frame)?)
            .local_private_key(&self.local_static)
            .map_err(|_| Error::Frame)?
            .remote_public_key(&self.expected_peer)
            .map_err(|_| Error::Frame)?
            .build_initiator()
            .map_err(|_| Error::Frame)?;

        let mut stream = TcpStream::connect(&self.addr)?;
        let mut buf = vec![0u8; 1024];

        // Message 1: e, es, s, ss.
        let n = hs.write_message(&[], &mut buf).map_err(|_| Error::Frame)?;
        frame::write_bytes(&mut stream, &buf[..n])?;

        // Message 2: e, ee, se.
        let msg2 = frame::read_bytes(&mut stream)?.ok_or(Error::Frame)?;
        hs.read_message(&msg2, &mut buf).map_err(|_| Error::Frame)?;

        // IK gives the initiator the responder's static up front, so this
        // confirms the responder proved possession of the key we expected
        // rather than merely claiming it.
        self.check_peer(hs.get_remote_static())?;

        let noise = hs.into_transport_mode().map_err(|_| Error::Frame)?;
        Ok(Box::new(TcpSession { stream, noise, buf }))
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

        let mut hs = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Frame)?)
            .local_private_key(&self.local_static)
            .map_err(|_| Error::Frame)?
            .build_responder()
            .map_err(|_| Error::Frame)?;

        let mut buf = vec![0u8; 1024];
        let msg1 = frame::read_bytes(&mut stream)?.ok_or(Error::Frame)?;
        hs.read_message(&msg1, &mut buf).map_err(|_| Error::Frame)?;

        // **The responder's check.** IK transmits the initiator's static inside
        // message 1, encrypted — so this is where the responder learns who is
        // calling, and it must refuse anyone else. RFC 4 §4.1 requires *both*
        // parties to verify, and the responder's half is the one an
        // implementation is likelier to omit, because the connection already
        // "worked".
        self.check_peer(hs.get_remote_static())?;

        let n = hs.write_message(&[], &mut buf).map_err(|_| Error::Frame)?;
        frame::write_bytes(&mut stream, &buf[..n])?;

        let noise = hs.into_transport_mode().map_err(|_| Error::Frame)?;
        Ok(Some(Box::new(TcpSession { stream, noise, buf })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_proto::control::Control;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let b = Builder::new(NOISE_PARAMS.parse().unwrap());
        let kp = b.generate_keypair().unwrap();
        let _ = seed;
        (
            kp.private.try_into().unwrap(),
            kp.public.try_into().unwrap(),
        )
    }

    /// A handshake, in both directions, with real sockets.
    #[test]
    fn a_session_establishes_and_carries_control_messages() {
        let (a_sk, a_pk) = keypair(1);
        let (b_sk, b_pk) = keypair(2);

        let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, a_pk);
        let port = responder.listen("127.0.0.1:0").unwrap();

        let initiator = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, b_pk);

        let handle = std::thread::spawn(move || {
            for _ in 0..200 {
                if let Some(mut s) = responder.accept().unwrap() {
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
        let echoed = client.recv().unwrap();
        assert!(matches!(echoed, Some(Control::Done)));
        assert!(matches!(handle.join().unwrap(), Some(Control::Done)));
    }

    /// **RFC 4 §4.1's hard failure.** An initiator that expects a different
    /// static key must refuse, and there is no path that prompts instead.
    #[test]
    fn an_initiator_refuses_a_peer_whose_static_does_not_match() {
        let (a_sk, a_pk) = keypair(1);
        let (b_sk, _b_pk) = keypair(2);
        let (_c_sk, c_pk) = keypair(3);

        let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, a_pk);
        let port = responder.listen("127.0.0.1:0").unwrap();
        std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = responder.accept();
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        // Expecting C's key, talking to B.
        let wrong = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, c_pk);
        assert!(
            wrong.connect().is_err(),
            "a mismatched static must be a hard failure"
        );
    }

    /// **The responder's half**, which is the one likelier to be omitted
    /// because the connection already appears to have worked.
    #[test]
    fn a_responder_refuses_an_unexpected_initiator() {
        let (a_sk, _a_pk) = keypair(1);
        let (b_sk, b_pk) = keypair(2);
        let (_c_sk, c_pk) = keypair(3);

        // The responder expects C; A calls.
        let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, c_pk);
        let port = responder.listen("127.0.0.1:0").unwrap();

        let handle = std::thread::spawn(move || {
            for _ in 0..200 {
                match responder.accept() {
                    Ok(Some(_)) => return Ok(()),
                    Err(_) => return Err(()),
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
            Err(())
        });

        let initiator = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, b_pk);
        let _ = initiator.connect();
        assert!(
            handle.join().unwrap().is_err(),
            "the responder must refuse A"
        );
    }

    /// RFC 4 §4.1's sizes: 96 B then 48 B, 144 B total.
    #[test]
    fn the_handshake_is_the_size_rfc4_says() {
        let (a_sk, _) = keypair(1);
        let (b_sk, b_pk) = keypair(2);

        let mut i = Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(&a_sk)
            .unwrap()
            .remote_public_key(&b_pk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut r = Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(&b_sk)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut buf = [0u8; 1024];
        let n1 = i.write_message(&[], &mut buf).unwrap();
        assert_eq!(n1, 96, "message 1: e, es, s, ss");
        let mut scratch = [0u8; 1024];
        r.read_message(&buf[..n1], &mut scratch).unwrap();
        let n2 = r.write_message(&[], &mut buf).unwrap();
        assert_eq!(n2, 48, "message 2: e, ee, se");
        assert_eq!(n1 + n2, 144, "RFC 4 §4.1 — 1-RTT, mutual auth");
    }

    /// A link to nowhere fails rather than hanging or panicking.
    #[test]
    fn an_unreachable_peer_is_an_error() {
        let (a_sk, _) = keypair(1);
        let (_, b_pk) = keypair(2);
        // Port 1 on loopback: reserved, and nothing is listening.
        let f = TcpFabric::new(LinkProfile::tcp(), "127.0.0.1:1", a_sk, b_pk);
        assert!(f.connect().is_err());
    }

    /// `accept` on a fabric that never listened is not an error — it is the
    /// normal state of an outbound-only link.
    #[test]
    fn accept_without_listening_yields_nothing() {
        let (a_sk, _) = keypair(1);
        let (_, b_pk) = keypair(2);
        let f = TcpFabric::new(LinkProfile::tcp(), "127.0.0.1:1", a_sk, b_pk);
        assert!(f.accept().unwrap().is_none());
    }
}
