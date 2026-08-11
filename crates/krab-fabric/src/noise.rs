//! RFC 4 §4.1's Noise IK handshake over any byte stream.
//!
//! Extracted so every stream transport gets **identical** cryptography. TCP and
//! serial differ in how bytes arrive and in nothing else, and a second copy of
//! a handshake is a second place for the static-key check to be softened.
//!
//! | message | size | contents |
//! |---|---|---|
//! | 1, initiator → responder | 96 B | `e, es, s, ss` |
//! | 2, responder → initiator | 48 B | `e, ee, se` |
//!
//! IK is right because the initiator already knows the responder's static key —
//! that is what the credential is.
//!
//! # The check that must never become a prompt
//!
//! > "Both parties MUST verify that the peer's presented static key matches the
//! > credential. A mismatch is a hard failure, **never a TOFU prompt** — the
//! > credential *is* the trust decision and it was made out of band."
//!
//! RFC 4 §4.1. Every caller passes the expected key as a required argument;
//! there is no variant that omits it, so a caller who does not know who they
//! are talking to cannot express that.

use crate::Error;
use snow::{Builder, TransportState};
use std::io::{Read, Write};

/// RFC 4 §4.1's pattern, with RFC 1 §6.1's primitives.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Generate a Noise static keypair.
///
/// Lives in this crate rather than `krab-crypto` because it is a *link* key —
/// see `Documentation/CRYPTO-BOUNDARIES.md`.
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

/// Verify a presented static against the credential — RFC 4 §4.1.
///
/// Constant-time: the comparison is against a value an attacker may be trying
/// to guess a prefix of.
fn check_peer(presented: Option<&[u8]>, expected: &[u8; 32]) -> Result<(), Error> {
    use subtle::ConstantTimeEq;
    let Some(k) = presented else {
        return Err(Error::Frame);
    };
    if k.len() != 32 || !bool::from(k.ct_eq(expected)) {
        // A hard failure. Never a prompt.
        return Err(Error::Frame);
    }
    Ok(())
}

/// Run the handshake as the initiator.
pub fn handshake_initiator<S: Read + Write>(
    stream: &mut S,
    local_static: &[u8; 32],
    expected_peer: &[u8; 32],
) -> Result<TransportState, Error> {
    let mut hs = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Frame)?)
        .local_private_key(local_static)
        .map_err(|_| Error::Frame)?
        .remote_public_key(expected_peer)
        .map_err(|_| Error::Frame)?
        .build_initiator()
        .map_err(|_| Error::Frame)?;

    let mut buf = [0u8; 1024];
    let n = hs.write_message(&[], &mut buf).map_err(|_| Error::Frame)?;
    crate::frame::write_bytes(stream, &buf[..n])?;

    let msg2 = crate::frame::read_bytes(stream)?.ok_or(Error::Frame)?;
    hs.read_message(&msg2, &mut buf).map_err(|_| Error::Frame)?;

    // IK gives the initiator the responder's static up front, so this confirms
    // the responder proved possession of the expected key rather than merely
    // claiming it.
    check_peer(hs.get_remote_static(), expected_peer)?;
    hs.into_transport_mode().map_err(|_| Error::Frame)
}

/// Run the handshake as the responder.
///
/// The responder's half of the check is the one an implementation is likelier
/// to omit, because by the time it fails the connection already appears to have
/// worked.
pub fn handshake_responder<S: Read + Write>(
    stream: &mut S,
    local_static: &[u8; 32],
    expected_peer: &[u8; 32],
) -> Result<TransportState, Error> {
    let mut hs = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Frame)?)
        .local_private_key(local_static)
        .map_err(|_| Error::Frame)?
        .build_responder()
        .map_err(|_| Error::Frame)?;

    let mut buf = [0u8; 1024];
    let msg1 = crate::frame::read_bytes(stream)?.ok_or(Error::Frame)?;
    hs.read_message(&msg1, &mut buf).map_err(|_| Error::Frame)?;

    // IK carries the initiator's static inside message 1, encrypted, so this
    // is where the responder learns who is calling — and must refuse anyone
    // else.
    check_peer(hs.get_remote_static(), expected_peer)?;

    let n = hs.write_message(&[], &mut buf).map_err(|_| Error::Frame)?;
    crate::frame::write_bytes(stream, &buf[..n])?;
    hs.into_transport_mode().map_err(|_| Error::Frame)
}

/// Respond to whoever calls, provided they are someone we know.
///
/// Returns the static key the caller presented, so the listener can tell which
/// peering the session belongs to.
///
/// # Why this is not a weaker check
///
/// RFC 4 §4.1 forbids trust-on-first-use, and this does not introduce it. The
/// caller's static must appear in `allowed`, which is built from the
/// peer-links on disk — every entry is a peering an operator completed
/// deliberately, out of band. What changes is only *when* the set is narrowed:
/// [`handshake_responder`] is told one key before the call arrives,
/// this one is told every acceptable key and reports which called.
///
/// A node with one socket cannot know who is dialling before they dial, and
/// the alternative — a port per peer — publishes the size of the operator's
/// friend list to a port scanner.
pub fn handshake_responder_any<S: Read + Write>(
    stream: &mut S,
    local_static: &[u8; 32],
    allowed: &[[u8; 32]],
) -> Result<(TransportState, [u8; 32]), Error> {
    let mut hs = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Frame)?)
        .local_private_key(local_static)
        .map_err(|_| Error::Frame)?
        .build_responder()
        .map_err(|_| Error::Frame)?;

    let mut buf = [0u8; 1024];
    let msg1 = crate::frame::read_bytes(stream)?.ok_or(Error::Frame)?;
    hs.read_message(&msg1, &mut buf).map_err(|_| Error::Frame)?;

    // IK puts the initiator's static inside message 1, encrypted to us. This
    // is the first moment anyone could know who called, and it is before a
    // single byte of theirs has been acted on.
    let remote: [u8; 32] = hs
        .get_remote_static()
        .and_then(|r| r.try_into().ok())
        .ok_or(Error::Frame)?;
    // Constant-time is not needed: `allowed` is derived from public keys and
    // the caller already proved possession of the matching private key.
    if !allowed.contains(&remote) {
        // A hard failure, the same as a mismatch in `handshake_responder`.
        // Never a prompt, and indistinguishable from a framing error to the
        // caller — an unknown dialler learns only that it did not work.
        return Err(Error::Frame);
    }

    let n = hs.write_message(&[], &mut buf).map_err(|_| Error::Frame)?;
    crate::frame::write_bytes(stream, &buf[..n])?;
    Ok((hs.into_transport_mode().map_err(|_| Error::Frame)?, remote))
}

/// A `Session` over any byte stream, once the handshake has completed.
pub struct StreamSession<S: Read + Write> {
    stream: S,
    noise: TransportState,
    buf: Vec<u8>,
}

impl<S: Read + Write> StreamSession<S> {
    /// Adopt a completed handshake.
    pub fn new(stream: S, noise: TransportState) -> StreamSession<S> {
        StreamSession {
            stream,
            noise,
            buf: Vec::new(),
        }
    }

    /// The peer's static key, as presented and verified.
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.noise
            .get_remote_static()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
    }
}

impl<S: Read + Write + Send> crate::Session for StreamSession<S> {
    fn send(&mut self, msg: &krab_proto::control::Control) -> Result<(), Error> {
        let plain = msg.write();
        self.buf.resize(plain.len() + 16, 0);
        let n = self
            .noise
            .write_message(&plain, &mut self.buf)
            .map_err(|_| Error::Frame)?;
        crate::frame::write_bytes(&mut self.stream, &self.buf[..n])?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<krab_proto::control::Control>, Error> {
        let Some(ct) = crate::frame::read_bytes(&mut self.stream)? else {
            return Ok(None);
        };
        self.buf.resize(ct.len(), 0);
        let n = self
            .noise
            .read_message(&ct, &mut self.buf)
            .map_err(|_| Error::Frame)?;
        krab_proto::control::Control::parse(&self.buf[..n])
            .map(Some)
            .map_err(|_| Error::Frame)
    }

    fn close(&mut self) -> Result<(), Error> {
        let _ = self.stream.flush();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bidirectional in-memory pipe, so the handshake is testable without a
    /// socket or a serial port.
    struct Pipe {
        rx: std::sync::mpsc::Receiver<u8>,
        tx: std::sync::mpsc::Sender<u8>,
        pending: Vec<u8>,
    }

    fn pipe_pair() -> (Pipe, Pipe) {
        let (a_tx, a_rx) = std::sync::mpsc::channel();
        let (b_tx, b_rx) = std::sync::mpsc::channel();
        (
            Pipe {
                rx: a_rx,
                tx: b_tx,
                pending: Vec::new(),
            },
            Pipe {
                rx: b_rx,
                tx: a_tx,
                pending: Vec::new(),
            },
        )
    }

    impl Read for Pipe {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            for slot in out.iter_mut() {
                if let Some(b) = self.pending.pop() {
                    *slot = b;
                    continue;
                }
                match self.rx.recv() {
                    Ok(b) => *slot = b,
                    Err(_) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                }
            }
            Ok(out.len())
        }
    }

    impl Write for Pipe {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            for b in data {
                self.tx
                    .send(*b)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            }
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// **Transport-independent.** The same handshake runs over anything that
    /// reads and writes bytes, which is what lets serial and TCP share it.
    #[test]
    fn the_handshake_completes_over_any_byte_stream() {
        use crate::Session;
        let (a_sk, a_pk) = generate_static().unwrap();
        let (b_sk, b_pk) = generate_static().unwrap();
        let (mut a_pipe, mut b_pipe) = pipe_pair();

        let responder = std::thread::spawn(move || {
            let noise = handshake_responder(&mut b_pipe, &b_sk, &a_pk).expect("responder");
            let mut s = StreamSession::new(b_pipe, noise);
            let got = s.recv().unwrap();
            s.send(&krab_proto::control::Control::Done).unwrap();
            got
        });

        let noise = handshake_initiator(&mut a_pipe, &a_sk, &b_pk).expect("initiator");
        let mut s = StreamSession::new(a_pipe, noise);
        assert_eq!(
            s.peer_static(),
            Some(b_pk),
            "the verified static is the expected one"
        );
        s.send(&krab_proto::control::Control::Done).unwrap();
        assert!(matches!(
            s.recv().unwrap(),
            Some(krab_proto::control::Control::Done)
        ));
        assert!(matches!(
            responder.join().unwrap(),
            Some(krab_proto::control::Control::Done)
        ));
    }

    /// RFC 4 §4.1's hard failure, on the initiator's side.
    #[test]
    fn an_initiator_refuses_an_unexpected_static() {
        let (a_sk, a_pk) = generate_static().unwrap();
        let (b_sk, _) = generate_static().unwrap();
        let (_, c_pk) = generate_static().unwrap();
        let (mut a_pipe, mut b_pipe) = pipe_pair();

        std::thread::spawn(move || {
            let _ = handshake_responder(&mut b_pipe, &b_sk, &a_pk);
        });
        // Expecting C, talking to B.
        assert!(handshake_initiator(&mut a_pipe, &a_sk, &c_pk).is_err());
    }

    /// And the responder's, which is the one likelier to be omitted.
    #[test]
    fn a_responder_refuses_an_unexpected_initiator() {
        let (a_sk, _) = generate_static().unwrap();
        let (b_sk, b_pk) = generate_static().unwrap();
        let (_, c_pk) = generate_static().unwrap();
        let (mut a_pipe, mut b_pipe) = pipe_pair();

        let responder = std::thread::spawn(move || {
            // Expecting C; A calls.
            handshake_responder(&mut b_pipe, &b_sk, &c_pk).is_err()
        });
        let _ = handshake_initiator(&mut a_pipe, &a_sk, &b_pk);
        assert!(responder.join().unwrap(), "the responder must refuse A");
    }

    /// RFC 4 §4.1's sizes.
    #[test]
    fn the_handshake_is_144_bytes() {
        let (a_sk, _) = generate_static().unwrap();
        let (b_sk, b_pk) = generate_static().unwrap();
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
        let (mut buf, mut scratch) = ([0u8; 1024], [0u8; 1024]);
        let n1 = i.write_message(&[], &mut buf).unwrap();
        r.read_message(&buf[..n1], &mut scratch).unwrap();
        let n2 = r.write_message(&[], &mut buf).unwrap();
        assert_eq!((n1, n2, n1 + n2), (96, 48, 144), "RFC 4 §4.1");
    }
}
