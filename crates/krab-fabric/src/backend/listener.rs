//! One socket, every peer.
//!
//! # Why one socket and not one per peer
//!
//! A port per peer publishes the size of the operator's friend list to anyone
//! who runs a port scan, and it grows the attack surface with the social
//! graph. One socket discloses that a node exists, which is unavoidable for
//! anything that accepts calls at all.
//!
//! The responder cannot be told who is dialling before they dial, so it is
//! given the set of peers it will accept and reports which one arrived — see
//! [`crate::noise::handshake_responder_any`]. That is not trust-on-first-use:
//! every key in the set comes from a peer-link an operator established out of
//! band, and RFC 4 §4.1's prohibition is on *prompting*, not on holding more
//! than one acceptable key.
//!
//! # Why the set is shared and mutable
//!
//! A peering completed while the listener is running must be accepted without
//! a restart, and a peering removed must stop being accepted immediately. The
//! set lives behind a lock the accept loop takes once per call.

use crate::noise::{handshake_responder_any, StreamSession};
use crate::{Error, Session};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

/// Statics this listener will accept, updatable while it runs.
#[derive(Clone, Default)]
pub struct Allowed(Arc<Mutex<Vec<[u8; 32]>>>);

impl Allowed {
    /// The set a listener starts with.
    pub fn new(keys: Vec<[u8; 32]>) -> Allowed {
        Allowed(Arc::new(Mutex::new(keys)))
    }

    /// Replace the set. Called when the peerings on disk change.
    pub fn set(&self, keys: Vec<[u8; 32]>) {
        if let Ok(mut g) = self.0.lock() {
            *g = keys;
        }
    }

    fn snapshot(&self) -> Vec<[u8; 32]> {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// A bound socket accepting calls from any known peer.
pub struct Listener {
    inner: TcpListener,
    local_static: [u8; 32],
    allowed: Allowed,
}

impl Listener {
    /// Bind, and report the port actually taken — which matters when the
    /// operator asked for port 0.
    pub fn bind(
        addr: impl ToSocketAddrs,
        local_static: [u8; 32],
        allowed: Allowed,
    ) -> Result<(Listener, u16), Error> {
        let inner = TcpListener::bind(addr)?;
        let port = inner.local_addr()?.port();
        // Non-blocking, so a caller can poll on its own schedule and stop when
        // asked. A blocking accept on a background thread cannot be told to
        // stop without connecting to it.
        inner.set_nonblocking(true)?;
        Ok((
            Listener {
                inner,
                local_static,
                allowed,
            },
            port,
        ))
    }

    /// Take one call, if one is waiting.
    ///
    /// `Ok(None)` means nobody called — the normal case, not an error.
    /// A caller that fails the handshake is dropped and also reported as
    /// `Ok(None)`: an unknown dialler is not an event the operator needs, and
    /// making it one would let anyone fill the activity log from outside.
    pub fn accept(&self) -> Result<Option<Accepted>, Error> {
        let mut stream = match self.inner.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        // The handshake blocks; the listen socket does not. Without this the
        // first read returns WouldBlock and the handshake fails against a
        // peer that is doing nothing wrong.
        stream.set_nonblocking(false)?;
        // And it must not block forever: a caller that opens a connection and
        // says nothing would otherwise hold the accept loop for good, which is
        // a denial of service costing the attacker one socket.
        let t = Some(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_S));
        stream.set_read_timeout(t)?;
        stream.set_write_timeout(t)?;

        let allowed = self.allowed.snapshot();
        match handshake_responder_any(&mut stream, &self.local_static, &allowed) {
            Ok((noise, peer)) => {
                // Clear the timeouts: a session is long-lived and legitimately
                // silent between reconciliations.
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                Ok(Some((Box::new(StreamSession::new(stream, noise)), peer)))
            }
            Err(_) => Ok(None),
        }
    }
}

/// Open a first-contact session to `addr` — RFC 3 §11 over a live link.
///
/// **Unauthenticated by construction.** There is no peer-link yet, so there is
/// no static key to check against; see [`crate::noise::NOISE_PARAMS_XX`] for
/// why that is the ceremony's shape rather than a gap in it. The static the
/// far end presented is returned so the caller can bind it to the card that
/// arrives inside.
pub fn bootstrap_connect(addr: &str, local_static: [u8; 32]) -> Result<Accepted, Error> {
    let mut stream = TcpStream::connect(addr)?;
    let t = Some(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_S));
    stream.set_read_timeout(t)?;
    stream.set_write_timeout(t)?;
    let (noise, peer) = crate::noise::handshake_initiator_xx(&mut stream, &local_static)?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok((Box::new(StreamSession::new(stream, noise)), peer))
}

/// A bound socket waiting for one first-contact call.
///
/// **Bind and wait are separate.** They were one call with a deadline, which
/// meant the wait could not be cancelled and had to be short enough to run on
/// the interface thread — thirty seconds, which is not long enough to
/// coordinate a call with somebody. A caller that owns the socket can poll it
/// on a thread of its own and stop when told.
pub struct Bootstrap {
    inner: TcpListener,
    local_static: [u8; 32],
}

impl Bootstrap {
    /// Bind, and report the port taken.
    pub fn bind(addr: &str, local_static: [u8; 32]) -> Result<(Bootstrap, u16), Error> {
        let inner = TcpListener::bind(addr)?;
        let port = inner.local_addr()?.port();
        inner.set_nonblocking(true)?;
        Ok((
            Bootstrap {
                inner,
                local_static,
            },
            port,
        ))
    }

    /// Take one first-contact call, if one is waiting.
    ///
    /// `Ok(None)` means nobody called — the normal case. A caller that fails
    /// the handshake is dropped and also reported as `Ok(None)`: this socket
    /// accepts strangers by design, so a failed one is not an event, and
    /// making it one would let anyone fill the operator's log from outside.
    pub fn accept_once(&self) -> Result<Option<Accepted>, Error> {
        let mut stream = match self.inner.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        let t = Some(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_S));
        stream.set_read_timeout(t)?;
        stream.set_write_timeout(t)?;
        match crate::noise::handshake_responder_xx(&mut stream, &self.local_static) {
            Ok((noise, peer)) => {
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                Ok(Some((Box::new(StreamSession::new(stream, noise)), peer)))
            }
            Err(_) => Ok(None),
        }
    }
}

/// Open a first-contact session to `addr`, waiting up to `wait`.
///
/// Kept for the dialling side, which has somebody to call and does not need
/// to be cancellable — it is one connection attempt, not an open door.
pub fn bootstrap_accept(
    addr: &str,
    local_static: [u8; 32],
    wait: std::time::Duration,
) -> Result<Option<Accepted>, Error> {
    let (l, _) = Bootstrap::bind(addr, local_static)?;
    let deadline = std::time::Instant::now() + wait;
    while std::time::Instant::now() < deadline {
        if let Some(a) = l.accept_once()? {
            return Ok(Some(a));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(None)
}

/// How long a caller has to complete a handshake.
///
/// Bounded because the accept loop is serial: one caller that connects and
/// stays silent would otherwise stop every other peer from ever getting in,
/// at a cost to the attacker of one open socket.
pub const HANDSHAKE_TIMEOUT_S: u64 = 10;

/// A session, and the static key of the peer it belongs to.
pub type Accepted = (Box<dyn Session>, [u8; 32]);

/// A `TcpStream` is what `accept` yields; named so callers need not import it.
pub type Stream = TcpStream;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::tcp::TcpFabric;
    use crate::noise::generate_static;
    use crate::profile::LinkProfile;
    use crate::Fabric;

    fn keypair(_seed: u64) -> ([u8; 32], [u8; 32]) {
        generate_static().expect("a keypair")
    }

    /// **One socket serves every peer.** The responder is not told who is
    /// calling in advance, and reports which of the known peers arrived.
    #[test]
    fn one_socket_accepts_any_known_peer_and_says_which() {
        let (me_sk, me_pk) = keypair(1);
        let (a_sk, a_pk) = keypair(2);
        let (b_sk, b_pk) = keypair(3);

        let allowed = Allowed::new(vec![a_pk, b_pk]);
        let (l, port) = Listener::bind("127.0.0.1:0", me_sk, allowed).expect("binds");

        for (sk, pk) in [(a_sk, a_pk), (b_sk, b_pk)] {
            let dialler = std::thread::spawn(move || {
                TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), sk, me_pk)
                    .connect()
                    .map(|_| ())
                    .map_err(|e| format!("{e:?}"))
            });

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut got = None;
            while std::time::Instant::now() < deadline && got.is_none() {
                got = l.accept().expect("accept must not error");
                if got.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            let (_session, who) = got.expect("the call was not accepted");
            assert_eq!(who, pk, "the listener misidentified the caller");
            dialler.join().unwrap().expect("the dial succeeded");
        }
    }

    /// **A stranger is refused**, and is not reported as an event. RFC 4 §4.1
    /// makes this a hard failure and never a prompt; making it a log line
    /// would let anyone fill the activity log from outside.
    #[test]
    fn an_unknown_caller_is_dropped_silently() {
        let (me_sk, me_pk) = keypair(1);
        let (_known_sk, known_pk) = keypair(2);
        let (stranger_sk, _stranger_pk) = keypair(9);

        let (l, port) =
            Listener::bind("127.0.0.1:0", me_sk, Allowed::new(vec![known_pk])).expect("binds");

        let dialler = std::thread::spawn(move || {
            TcpFabric::new(
                LinkProfile::tcp(),
                format!("127.0.0.1:{port}"),
                stranger_sk,
                me_pk,
            )
            .connect()
            .is_ok()
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            assert!(
                l.accept().expect("no error").is_none(),
                "a stranger got a session"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!dialler.join().unwrap(), "the stranger's dial succeeded");
    }

    /// A peering completed while the listener runs is accepted without a
    /// restart — otherwise `peer seal` would need one, which nothing says.
    #[test]
    fn the_allowed_set_can_change_while_listening() {
        let (me_sk, me_pk) = keypair(1);
        let (new_sk, new_pk) = keypair(4);

        let allowed = Allowed::new(Vec::new());
        let (l, port) = Listener::bind("127.0.0.1:0", me_sk, allowed.clone()).expect("binds");

        // Not yet known.
        let sk = new_sk;
        let refused = std::thread::spawn(move || {
            TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), sk, me_pk)
                .connect()
                .is_ok()
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            assert!(l.accept().expect("no error").is_none());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!refused.join().unwrap());

        // Now peered.
        allowed.set(vec![new_pk]);
        let sk = new_sk;
        let accepted = std::thread::spawn(move || {
            TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), sk, me_pk)
                .connect()
                .is_ok()
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut got = None;
        while std::time::Instant::now() < deadline && got.is_none() {
            got = l.accept().expect("no error");
            if got.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        assert!(got.is_some(), "a newly peered node was still refused");
        assert!(accepted.join().unwrap());
    }

    /// Nobody calling is not an error. An accept loop that treated it as one
    /// would spend the operator's log on silence.
    #[test]
    fn an_idle_listener_reports_nothing_rather_than_failing() {
        let (me_sk, _) = keypair(1);
        let (l, _) = Listener::bind("127.0.0.1:0", me_sk, Allowed::default()).expect("binds");
        assert!(l.accept().expect("not an error").is_none());
    }

    /// **First contact needs no prior key.** `IK` cannot do this at all: it
    /// wants the responder's static before the first message, which is
    /// precisely what two nodes that have never met do not have.
    #[test]
    fn two_strangers_complete_a_bootstrap_handshake() {
        use krab_proto::control::Control;

        let (a_sk, a_pk) = keypair(1);
        let (b_sk, b_pk) = keypair(2);

        let responder = std::thread::spawn(move || {
            bootstrap_accept("127.0.0.1:45571", b_sk, std::time::Duration::from_secs(10))
        });
        std::thread::sleep(std::time::Duration::from_millis(150));

        let (mut client, saw_b) =
            bootstrap_connect("127.0.0.1:45571", a_sk).expect("the dial completes");
        let (mut server, saw_a) = responder
            .join()
            .unwrap()
            .expect("no error")
            .expect("a call arrived");

        // Each learned the other's static without either knowing it before.
        assert_eq!(saw_b, b_pk, "the initiator misread the responder's key");
        assert_eq!(saw_a, a_pk, "the responder misread the initiator's key");

        // And the session carries control messages.
        client.send(&Control::Done).expect("send");
        assert_eq!(server.recv().expect("recv"), Some(Control::Done));
    }

    /// Nobody calling is not an error, and the wait is bounded — a socket that
    /// waits for ever is one an operator cannot cancel.
    #[test]
    fn a_bootstrap_that_nobody_answers_gives_up() {
        let (sk, _) = keypair(3);
        let got = bootstrap_accept("127.0.0.1:45572", sk, std::time::Duration::from_millis(200));
        assert!(matches!(got, Ok(None)), "an unanswered wait did not return");
    }
}
