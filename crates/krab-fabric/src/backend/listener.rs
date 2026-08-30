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

/// In-progress handshakes this listener holds at once.
///
/// RFC 4 §9 requires the cap and suggests four *per peer*. Before a handshake
/// completes there is no peer to attribute it to — that is the whole of the
/// attack — so this is a cap on the total, set at four times §9's figure so
/// that several honest peers reconnecting together are never turned away.
///
/// Reaching it drops the newest connection without a word. RFC 4 §9 calls
/// handshake slowloris "the cheapest attack against a reachable node", and an
/// operator log entry for it would be the attacker writing to the log.
pub const MAX_PENDING_HANDSHAKES: usize = 16;

/// A bound socket accepting calls from any known peer.
pub struct Listener {
    inner: TcpListener,
    local_static: [u8; 32],
    allowed: Allowed,
    /// Handshakes running on their own threads, and the completed sessions
    /// they hand back.
    ///
    /// # Why the handshake is not done here
    ///
    /// It was, inline, on the one thread that accepts. The comment beside it
    /// argued that the timeout made this safe, and the timeout is what made it
    /// unsafe: **a caller that connects and says nothing holds the accept loop
    /// for the full [`HANDSHAKE_TIMEOUT_S`]**, so one connection every ten
    /// seconds — from anywhere, with no credential, sending no data — denies
    /// every real peer entry, and failed handshakes are `Ok(None)` by design
    /// so nothing is logged. The cost to the attacker is one socket.
    ///
    /// Accepting is cheap and handshaking is not, so they are separated: this
    /// end takes the connection immediately and completes it elsewhere. A
    /// silent caller now occupies one slot of [`MAX_PENDING_HANDSHAKES`] for
    /// ten seconds and blocks nobody.
    pending: Arc<std::sync::atomic::AtomicUsize>,
    done_tx: std::sync::mpsc::Sender<Accepted>,
    done_rx: std::sync::mpsc::Receiver<Accepted>,
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
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        Ok((
            Listener {
                inner,
                local_static,
                allowed,
                pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                done_tx,
                done_rx,
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
        use std::sync::atomic::Ordering;

        // A handshake that finished since the last call, before taking a new
        // connection: a session that is ready outranks one that is not.
        if let Ok(session) = self.done_rx.try_recv() {
            return Ok(Some(session));
        }

        let stream = match self.inner.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // RFC 4 §9's cap. Dropping the stream closes it; a caller that finds
        // the node busy retries, and an attacker holding every slot has bought
        // ten seconds rather than the loop.
        if self.pending.load(Ordering::Relaxed) >= MAX_PENDING_HANDSHAKES {
            return Ok(None);
        }
        self.pending.fetch_add(1, Ordering::Relaxed);

        let local_static = self.local_static;
        let allowed = self.allowed.snapshot();
        let tx = self.done_tx.clone();
        let pending = self.pending.clone();
        std::thread::spawn(move || {
            let mut stream = stream;
            let finish = || -> Result<Accepted, Error> {
                // The handshake blocks; the listen socket does not. Without
                // this the first read returns WouldBlock and the handshake
                // fails against a peer that is doing nothing wrong.
                // It no longer blocks the accept loop, but a thread that
                // never returns is a thread leak, and the slot it holds is
                // the resource RFC 4 §9 caps.
                arm_handshake(&stream)?;
                let (noise, peer) =
                    handshake_responder_any(&mut stream, &local_static, &allowed)?;
                arm_session(&stream)?;
                Ok((
                    Box::new(StreamSession::new(stream, noise)) as Box<dyn Session>,
                    peer,
                ))
            };
            if let Ok(session) = finish() {
                let _ = tx.send(session);
            }
            pending.fetch_sub(1, Ordering::Relaxed);
        });

        // Nothing to hand back yet. The caller polls, which it already does.
        Ok(None)
    }

    /// Handshakes in progress. For tests and for RFC 3 §12's metrics.
    pub fn pending_handshakes(&self) -> usize {
        self.pending.load(std::sync::atomic::Ordering::Relaxed)
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
    let resolved = addr
        .to_socket_addrs()?
        .next()
        .ok_or(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
    let mut stream = TcpStream::connect_timeout(
        &resolved,
        std::time::Duration::from_secs(CONNECT_TIMEOUT_S),
    )?;
    arm_handshake(&stream)?;
    let (noise, peer) = crate::noise::handshake_initiator_xx(&mut stream, &local_static)?;
    arm_session(&stream)?;
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
    pending: Arc<std::sync::atomic::AtomicUsize>,
    done_tx: std::sync::mpsc::Sender<Accepted>,
    done_rx: std::sync::mpsc::Receiver<Accepted>,
}

impl Bootstrap {
    /// Bind, and report the port taken.
    pub fn bind(addr: &str, local_static: [u8; 32]) -> Result<(Bootstrap, u16), Error> {
        let inner = TcpListener::bind(addr)?;
        let port = inner.local_addr()?.port();
        inner.set_nonblocking(true)?;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        Ok((
            Bootstrap {
                inner,
                local_static,
                pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                done_tx,
                done_rx,
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
    /// # The same fix as [`Listener::accept`], which this did not get
    ///
    /// The handshake was inline here too. It is a smaller hole — the poll
    /// loop is on its own thread and this door is open for minutes, not for
    /// the life of the process — but the shape is identical: a caller that
    /// connects and says nothing owns the door for [`HANDSHAKE_TIMEOUT_S`],
    /// and repeating that costs one socket and shuts out the person the
    /// operator is actually waiting for. First contact is arranged for a
    /// particular minute, so blocking it is enough.
    ///
    /// Two siblings in one file, one fixed and one not, is the shape of every
    /// omission this series has found.
    pub fn accept_once(&self) -> Result<Option<Accepted>, Error> {
        use std::sync::atomic::Ordering;

        if let Ok(session) = self.done_rx.try_recv() {
            return Ok(Some(session));
        }
        let stream = match self.inner.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if self.pending.load(Ordering::Relaxed) >= MAX_PENDING_HANDSHAKES {
            return Ok(None);
        }
        self.pending.fetch_add(1, Ordering::Relaxed);

        let local_static = self.local_static;
        let tx = self.done_tx.clone();
        let pending = self.pending.clone();
        std::thread::spawn(move || {
            let mut stream = stream;
            let finish = || -> Result<Accepted, Error> {
                arm_handshake(&stream)?;
                let (noise, peer) =
                    crate::noise::handshake_responder_xx(&mut stream, &local_static)?;
                arm_session(&stream)?;
                Ok((
                    Box::new(StreamSession::new(stream, noise)) as Box<dyn Session>,
                    peer,
                ))
            };
            if let Ok(session) = finish() {
                let _ = tx.send(session);
            }
            pending.fetch_sub(1, Ordering::Relaxed);
        });
        Ok(None)
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

/// How long a dial may take before it is abandoned.
///
/// `TcpStream::connect` waits for the operating system's own timeout, which
/// is about two minutes on Linux and is not a number this program chose.
/// `connect <peer> tcp <addr>` runs on the interface thread, so that is two
/// minutes in which no key is read — including the panic chord.
pub const CONNECT_TIMEOUT_S: u64 = 10;

/// How long a driver waits for the next message inside an exchange.
///
/// # Why an established session has a deadline
///
/// It did not, and the reasoning for that was right about the link and wrong
/// about the drivers: a session is long-lived and legitimately silent
/// *between* reconciliations, so the timeouts were cleared once the handshake
/// finished. But nothing reads a socket between reconciliations. Every read
/// happens inside `krab_node::exchange`, where the driver is waiting for the
/// peer's next message and a peer that never sends one is not idle — it is
/// holding a thread that will never return, on a session `take_session` has
/// already removed, so no event is ever logged and the operator is told
/// nothing.
///
/// Generous rather than tight: an honest peer on a slow link may take a while
/// to answer a manifest, and cutting it off would turn a slow exchange into a
/// failed one. It bounds a stall, not a delay.
pub const SESSION_TIMEOUT_S: u64 = 120;

/// Put the handshake's deadline on a stream.
///
/// The handshake blocks and the listen socket does not, so blocking mode is
/// restored here too — without it the first read returns `WouldBlock` and the
/// handshake fails against a peer doing nothing wrong.
pub fn arm_handshake(stream: &TcpStream) -> Result<(), Error> {
    stream.set_nonblocking(false)?;
    let t = Some(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_S));
    stream.set_read_timeout(t)?;
    stream.set_write_timeout(t)?;
    Ok(())
}

/// Put the session's deadline on a stream, once the handshake has completed.
///
/// One function rather than four copies of `set_read_timeout(None)`, which is
/// what the four sites had — and each one was independently correct about the
/// link and independently wrong about the drivers.
pub fn arm_session(stream: &TcpStream) -> Result<(), Error> {
    let t = Some(std::time::Duration::from_secs(SESSION_TIMEOUT_S));
    stream.set_read_timeout(t)?;
    stream.set_write_timeout(t)?;
    Ok(())
}

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
