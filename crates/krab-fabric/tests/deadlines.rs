//! Pass 15's axis: the clock inside a session.
//!
//! Every bound in the network path was a count — frame size, message count,
//! manifest rows, objects served, handshake slots, descent rounds. None was a
//! deadline, and the only two clocks in the stack were both spent before the
//! session existed. The hardening stopped at the door.

use krab_fabric::backend::tcp::{generate_static, TcpFabric};
use krab_fabric::profile::LinkProfile;
use krab_fabric::Fabric;
use krab_proto::control::Control;
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// **A dial has a deadline.**
///
/// `TcpStream::connect` waits for the operating system's timeout — about two
/// minutes on Linux — and the handshake that followed had none at all. This
/// runs on the interface thread: `connect <peer> tcp <addr>` is typed at the
/// command line, and while it blocks, `event::poll` is not called, so no key
/// reaches the handler. The panic chord, one commit after being made to fire
/// on one press, fired on none.
///
/// The socket here accepts and then says nothing, which is the case an OS
/// connect timeout never covers: the connection succeeds and the handshake
/// hangs.
#[test]
fn a_dial_to_a_silent_socket_gives_up() {
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = sink.local_addr().unwrap().port();
    // Accept and hold, saying nothing.
    let held = std::thread::spawn(move || {
        let s = sink.accept().map(|(s, _)| s);
        std::thread::sleep(Duration::from_secs(30));
        drop(s);
    });

    let (sk, _) = generate_static().unwrap();
    let (_, peer_pk) = generate_static().unwrap();
    let fabric = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), sk, peer_pk);

    let started = Instant::now();
    let outcome = fabric.connect();
    let took = started.elapsed();

    assert!(outcome.is_err(), "the dial reported success against silence");
    assert!(
        took < Duration::from_secs(25),
        "the dial blocked for {took:?} — on the interface thread, that is {took:?} \
         in which the panic chord cannot be pressed"
    );
    drop(held);
}

/// **An established session has a deadline too.**
///
/// The timeouts were cleared once the handshake completed, and the reasoning
/// was right about the link and wrong about the drivers: a session is
/// legitimately silent *between* reconciliations, but nothing reads a socket
/// between reconciliations. Every read happens inside a driver that is waiting
/// for the peer's next message, and a peer that never sends one holds a thread
/// that never returns — on a session `take_session` has already removed, so
/// nothing is ever logged.
///
/// Bounded here by the test's own patience rather than by
/// `SESSION_TIMEOUT_S`, which is two minutes: what is asserted is that the
/// read *has* a deadline, not what it is.
#[test]
fn a_session_read_has_a_deadline() {
    let (a_sk, a_pk) = generate_static().unwrap();
    let (b_sk, b_pk) = generate_static().unwrap();
    let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, a_pk);
    let port = responder.listen("127.0.0.1:0").unwrap();

    let handle = std::thread::spawn(move || {
        for _ in 0..400 {
            if let Ok(Some(session)) = responder.accept() {
                // Handshake done, and then nothing at all.
                std::thread::sleep(Duration::from_secs(3));
                drop(session);
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let initiator = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, b_pk);
    let mut session = initiator.connect().expect("handshake");
    session.send(&Control::Done).unwrap();

    // The far end never answers, then closes. Without a deadline this read
    // waits on a socket nobody will write to.
    let started = Instant::now();
    let _ = session.recv();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "a read against a silent peer did not return"
    );
    handle.join().unwrap();
}
