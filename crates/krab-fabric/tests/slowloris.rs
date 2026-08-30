//! One silent socket must not deny inbound peering — RFC 4 §9.
//!
//! "Handshake slowloris is the cheapest attack against a reachable node."
//! The accept loop completed the handshake inline, so a caller that connected
//! and said nothing held it for the full `HANDSHAKE_TIMEOUT_S`. One connection
//! every ten seconds, from anywhere, with no credential and no data, shut out
//! every real peer — and failed handshakes are `Ok(None)` by design, so
//! nothing was logged while it happened.

use krab_fabric::backend::listener::{Allowed, Listener, MAX_PENDING_HANDSHAKES};
use krab_fabric::backend::tcp::{generate_static, TcpFabric};
use krab_fabric::profile::LinkProfile;
use krab_fabric::Fabric;
use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// **A real peer gets in while a silent caller is still connected.**
///
/// The silent socket is opened first and never written to. Under the inline
/// handshake this test cannot pass in less than `HANDSHAKE_TIMEOUT_S`; the
/// bound below is a fifth of that, so it discriminates rather than merely
/// succeeding.
#[test]
fn a_silent_caller_does_not_block_a_real_peer() {
    let (peer_sk, peer_pk) = generate_static().unwrap();
    let (node_sk, node_pk) = generate_static().unwrap();

    let (listener, port) =
        Listener::bind("127.0.0.1:0", node_sk, Allowed::new(vec![peer_pk])).unwrap();

    // The attack: connect, say nothing, hold it open.
    let mut silent = TcpStream::connect(("127.0.0.1", port)).expect("silent connect");
    // Poll until the listener has taken it up. `connect` returning does not
    // mean the connection has reached the accept queue, so a single poll is a
    // race — one that fails only under load, which is the worst kind.
    let armed = Instant::now();
    while listener.pending_handshakes() == 0 && armed.elapsed() < Duration::from_secs(5) {
        let _ = listener.accept();
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        listener.pending_handshakes() >= 1,
        "the silent caller was not taken up"
    );

    // The peer, dialling normally.
    let dialler = TcpFabric::new(
        LinkProfile::tcp(),
        format!("127.0.0.1:{port}"),
        peer_sk,
        node_pk,
    );
    let handle = std::thread::spawn(move || dialler.connect().is_ok());

    let started = Instant::now();
    let mut got = None;
    while started.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(session)) = listener.accept() {
            got = Some(session);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let took = started.elapsed();

    assert!(got.is_some(), "the real peer never got in");
    assert!(
        took < Duration::from_secs(2),
        "the real peer waited {took:?} behind a caller that sent nothing"
    );
    assert!(handle.join().unwrap(), "the dialler's handshake failed");
    // Keep the silent socket alive to the end, so it is genuinely concurrent.
    let _ = silent.read(&mut [0u8; 1]);
}

/// And the slots are bounded, so the threads are too. RFC 4 §9 requires the
/// cap; before a handshake completes there is no peer to attribute it to, so
/// it is a cap on the total.
#[test]
fn in_progress_handshakes_are_capped() {
    let (_, peer_pk) = generate_static().unwrap();
    let (node_sk, port_of) = generate_static().unwrap();
    let _ = port_of;
    let (listener, port) =
        Listener::bind("127.0.0.1:0", node_sk, Allowed::new(vec![peer_pk])).unwrap();

    // More silent callers than the cap allows.
    let mut held = Vec::new();
    for _ in 0..(MAX_PENDING_HANDSHAKES + 8) {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            held.push(s);
        }
        let _ = listener.accept();
    }
    assert!(
        listener.pending_handshakes() <= MAX_PENDING_HANDSHAKES,
        "in-progress handshakes reached {}, above the cap of {MAX_PENDING_HANDSHAKES}",
        listener.pending_handshakes()
    );
    drop(held);
}
