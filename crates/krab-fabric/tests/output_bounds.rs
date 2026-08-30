//! What this node can *put on a link* — Pass 14's axis.
//!
//! Every bound in the codebase is written as a check on what arrives. These
//! are checks on what leaves, which is where two of RFC 1 §8.1's six size
//! buckets turned out to be unsendable.

use krab_fabric::frame;
use krab_proto::control::Control;

/// **Every legal object must fit a control message that can be written.**
///
/// RFC 1 §8.1 defines six buckets. RFC 4 §4.2's own table says the top two
/// take more than one frame — 2 for 65 536 and 5 for 262 144 — so carrying
/// them was always meant to span Noise transport messages. The implementation
/// refused instead: `Control::Obj` of a bucket-4 object encodes to 65 543
/// bytes against a 65 535 ceiling, over by eight.
///
/// `serve_wants` propagates the error rather than skipping the object, so one
/// legal picture in the corpus ended every exchange with every peer, on every
/// link, permanently.
#[test]
fn every_size_bucket_can_be_written_as_a_control_message() {
    for (i, &bucket) in krab_core::object::BUCKETS.iter().enumerate() {
        let msg = Control::Obj(vec![0u8; bucket as usize]);
        let encoded = msg.write();
        let mut out = Vec::new();
        assert!(
            frame::write(&mut out, &msg).is_ok(),
            "bucket {i} ({bucket} bytes) encodes to {} and cannot be framed",
            encoded.len()
        );
        // And it reads back as what went in.
        let mut cur = std::io::Cursor::new(out);
        assert_eq!(frame::read(&mut cur).unwrap(), Some(msg), "bucket {i}");
    }
}

/// **And over a real encrypted session, not only on paper.**
///
/// `frame::write` is the courier path. The network path is
/// `noise::StreamSession`, which encrypts into Noise transport messages — and
/// that is where the 65 535 ceiling is a property of the construction rather
/// than a constant anyone may raise. Every bucket has to cross it.
#[test]
fn every_size_bucket_crosses_a_real_noise_session() {
    use krab_fabric::backend::tcp::{generate_static, TcpFabric};
    use krab_fabric::profile::LinkProfile;
    use krab_fabric::Fabric;

    let (a_sk, a_pk) = generate_static().unwrap();
    let (b_sk, b_pk) = generate_static().unwrap();
    let responder = TcpFabric::new(LinkProfile::tcp(), "", b_sk, a_pk);
    let port = responder.listen("127.0.0.1:0").unwrap();

    let handle = std::thread::spawn(move || {
        let mut got = Vec::new();
        for _ in 0..400 {
            if let Ok(Some(mut s)) = responder.accept() {
                while let Ok(Some(m)) = s.recv() {
                    match m {
                        Control::Obj(b) => got.push(b.len()),
                        Control::Done => break,
                        _ => {}
                    }
                }
                return got;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        got
    });

    let initiator = TcpFabric::new(LinkProfile::tcp(), format!("127.0.0.1:{port}"), a_sk, b_pk);
    let mut session = initiator.connect().expect("handshake");
    for &bucket in krab_core::object::BUCKETS.iter() {
        session
            .send(&Control::Obj(vec![0u8; bucket as usize]))
            .unwrap_or_else(|e| panic!("bucket {bucket} could not be sent: {e:?}"));
    }
    session.send(&Control::Done).unwrap();
    let _ = session.close();

    let got = handle.join().unwrap();
    let want: Vec<usize> = krab_core::object::BUCKETS.iter().map(|&b| b as usize).collect();
    assert_eq!(got, want, "objects did not arrive whole, or at all");
}

/// The bound is derived from the largest object, not chosen — so a reader
/// still refuses to allocate against a length no message can legitimately
/// have. RFC 4 §9's rule is unchanged; only the number moved.
#[test]
fn a_length_above_the_largest_control_message_is_still_refused() {
    let mut bytes = (frame::MAX_CONTROL as u32 + 1).to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 8]);
    let mut cur = std::io::Cursor::new(bytes);
    assert!(matches!(
        frame::read(&mut cur),
        Err(krab_fabric::Error::Frame)
    ));
}
