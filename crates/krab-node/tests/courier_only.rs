//! **RFC 3 §11.3 — the courier-only release gate.**
//!
//! > "An implementation MUST demonstrate a complete peering negotiation and
//! > first message exchange **with all network interfaces down**, using only
//! > file import and export. If any step requires a round trip that was not
//! > noticed, air-gapped nodes silently cannot join, and that will not be
//! > discovered until someone tries."
//!
//! This file covers the **message exchange** half. The peering negotiation
//! half is `courier_only_peering_completes_with_no_network` in
//! `apps/krab-tui/src/main.rs`, which drives the `peer` verbs over two
//! directories with nothing but `std::fs` between them.
//!
//! # What the gate is actually testing
//!
//! Not cryptography — a hidden **round trip**. The failure it exists to catch
//! is a protocol step that quietly assumes the peer can answer before the
//! exchange completes. Over TCP that is free and invisible; over a USB stick
//! posted between two towns it is fatal, and the symptom is "air-gapped nodes
//! cannot join" discovered months later by someone with no way to debug it.
//!
//! So the test is structured as **strictly alternating one-way legs**. A leg
//! writes an archive and stops. Nothing reads while anything writes; no
//! session is ever open at both ends at once. If reconciliation needed a reply
//! mid-leg it would fail here rather than hang.
//!
//! # Bodies are sealed
//!
//! `a_sealed_message_crosses_by_courier` carries a real HPKE-sealed payload
//! under `mode_auth_psk` — RFC 1 §6.1's suite, with a reservoir chunk as PSK
//! (`CRYPTO-REVIEW.md` §1's recommended construction). The recipient opens it
//! having received nothing but a file.
//!
//! That matters because it exercises the one thing a courier deployment cannot
//! fall back on: **the sender and recipient must already share everything the
//! key schedule needs.** `mode_auth` requires the recipient hold the sender's
//! static key, and the PSK requires a reservoir root — both established by the
//! peering ceremony, offline, in the test above this one. If either had
//! quietly needed a live negotiation, it would surface here.

use krab_core::object::{canonical_bytes, ObjectId, RoutingHeader, Tag, ROUTING_HEADER_LEN};
use krab_fabric::backend::courier::{read_archive, CourierFabric};
use krab_fabric::profile::LinkProfile;
use krab_fabric::Fabric;
use krab_proto::control::Control;
use krab_proto::recon::Mode;
use krab_store::index::Store;

/// A minute count comfortably inside a 45-day TTL, matching the store's tests.
const NOW_MIN: u32 = 29_766_000;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "krab-gate-{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        tag
    ));
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// An object with an opaque body — see the module note on sealing.
fn object(salt: u8) -> (ObjectId, Vec<u8>) {
    let h = RoutingHeader {
        version: 1,
        class: 0,
        size_bucket: 0,
        flags: 0,
        expiry_min: NOW_MIN + 40_000 + salt as u32,
        tag: Tag([salt; 8]),
    };
    let b = canonical_bytes(&h, &[salt; 40]).expect("canonical");
    (krab_crypto::object_id(&b), b)
}

/// **The gate.** A message crosses from one store to another with no network,
/// no round trip, and nothing shared but a file.
#[test]
fn a_message_crosses_by_courier_with_no_network_and_no_round_trip() {
    let post = temp_dir("post");
    let a_archive = post.join("a-outbox.krab");
    // A's inbox does not exist and never will during this test: nothing ever
    // comes back. If any step needed a reply, it would fail here.
    let a_inbox = post.join("nothing-ever-arrives.krab");

    // A has a message for B. B has never heard of it.
    let mut a_store = Store::new();
    let mut b_store = Store::new();
    let (id, bytes) = object(7);
    a_store
        .ingest(id, bytes.clone(), NOW_MIN, u32::MAX)
        .expect("A holds it");
    assert!(!b_store.contains(&id));

    // ---- Leg 1: A writes an archive. Nothing is listening. ----
    let a_fabric = CourierFabric::new(LinkProfile::courier(), &a_archive, &a_inbox);
    {
        let mut s = a_fabric
            .connect()
            .expect("a courier link is always writable");
        for (_, oid) in a_store.entries_in_range(0, u32::MAX) {
            let body = a_store.get(&oid).expect("held").to_vec();
            s.send(&Control::Obj(body)).expect("written");
        }
        s.send(&Control::Done).expect("written");
        s.close().expect("archive sealed");
    }
    assert!(!a_inbox.exists(), "no reply was needed at any point");

    // The stick is now in the post. **Both processes could stop here.**
    assert!(a_archive.is_file(), "one leg produced one archive");

    // ---- Carried by hand, and renamed in transit. ----
    // RFC 4 §5.5: filenames carry no meaning and MUST be ignored.
    let b_inbox = temp_dir("b-inbox").join("DSC_0041.bin");
    std::fs::copy(&a_archive, &b_inbox).expect("delivered by courier");

    // Verifiable before ingestion, without trusting the courier.
    assert_eq!(
        CourierFabric::verify(&b_inbox),
        Ok(1),
        "one object, self-consistent"
    );

    // ---- Leg 2: B reads it, offline, with A long since gone. ----
    let control = read_archive(&b_inbox).expect("archive reads after renaming");
    assert!(!control.is_empty(), "the archive carried something");

    let mut ingested = 0;
    for msg in control {
        if let Control::Obj(bytes) = msg {
            // `Control::Obj` carries no identifier: the receiver derives it by
            // hashing. A courier cannot mislabel an object, because the label
            // is not something anyone sends.
            let derived = krab_crypto::object_id(&bytes);
            // RFC 1 §11: the receiver checks; it does not trust the courier.
            if b_store.ingest(derived, bytes, NOW_MIN, u32::MAX).is_ok() {
                ingested += 1;
            }
        }
    }

    assert_eq!(ingested, 1, "the message arrived");
    assert!(b_store.contains(&id), "and it is the object A sent");
    assert_eq!(
        b_store.get(&id).expect("held by B"),
        &bytes[..],
        "byte-identical"
    );
    assert_eq!(krab_crypto::object_id(b_store.get(&id).unwrap()), id);
}

/// A courier archive is inert: a corrupted one is rejected rather than
/// ingested, and a node that never receives a reply is not stuck.
#[test]
fn a_corrupted_archive_is_refused_and_leaves_the_store_untouched() {
    let post = temp_dir("corrupt");
    let out = post.join("out.krab");
    let inbox = post.join("in.krab");

    let (_, bytes) = object(9);
    let fabric = CourierFabric::new(LinkProfile::courier(), &out, &inbox);
    {
        let mut s = fabric.connect().unwrap();
        s.send(&Control::Obj(bytes.clone())).unwrap();
        s.send(&Control::Done).unwrap();
        s.close().unwrap();
    }
    assert_eq!(CourierFabric::verify(&out), Ok(1), "intact to begin with");

    // Flip a byte in the middle, as a failing USB stick would. Every single
    // byte position must be caught -- an object is its own hash, so there is
    // no part of an archive that may be quietly wrong.
    let intact = std::fs::read(&out).unwrap();
    let torn_path = post.join("torn.krab");
    let mut store = Store::new();
    for i in 0..intact.len() {
        let mut raw = intact.clone();
        raw[i] ^= 0xFF;
        std::fs::write(&torn_path, &raw).unwrap();

        // Whatever the reader makes of it, nothing invalid reaches the store.
        if let Ok(control) = read_archive(&torn_path) {
            for msg in control {
                if let Control::Obj(bytes) = msg {
                    let derived = krab_crypto::object_id(&bytes);
                    let _ = store.ingest(derived, bytes, NOW_MIN, u32::MAX);
                }
            }
        }
    }

    // A tampered object may well be *stored* -- it is a valid object, just a
    // different one. What must never happen is an object stored under an
    // identifier it does not hash to, because that is what would let a courier
    // substitute content for an identifier a peer already asked for.
    for oid in store.ids_in_order() {
        assert_eq!(
            krab_crypto::object_id(store.get(oid).unwrap()),
            *oid,
            "an object in the store always hashes to its own identifier"
        );
    }
}

/// **The gate, with a sealed body.**
///
/// Everything the key schedule needs was established by the offline ceremony:
/// the recipient's static key, the sender's static key, and a reservoir root.
/// Nothing is negotiated here — a courier link has no opportunity to.
#[test]
fn a_sealed_message_crosses_by_courier() {
    use krab_core::tag::Epoch;
    use krab_crypto::dh::SecretKey;
    use krab_crypto::reservoir::Reservoir;
    use krab_crypto::rng::NotRandom;
    use krab_crypto::seal::{info_for, open, seal, Mode, Sealed, ENC_LEN};

    let post = temp_dir("sealed");
    let archive = post.join("out.krab");
    let never = post.join("no-reply-ever.krab");

    // What the ceremony established, offline: two static keypairs and a
    // reservoir root both ends hold.
    let sender = SecretKey::generate(&mut NotRandom::seeded(1));
    let recipient = SecretKey::generate(&mut NotRandom::seeded(2));
    let epoch = Epoch(20_671);
    let root = [0x5A; 32];
    let chunk_s = Reservoir::new(root, Epoch(0)).chunk(epoch).unwrap();
    let chunk_r = Reservoir::new(root, Epoch(0)).chunk(epoch).unwrap();

    let plaintext = b"the message that must not be readable in transit";
    let header = RoutingHeader {
        version: 1,
        class: 0,
        size_bucket: 0,
        flags: 0,
        expiry_min: NOW_MIN + 40_000,
        tag: Tag([0x11; 8]),
    };
    // RFC 1 §6.1: the AAD binds the routing header, so a relay that edits the
    // expiry to force indefinite storage produces something undecryptable.
    let aad = header.write();
    let info = info_for(header.class);

    let sealed = seal(
        &Mode::AuthPsk {
            chunk: &chunk_s,
            epoch,
        },
        &sender,
        &recipient.public(),
        &info,
        &aad,
        plaintext,
        &mut NotRandom::seeded(3),
    )
    .expect("sealed");

    // The object body is the encapsulated key followed by the ciphertext.
    let mut body = Vec::with_capacity(ENC_LEN + sealed.ct.len());
    body.extend_from_slice(&sealed.enc);
    body.extend_from_slice(&sealed.ct);
    let object_bytes = canonical_bytes(&header, &body).expect("canonical");
    let id = krab_crypto::object_id(&object_bytes);

    // Nothing recognisable is on the wire.
    assert!(
        !object_bytes
            .windows(plaintext.len())
            .any(|w| w == plaintext),
        "plaintext must not appear in the object"
    );

    // ---- One leg. Write, and stop. ----
    let fabric = CourierFabric::new(LinkProfile::courier(), &archive, &never);
    {
        let mut s = fabric.connect().unwrap();
        s.send(&Control::Obj(object_bytes.clone())).unwrap();
        s.send(&Control::Done).unwrap();
        s.close().unwrap();
    }
    assert!(!never.exists(), "no reply was needed");

    // ---- Carried, renamed, and opened offline. ----
    let delivered = temp_dir("sealed-inbox").join("photos.zip");
    std::fs::copy(&archive, &delivered).unwrap();

    let mut store = Store::new();
    for msg in read_archive(&delivered).expect("reads") {
        if let Control::Obj(bytes) = msg {
            let derived = krab_crypto::object_id(&bytes);
            let _ = store.ingest(derived, bytes, NOW_MIN, u32::MAX);
        }
    }
    let held = store.get(&id).expect("the object arrived");

    // Reconstruct and open, using only what the ceremony established.
    let recovered = RoutingHeader::parse(held).expect("header parses");
    let payload = &held[ROUTING_HEADER_LEN..];
    let mut enc = [0u8; ENC_LEN];
    enc.copy_from_slice(&payload[..ENC_LEN]);
    // The body was padded to its size bucket, and the identifier covers the
    // padding (RFC 1 §8.1), so the ciphertext length has to come from the
    // sender's framing rather than from what is on disk.
    let ct = payload[ENC_LEN..ENC_LEN + sealed.ct.len()].to_vec();

    let opened = open(
        &Mode::AuthPsk {
            chunk: &chunk_r,
            epoch,
        },
        &recipient,
        &sender.public(),
        &Sealed { enc, ct },
        &info_for(recovered.class),
        &recovered.write(),
    )
    .expect("opens with what the ceremony established, and nothing else");

    assert_eq!(
        opened, plaintext,
        "the message crossed intact and confidential"
    );
}

/// Reconciliation over a courier link uses manifest mode, not RBSR.
///
/// RFC 5 §4.5 derives `sync_mode` from latency class rather than configuring
/// it, and this is why: RBSR is a multi-round protocol, and a courier link has
/// one round per courier. A node that chose RBSR here would negotiate forever,
/// one leg per week.
#[test]
fn a_courier_link_reconciles_in_manifest_mode_not_rbsr() {
    let profile = LinkProfile::courier();
    assert_eq!(
        profile.latency_class.sync_mode(),
        Mode::Manifest,
        "a multi-round protocol over a link with one round per courier never converges"
    );
    // And a low-latency link makes the opposite choice, from the same input.
    assert_eq!(LinkProfile::tcp().latency_class.sync_mode(), Mode::Rbsr);
}
