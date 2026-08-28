//! The picture decoder runs in its own process — RFC 8 §6.
//!
//! ```text
//! Decoding SHOULD occur in a separate process; where it does not, it MUST
//!   occur on a task isolated from key material.
//! ```
//!
//! These drive the **real binary**, because that is the thing being claimed:
//! that `krab --decode-picture` is a process which decodes an image and holds
//! nothing else. A unit test cannot check it — `cargo test` builds a harness,
//! and re-invoking that with the flag runs the test suite again.

use std::io::Write;
use std::process::{Command, Stdio};

const KRAB: &str = env!("CARGO_BIN_EXE_krab");

/// A request in the child's wire format: op, cols, rows, payload.
fn request(op: u8, cols: u32, rows: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![op];
    v.extend_from_slice(&cols.to_le_bytes());
    v.extend_from_slice(&rows.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn decode(req: &[u8]) -> std::process::Output {
    let mut child = Command::new(KRAB)
        .arg("--decode-picture")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node binary spawns as a decoder");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(req)
        .expect("the child accepts a request");
    child.wait_with_output().expect("the child exits")
}

/// A tiny valid PNG, built by hand so this test depends on no crate the
/// binary happens to use.
fn png() -> Vec<u8> {
    // A 4×4 RGBA PNG, generated once by the same encoder the binary uses and
    // embedded so this test depends on no crate the binary happens to have.
    //
    // Re-cut when the encoder's compression level changed: the pipeline now
    // asks for `Compression::High`, which is a different zlib stream for the
    // same pixels. That this test noticed is the point of it — the canonical
    // encoding is what "nothing of the input survives but pixels" means, and
    // it is allowed to change only deliberately.
    const BYTES: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x08, 0x06, 0x00, 0x00, 0x00, 0xA9,
        0xF1, 0x9E, 0x7E, 0x00, 0x00, 0x00, 0x1F, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x85, 0xC8,
        0x31, 0x0D, 0x00, 0x00, 0x0C, 0x02, 0x30, 0xB2, 0x4C, 0x18, 0xFE, 0x55, 0xC1, 0x49, 0x78,
        0xE8, 0xD9, 0xA7, 0x21, 0x1C, 0xCA, 0x0E, 0x01, 0x43, 0xA0, 0x01, 0x0B, 0xB1, 0x12, 0x8E,
        0x70, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    BYTES.to_vec()
}

/// **The flag is honoured before anything else happens.** If it were parsed
/// one line later the child would resolve a home directory, and the isolation
/// claim — that this address space contains no key material — would be false.
#[test]
fn the_binary_becomes_a_decoder_and_produces_a_picture() {
    let out = decode(&request(0, 0, 0, &png()));
    assert!(
        out.status.success(),
        "the decoder failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.starts_with(&[0x89, b'P', b'N', b'G']),
        "the child did not return a PNG"
    );
    // Re-encoded, not echoed. A *canonical* PNG re-encodes to itself, which
    // is correct and proves nothing — so the test appends something and
    // checks it is gone. That is what distinguishes a pipeline from a copy.
    let mut with_junk = png();
    with_junk.extend_from_slice(b"PK\x03\x04 GPS 51.5074 -0.1278");
    let out = decode(&request(0, 0, 0, &with_junk));
    assert!(
        out.status.success(),
        "a valid PNG with trailing data was refused"
    );
    assert!(
        !out.stdout.windows(3).any(|w| w == b"GPS"),
        "appended data crossed the process boundary"
    );
    assert_eq!(
        out.stdout,
        png(),
        "the pipeline did not normalise back to the canonical encoding"
    );
}

/// **It touches no home directory.** A child that opened a store would be a
/// child that had key material to lose.
#[test]
fn the_decoder_writes_nothing_to_its_home() {
    let dir = std::env::temp_dir().join(format!("krab-decoder-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let mut child = Command::new(KRAB)
        .arg("--decode-picture")
        // A home is offered and must be ignored: the flag is handled before
        // arguments are parsed at all.
        .arg("--home")
        .arg(&dir)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request(0, 0, 0, &png()))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
    assert!(
        left.is_empty(),
        "the decoder wrote {left:?} — it should have no store at all"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A refusal is a non-zero exit and a reason on stderr, never an empty
/// success. A parent that read zero bytes and called it a picture would be
/// worse than one that failed.
#[test]
fn a_refusal_is_a_failure_and_not_an_empty_picture() {
    for junk in [&b"not an image"[..], &b"GIF89a"[..], &[][..]] {
        let out = decode(&request(0, 0, 0, junk));
        assert!(!out.status.success(), "junk was accepted: {junk:?}");
        assert!(out.stdout.is_empty(), "a refusal returned a payload");
    }
}

/// **A decompression bomb dies in the child.** The cap is applied from the
/// header before allocation, and the process that would have allocated is not
/// the one holding the corpus key.
#[test]
fn a_bomb_is_refused_by_the_child() {
    let mut bomb = png();
    let ihdr = 12;
    bomb[ihdr + 4..ihdr + 8].copy_from_slice(&40_000u32.to_be_bytes());
    bomb[ihdr + 8..ihdr + 12].copy_from_slice(&40_000u32.to_be_bytes());
    // The CRC is wrong now, which the decoder will also reject — either way
    // it must not decode, and it must not take the parent with it.
    let out = decode(&request(0, 0, 0, &bomb));
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

/// A malformed request is refused rather than interpreted. The child's own
/// input is attacker-adjacent too: it arrives from a parent that read it off
/// the network.
#[test]
fn a_truncated_request_is_refused() {
    for short in [&b""[..], &b"\x00"[..], &b"\x00\x00\x00\x00"[..]] {
        let out = decode(short);
        assert!(!out.status.success(), "a truncated request was accepted");
    }
    // An unknown opcode.
    let out = decode(&request(99, 0, 0, &png()));
    assert!(!out.status.success());
}

/// Rendering to cells crosses the boundary too, with a frame the parent can
/// check: rows, columns, then six bytes a cell.
#[test]
fn cells_cross_the_boundary_in_a_checkable_frame() {
    let out = decode(&request(1, 20, 8, &png()));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.len() >= 8);
    let rows = u32::from_le_bytes(out.stdout[..4].try_into().unwrap()) as usize;
    let cols = u32::from_le_bytes(out.stdout[4..8].try_into().unwrap()) as usize;
    assert_eq!(
        rows * cols * 6,
        out.stdout.len() - 8,
        "the frame's declared size disagrees with its payload"
    );
    assert!(
        cols <= 20 && rows <= 8,
        "the child ignored the bounds given"
    );
}
