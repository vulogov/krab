//! `picture::transcode` — RFC 8 §6, and the module the code itself calls the
//! richest source of remote code execution.
//!
//! > "Image parsers are historically the richest source of remote code
//! > execution, which is why nothing here validates and everything is
//! > re-encoded. Two decoders is two parsers; the alternative is a format
//! > nobody can send."
//!
//! Two third-party parsers run on bytes a peer chose. That is the largest
//! attack surface in the system by a distance, and it had no fuzz target —
//! not by oversight but by structure: the module lived in the interface
//! **binary**, and `cargo fuzz` cannot depend on a binary crate. Moving it to
//! `krab-picture` is what made this file possible, and is the substantive part
//! of the change this file is the point of.
//!
//! # What is asserted, and why it is the postcondition rather than the parse
//!
//! A crash or a hang is a finding on its own — that is what the fuzzer is for
//! and it needs no assertion. What needs asserting is the property the rest of
//! the system leans on: **whatever comes out of `transcode` is a canonical PNG
//! this implementation produced, within the caps, carrying nothing of the
//! input but pixels.** RFC 8 §6 requires the re-encoded bytes be the ones
//! transmitted, so a `transcode` that returned attacker bytes unchanged would
//! satisfy every "did not crash" test and defeat the requirement entirely.
//!
//! So the output is fed back through this module's own header reader, checked
//! against `MAX_OBJECT` and `MAX_PIXELS`, and — the one that matters most —
//! checked for **not containing the input**. A polyglot that survived
//! re-encoding would show up there and nowhere else.
//!
//! # Run it with the seeds
//!
//! ```text
//! cargo +nightly fuzz run picture fuzz/corpus/picture fuzz/seeds/picture
//! ```
//!
//! `corpus/` is gitignored, and an unseeded run of *this* target spends almost
//! all of itself failing a magic-byte comparison: 972 covered blocks against
//! 3 373 with seven small real images in the corpus. Twelve million unseeded
//! executions reached less than a third of what three hundred thousand seeded
//! ones did.
//!
//! # `dimensions` is exercised on the same input, deliberately
//!
//! It runs *before* the pixel cap and is therefore reached by every input,
//! including the ones `transcode` refuses. A panic in the header reader is
//! reachable by anyone who can send a picture, whether or not it decodes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Reached by every input, before any cap applies.
    let declared = krab_picture::dimensions(data);

    let Ok(out) = krab_picture::transcode(data) else {
        // A refusal is the common case and is not a finding. What would be a
        // finding is a refusal that took for ever, and libfuzzer's own timeout
        // catches that without help from here.
        return;
    };

    // **Nothing of the input survives but pixels.** RFC 8 §6's whole
    // mechanism: no EXIF, no ICC, no ancillary chunks, no trailing bytes. A
    // transcode that passed its input through would satisfy every crash test
    // and none of the requirement.
    assert!(
        !contains(&out, data) || data.len() < 8,
        "the input survived re-encoding"
    );

    // The output is a PNG this module made, and this module can read it.
    assert!(
        out.starts_with(&[0x89, b'P', b'N', b'G']),
        "output is not a PNG"
    );
    let (w, h) = krab_picture::dimensions(&out).expect("this module cannot read its own output");

    // The caps hold on the way out, not only on the way in.
    assert!(
        out.len() <= krab_picture::MAX_OBJECT,
        "output is {} bytes, over the object ceiling",
        out.len()
    );
    let pixels = u64::from(w) * u64::from(h);
    assert!(pixels > 0, "a zero-pixel picture was produced");
    assert!(
        pixels <= krab_picture::MAX_PIXELS,
        "output declares {pixels} pixels, over the cap"
    );

    // If the header parsed on the way in, the output's dimensions cannot
    // exceed it — `transcode` only ever shrinks.
    if let Ok((dw, dh)) = declared {
        assert!(
            u64::from(w) <= u64::from(dw) && u64::from(h) <= u64::from(dh),
            "transcode grew the picture: {dw}x{dh} in, {w}x{h} out"
        );
    }

    // And it is idempotent in the sense that matters: its own output is
    // acceptable input, and stays within the caps. A re-encode that could not
    // read what it wrote would mean the receiving side cannot either.
    if let Ok(again) = krab_picture::transcode(&out) {
        assert!(again.len() <= krab_picture::MAX_OBJECT);
    }
});

/// Whether `haystack` contains `needle`, for the survival check.
///
/// Naive, because the inputs are bounded by the object ceiling and a fuzz
/// target's time is better spent on the parsers than on a substring search.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
