//! The deterministic CBOR reader — RFC 1 §4.3.
//!
//! Everything else parses through this: envelopes, control messages,
//! credentials, ceremony state. It is the widest hostile-input surface in the
//! system and the only one every other decoder depends on.
//!
//! **What a finding looks like here:** a panic. The profile deliberately
//! unwinds rather than aborting, unlike the shipped binary, because a panic is
//! the thing being hunted rather than a thing to survive.
//!
//! The reader is also required to *reject* rather than accept: RFC 1 §4.3's
//! profile forbids indefinite lengths, floats, tags, non-canonical integers and
//! out-of-order map keys. Accepting one silently is a finding this target
//! cannot see — see `fuzz/README.md`.
#![no_main]

use krab_core::cbor::{Item, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Top-level item.
    let mut r = Reader::new(data);
    let _ = r.item();

    // Map traversal, which is where a length claim can outrun the buffer.
    let mut r = Reader::new(data);
    if let Ok(mut m) = r.map() {
        let mut guard = 0u32;
        while let Ok(Some(_key)) = m.key() {
            if m.value().is_err() {
                break;
            }
            // A malformed map must not be able to spin forever; if it can,
            // that is the finding.
            guard += 1;
            if guard > 100_000 {
                panic!("map traversal did not terminate");
            }
        }
    }

    // Nested reads: an item that claims to be a map head inside a byte string.
    let mut r = Reader::new(data);
    if let Ok(Item::Bstr(inner)) = r.item() {
        let mut r2 = Reader::new(inner);
        let _ = r2.item();
    }
});
