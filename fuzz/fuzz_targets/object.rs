//! Object parsing — RFC 1 §4, §8.1.
//!
//! `RoutingHeader::parse` is the one thing RFC 1 §10 requires *every* version
//! of *every* implementation to be able to read, forever: a relay that does not
//! understand an object still routes, filters and expires from these 16 bytes.
//! It is therefore the least revisable code in the system.
//!
//! `decode_envelope` and `verify_padding` follow it, and both run on bytes a
//! stranger supplied.
#![no_main]

use krab_core::object::{decode_envelope, verify_padding, RoutingHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The 16 bytes RFC 1 §10 makes permanent.
    if let Ok(h) = RoutingHeader::parse(data) {
        // A parsed header must round-trip: `write` of a parsed header must
        // reproduce the bytes it came from, or the header is not canonical and
        // the identifier covers something the parser did not represent.
        let written = h.write();
        assert_eq!(
            &written[..],
            &data[..16],
            "a parsed header did not round-trip"
        );
        // These must not panic on any header the parser accepted.
        let _ = h.bucket_size();
        let _ = h.expiry_secs();
        let _ = h.is_link_local();
    }

    if data.len() > 16 {
        if let Ok((env, consumed)) = decode_envelope(&data[16..]) {
            // A decoder reporting more consumed than it was given would let a
            // caller index past the buffer.
            assert!(consumed <= data.len() - 16, "consumed more than was offered");
            let _ = env.aad();
            let _ = env.write();
            let _ = verify_padding(data, consumed);
        }
    }
    let _ = verify_padding(data, data.len().saturating_sub(16));
});
