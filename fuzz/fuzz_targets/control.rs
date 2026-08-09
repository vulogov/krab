//! The wire protocol — RFC 4 §4.2, RFC 5.
//!
//! Control messages arrive from a peer that has completed a Noise handshake,
//! so they are authenticated — but authenticated is not trusted. RFC 4 §5.5
//! says "the archive is hostile input", and a courier archive is exactly these
//! records with no handshake at all.
#![no_main]

use krab_proto::control::Control;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Control::parse(data) {
        // Anything that parses must re-encode, and re-encoding must parse back
        // to the same message. A decoder that accepts what its encoder cannot
        // produce has a wider input language than the specification.
        let encoded = msg.write();
        match Control::parse(&encoded) {
            Ok(again) => assert_eq!(msg, again, "parse ∘ write ∘ parse diverged"),
            Err(e) => panic!("re-encoding a parsed message failed to parse: {e:?}"),
        }
    }
});
