//! Control opcodes, RFC 5 §3.
//!
//! Control messages are **not objects**: never stored, never hashed, never
//! relayed, never assigned an identifier. They exist for the duration of one
//! reconciliation.
//!
//! Deterministic CBOR arrays with a leading opcode, carried over RFC 4 §4's
//! framing. The same encoding runs over a socket and into a courier archive —
//! RFC 4 §5.5 makes the archive "the control-message sequence written to disk
//! with the round trips removed", and that only works if the messages are
//! transport-agnostic bytes.

use alloc::vec::Vec;
use krab_core::cbor;
use krab_core::object::ObjectId;
use krab_crypto::Fingerprint;

/// Truncated identifier width in manifests, RFC 1 §9.3.
pub const TRUNC: usize = krab_core::object::TRUNC_LEN;

/// One manifest row: `(expiry_min, id[0..16])` — 20 bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// Absolute expiry in minutes, as in the frozen header.
    pub expiry_min: u32,
    /// The leading 12 bytes of the object identifier.
    pub id: [u8; TRUNC],
}

impl Entry {
    /// Build a row from a full identifier.
    pub fn new(expiry_min: u32, id: &ObjectId) -> Entry {
        Entry {
            expiry_min,
            id: id.truncated(),
        }
    }
}

/// A fingerprint over a half-open expiry range, RFC 5 §4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// Inclusive lower bound, expiry minutes.
    pub lo: u32,
    /// Exclusive upper bound.
    pub hi: u32,
    /// Additive fingerprint over the range.
    pub fingerprint: Fingerprint,
    /// Objects in the range.
    pub count: u32,
}

/// The eight opcodes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Control {
    /// 0 — open a reconciliation.
    Hello {
        /// Protocol version.
        version: u16,
        /// Sender's node identifier.
        node: [u8; 32],
        /// Oldest expiry the sender still holds (RFC 5 §3).
        ///
        /// A peer offline longer than this learns immediately that the
        /// exchange cannot close its gap and can stop, rather than burning a
        /// full cycle to discover it.
        watermark: u32,
        /// Hash of the four filter components, derived from the credential.
        filter_digest: [u8; 32],
    },
    /// 1 — everything the sender holds within the filter.
    Manifest {
        /// Repeated so a mismatch is caught before the rows are trusted.
        filter_digest: [u8; 32],
        /// Rows in `(expiry, id)` order.
        entries: Vec<Entry>,
    },
    /// 2 — request a subset.
    Want(Vec<[u8; TRUNC]>),
    /// 3 — deliver one object's canonical bytes.
    Obj(Vec<u8>),
    /// 4 — this direction is complete.
    Done,
    /// 5 — range fingerprints for an RBSR descent.
    Range(Vec<Range>),
    /// 6 — the descent has converged.
    RangeDone,
    /// 7 — close.
    Bye {
        /// Machine-readable close reason.
        reason: u16,
    },
    /// 8 — one end's half of a re-key, and its current policy.
    ///
    /// See `krab_crypto::rekey`. The payload is already sealed under a carrier
    /// key derived from `root_n` before it reaches this layer, so what travels
    /// here is opaque: an eavesdropper on the Noise session learns the two
    /// nodes re-keyed and nothing else.
    ///
    /// Policy rides along because a re-key is a periodic, authenticated,
    /// encrypted, peer-to-peer state update, and so is a policy change.
    /// Building a second mechanism for the same shape is how two mechanisms
    /// come to disagree.
    Rekey {
        /// The ratchet index this re-key produces — `n+1`.
        index: u32,
        /// Sealed contribution and policy. Opaque here.
        sealed: Vec<u8>,
        /// Ephemeral X25519 public key for the healing half of the mix.
        ///
        /// In the clear: it is a public key, and both ends need it before
        /// either can derive the shared secret that protects everything else.
        ephemeral: [u8; 32],
    },
    /// 10 — a signed card, during first contact over a live link.
    ///
    /// RFC 3 §11 step 1's artifact, on a session instead of in a file. It is
    /// public and signed, so carrying it here costs nothing that carrying it
    /// by email would not.
    Card(Vec<u8>),
    /// 11 — a reservoir contribution, during first contact.
    ///
    /// **Half a shared secret, on a channel secured by X25519.** The link is
    /// therefore `Channel::Network` and earns no post-quantum credit: an
    /// adversary recording this session and later breaking X25519 recovers it.
    /// `peer reseal` is how that is repaired without redoing the peering.
    Contribution(Vec<u8>),
    /// 9 — `index` adopted, and here is the confirmation.
    ///
    /// A re-key that half-completes is worse than one that fails: one end
    /// advances, the other does not, and every subsequent tag silently stops
    /// matching. RFC 0 §6 guarantees nobody is told.
    RekeyAck {
        /// The index being confirmed.
        index: u32,
        /// `krab_crypto::rekey::confirm_tag` of the root just derived.
        confirm: [u8; 8],
    },
}

/// Why a control message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a well-formed deterministic CBOR array with a known opcode.
    Malformed,
    /// A field was the wrong type or width.
    BadField,
    /// The opcode is not one of the eight.
    UnknownOpcode,
}

fn bytes32(v: &[u8]) -> Result<[u8; 32], Error> {
    v.try_into().map_err(|_| Error::BadField)
}

impl Control {
    /// Opcode.
    pub fn opcode(&self) -> u64 {
        match self {
            Control::Hello { .. } => 0,
            Control::Manifest { .. } => 1,
            Control::Want(_) => 2,
            Control::Obj(_) => 3,
            Control::Done => 4,
            Control::Range(_) => 5,
            Control::RangeDone => 6,
            Control::Bye { .. } => 7,
            Control::Rekey { .. } => 8,
            Control::RekeyAck { .. } => 9,
            Control::Card(_) => 10,
            Control::Contribution(_) => 11,
        }
    }

    /// Encode to deterministic CBOR.
    pub fn write(&self) -> Vec<u8> {
        let mut w = cbor::Writer::new();
        match self {
            Control::Hello {
                version,
                node,
                watermark,
                filter_digest,
            } => {
                w.array(5)
                    .uint(0)
                    .uint(*version as u64)
                    .bstr(node)
                    .uint(*watermark as u64);
                w.bstr(filter_digest);
            }
            Control::Manifest {
                filter_digest,
                entries,
            } => {
                w.array(3)
                    .uint(1)
                    .bstr(filter_digest)
                    .array(entries.len() * 2);
                for e in entries {
                    w.uint(e.expiry_min as u64).bstr(&e.id);
                }
            }
            Control::Want(ids) => {
                w.array(2).uint(2).array(ids.len());
                for id in ids {
                    w.bstr(id);
                }
            }
            Control::Obj(b) => {
                w.array(2).uint(3).bstr(b);
            }
            Control::Done => {
                w.array(1).uint(4);
            }
            Control::Range(rs) => {
                w.array(2).uint(5).array(rs.len() * 4);
                for r in rs {
                    w.uint(r.lo as u64)
                        .uint(r.hi as u64)
                        .bstr(&r.fingerprint.to_bytes())
                        .uint(r.count as u64);
                }
            }
            Control::RangeDone => {
                w.array(1).uint(6);
            }
            Control::Bye { reason } => {
                w.array(2).uint(7).uint(*reason as u64);
            }
            Control::Rekey {
                index,
                sealed,
                ephemeral,
            } => {
                w.array(4)
                    .uint(8)
                    .uint(*index as u64)
                    .bstr(sealed)
                    .bstr(ephemeral);
            }
            Control::RekeyAck { index, confirm } => {
                w.array(3).uint(9).uint(*index as u64).bstr(confirm);
            }
            Control::Card(b) => {
                w.array(2).uint(10).bstr(b);
            }
            Control::Contribution(b) => {
                w.array(2).uint(11).bstr(b);
            }
        }
        w.finish()
    }

    /// How many elements the outer array holds, for each opcode.
    ///
    /// The mirror of [`Control::write`], and the only place the two tables
    /// meet — `every_opcode_round_trips` walks both, so a new opcode written
    /// without an arity fails to parse rather than parsing loosely.
    fn arity(op: u64) -> Option<usize> {
        Some(match op {
            0 => 5,  // Hello: version, node, watermark, filter digest
            1 => 3,  // Manifest: filter digest, rows
            2 => 2,  // Want: identifiers
            3 => 2,  // Obj: bytes
            4 => 1,  // Done
            5 => 2,  // Range: descriptions
            6 => 1,  // RangeDone
            7 => 2,  // Bye: reason
            8 => 4,  // Rekey: index, sealed, ephemeral
            9 => 3,  // RekeyAck: index, confirmation
            10 => 2, // Card: bytes
            11 => 2, // Contribution: bytes
            _ => return None,
        })
    }

    /// Decode. Never panics: this is pre-authentication input (RFC 0 §9).
    /// Decode one control message.
    ///
    /// # Never allocate on a declared count
    ///
    /// The three collection arms build with `Vec::new` and push, rather than
    /// pre-sizing from the array length the input claims. RFC 4 §9 states the
    /// rule for frames — "the length is validated **before** any allocation" —
    /// and `frame::read` obeys it; this decoder did not, one layer down.
    ///
    /// A found crash, not a hypothetical: a 40-byte frame whose CBOR array
    /// head declares roughly 2⁶⁰ items reached `Vec::with_capacity`, which
    /// multiplied by the element size and overflowed. RFC 7 §9 sets
    /// `panic = "abort"` so a core dump cannot carry key material, which means
    /// the panic was not a caught error — **the node died.** Any peer past the
    /// Noise handshake could do it, repeatedly, for the cost of one small
    /// frame.
    ///
    /// Pushing removes the attacker's control over the allocation entirely: a
    /// truncated body fails on the first missing element, and the vector never
    /// grows past what the buffer actually contained. Capping the capacity
    /// against the remaining bytes would also work and is one arithmetic
    /// mistake away from the same bug.
    pub fn parse(bytes: &[u8]) -> Result<Control, Error> {
        let mut r = cbor::Reader::new(bytes);
        let n = match r.item().map_err(|_| Error::Malformed)? {
            cbor::Item::Array(n) => n,
            _ => return Err(Error::Malformed),
        };
        if n == 0 {
            return Err(Error::Malformed);
        }
        let op = match r.item().map_err(|_| Error::Malformed)? {
            cbor::Item::Uint(v) => v,
            _ => return Err(Error::Malformed),
        };
        // **The outer length is part of the message, not decoration.** It was
        // read, checked against zero, and then ignored — so every opcode
        // accepted an array of any length, and the same logical message had
        // unboundedly many encodings. RFC 1 §4.3 requires deterministic CBOR
        // precisely so that it does not: a canonical encoding is what lets a
        // signature or a digest over a message mean anything.
        if Control::arity(op).ok_or(Error::UnknownOpcode)? != n {
            return Err(Error::Malformed);
        }
        let uint = |r: &mut cbor::Reader| -> Result<u64, Error> {
            match r.item().map_err(|_| Error::Malformed)? {
                cbor::Item::Uint(v) => Ok(v),
                _ => Err(Error::BadField),
            }
        };
        let bstr = |r: &mut cbor::Reader<'_>| -> Result<Vec<u8>, Error> {
            match r.item().map_err(|_| Error::Malformed)? {
                cbor::Item::Bstr(v) => Ok(v.to_vec()),
                _ => Err(Error::BadField),
            }
        };
        let arr = |r: &mut cbor::Reader| -> Result<usize, Error> {
            match r.item().map_err(|_| Error::Malformed)? {
                cbor::Item::Array(v) => Ok(v),
                _ => Err(Error::BadField),
            }
        };
        let u32f = |v: u64| -> Result<u32, Error> { u32::try_from(v).map_err(|_| Error::BadField) };
        // **Narrowing is a check, not a cast.** `u32f(..)? as u16` silently
        // truncated: a `version` of 65 536 parsed as 0, which is the value
        // that means "the version this node speaks". A field whose out-of-
        // range values fold onto a meaningful one is not a version field.
        let u16f = |v: u64| -> Result<u16, Error> { u16::try_from(v).map_err(|_| Error::BadField) };

        let msg = match op {
            0 => {
                let version = u16f(uint(&mut r)?)?;
                let node = bytes32(&bstr(&mut r)?)?;
                let watermark = u32f(uint(&mut r)?)?;
                let filter_digest = bytes32(&bstr(&mut r)?)?;
                Control::Hello {
                    version,
                    node,
                    watermark,
                    filter_digest,
                }
            }
            1 => {
                let filter_digest = bytes32(&bstr(&mut r)?)?;
                let n = arr(&mut r)?;
                if n % 2 != 0 {
                    return Err(Error::BadField);
                }
                let mut entries = Vec::new();
                for _ in 0..n / 2 {
                    let expiry_min = u32f(uint(&mut r)?)?;
                    let id: [u8; TRUNC] = bstr(&mut r)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::BadField)?;
                    entries.push(Entry { expiry_min, id });
                }
                Control::Manifest {
                    filter_digest,
                    entries,
                }
            }
            2 => {
                let n = arr(&mut r)?;
                let mut ids = Vec::new();
                for _ in 0..n {
                    ids.push(
                        bstr(&mut r)?
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::BadField)?,
                    );
                }
                Control::Want(ids)
            }
            3 => Control::Obj(bstr(&mut r)?),
            4 => Control::Done,
            5 => {
                let n = arr(&mut r)?;
                if n % 4 != 0 {
                    return Err(Error::BadField);
                }
                let mut rs = Vec::new();
                for _ in 0..n / 4 {
                    let lo = u32f(uint(&mut r)?)?;
                    let hi = u32f(uint(&mut r)?)?;
                    let fingerprint = Fingerprint::from_bytes(&bytes32(&bstr(&mut r)?)?);
                    let count = u32f(uint(&mut r)?)?;
                    rs.push(Range {
                        lo,
                        hi,
                        fingerprint,
                        count,
                    });
                }
                Control::Range(rs)
            }
            6 => Control::RangeDone,
            7 => Control::Bye {
                reason: u16f(uint(&mut r)?)?,
            },
            8 => {
                let index = u32f(uint(&mut r)?)?;
                // No `with_capacity` on a declared length anywhere near this:
                // a 40-byte frame declaring a huge array killed the node once
                // already (see `ADVERSARIAL-PASS.md`). `bstr` is bounded by
                // what actually arrived.
                let sealed = bstr(&mut r)?.to_vec();
                let ephemeral = bytes32(&bstr(&mut r)?)?;
                Control::Rekey {
                    index,
                    sealed,
                    ephemeral,
                }
            }
            10 => Control::Card(bstr(&mut r)?.to_vec()),
            11 => Control::Contribution(bstr(&mut r)?.to_vec()),
            9 => {
                let index = u32f(uint(&mut r)?)?;
                let raw = bstr(&mut r)?;
                let confirm: [u8; 8] = raw.try_into().map_err(|_| Error::BadField)?;
                Control::RekeyAck { index, confirm }
            }
            // `arity` already refused anything not listed there, so this is
            // unreachable rather than a second gate — kept so the two tables
            // cannot drift apart silently.
            _ => return Err(Error::UnknownOpcode),
        };

        // **Nothing may follow the message.** The reader stopped where the
        // message ended and never asked whether the buffer did, so any number
        // of trailing bytes rode along inside the frame and parsed to exactly
        // the same value. That is the same malleability the outer length
        // check above closes, one layer out.
        if !r.is_done() {
            return Err(Error::Malformed);
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(n: u8) -> ObjectId {
        ObjectId([n; 32])
    }

    fn all() -> Vec<Control> {
        alloc::vec![
            Control::Hello {
                version: 1,
                node: [3; 32],
                watermark: 4_200,
                filter_digest: [9; 32]
            },
            Control::Manifest {
                filter_digest: [9; 32],
                entries: alloc::vec![Entry::new(100, &oid(1)), Entry::new(200, &oid(2))],
            },
            Control::Want(alloc::vec![oid(1).truncated(), oid(2).truncated()]),
            Control::Obj(alloc::vec![0xAB; 64]),
            Control::Done,
            Control::Range(alloc::vec![Range {
                lo: 0,
                hi: 1_440,
                fingerprint: Fingerprint::over([oid(1), oid(2)].iter()),
                count: 2,
            }]),
            Control::RangeDone,
            Control::Bye { reason: 0 },
        ]
    }

    #[test]
    fn every_opcode_round_trips() {
        for msg in all() {
            let bytes = msg.write();
            assert_eq!(
                Control::parse(&bytes),
                Ok(msg.clone()),
                "opcode {}",
                msg.opcode()
            );
        }
    }

    #[test]
    fn opcodes_match_rfc5_table() {
        let ops: Vec<u64> = all().iter().map(|m| m.opcode()).collect();
        assert_eq!(ops, alloc::vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    /// RFC 1 §9.3 sizes a manifest row at **16 bytes** — `expiry` as a raw
    /// `u32` plus a 12-byte identifier. That is a packed-binary figure, and
    /// RFC 5 §3 carries manifests as **deterministic CBOR**, where a realistic
    /// expiry needs a 5-byte uint head and the identifier a 1-byte bstr head:
    ///
    /// ```text
    ///   RFC 1 §9.3 packed   4 + 12 = 16 B/row
    ///   RFC 5 §3 as CBOR    5 + 13 = 18 B/row     +12.5%
    /// ```
    ///
    /// SIM-1's LoRa starvation measurement used 16, so the real cost is
    /// higher and its conclusion holds a fortiori. Recorded here rather than
    /// silently accommodated.
    /// **Found by fuzzing.** A small frame declaring an enormous array reached
    /// `Vec::with_capacity`, overflowed, and — under RFC 7 §9's
    /// `panic = "abort"` — killed the node. Reachable by any peer past the
    /// handshake, and by anyone at all through a courier archive.
    #[test]
    fn a_huge_declared_array_does_not_allocate() {
        // The reduced crash input: 0x9b is a CBOR array head with an 8-byte
        // length, so this claims ~2^60 elements in 46 bytes.
        const CRASH: &[u8] = &[
            0x9b, 0x9b, 0x9b, 0x9b, 0x9b, 0x9b, 0x9b, 0x02, 0x02, 0x02, 0x9b, 0x9b, 0x77, 0x9b,
            0x91, 0x00, 0xfe, 0x99, 0x00, 0x77, 0x2d, 0x84, 0x05, 0x84, 0xff, 0x00, 0x2d, 0x2d,
            0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x9b, 0x91, 0x00,
            0xfe, 0x99, 0x00, 0x00,
        ];
        assert!(
            Control::parse(CRASH).is_err(),
            "it must be refused, not fatal"
        );

        // Every message type, with a declared length far beyond the buffer.
        for tag in 0u8..=7 {
            for head in [0x9bu8, 0x9a, 0x99, 0x98] {
                let probe = [
                    0x82, tag, head, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                ];
                let _ = Control::parse(&probe);
            }
        }
    }

    #[test]
    fn a_manifest_row_costs_twenty_two_bytes_as_cbor_not_twenty() {
        // A realistic expiry: minutes since the Unix epoch is ~29.7 million,
        // which needs a 5-byte CBOR head. Small test values do not.
        const REALISTIC: u32 = 29_766_240;
        let one = Control::Manifest {
            filter_digest: [0; 32],
            entries: alloc::vec![Entry::new(REALISTIC, &oid(1))],
        };
        let two = Control::Manifest {
            filter_digest: [0; 32],
            entries: alloc::vec![
                Entry::new(REALISTIC, &oid(1)),
                Entry::new(REALISTIC + 1, &oid(2))
            ],
        };
        let delta = two.write().len() - one.write().len();
        assert_eq!(delta, 22, "CBOR row cost, against RFC 1 §9.3\'s packed 20");
    }

    #[test]
    fn rejects_unknown_opcodes_and_truncation() {
        let mut w = cbor::Writer::new();
        w.array(1).uint(99);
        assert_eq!(Control::parse(&w.finish()), Err(Error::UnknownOpcode));

        let full = Control::Hello {
            version: 1,
            node: [0; 32],
            watermark: 0,
            filter_digest: [0; 32],
        }
        .write();
        for n in 0..full.len() {
            // Truncated input must error, never panic.
            let _ = Control::parse(&full[..n]);
        }
    }

    #[test]
    fn rejects_wrong_width_identifiers() {
        let mut w = cbor::Writer::new();
        w.array(2).uint(2).array(1).bstr(&[0u8; 8]); // 8-byte id, not 12
        assert_eq!(Control::parse(&w.finish()), Err(Error::BadField));
    }

    /// RFC 0 §9 — reachable pre-authentication, so it must never panic.
    #[test]
    fn never_panics_on_arbitrary_input() {
        for a in 0u16..=255 {
            let _ = Control::parse(&[a as u8]);
            for b in 0u16..=255 {
                let _ = Control::parse(&[a as u8, b as u8]);
            }
        }
        for n in 0..64usize {
            let _ = Control::parse(&alloc::vec![0xABu8; n]);
        }
    }

    /// The two re-key opcodes survive a round trip, and a truncated one is
    /// refused rather than accepted with a short field.
    #[test]
    fn rekey_messages_round_trip() {
        let m = Control::Rekey {
            index: 4_294_967_295,
            sealed: alloc::vec![7u8; 96],
            ephemeral: [3u8; 32],
        };
        assert_eq!(Control::parse(&m.write()), Ok(m.clone()));

        let a = Control::RekeyAck {
            index: 12,
            confirm: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(Control::parse(&a.write()), Ok(a));

        // A confirmation of the wrong width is a different message, not a
        // shorter one — accepting it would compare eight bytes against seven.
        let short = {
            let mut w = cbor::Writer::new();
            w.array(3).uint(9).uint(12).bstr(&[1, 2, 3]);
            w.finish()
        };
        assert_eq!(Control::parse(&short), Err(Error::BadField));
    }

    /// **Pre-authentication input.** A declared length must never become an
    /// allocation — the defect that let a 40-byte frame kill a node.
    #[test]
    fn a_rekey_declaring_an_enormous_payload_does_not_allocate_it() {
        // A bstr header claiming 4 GiB, with nothing behind it.
        let mut raw = alloc::vec![0x84, 0x08, 0x0c];
        raw.push(0x5a);
        raw.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(Control::parse(&raw).is_err());
    }

    /// **The outer array length is part of the message.** It was read, checked
    /// against zero, and then ignored, so every opcode accepted an array of
    /// any length and the same logical message had unboundedly many
    /// encodings. RFC 1 §4.3 requires deterministic CBOR precisely so it does
    /// not.
    #[test]
    fn the_outer_array_length_must_match_the_opcode() {
        for msg in all() {
            let bytes = msg.write();
            assert_eq!(Control::parse(&bytes), Ok(msg.clone()), "the fixture");
            // The head is `array(n)`, a single byte for n < 24. Rewriting it
            // changes nothing else about the encoding.
            let head = bytes[0];
            assert_eq!(head & 0xE0, 0x80, "array head expected");
            for wrong in [1u8, 2, 3, 4, 5, 6] {
                if wrong == head & 0x1F {
                    continue;
                }
                let mut bad = bytes.clone();
                bad[0] = 0x80 | wrong;
                assert!(
                    Control::parse(&bad).is_err(),
                    "opcode {} accepted an array of {wrong}",
                    msg.opcode()
                );
            }
        }
    }

    /// **Nothing may follow the message.** The reader stopped where the
    /// message ended and never asked whether the buffer did, so any number of
    /// trailing bytes rode along inside the frame and parsed to the same
    /// value — the same malleability, one layer out.
    #[test]
    fn trailing_bytes_are_refused() {
        for msg in all() {
            let mut bytes = msg.write();
            bytes.extend_from_slice(&[0xFF, 0x00, 0x42]);
            assert!(
                Control::parse(&bytes).is_err(),
                "opcode {} accepted trailing bytes",
                msg.opcode()
            );
        }
    }

    /// **Narrowing is a check, not a cast.** `u32f(..)? as u16` truncated, so
    /// a version of 65 536 parsed as 0 — the value that means "the version
    /// this node speaks". A field whose out-of-range values fold onto a
    /// meaningful one is not a version field.
    #[test]
    fn an_out_of_range_version_is_refused_not_truncated() {
        let mut w = cbor::Writer::new();
        w.array(5)
            .uint(0)
            .uint(65_536)
            .bstr(&[3u8; 32])
            .uint(4_200)
            .bstr(&[9u8; 32]);
        let bytes = w.finish();
        assert_eq!(Control::parse(&bytes), Err(Error::BadField));

        // And the same for a close reason.
        let mut w = cbor::Writer::new();
        w.array(2).uint(7).uint(65_536 + 7);
        assert_eq!(Control::parse(&w.finish()), Err(Error::BadField));

        // The largest value that does fit still round-trips.
        let mut w = cbor::Writer::new();
        w.array(2).uint(7).uint(65_535);
        assert_eq!(
            Control::parse(&w.finish()),
            Ok(Control::Bye { reason: 65_535 })
        );
    }

    /// `arity` and `write` must not drift: a new opcode written without an
    /// entry there would parse loosely, which is the state this replaced.
    #[test]
    fn every_written_opcode_has_an_arity() {
        for op in 0..=11u64 {
            assert!(Control::arity(op).is_some(), "opcode {op} has no arity");
        }
        assert_eq!(Control::arity(12), None);
    }
}
