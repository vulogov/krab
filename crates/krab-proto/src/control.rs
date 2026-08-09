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
        }
        w.finish()
    }

    /// Decode. Never panics: this is pre-authentication input (RFC 0 §9).
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

        match op {
            0 => {
                let version = u32f(uint(&mut r)?)? as u16;
                let node = bytes32(&bstr(&mut r)?)?;
                let watermark = u32f(uint(&mut r)?)?;
                let filter_digest = bytes32(&bstr(&mut r)?)?;
                Ok(Control::Hello {
                    version,
                    node,
                    watermark,
                    filter_digest,
                })
            }
            1 => {
                let filter_digest = bytes32(&bstr(&mut r)?)?;
                let n = arr(&mut r)?;
                if n % 2 != 0 {
                    return Err(Error::BadField);
                }
                let mut entries = Vec::with_capacity(n / 2);
                for _ in 0..n / 2 {
                    let expiry_min = u32f(uint(&mut r)?)?;
                    let id: [u8; TRUNC] = bstr(&mut r)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::BadField)?;
                    entries.push(Entry { expiry_min, id });
                }
                Ok(Control::Manifest {
                    filter_digest,
                    entries,
                })
            }
            2 => {
                let n = arr(&mut r)?;
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    ids.push(
                        bstr(&mut r)?
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::BadField)?,
                    );
                }
                Ok(Control::Want(ids))
            }
            3 => Ok(Control::Obj(bstr(&mut r)?)),
            4 => Ok(Control::Done),
            5 => {
                let n = arr(&mut r)?;
                if n % 4 != 0 {
                    return Err(Error::BadField);
                }
                let mut rs = Vec::with_capacity(n / 4);
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
                Ok(Control::Range(rs))
            }
            6 => Ok(Control::RangeDone),
            7 => Ok(Control::Bye {
                reason: u32f(uint(&mut r)?)? as u16,
            }),
            _ => Err(Error::UnknownOpcode),
        }
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
}
