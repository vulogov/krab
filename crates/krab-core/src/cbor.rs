//! Deterministic CBOR, RFC 1 §4.3.
//!
//! # Why this is hand-written
//!
//! RFC 1 §4.3 is a *restriction* of RFC 8949, and the restriction is the
//! security property: an object's identifier covers its bytes, so any encoding
//! latitude is a route to two objects with the same meaning and different
//! identifiers. A general-purpose CBOR library accepts the whole format and
//! would have to be constrained after the fact; this accepts only what RFC 1
//! defines and rejects the rest by construction.
//!
//! The profile, verbatim from RFC 1 §4.3:
//!
//! 1. Integers in shortest form.
//! 2. Definite lengths only. Indefinite-length items MUST be rejected.
//! 3. Map keys are unsigned integers, ascending, no duplicates.
//! 4. No floating-point values anywhere.
//! 5. No tags, no `undefined`, no `simple` values other than `false`/`true`.
//!
//! # Threat model
//!
//! RFC 0 §9 names this parser as untrusted input reachable pre-authentication,
//! and a fuzz target. It therefore MUST NOT panic and MUST NOT allocate on a
//! declared length before checking that length against the input remaining —
//! a four-byte header claiming four gigabytes is the cheapest attack there is.
//! [`Reader`] borrows from the input and allocates nothing.

use alloc::vec::Vec;

/// Why a decode was rejected.
///
/// Deliberately coarse: a parser for untrusted input should not narrate which
/// check it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input ended mid-item.
    Truncated,
    /// Well-formed CBOR that this profile forbids — indefinite length, a
    /// float, a tag, a non-canonical integer, or out-of-order map keys.
    NotCanonical,
    /// Not CBOR, or a major type this profile does not define.
    Malformed,
}

/// Major types this profile admits.
const MT_UINT: u8 = 0;
const MT_BSTR: u8 = 2;
const MT_TSTR: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_SIMPLE: u8 = 7;

const AI_INDEFINITE: u8 = 31;
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;

/// Shortest-form encoded length of `v` as a CBOR head argument.
///
/// This is the whole of rule 1, and `krab-sizes` depends on it agreeing with
/// the size model — see `apps/krab-sizes/src/cbor.rs`.
pub const fn head_len(v: u64) -> usize {
    match v {
        0..=23 => 1,
        24..=0xFF => 2,
        0x100..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// Append a canonical head for `major` carrying argument `v`.
fn put_head(out: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    match v {
        0..=23 => out.push(m | v as u8),
        24..=0xFF => {
            out.push(m | 24);
            out.push(v as u8);
        }
        0x100..=0xFFFF => {
            out.push(m | 25);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(m | 26);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

/// Canonical encoder. Every method emits shortest-form, definite-length items.
///
/// Map key ordering is the caller's responsibility on write and is *checked*
/// on read — an encoder that emits keys out of order produces bytes this
/// crate's own [`Reader`] rejects, which is the intended failure.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new empty writer.
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }
    /// Emit an unsigned integer.
    pub fn uint(&mut self, v: u64) -> &mut Self {
        put_head(&mut self.buf, MT_UINT, v);
        self
    }
    /// Emit a byte string.
    pub fn bstr(&mut self, v: &[u8]) -> &mut Self {
        put_head(&mut self.buf, MT_BSTR, v.len() as u64);
        self.buf.extend_from_slice(v);
        self
    }
    /// Emit a text string. The caller guarantees UTF-8 by passing `&str`.
    pub fn tstr(&mut self, v: &str) -> &mut Self {
        put_head(&mut self.buf, MT_TSTR, v.len() as u64);
        self.buf.extend_from_slice(v.as_bytes());
        self
    }
    /// Emit a map head of `n` pairs. Keys MUST follow in ascending order.
    pub fn map(&mut self, n: usize) -> &mut Self {
        put_head(&mut self.buf, MT_MAP, n as u64);
        self
    }
    /// Emit an array head of `n` items.
    pub fn array(&mut self, n: usize) -> &mut Self {
        put_head(&mut self.buf, MT_ARRAY, n as u64);
        self
    }
    /// Emit `true` or `false`. No other simple value is representable.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf
            .push((MT_SIMPLE << 5) | if v { SIMPLE_TRUE } else { SIMPLE_FALSE });
        self
    }
    /// Consume the writer, yielding the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// One decoded item. Strings borrow from the input; nothing is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    /// An unsigned integer.
    Uint(u64),
    /// A byte string.
    Bstr(&'a [u8]),
    /// A text string, already validated as UTF-8.
    Tstr(&'a str),
    /// An array head; `n` items follow.
    Array(usize),
    /// A map head; `n` key/value pairs follow.
    Map(usize),
    /// `true` or `false`.
    Bool(bool),
}

/// Strict decoder over a byte slice.
///
/// Borrows throughout and allocates nothing, so a declared length can never
/// cause an allocation — it can only fail to fit the remaining input.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the start of `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Reader { input, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Whether the whole input has been consumed.
    pub fn is_done(&self) -> bool {
        self.pos == self.input.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        // Checked against the *actual* input, never against a declared length.
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.input.len() {
            return Err(Error::Truncated);
        }
        let s = &self.input[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Read a head, returning `(major, argument)`.
    ///
    /// Enforces rules 1 and 2: shortest form and definite length.
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let b = *self.take(1)?.first().ok_or(Error::Truncated)?;
        let major = b >> 5;
        let ai = b & 0x1f;
        let v = match ai {
            0..=23 => ai as u64,
            24 => {
                let n = self.take(1)?[0] as u64;
                // Rule 1: values below 24 must use the one-byte form.
                if n < 24 {
                    return Err(Error::NotCanonical);
                }
                n
            }
            25 => {
                let b = self.take(2)?;
                let n = u16::from_be_bytes([b[0], b[1]]) as u64;
                if n <= 0xFF {
                    return Err(Error::NotCanonical);
                }
                n
            }
            26 => {
                let b = self.take(4)?;
                let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if n <= 0xFFFF {
                    return Err(Error::NotCanonical);
                }
                n
            }
            27 => {
                let b = self.take(8)?;
                let n = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if n <= 0xFFFF_FFFF {
                    return Err(Error::NotCanonical);
                }
                n
            }
            // Rule 2. 31 is indefinite length; 28..30 are reserved.
            AI_INDEFINITE => return Err(Error::NotCanonical),
            _ => return Err(Error::Malformed),
        };
        Ok((major, v))
    }

    /// Decode the next item.
    pub fn item(&mut self) -> Result<Item<'a>, Error> {
        let (major, v) = self.head()?;
        match major {
            MT_UINT => Ok(Item::Uint(v)),
            MT_BSTR => {
                let n = usize::try_from(v).map_err(|_| Error::Truncated)?;
                Ok(Item::Bstr(self.take(n)?))
            }
            MT_TSTR => {
                let n = usize::try_from(v).map_err(|_| Error::Truncated)?;
                let b = self.take(n)?;
                core::str::from_utf8(b)
                    .map(Item::Tstr)
                    .map_err(|_| Error::Malformed)
            }
            MT_ARRAY => Ok(Item::Array(
                usize::try_from(v).map_err(|_| Error::Truncated)?,
            )),
            MT_MAP => Ok(Item::Map(usize::try_from(v).map_err(|_| Error::Truncated)?)),
            MT_SIMPLE => match v {
                x if x == SIMPLE_FALSE as u64 => Ok(Item::Bool(false)),
                x if x == SIMPLE_TRUE as u64 => Ok(Item::Bool(true)),
                // Rule 4 and rule 5: floats are major 7 with ai 25/26/27,
                // `null`/`undefined` are 22/23, and everything else here is
                // an undefined simple value.
                _ => Err(Error::NotCanonical),
            },
            // Rule 5: major 6 is a tag. Major 1 is a negative integer, which
            // no field in RFC 1 uses.
            _ => Err(Error::NotCanonical),
        }
    }

    /// Read a map head and check rule 3 as pairs are consumed.
    ///
    /// Returns a cursor that yields keys in order and rejects a key that is
    /// not a strictly ascending unsigned integer.
    pub fn map(&mut self) -> Result<MapReader<'a, '_>, Error> {
        match self.item()? {
            Item::Map(n) => Ok(MapReader {
                r: self,
                left: n,
                last: None,
            }),
            _ => Err(Error::Malformed),
        }
    }
}

/// Cursor over a map, enforcing RFC 1 §4.3 rule 3.
#[derive(Debug)]
pub struct MapReader<'a, 'r> {
    r: &'r mut Reader<'a>,
    left: usize,
    last: Option<u64>,
}

impl<'a> MapReader<'a, '_> {
    /// Pairs not yet consumed.
    pub fn left(&self) -> usize {
        self.left
    }

    /// Read the next key, rejecting duplicates and descending order.
    ///
    /// Returns `None` when the map is exhausted. The value must then be read
    /// from the underlying reader via [`MapReader::value`].
    pub fn key(&mut self) -> Result<Option<u64>, Error> {
        if self.left == 0 {
            return Ok(None);
        }
        let k = match self.r.item()? {
            Item::Uint(k) => k,
            // Rule 3: keys are unsigned integers.
            _ => return Err(Error::NotCanonical),
        };
        // Rule 3: ascending, no duplicates. `<=` catches both.
        if let Some(prev) = self.last {
            if k <= prev {
                return Err(Error::NotCanonical);
            }
        }
        self.last = Some(k);
        self.left -= 1;
        Ok(Some(k))
    }

    /// Read the value paired with the key just returned.
    pub fn value(&mut self) -> Result<Item<'a>, Error> {
        self.r.item()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn head_lengths_match_the_size_model() {
        // These boundaries are what krab-sizes computes RFC 1's byte counts
        // from; if they diverge, the published tables are wrong.
        assert_eq!(head_len(23), 1);
        assert_eq!(head_len(24), 2);
        assert_eq!(head_len(255), 2);
        assert_eq!(head_len(256), 3);
        assert_eq!(head_len(65_535), 3);
        assert_eq!(head_len(65_536), 5);
        assert_eq!(head_len(0xFFFF_FFFF), 5);
        assert_eq!(head_len(0x1_0000_0000), 9);
    }

    #[test]
    fn round_trips_every_supported_item() {
        let mut w = Writer::new();
        w.map(3)
            .uint(0)
            .uint(1)
            .uint(1)
            .bstr(&[1, 2, 3])
            .uint(2)
            .tstr("krab");
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        let mut m = r.map().unwrap();
        assert_eq!(m.key().unwrap(), Some(0));
        assert_eq!(m.value().unwrap(), Item::Uint(1));
        assert_eq!(m.key().unwrap(), Some(1));
        assert_eq!(m.value().unwrap(), Item::Bstr(&[1, 2, 3]));
        assert_eq!(m.key().unwrap(), Some(2));
        assert_eq!(m.value().unwrap(), Item::Tstr("krab"));
        assert_eq!(m.key().unwrap(), None);
        assert!(r.is_done());
    }

    #[test]
    fn writer_emits_shortest_form() {
        for (v, want) in [
            (0u64, 1usize),
            (23, 1),
            (24, 2),
            (255, 2),
            (256, 3),
            (65_536, 5),
        ] {
            let mut w = Writer::new();
            w.uint(v);
            assert_eq!(w.len(), want, "uint {v}");
        }
    }

    /// Rule 1.
    #[test]
    fn rejects_non_canonical_integers() {
        // 0x18 0x05 is 5 encoded in two bytes; 0x05 is canonical.
        assert_eq!(Reader::new(&[0x18, 0x05]).item(), Err(Error::NotCanonical));
        // 0x19 0x00 0xFF is 255 in three bytes.
        assert_eq!(
            Reader::new(&[0x19, 0x00, 0xFF]).item(),
            Err(Error::NotCanonical)
        );
        // 0x1a with a value that fits two bytes.
        assert_eq!(
            Reader::new(&[0x1a, 0, 0, 0xFF, 0xFF]).item(),
            Err(Error::NotCanonical)
        );
        // 0x1b with a value that fits four.
        assert_eq!(
            Reader::new(&[0x1b, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]).item(),
            Err(Error::NotCanonical)
        );
    }

    /// Rule 2.
    #[test]
    fn rejects_indefinite_lengths() {
        for major in [MT_BSTR, MT_TSTR, MT_ARRAY, MT_MAP] {
            let b = [(major << 5) | AI_INDEFINITE];
            assert_eq!(
                Reader::new(&b).item(),
                Err(Error::NotCanonical),
                "major {major}"
            );
        }
    }

    /// Rule 3.
    #[test]
    fn rejects_out_of_order_and_duplicate_map_keys() {
        // {1: 0, 0: 0} — descending.
        let bytes = vec![0xa2, 0x01, 0x00, 0x00, 0x00];
        let mut r = Reader::new(&bytes);
        let mut m = r.map().unwrap();
        assert_eq!(m.key().unwrap(), Some(1));
        assert_eq!(m.value().unwrap(), Item::Uint(0));
        assert_eq!(m.key(), Err(Error::NotCanonical));

        // {0: 0, 0: 0} — duplicate.
        let bytes = vec![0xa2, 0x00, 0x00, 0x00, 0x00];
        let mut r = Reader::new(&bytes);
        let mut m = r.map().unwrap();
        assert_eq!(m.key().unwrap(), Some(0));
        assert_eq!(m.value().unwrap(), Item::Uint(0));
        assert_eq!(m.key(), Err(Error::NotCanonical));
    }

    #[test]
    fn rejects_non_integer_map_keys() {
        // {"a": 0}
        let bytes = vec![0xa1, 0x61, b'a', 0x00];
        let mut r = Reader::new(&bytes);
        let mut m = r.map().unwrap();
        assert_eq!(m.key(), Err(Error::NotCanonical));
    }

    /// Rules 4 and 5.
    #[test]
    fn rejects_floats_tags_null_and_undefined() {
        // half, single, double float
        assert_eq!(Reader::new(&[0xf9, 0, 0]).item(), Err(Error::NotCanonical));
        assert_eq!(
            Reader::new(&[0xfa, 0, 0, 0, 0]).item(),
            Err(Error::NotCanonical)
        );
        assert_eq!(
            Reader::new(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]).item(),
            Err(Error::NotCanonical)
        );
        // null (0xf6) and undefined (0xf7)
        assert_eq!(Reader::new(&[0xf6]).item(), Err(Error::NotCanonical));
        assert_eq!(Reader::new(&[0xf7]).item(), Err(Error::NotCanonical));
        // tag 0
        assert_eq!(Reader::new(&[0xc0, 0x00]).item(), Err(Error::NotCanonical));
        // negative integer
        assert_eq!(Reader::new(&[0x20]).item(), Err(Error::NotCanonical));
    }

    #[test]
    fn accepts_only_true_and_false_as_simple() {
        assert_eq!(Reader::new(&[0xf4]).item(), Ok(Item::Bool(false)));
        assert_eq!(Reader::new(&[0xf5]).item(), Ok(Item::Bool(true)));
        // simple(0) and simple(19) are undefined values.
        assert_eq!(Reader::new(&[0xe0]).item(), Err(Error::NotCanonical));
        assert_eq!(Reader::new(&[0xf3]).item(), Err(Error::NotCanonical));
    }

    /// A declared length must be checked against the input, not trusted.
    #[test]
    fn a_huge_declared_length_truncates_rather_than_allocating() {
        // bstr claiming 2^32-1 bytes with none present.
        let bytes = [0x5a, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(Reader::new(&bytes).item(), Err(Error::Truncated));
        // bstr claiming 2^63 bytes.
        let bytes = [0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(Reader::new(&bytes).item(), Err(Error::Truncated));
    }

    #[test]
    fn rejects_invalid_utf8_in_text_strings() {
        // tstr of length 1 containing 0xFF.
        assert_eq!(Reader::new(&[0x61, 0xFF]).item(), Err(Error::Malformed));
    }

    /// The property RFC 0 §9 asks for: never panic on arbitrary input.
    #[test]
    fn never_panics_on_arbitrary_input() {
        // Exhaustive over every one- and two-byte input.
        for a in 0u16..=255 {
            let _ = Reader::new(&[a as u8]).item();
            for b in 0u16..=255 {
                let _ = Reader::new(&[a as u8, b as u8]).item();
            }
        }
        // And over every three-byte input beginning with a map or array head.
        for major in [MT_ARRAY, MT_MAP] {
            for a in 0u16..=255 {
                for b in 0u16..=255 {
                    let bytes = [(major << 5) | 2, a as u8, b as u8];
                    let mut r = Reader::new(&bytes);
                    let _ = r.item();
                    let _ = r.item();
                    let _ = r.item();
                }
            }
        }
    }
}
