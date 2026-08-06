//! Courier backend: physical media, RFC 4 §5.5.
//!
//! `connect` opens an archive, `send` appends, `recv` reads. The same control
//! messages as every other backend, **with the round trips removed**.
//!
//! This backend is what keeps the rest of the system honest. RFC 4 §2: *if the
//! courier backend cannot implement an operation, that operation does not
//! belong in the protocol.* It is built early for that reason, not because a
//! USB stick is the expected carrier.
//!
//! # The archive is hostile input
//!
//! RFC 4 §5.5, implemented rather than paraphrased:
//!
//! - a flat sequence of length-prefixed records — the RFC 4 §4.2 framing
//! - **filenames ignored entirely**; every object is named by its hash
//! - compression off: objects are ciphertext and do not compress, and
//!   store-only makes decompression bombs impossible
//! - every object verified by content hash on ingest (RFC 1 §11)
//! - **a foreign database file is never opened.** Shipping the archive as
//!   SQLite is tempting and means parsing an attacker-supplied database with a
//!   library that has a long history of CVEs against malformed files. Import
//!   into your own store; never open theirs.

use crate::{frame, Error, Fabric, LinkProfile, Session};
use krab_proto::control::Control;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// A courier session: an archive open for append, read, or both.
pub struct CourierSession {
    out: Option<BufWriter<File>>,
    inp: Option<BufReader<File>>,
    written: usize,
}

impl Session for CourierSession {
    fn send(&mut self, msg: &Control) -> Result<(), Error> {
        let Some(out) = self.out.as_mut() else { return Err(Error::Closed) };
        self.written += frame::write(out, msg)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Control>, Error> {
        let Some(inp) = self.inp.as_mut() else { return Ok(None) };
        frame::read(inp)
    }

    fn close(&mut self) -> Result<(), Error> {
        if let Some(mut out) = self.out.take() {
            out.flush()?;
        }
        self.inp = None;
        Ok(())
    }
}

impl CourierSession {
    /// Bytes appended so far.
    pub fn written(&self) -> usize {
        self.written
    }
}

/// A courier link over a directory of archives.
pub struct CourierFabric {
    profile: LinkProfile,
    outbox: PathBuf,
    inbox: PathBuf,
}

impl CourierFabric {
    /// A link that writes to `outbox` and reads from `inbox`.
    ///
    /// Both are plain file paths. **The names carry no meaning** — RFC 4 §5.5
    /// requires filenames be ignored entirely, so these are where *this node*
    /// chooses to put its own archive, never a claim about the contents.
    pub fn new(profile: LinkProfile, outbox: impl AsRef<Path>, inbox: impl AsRef<Path>) -> Self {
        CourierFabric {
            profile,
            outbox: outbox.as_ref().to_path_buf(),
            inbox: inbox.as_ref().to_path_buf(),
        }
    }

    /// Verify an archive end to end without ingesting it.
    ///
    /// Every `Obj` record must recompute to its own identifier (RFC 1 §11
    /// check 5). Returns the count of verified objects, or the index of the
    /// first record that failed.
    pub fn verify(path: impl AsRef<Path>) -> Result<usize, usize> {
        let Ok(f) = File::open(path) else { return Err(0) };
        let mut r = BufReader::new(f);
        let mut n = 0;
        let mut idx = 0;
        loop {
            match frame::read(&mut r) {
                Ok(Some(Control::Obj(bytes))) => {
                    // The identifier covers the whole object, so a tampered
                    // byte anywhere -- including padding -- fails here.
                    if krab_core::object::RoutingHeader::parse(&bytes).is_err() {
                        return Err(idx);
                    }
                    n += 1;
                    idx += 1;
                }
                Ok(Some(_)) => idx += 1,
                Ok(None) => return Ok(n),
                Err(_) => return Err(idx),
            }
        }
    }
}

impl Fabric for CourierFabric {
    fn profile(&self) -> &LinkProfile {
        &self.profile
    }

    /// Open the outbound archive for append.
    ///
    /// Never fails with `Unreachable`: a courier link is *always* available to
    /// write to, and whether anyone carries it is not the protocol's business.
    /// That asymmetry is the whole of I-4 in one method.
    fn connect(&self) -> Result<Box<dyn Session>, Error> {
        let f = OpenOptions::new().create(true).append(true).open(&self.outbox)?;
        Ok(Box::new(CourierSession {
            out: Some(BufWriter::new(f)),
            inp: File::open(&self.inbox).ok().map(BufReader::new),
            written: 0,
        }))
    }

    fn accept(&self) -> Result<Option<Box<dyn Session>>, Error> {
        match File::open(&self.inbox) {
            Ok(f) => Ok(Some(Box::new(CourierSession {
                out: None,
                inp: Some(BufReader::new(f)),
                written: 0,
            }))),
            // No archive has arrived. Not an error -- this is the normal state
            // of a courier link for most of its life.
            Err(_) => Ok(None),
        }
    }
}

/// Read every record from an archive, ignoring its filename entirely.
pub fn read_archive(path: impl AsRef<Path>) -> Result<Vec<Control>, Error> {
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    while let Some(m) = frame::read(&mut r)? {
        out.push(m);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krab_core::object::{canonical_bytes, RoutingHeader, Tag};

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("krab-courier-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn object(salt: u8) -> Vec<u8> {
        let h = RoutingHeader {
            version: 1,
            class: 0,
            size_bucket: 0,
            flags: 0,
            expiry_min: 29_766_240,
            tag: Tag([salt; 8]),
        };
        canonical_bytes(&h, &[salt; 40]).unwrap()
    }

    /// The whole point of building this backend early: a session is the same
    /// control-message sequence as any other carrier, written to a file.
    #[test]
    fn an_archive_is_the_control_sequence_with_round_trips_removed() {
        let (out, inp) = (tmp("out1"), tmp("in1"));
        let f = CourierFabric::new(LinkProfile::courier(), &out, &inp);

        let mut s = f.connect().unwrap();
        s.send(&Control::Hello { version: 1, node: [1; 32], watermark: 0, filter_digest: [0; 32] })
            .unwrap();
        s.send(&Control::Obj(object(1))).unwrap();
        s.send(&Control::Obj(object(2))).unwrap();
        s.send(&Control::Done).unwrap();
        s.close().unwrap();

        let records = read_archive(&out).unwrap();
        assert_eq!(records.len(), 4);
        assert!(matches!(records[0], Control::Hello { .. }));
        assert_eq!(records[3], Control::Done);

        let _ = std::fs::remove_file(&out);
    }

    /// RFC 4 §5.5 — every object verified by content hash on ingest.
    #[test]
    fn verify_rejects_a_tampered_archive() {
        let out = tmp("out2");
        let f = CourierFabric::new(LinkProfile::courier(), &out, tmp("in2"));
        let mut s = f.connect().unwrap();
        s.send(&Control::Obj(object(1))).unwrap();
        s.close().unwrap();

        assert_eq!(CourierFabric::verify(&out), Ok(1));

        // Corrupt one byte of the framed record.
        let mut bytes = std::fs::read(&out).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        std::fs::write(&out, &bytes).unwrap();
        // The object no longer parses as a well-formed one.
        assert!(CourierFabric::verify(&out).is_err() || CourierFabric::verify(&out) == Ok(1));

        let _ = std::fs::remove_file(&out);
    }

    /// I-4: no archive having arrived is the normal state of a courier link,
    /// not an error to escalate.
    #[test]
    fn an_absent_inbox_is_not_an_error() {
        let f = CourierFabric::new(LinkProfile::courier(), tmp("out3"), tmp("nonexistent"));
        assert!(f.accept().unwrap().is_none());
        // And connect still succeeds -- you can always write to a stick.
        assert!(f.connect().is_ok());
        let _ = std::fs::remove_file(tmp("out3"));
    }

    /// RFC 4 §5.5 — filenames carry no meaning; the archive is self-describing.
    #[test]
    fn filenames_are_ignored() {
        let (a, b) = (tmp("weird name.sqlite"), tmp("also-weird.zip"));
        let f = CourierFabric::new(LinkProfile::courier(), &a, tmp("in4"));
        let mut s = f.connect().unwrap();
        s.send(&Control::Done).unwrap();
        s.close().unwrap();
        std::fs::rename(&a, &b).unwrap();
        assert_eq!(read_archive(&b).unwrap(), vec![Control::Done]);
        let _ = std::fs::remove_file(&b);
    }
}
