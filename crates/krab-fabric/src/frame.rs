//! Length-delimited framing, RFC 4 §4.2.
//!
//! `[u32 LE length][payload]`. Under Noise the payload is a transport message
//! capped at 65 535 bytes including its 16-byte tag; Noise itself is phase B.
//!
//! The length is validated **before** any allocation. RFC 4 §9 requires it, and
//! a four-byte header claiming four gigabytes is the cheapest attack there is.

use crate::Error;
use krab_proto::control::Control;
use std::io::{Read, Write};

/// Noise's transport-message ceiling, RFC 4 §4.2.
pub const MAX_FRAME: usize = 65_535;

/// Write one framed control message.
pub fn write(out: &mut impl Write, msg: &Control) -> Result<usize, Error> {
    let body = msg.write();
    if body.len() > MAX_FRAME {
        return Err(Error::Frame);
    }
    out.write_all(&(body.len() as u32).to_le_bytes())?;
    out.write_all(&body)?;
    Ok(4 + body.len())
}

/// Write raw framed bytes.
///
/// Used for Noise: handshake messages and transport ciphertext are opaque at
/// this layer, and the framing is identical. Sharing the length check matters
/// more than the type — RFC 4 §9's "validate before allocating" applies to
/// ciphertext exactly as it does to control messages.
pub fn write_bytes(out: &mut impl Write, body: &[u8]) -> Result<usize, Error> {
    if body.len() > MAX_FRAME {
        return Err(Error::Frame);
    }
    out.write_all(&(body.len() as u32).to_le_bytes())?;
    out.write_all(body)?;
    Ok(4 + body.len())
}

/// Read the four-byte length prefix, or `None` at a clean end of input.
///
/// # A short prefix is not a clean end
///
/// `read_exact` reports "the stream ended before I read anything" and "the
/// stream ended after two of the four bytes" as the same `UnexpectedEof`, and
/// both used to become `Ok(None)`. Those are opposite outcomes. Every driver
/// in `krab_node::exchange` treats `None` as *the peer said nothing more* —
/// the normal, successful end of a conversation — so a peer that cut the
/// connection in the middle of a header was recorded as having finished, and
/// a partial exchange was indistinguishable from a complete one.
///
/// That is exactly the failure RFC 0 §6 warns about: delivery failure is
/// silent by design, so the layers that *can* tell the difference have to.
fn read_len(input: &mut impl Read) -> Result<Option<usize>, Error> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match input.read(&mut len[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    match got {
        0 => Ok(None),
        4 => Ok(Some(u32::from_le_bytes(len) as usize)),
        // One, two or three bytes: a header that started and stopped.
        _ => Err(Error::Frame),
    }
}

/// Read raw framed bytes, or `None` at clean end of input.
pub fn read_bytes(input: &mut impl Read) -> Result<Option<Vec<u8>>, Error> {
    let Some(n) = read_len(input)? else {
        return Ok(None);
    };
    if n > MAX_FRAME {
        return Err(Error::Frame);
    }
    let mut body = vec![0u8; n];
    input.read_exact(&mut body).map_err(|_| Error::Frame)?;
    Ok(Some(body))
}

/// Read one framed control message, or `None` at clean end of input.
pub fn read(input: &mut impl Read) -> Result<Option<Control>, Error> {
    let Some(n) = read_len(input)? else {
        return Ok(None);
    };
    // Checked before allocating, never after.
    if n > MAX_FRAME {
        return Err(Error::Frame);
    }
    let mut body = vec![0u8; n];
    input.read_exact(&mut body).map_err(|_| Error::Frame)?;
    Control::parse(&body).map(Some).map_err(|_| Error::Frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs() -> Vec<Control> {
        vec![
            Control::Hello {
                version: 1,
                node: [1; 32],
                watermark: 9,
                filter_digest: [2; 32],
            },
            Control::Obj(vec![7; 512]),
            Control::Done,
        ]
    }

    #[test]
    fn frames_round_trip_in_sequence() {
        let mut buf = Vec::new();
        for m in msgs() {
            write(&mut buf, &m).unwrap();
        }
        let mut cur = std::io::Cursor::new(buf);
        for want in msgs() {
            assert_eq!(read(&mut cur).unwrap(), Some(want));
        }
        assert_eq!(
            read(&mut cur).unwrap(),
            None,
            "clean end of input, not an error"
        );
    }

    /// RFC 4 §9 — validate the length before allocating.
    #[test]
    fn a_huge_declared_length_is_refused_before_allocation() {
        let mut bytes = (u32::MAX).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let mut cur = std::io::Cursor::new(bytes);
        assert!(matches!(read(&mut cur), Err(Error::Frame)));
    }

    #[test]
    fn truncated_input_errors_rather_than_hanging() {
        let mut buf = Vec::new();
        write(&mut buf, &Control::Obj(vec![3; 100])).unwrap();
        buf.truncate(20);
        let mut cur = std::io::Cursor::new(buf);
        assert!(matches!(read(&mut cur), Err(Error::Frame)));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        for n in 0..64usize {
            let mut cur = std::io::Cursor::new(vec![0xABu8; n]);
            let _ = read(&mut cur);
        }
    }

    /// **A truncated header is not a clean close.** `read_exact` reports "the
    /// stream ended before I read anything" and "the stream ended after two of
    /// the four bytes" identically, and both became `Ok(None)` — which every
    /// exchange driver reads as the peer having finished normally.
    #[test]
    fn a_truncated_length_prefix_is_an_error_not_an_ending() {
        // Nothing at all: a clean end, on a frame boundary.
        assert_eq!(read(&mut std::io::Cursor::new(Vec::new())).unwrap(), None);
        assert_eq!(
            read_bytes(&mut std::io::Cursor::new(Vec::new())).unwrap(),
            None
        );

        // One, two or three bytes of a header, and then nothing.
        for partial in 1..4usize {
            let mut buf = Vec::new();
            write(&mut buf, &Control::Done).unwrap();
            buf.truncate(partial);
            assert!(
                matches!(read(&mut std::io::Cursor::new(buf.clone())), Err(Error::Frame)),
                "{partial} byte(s) of a header read as a clean end"
            );
            assert!(matches!(
                read_bytes(&mut std::io::Cursor::new(buf)),
                Err(Error::Frame)
            ));
        }
    }

    /// A whole header followed by a short body was already an error, and stays
    /// one — the fix must not have moved the boundary.
    #[test]
    fn a_truncated_body_is_still_an_error() {
        let mut buf = Vec::new();
        write(&mut buf, &Control::Obj(vec![3; 100])).unwrap();
        buf.truncate(4 + 10);
        assert!(matches!(
            read(&mut std::io::Cursor::new(buf)),
            Err(Error::Frame)
        ));
    }

    /// A reader that hands back one byte at a time must not look like an end
    /// of stream: `read` may return fewer bytes than asked for at any time.
    #[test]
    fn a_dribbling_reader_still_reads_a_whole_frame() {
        struct OneAtATime(std::io::Cursor<Vec<u8>>);
        impl Read for OneAtATime {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                self.0.read(&mut buf[..1])
            }
        }
        let mut buf = Vec::new();
        write(&mut buf, &Control::Done).unwrap();
        let mut r = OneAtATime(std::io::Cursor::new(buf));
        assert_eq!(read(&mut r).unwrap(), Some(Control::Done));
        assert_eq!(read(&mut r).unwrap(), None);
    }
}
