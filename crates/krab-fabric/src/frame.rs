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

/// Read one framed control message, or `None` at clean end of input.
pub fn read(input: &mut impl Read) -> Result<Option<Control>, Error> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    }
    let n = u32::from_le_bytes(len) as usize;
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
}
