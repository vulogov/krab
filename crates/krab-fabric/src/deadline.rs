//! A **total** deadline for an exchange of bytes, over any stream.
//!
//! # The bug this exists for
//!
//! Every deadline on the network path was a socket option —
//! `set_read_timeout`, `set_write_timeout` — and a socket timeout bounds **one
//! read**, not a conversation. `frame::read_len` and `read_exact` both loop
//! while `read` returns `Ok(n)`, so **every byte that arrives re-arms the
//! clock**. A peer sending one byte every nine seconds never trips a
//! ten-second timeout, and holds the connection open for as long as it likes.
//!
//! On the handshake path that is a denial of service with a bounded and very
//! small cost to the attacker. `MAX_PENDING_HANDSHAKES` is 16 *in total* — a
//! deliberate bound, because handshaking is expensive and accepting is not —
//! so sixteen dribbling sockets occupy every slot indefinitely and no real
//! peer can connect. It is silent at the defender's end by design: a failed
//! handshake is `Ok(None)` and nothing is logged, because logging strangers is
//! the provenance RFC 3 §12 forbids.
//!
//! The existing `slowloris.rs` and `deadlines.rs` suites miss it because all of
//! them test *silence*, and silence is the one case a per-read timeout does
//! bound. The attack is not saying nothing; it is saying almost nothing.
//!
//! # Why this wraps the stream rather than shortening the timeout
//!
//! No per-read timeout fixes it. Shortening it to one second makes the
//! attacker send a byte every 0.9 seconds and breaks honest peers on slow
//! links, where a single 144-byte handshake is minutes of airtime (RFC 4
//! §5.4). The two quantities are different: how long one read may block, and
//! how long the whole exchange may take. Only the second bounds an attacker
//! who is willing to keep talking.
//!
//! So the budget is wall-clock and total, and the socket keeps its per-read
//! timeout as well. Whichever expires first ends the exchange.
//!
//! # It is checked before the read, not after
//!
//! A read that is already in progress cannot be interrupted from here, so the
//! worst case overshoot is one per-read timeout beyond the budget. Bounded and
//! stated, rather than pursued with a second thread — a watchdog per handshake
//! would cost more than the handshake.

use std::io::{Read, Result as IoResult, Write};
use std::time::{Duration, Instant};

/// A stream that refuses to carry bytes past a wall-clock budget.
pub struct Deadline<S> {
    inner: S,
    until: Instant,
}

impl<S> Deadline<S> {
    /// Wrap `inner`, giving the whole exchange `budget` from now.
    pub fn new(inner: S, budget: Duration) -> Deadline<S> {
        Deadline {
            inner,
            until: Instant::now() + budget,
        }
    }

    /// Whether the budget is spent.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.until
    }

    /// The stream back, for a caller that has finished with the deadline —
    /// the handshake is bounded, the session that follows has its own bound.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn check(&self) -> IoResult<()> {
        if self.expired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the exchange exceeded its total deadline",
            ));
        }
        Ok(())
    }
}

impl<S: Read> Read for Deadline<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.check()?;
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Deadline<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.check()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that yields one byte at a time, for ever, with a delay —
    /// the attack, in miniature.
    struct Dribble {
        per_byte: Duration,
        served: usize,
    }

    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            std::thread::sleep(self.per_byte);
            self.served += 1;
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = 0;
            Ok(1)
        }
    }

    /// **The bug, reproduced and then bounded.**
    ///
    /// A reader that never stops and never says nothing would fill any buffer
    /// eventually and re-arm a per-read timeout for ever. Under a total
    /// deadline it stops, and it stops within one read of the budget.
    #[test]
    fn a_dribbling_reader_is_cut_off_at_the_budget() {
        let mut s = Deadline::new(
            Dribble {
                per_byte: Duration::from_millis(10),
                served: 0,
            },
            Duration::from_millis(120),
        );
        let started = Instant::now();
        let mut sink = [0u8; 4096];
        let err = loop {
            // The count is deliberately ignored: this loop is about *when*
            // the reader is cut off, not about what it delivered.
            match s.read(&mut sink) {
                Ok(0) => continue,
                Ok(_n) => continue,
                Err(e) => break e,
            }
        };
        let took = started.elapsed();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            took < Duration::from_millis(600),
            "cut off after {took:?}, which is not a bound"
        );
        assert!(
            s.inner.served > 1,
            "the reader never got going, so this proves nothing"
        );
    }

    /// An exchange that finishes inside its budget is untouched — the bound
    /// must not cost an honest peer on a slow link.
    #[test]
    fn a_prompt_exchange_is_not_disturbed() {
        let mut s = Deadline::new(&b"hello"[..], Duration::from_secs(30));
        let mut out = Vec::new();
        s.read_to_end(&mut out).expect("no deadline should fire");
        assert_eq!(out, b"hello");
    }

    /// Writes are bounded too. A peer that reads slowly can hold a writer as
    /// surely as one that writes slowly holds a reader.
    #[test]
    fn writes_are_bounded_as_well_as_reads() {
        let mut s = Deadline::new(Vec::new(), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            s.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
