//! SOCKS5 client — the dialling half of RFC 4 §5.2's Tor backend.
//!
//! This file was six lines of doc comment and no code, and was not declared in
//! `backend/mod.rs`, so it never compiled. The `socks` cargo feature named it
//! and `LinkProfile::location_privacy` claimed `"socks"` and `"tor"` were
//! location-private kinds, while `profile_named` had no arm for either — so the
//! claim was unreachable rather than false. It is code now.
//!
//! # Why SOCKS5 and not a Tor implementation
//!
//! `Documentation/PLAN.md` records the reasoning at length. In short: the
//! property RFC 4 §5.2 wants is that the sync endpoint be "unenumerable and
//! unconfirmable by anyone who is not already a peer", and that property comes
//! from the global HSDir hashring and the anonymity set using it — not from the
//! protocol. A second Tor implementation cannot build it, only join it, and a
//! distinguishable client shrinks the set it joins.
//!
//! So Krab speaks SOCKS5 to a `tor` that Krab itself launches. See
//! [`super::tor`] for the launching, which is what keeps this from being the
//! "external tool" arrangement RFC 4 §5.2 is unenthusiastic about.
//!
//! # The one detail that matters
//!
//! **The address is always sent as a domain name, never resolved here.**
//! `ATYP = 0x03` hands `"…onion:9001"` to tor as text. Resolving it locally
//! would fail — there is no DNS record for a `.onion` — and an implementation
//! that fell back to the system resolver would leak the peer's address to the
//! local network's DNS on every dial. RFC 4 §5.2's whole subject is that this
//! endpoint is not discoverable; leaking it to a resolver would give it away
//! at the first connection.
//!
//! That is why [`connect_through`] takes `&str` and not `SocketAddr`. A
//! `SocketAddr` cannot express `.onion`, and a signature that took one would
//! have made the mistake unavoidable rather than merely possible.

use crate::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

/// SOCKS protocol version 5.
const VER: u8 = 0x05;
/// "No authentication required" — the only method offered.
///
/// Tor's SOCKS port accepts it. Username/password exists in SOCKS5 and tor
/// gives it a *different* meaning — stream isolation, where distinct
/// credentials get distinct circuits — so offering it would either be ignored
/// or silently change circuit behaviour. Neither is wanted here.
const NO_AUTH: u8 = 0x00;
/// The method the server returns when it accepts none of ours.
const NO_ACCEPTABLE: u8 = 0xFF;
/// `CONNECT`, as opposed to `BIND` or `UDP ASSOCIATE`.
const CMD_CONNECT: u8 = 0x01;
/// `ATYP` for a domain name — see the module note.
const ATYP_DOMAIN: u8 = 0x03;
/// `ATYP` for IPv4, which only ever appears in a *reply* here.
const ATYP_IPV4: u8 = 0x01;
/// `ATYP` for IPv6, likewise.
const ATYP_IPV6: u8 = 0x04;
/// `REP` value for success.
const REP_SUCCEEDED: u8 = 0x00;

/// The longest host SOCKS5 can carry: the length is one byte.
///
/// A v3 onion address is 56 characters plus `.onion`, so 62 — comfortably
/// inside it. The check exists so that a caller passing something absurd gets
/// a refusal rather than a truncated host that dials somewhere else.
pub const MAX_HOST: usize = 255;

/// Ask a SOCKS5 proxy to connect `stream` to `host:port`.
///
/// `stream` must already be connected to the proxy, and is left carrying the
/// tunnelled connection on success — so the caller can hand it straight to the
/// Noise handshake. [`super::tor::dial`] is that caller.
///
/// *(An earlier version of this sentence named a `TorFabric` that does not
/// exist. `dial` returns a `TcpStream` and nothing yet implements
/// [`crate::Fabric`] over it — see `Documentation/PLAN.md`.)*
///
/// `host` is passed through verbatim. It is not resolved, not lowercased, and
/// not validated as an onion address: this function is SOCKS5 and nothing
/// more, and a caller dialling a plain hostname through a proxy is a legitimate
/// use of it.
///
/// # Failure
///
/// Every failure is [`Error::Unreachable`] rather than something more
/// specific, deliberately. RFC 4's I-4 forbids treating unreachability as
/// exceptional — an intermittent link is the normal case — and the SOCKS reply
/// code distinguishes "host unreachable" from "connection refused" in ways that
/// would tempt a caller into escalating one and not the other. The one
/// exception is a malformed reply, which is [`Error::Frame`]: that is a broken
/// proxy, not an absent peer.
pub fn connect_through(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), Error> {
    if host.is_empty() || host.len() > MAX_HOST {
        return Err(Error::Frame);
    }

    // ---- Greeting: one method offered. ----
    stream.write_all(&[VER, 1, NO_AUTH])?;
    stream.flush()?;

    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting[0] != VER {
        return Err(Error::Frame);
    }
    if greeting[1] == NO_ACCEPTABLE || greeting[1] != NO_AUTH {
        // The proxy wants authentication this does not offer. That is a
        // misconfiguration rather than an unreachable peer, but it is also not
        // a malformed frame — `Unreachable` is the honest one, and the tor
        // this crate launches never takes this branch.
        return Err(Error::Unreachable);
    }

    // ---- Request. ----
    //
    // 4 fixed bytes, then a length-prefixed host, then a big-endian port.
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[VER, CMD_CONNECT, 0x00, ATYP_DOMAIN]);
    // The cast is checked above: `host.len() <= MAX_HOST == 255`.
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;
    stream.flush()?;

    // ---- Reply. ----
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != VER {
        return Err(Error::Frame);
    }
    if head[1] != REP_SUCCEEDED {
        return Err(Error::Unreachable);
    }

    // **The bound address must be consumed even though it is not wanted.**
    //
    // It is variable-length, it precedes the tunnelled bytes on the same
    // stream, and leaving it there would prepend garbage to the Noise
    // handshake — which would then fail as an authentication error, sending
    // whoever debugged it to look at the credential rather than at the four
    // bytes of leftover SOCKS reply.
    let bound_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n)?;
            n[0] as usize
        }
        _ => return Err(Error::Frame),
    };
    // The address, then the two-byte port.
    let mut discard = vec![0u8; bound_len + 2];
    stream.read_exact(&mut discard)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// A one-shot fake proxy: one greeting round trip, one CONNECT round trip.
    ///
    /// Real enough to be worth having — it speaks over an actual socket, so
    /// `read_exact`'s framing is exercised rather than a `Vec` being parsed.
    ///
    /// # Two details that are not incidental
    ///
    /// **Every read has a timeout.** An earlier version of this helper had
    /// none and deadlocked the whole test binary: `an_overlong_host_is_refused`
    /// makes the client return *before it writes anything*, so the proxy sat
    /// in `read_exact` for ever. A test helper that can hang is worse than a
    /// failing test, because CI reports it as a timeout with no failing
    /// assertion to read.
    ///
    /// **The thread hands the socket back rather than dropping it.** Returning
    /// it from the closure keeps it alive inside the `JoinHandle` until the
    /// test joins, so a test can still read trailing bytes the proxy wrote —
    /// which is exactly what `the_bound_address_is_consumed` needs. Dropping
    /// it would race a `FIN` against that read.
    type Proxied = (Vec<u8>, Option<TcpStream>);
    fn proxy(
        method: u8,
        reply: Vec<u8>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Proxied>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let t = Some(std::time::Duration::from_secs(5));
            s.set_read_timeout(t).unwrap();
            let mut seen = Vec::new();

            let mut greeting = [0u8; 3];
            if s.read_exact(&mut greeting).is_err() {
                return (seen, Some(s));
            }
            seen.extend_from_slice(&greeting);
            if s.write_all(&[VER, method]).is_err() || method != NO_AUTH {
                return (seen, Some(s));
            }

            // 4 fixed bytes and the host length, then the host and the port.
            let mut head = [0u8; 5];
            if s.read_exact(&mut head).is_err() {
                return (seen, Some(s));
            }
            let mut rest = vec![0u8; head[4] as usize + 2];
            if s.read_exact(&mut rest).is_err() {
                return (seen, Some(s));
            }
            seen.extend_from_slice(&head);
            seen.extend_from_slice(&rest);

            let _ = s.write_all(&reply);
            let _ = s.flush();
            (seen, Some(s))
        });
        (addr, h)
    }

    /// **The address goes out as a domain name, unresolved.**
    ///
    /// This is the test the module exists for: a `.onion` has no DNS record,
    /// and an implementation that resolved locally would both fail and leak
    /// the endpoint to the local resolver.
    #[test]
    fn the_onion_address_is_sent_as_a_domain_name() {
        let onion = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
        // Success, bound to 0.0.0.0:0.
        let (addr, h) = proxy(
            NO_AUTH,
            vec![VER, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0],
        );
        let mut s = TcpStream::connect(addr).unwrap();
        connect_through(&mut s, onion, 9001).unwrap();
        let (sent, _sock) = h.join().unwrap();

        assert_eq!(&sent[..3], &[VER, 1, NO_AUTH], "greeting");
        assert_eq!(sent[3], VER);
        assert_eq!(sent[4], CMD_CONNECT);
        assert_eq!(sent[6], ATYP_DOMAIN, "must not be an IP address type");
        assert_eq!(sent[7] as usize, onion.len());
        assert_eq!(&sent[8..8 + onion.len()], onion.as_bytes());
        let port = &sent[8 + onion.len()..8 + onion.len() + 2];
        assert_eq!(u16::from_be_bytes([port[0], port[1]]), 9001);
    }

    /// A refusal from the proxy is `Unreachable`, not an error to escalate —
    /// RFC 4's I-4.
    #[test]
    fn a_refused_connection_is_unreachable() {
        // REP = 0x05, connection refused.
        let (addr, h) = proxy(NO_AUTH, vec![VER, 0x05, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
        let mut s = TcpStream::connect(addr).unwrap();
        assert!(matches!(
            connect_through(&mut s, "example.onion", 9001),
            Err(Error::Unreachable)
        ));
        let _ = h.join();
    }

    /// **The bound address is consumed**, whatever its type, so the stream is
    /// left positioned at the tunnelled bytes and not at leftover reply.
    ///
    /// Checked by having the proxy append a known marker after the reply: if
    /// the bound address were left unread, the first thing the caller read
    /// would be reply bytes rather than the marker — which in production is a
    /// Noise handshake failing for a reason that looks like a bad credential.
    #[test]
    fn the_bound_address_is_consumed_for_every_type() {
        for (atyp, bound) in [
            (ATYP_IPV4, vec![1, 2, 3, 4]),
            (ATYP_IPV6, vec![9u8; 16]),
            (ATYP_DOMAIN, {
                let mut v = vec![3u8];
                v.extend_from_slice(b"abc");
                v
            }),
        ] {
            let mut reply = vec![VER, REP_SUCCEEDED, 0x00, atyp];
            reply.extend_from_slice(&bound);
            reply.extend_from_slice(&[0x23, 0x29]); // port
            reply.extend_from_slice(b"MARKER");

            let (addr, h) = proxy(NO_AUTH, reply);
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            connect_through(&mut s, "example.onion", 9001).unwrap();

            let mut marker = [0u8; 6];
            s.read_exact(&mut marker).unwrap();
            assert_eq!(
                &marker, b"MARKER",
                "bound address of type {atyp} was left on the stream"
            );
            let _ = h.join();
        }
    }

    /// A proxy demanding authentication is refused rather than half-spoken to.
    #[test]
    fn an_auth_demanding_proxy_is_refused() {
        let (addr, h) = proxy(NO_ACCEPTABLE, Vec::new());
        let mut s = TcpStream::connect(addr).unwrap();
        assert!(matches!(
            connect_through(&mut s, "example.onion", 9001),
            Err(Error::Unreachable)
        ));
        let _ = h.join();
    }

    /// A host that cannot fit SOCKS5's one-byte length is refused before any
    /// byte goes out — not truncated into a dial somewhere else.
    #[test]
    fn an_overlong_host_is_refused_without_dialling() {
        let (addr, h) = proxy(NO_AUTH, Vec::new());
        let mut s = TcpStream::connect(addr).unwrap();
        let huge = "a".repeat(MAX_HOST + 1);
        assert!(matches!(
            connect_through(&mut s, &huge, 9001),
            Err(Error::Frame)
        ));
        assert!(matches!(
            connect_through(&mut s, "", 9001),
            Err(Error::Frame)
        ));
        // The proxy is blocked reading a greeting that will never come; closing
        // is what lets it finish. This is the case that deadlocked the earlier
        // helper, and the read timeout there is the belt to this braces.
        drop(s);
        let (sent, _) = h.join().unwrap();
        assert!(sent.is_empty(), "a refusal must not put bytes on the wire");
    }
}
