//! `krab` — the TUI application (RFC 8).
//!
//! # Node/TUI seam
//!
//! The TUI communicates with the node over a channel, never by direct call
//! into node internals. In a single binary that is an in-process channel; the
//! same interface over a Unix socket yields headless operation with no code
//! change on either side. The seam is why it is a configuration rather than a
//! rewrite.
//!
//! # Security boundary
//!
//! Two tabs: secure messaging (default) and channels. The boundary between
//! them is visible in the composer, not only in the tab — distinct border, a
//! persistent `PUBLIC — SIGNED — PERMANENT` banner, and confirmation on the
//! first channel post of a session. Reply semantics differ per tab, and `r`
//! on a channel post defaults to a private message to the author and must
//! never publish.
//!
//! Status: scaffold. Renders nothing yet; ratatui is not wired in because
//! RFC 8 depends on RFC 6 and RFC 7, neither of which is at Draft.

mod activity;

/// Commands the application will expose (RFC 8).
///
/// Enumerated ahead of implementation so the RFC 8 command surface is visible
/// in one place; unused until the node seam exists.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// Establish a transport. Does **not** trigger a sync — that would
    /// violate I-5, which forbids sync timing correlating with user action.
    Connect,
    /// Tear down a transport.
    Disconnect,
    /// List self-published node bulletins. Nodes, never links.
    Rollcall,
    /// Ingest a courier container.
    Import,
    /// Produce a courier container.
    Pack,
    /// Compose and seal a message.
    Send,
    /// Prekey burn rate. Forward secrecy degrades silently without it.
    Keys,
    /// Path admission diagnostic for a node.
    Reach,
    /// Per-peer metrics panel, including the coverage and peer-count warnings
    /// required by RFC 0 §8.2.
    Peers,
    /// Fingerprint word list for out-of-band peer verification.
    Verify,
}

fn main() {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    println!("krab {version} ({name}) — scaffold, not yet operational");
    println!();
    println!("The RFC series is in planning. RFC 1 (Object Format and");
    println!("Cryptography) freezes permanently and is not yet at Draft, so no");
    println!("wire format exists to speak. See Documentation/ for the SIM-0");
    println!("measurements and the audit of them.");
    let _ = Command::Peers;
}
