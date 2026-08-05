//! Courier backend: physical media (RFC 4).
//!
//! The container is a flat framed byte stream. Filenames are ignored. Every
//! object is verified by hash on ingest, and a foreign database file is never
//! opened — the container is data, not a program.
//!
//! This backend is the one that keeps the rest of the system honest: if an
//! API cannot be driven by a USB stick delivered fortnightly, it violates
//! I-4 and belongs above the `Fabric` boundary rather than at it.
//!
//! Per SIM-0 §3 a courier-only component does not work (52.5% delivery, 1.8%
//! coverage). A courier-only node MUST be a leaf attached to at least one
//! better-connected peer, not a participant in a courier-only component.
