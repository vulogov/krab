//! Simulation backend: seeded, controllable clock, injectable partitions,
//! churn, and byzantine peers (RFC 0 §9).
//!
//! This is the deterministic-simulation target. It is a `Fabric` backend
//! rather than a separate harness so that production code paths are the ones
//! under test.
