//! Reconciliation filters (RFC 5).
//!
//! A filter is derived from the signed peer credential so that both sides
//! provably agree on it. Reconciliation is scoped to the filter; otherwise
//! phantom divergence recurs every cycle, permanently.

use crate::object::Class;

/// The agreed scope of a reconciliation: `shard_mask ∩ size_cap ∩ class_mask
/// ∩ retention_window`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Number of leading tag bits used for shard selection. `0` means no
    /// sharding.
    pub shard_k: u8,
    /// Accepted shard prefixes. Empty with `shard_k == 0` means "everything".
    pub shards: alloc::vec::Vec<u64>,
    /// Maximum object size accepted across this link, bytes.
    ///
    /// # SIM-0 audit
    ///
    /// This is the field that silently disabled LoRa in SIM-0: a 512 B cap
    /// against a traffic model whose smallest object was 500 B admitted 0.16%
    /// of objects. A `LinkProfile` whose `size_cap` excludes most of the
    /// traffic distribution is not a slow link, it is an absent one, and the
    /// client MUST be able to say which it has.
    pub size_cap: u32,
    /// Object classes accepted across this link. Channels are excluded by
    /// default (RFC 6).
    pub classes: alloc::vec::Vec<Class>,
    /// Retention floor commitment, seconds. Distinct from an object's expiry.
    pub retention: u64,
}

impl Filter {
    /// Fraction of a size distribution this filter admits, for the client
    /// warning required by RFC 0 §8.2 and by the SIM-0 audit.
    ///
    /// `sizes` is a sample of recent object sizes. Returns `None` when the
    /// sample is empty rather than inventing a figure.
    pub fn admitted_fraction(&self, sizes: &[u32]) -> Option<f64> {
        if sizes.is_empty() {
            return None;
        }
        let n = sizes.iter().filter(|&&s| s <= self.size_cap).count();
        Some(n as f64 / sizes.len() as f64)
    }
}
