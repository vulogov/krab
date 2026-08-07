//! RFC 3 credential and nodelist-fragment sizes.
//!
//! # What is derivable and what is not
//!
//! RFC 3 §3 and §5.1 give credential *field lists* but not the sub-structure
//! of `party`, `terms`, `flags`, or `transports`. The document's own byte
//! counts — a 343-byte `peer-link` with no endpoints, 416 with one, a
//! 284-byte unsigned body — therefore cannot be recomputed from the document.
//! They are taken here as stated inputs, and flagged in
//! `Documentation/RFC-3-review.md`.
//!
//! Everything built *on top* of a credential size is fully derivable, and is
//! computed rather than assumed: fragment size, the O(P²) copy cost, delta
//! size, and airtime. Those are RFC 3 §8.1 and §8.2, and they reproduce
//! exactly.

/// RFC 3 §3, stated. A `peer-link` carrying one endpoint.
pub const PEER_LINK_1EP: usize = 416;
/// RFC 3 §3, stated. No endpoints.
pub const PEER_LINK_0EP: usize = 343;
/// RFC 3 §3, stated. Three endpoints.
pub const PEER_LINK_3EP: usize = 562;
/// RFC 3 §3, stated. The hash-chain input.
pub const PEER_LINK_BODY: usize = 284;
/// RFC 3 §9.1, stated. A self-signed rollcall bulletin.
pub const ROLLCALL_ENTRY: usize = 153;

/// Signed wrapper around a full nodelist fragment, recovered from RFC 3 §8.1.
pub const FRAGMENT_WRAPPER: usize = 220;
/// Signed wrapper around a `NODEDIFF` delta, recovered from RFC 3 §8.2.
/// Smaller than a full fragment's: a delta references its base by hash rather
/// than restating it.
pub const DELTA_WRAPPER: usize = 200;

/// Bytes movable in one LoRa reconciliation (RFC 1 §8.3, SIM-0 §1).
pub const LORA_WINDOW: usize = 18_000;

/// One node's fragment: its valid credentials under a signed wrapper.
pub fn fragment(peers: usize, cred: usize) -> usize {
    FRAGMENT_WRAPPER + peers * cred
}

/// Every copy a node emits per publication.
///
/// The fragment is encrypted individually to each peer (RFC 3 §8), so cost is
/// quadratic in peer count. This is the term that bounds peer count from
/// above, and it is why RFC 3 §13 caps constrained links at 25 peers while
/// SIM-0 bounds them from below at 12.
pub fn all_copies(peers: usize, cred: usize) -> usize {
    peers * fragment(peers, cred)
}

/// A `NODEDIFF` delta covering `changed` links, all copies.
pub fn delta_all_copies(peers: usize, changed: usize, cred: usize) -> usize {
    peers * (DELTA_WRAPPER + changed * cred)
}

/// LoRa reconciliations needed to move `bytes`.
pub fn lora_reconciliations(bytes: usize) -> f64 {
    bytes as f64 / LORA_WINDOW as f64
}

/// Days of LoRa airtime, at one reconciliation per 6 hours (SIM-0 §1).
pub fn lora_days(bytes: usize) -> f64 {
    lora_reconciliations(bytes) * 6.0 / 24.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Agreement to RFC 3's stated precision.
    ///
    /// RFC 3 gives these to two significant figures and is not consistent
    /// about rounding versus truncating — §8.1 truncates 11.5 KB to "11",
    /// while §8.2 rounds a ratio of 13.86 to "14". Two significant figures on
    /// a small number is coarse: the tightest case here is 0.639 LoRa
    /// reconciliations presented as "0.6", which is 6.5% off on its own.
    ///
    /// A 7% band therefore admits the typography while still having teeth. A
    /// real model error — a wrong wrapper size, or missing the quadratic —
    /// misses by tens of percent or more.
    fn two_sig_figs(got: f64, want: f64) -> bool {
        (got - want).abs() / want < 0.07
    }

    /// RFC 3 §8.1, reproduced exactly.
    #[test]
    fn fragment_table_matches_rfc3() {
        // (peers, fragment KB, all copies KB, LoRa reconciliations)
        let want = [
            (5usize, 2.3f64, 11.0f64, 0.6f64),
            (8, 3.5, 28.0, 1.6),
            (12, 5.2, 62.0, 3.5),
            (20, 8.5, 170.0, 9.5),
            (50, 21.0, 1_050.0, 58.0),
        ];
        let close = two_sig_figs;
        for (peers, frag_kb, copies_kb, recons) in want {
            let f = fragment(peers, PEER_LINK_1EP) as f64 / 1000.0;
            let c = all_copies(peers, PEER_LINK_1EP) as f64 / 1000.0;
            let r = lora_reconciliations(all_copies(peers, PEER_LINK_1EP));
            assert!(
                close(f, frag_kb),
                "{peers} peers: fragment {f:.2} KB, RFC says {frag_kb}"
            );
            assert!(
                close(c, copies_kb),
                "{peers} peers: copies {c:.1} KB, RFC says {copies_kb}"
            );
            assert!(
                close(r, recons),
                "{peers} peers: {r:.2} reconciliations, RFC says {recons}"
            );
        }
    }

    /// RFC 3 §8.2, reproduced exactly, including the stated ratios.
    #[test]
    fn nodediff_table_matches_rfc3() {
        // (peers, delta KB, full KB, ratio)
        let want = [
            (12usize, 7.4f64, 62.0f64, 8.0f64),
            (20, 12.0, 170.0, 14.0),
            (50, 31.0, 1_050.0, 34.0),
        ];
        let close = two_sig_figs;
        for (peers, delta_kb, full_kb, ratio) in want {
            let d = delta_all_copies(peers, 1, PEER_LINK_1EP) as f64 / 1000.0;
            let f = all_copies(peers, PEER_LINK_1EP) as f64 / 1000.0;
            assert!(
                close(d, delta_kb),
                "{peers} peers: delta {d:.1} KB, RFC says {delta_kb}"
            );
            assert!(
                close(f, full_kb),
                "{peers} peers: full {f:.1} KB, RFC says {full_kb}"
            );
            assert!(
                close(f / d, ratio),
                "{peers} peers: ratio {:.1}x, RFC says {ratio}x",
                f / d
            );
        }
    }

    /// RFC 3 §8.1's prose claim about the 50-peer case.
    #[test]
    fn fifty_peers_is_two_weeks_of_lora_airtime() {
        let d = lora_days(all_copies(50, PEER_LINK_1EP));
        assert!(
            (14.0..15.5).contains(&d),
            "50 peers: {d:.1} days, RFC says roughly two weeks"
        );
    }

    /// RFC 3 §13 caps constrained links at 25 peers. Check that a weekly
    /// publication actually fits inside a week of LoRa airtime there, and
    /// does not at 50.
    #[test]
    fn peer_cap_of_25_is_what_makes_weekly_publication_fit() {
        assert!(lora_days(all_copies(25, PEER_LINK_1EP)) < 7.0);
        assert!(lora_days(all_copies(50, PEER_LINK_1EP)) > 7.0);
    }
}
