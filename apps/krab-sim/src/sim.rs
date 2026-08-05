//! Discrete-event engine.
//!
//! Time spans nine orders of magnitude here -- a Tor round trip is seconds, a
//! courier journey is days -- so this is event-driven, not stepped. Everything
//! is integer seconds; the event queue is a min-heap keyed on (time, seq),
//! with `seq` making ordering total and therefore reproducible for a seed.

use crate::graph::Graph;
use crate::model::*;
use crate::rng::Rng;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

enum Ev {
    Inject(u32),
    Sync(u32),
    Deliver { node: u32, objs: Vec<u32> },
    /// Periodic measurement of live corpus size. Necessary because a node's
    /// bitmap is never cleared -- expiry is handled by masking the live
    /// window, so store size has to be recomputed over that window rather
    /// than accumulated, or the figure reports cumulative receipts instead.
    Sample,
}

struct Sched {
    t: u64,
    seq: u64,
    ev: Ev,
}
impl PartialEq for Sched {
    fn eq(&self, o: &Self) -> bool {
        self.t == o.t && self.seq == o.seq
    }
}
impl Eq for Sched {}
impl Ord for Sched {
    fn cmp(&self, o: &Self) -> Ordering {
        // Reversed: BinaryHeap is a max-heap, we want earliest-first.
        o.t.cmp(&self.t).then(o.seq.cmp(&self.seq))
    }
}
impl PartialOrd for Sched {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

pub struct RunResult {
    pub objects_measured: usize,
    pub delivered: usize,
    /// Delivery latency in hours over delivered messages in the analysis window.
    pub lat_p50: f64,
    pub lat_p90: f64,
    pub lat_p99: f64,
    /// Fraction of live objects a node holds, averaged over nodes at horizon.
    pub coverage_mean: f64,
    pub coverage_p10: f64,
    /// Peak corpus size per node, MB.
    pub store_mb_p50: f64,
    pub store_mb_p99: f64,
    /// Ingress per node per day, MB.
    pub rx_mb_day_p50: f64,
    pub rx_mb_day_p99: f64,
    /// Delivery rate split by the slowest transport on the path is not tracked
    /// directly; this is the share of measured objects whose destination was
    /// reachable only across a size-gated link.
    pub lora_gated_objects: usize,

    // ---- diagnostics added for audit ---------------------------------------
    /// Exact coverage (no boundary-word overcount), object count weighted.
    pub cov_exact: f64,
    /// Coverage weighted by object bytes rather than object count.
    pub cov_bytes: f64,
    /// Coverage restricted to the oldest quartile of the live window, i.e.
    /// objects that have had at least 0.75*TTL in which to propagate.
    pub cov_settled: f64,
    /// Coverage bucketed by object age, youngest bucket first.
    pub cov_by_age: Vec<f64>,
    /// Mean (not p99) of per-node peak live-corpus bytes, MB.
    pub store_mb_mean: f64,
    /// Mean (not p99) ingress per node per day, MB.
    pub rx_mb_day_mean: f64,
    /// Fraction of measured objects small enough to cross a LoRa edge.
    pub lora_eligible: f64,
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i]
}

/// Online/offline windows for one node, as an alternating renewal process.
fn online_windows(cfg: &Config, rng: &mut Rng) -> Vec<(u64, u64)> {
    let mut v = Vec::new();
    if cfg.uptime >= 0.999 {
        v.push((0, cfg.horizon));
        return v;
    }
    let mean_down = cfg.mean_session_up * (1.0 - cfg.uptime) / cfg.uptime;
    let mut t = 0f64;
    // Random phase so nodes are not synchronised at t=0.
    if rng.chance(1.0 - cfg.uptime) {
        t += rng.exp(mean_down);
    }
    while t < cfg.horizon as f64 {
        let up = rng.exp(cfg.mean_session_up).max(60.0);
        let start = t as u64;
        let end = ((t + up) as u64).min(cfg.horizon);
        if end > start {
            v.push((start, end));
        }
        t += up + rng.exp(mean_down).max(60.0);
    }
    v
}

fn is_online(w: &[(u64, u64)], t: u64) -> bool {
    // Windows are sorted and disjoint.
    match w.binary_search_by(|&(s, _)| if s <= t { Ordering::Less } else { Ordering::Greater }) {
        Ok(_) => true,
        Err(i) => i > 0 && w[i - 1].1 > t,
    }
}

pub fn run(cfg: &Config, seed: u64) -> Option<RunResult> {
    let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A_1234_5678);

    let g = Graph::generate(cfg.topo, cfg.n, cfg.degree, cfg.rewire, &mut rng);
    if !g.is_connected() {
        return None;
    }

    // ---- links -------------------------------------------------------------
    let links: Vec<Link> = g
        .edges
        .iter()
        .map(|&(a, b)| {
            let r = rng.f64();
            let kind = if r < cfg.mix_tcp {
                LinkKind::Tcp
            } else if r < cfg.mix_tcp + cfg.mix_lora {
                LinkKind::Lora
            } else {
                LinkKind::Courier
            };
            Link { a, b, kind }
        })
        .collect();

    // ---- objects, precomputed so indices are dense and ordered by time -----
    // Poisson injection per node. Sorting by creation time makes expiry a
    // prefix of the index space, which is what lets reconciliation work on a
    // contiguous word range instead of scanning the whole corpus.
    let mut objs: Vec<Object> = Vec::new();
    let social: Vec<Vec<u32>> = if cfg.dest == DestModel::Social {
        (0..cfg.n as u32).map(|u| g.within_hops(u, cfg.social_hops)).collect()
    } else {
        Vec::new()
    };
    let mean_gap = DAY as f64 / cfg.rate_per_day;
    for u in 0..cfg.n as u32 {
        let mut t = rng.exp(mean_gap);
        while t < cfg.horizon as f64 {
            let dest = match cfg.dest {
                DestModel::Uniform => {
                    let mut d = rng.below(cfg.n as u64) as u32;
                    if d == u {
                        d = (d + 1) % cfg.n as u32;
                    }
                    d
                }
                DestModel::Social => {
                    let cand = &social[u as usize];
                    if cand.is_empty() {
                        u
                    } else {
                        cand[rng.below(cand.len() as u64) as usize]
                    }
                }
            };
            // 90% text, 10% picture. Pictures are what LoRa cannot carry.
            let size = if rng.chance(0.90) {
                rng.range(500, 8_000) as u32
            } else {
                rng.range(50_000, 500_000) as u32
            };
            objs.push(Object { size, created: t as u64, origin: u, dest });
            t += rng.exp(mean_gap);
        }
    }
    objs.sort_by_key(|o| o.created);
    let m = objs.len();
    if m == 0 {
        return None;
    }
    let created: Vec<u64> = objs.iter().map(|o| o.created).collect();

    // Per-transport eligibility masks: object fits under the link's size gate.
    let mut size_mask = [BitSet::new(m), BitSet::new(m), BitSet::new(m)];
    for (i, o) in objs.iter().enumerate() {
        for (k, kind) in [LinkKind::Tcp, LinkKind::Lora, LinkKind::Courier].iter().enumerate() {
            if o.size <= kind.max_object() {
                size_mask[k].set(i);
            }
        }
    }
    let kidx = |k: LinkKind| match k {
        LinkKind::Tcp => 0usize,
        LinkKind::Lora => 1,
        LinkKind::Courier => 2,
    };

    // ---- node state --------------------------------------------------------
    let mut store: Vec<BitSet> = (0..cfg.n).map(|_| BitSet::new(m)).collect();
    let windows: Vec<Vec<(u64, u64)>> = (0..cfg.n).map(|_| online_windows(cfg, &mut rng)).collect();
    let mut delivered_at: Vec<u64> = vec![u64::MAX; m];
    let mut peak_bytes: Vec<u64> = vec![0; cfg.n];
    let mut rx_bytes: Vec<u64> = vec![0; cfg.n];

    // ---- event queue -------------------------------------------------------
    let mut q: BinaryHeap<Sched> = BinaryHeap::new();
    let mut seq: u64 = 0;
    let mut push = |q: &mut BinaryHeap<Sched>, seq: &mut u64, t: u64, ev: Ev| {
        *seq += 1;
        q.push(Sched { t, seq: *seq, ev });
    };
    for i in 0..m {
        push(&mut q, &mut seq, objs[i].created, Ev::Inject(i as u32));
    }
    for (li, l) in links.iter().enumerate() {
        let first = (rng.f64() * l.kind.sync_mean()) as u64;
        push(&mut q, &mut seq, first, Ev::Sync(li as u32));
    }
    // Measure live corpus size only once the network has reached steady state,
    // i.e. after one full TTL has elapsed and objects are expiring as fast as
    // they arrive.
    let mut st = cfg.ttl;
    while st <= cfg.horizon {
        push(&mut q, &mut seq, st, Ev::Sample);
        st += 2 * DAY;
    }

    // ---- main loop ---------------------------------------------------------
    let mut scratch: Vec<u32> = Vec::with_capacity(4096);

    while let Some(Sched { t, ev, .. }) = q.pop() {
        if t > cfg.horizon {
            break;
        }
        match ev {
            Ev::Inject(oi) => {
                let o = &objs[oi as usize];
                let n = o.origin as usize;
                store[n].set(oi as usize);
                if o.dest == o.origin {
                    delivered_at[oi as usize] = t;
                }
            }

            Ev::Deliver { node, objs: ids } => {
                let n = node as usize;
                for &oi in &ids {
                    if !store[n].get(oi as usize) {
                        store[n].set(oi as usize);
                        rx_bytes[n] += objs[oi as usize].size as u64;
                        if objs[oi as usize].dest == node && delivered_at[oi as usize] == u64::MAX {
                            delivered_at[oi as usize] = t;
                        }
                    }
                }
            }

            Ev::Sample => {
                let lo = created.partition_point(|&c| c + cfg.ttl <= t);
                let hi = created.partition_point(|&c| c <= t);
                if lo >= hi {
                    continue;
                }
                let lw = lo >> 6;
                let hw = ((hi + 63) >> 6).min(store[0].w.len());
                for u in 0..cfg.n {
                    let mut b: u64 = 0;
                    for wi in lw..hw {
                        let mut d = store[u].w[wi];
                        while d != 0 {
                            let bit = d.trailing_zeros() as usize;
                            d &= d - 1;
                            let oi = (wi << 6) | bit;
                            if oi >= lo && oi < hi {
                                b += objs[oi].size as u64;
                            }
                        }
                    }
                    peak_bytes[u] = peak_bytes[u].max(b);
                }
            }

            Ev::Sync(li) => {
                let l = links[li as usize];
                let next = t + l.kind.sync_mean().max(60.0) as u64;
                push(&mut q, &mut seq, next, Ev::Sync(li));

                // A courier does not require either endpoint to be up.
                if l.kind != LinkKind::Courier {
                    if !is_online(&windows[l.a as usize], t) || !is_online(&windows[l.b as usize], t)
                    {
                        continue;
                    }
                }

                // Live window: expiry is monotonic in index because objects
                // are sorted by creation and TTL is uniform, so expired
                // objects are exactly a prefix.
                let lo = created.partition_point(|&c| c + cfg.ttl <= t);
                let hi = created.partition_point(|&c| c <= t);
                if lo >= hi {
                    continue;
                }
                let lw = lo >> 6;
                let hw = ((hi + 63) >> 6).min(store[0].w.len());
                let mask = &size_mask[kidx(l.kind)];
                let cap = l.kind.capacity_bytes();
                let lat = l.kind.latency_s();
                let bw = cap as f64 / l.kind.sync_mean().max(1.0);

                // Both directions in one reconciliation.
                for (src, dst) in [(l.a as usize, l.b as usize), (l.b as usize, l.a as usize)] {
                    scratch.clear();
                    let mut bytes: u64 = 0;
                    'words: for wi in lw..hw {
                        let mut d = store[src].w[wi] & !store[dst].w[wi] & mask.w[wi];
                        while d != 0 {
                            let bit = d.trailing_zeros() as usize;
                            d &= d - 1;
                            let oi = (wi << 6) | bit;
                            if oi < lo || oi >= hi {
                                continue;
                            }
                            let sz = objs[oi].size as u64;
                            // Oldest-first within the window, which is also
                            // the eviction order: uniform, leaking nothing.
                            if bytes + sz > cap {
                                break 'words;
                            }
                            bytes += sz;
                            scratch.push(oi as u32);
                        }
                    }
                    if !scratch.is_empty() {
                        let dt = lat + bytes as f64 / bw.max(1.0);
                        push(
                            &mut q,
                            &mut seq,
                            t + dt as u64,
                            Ev::Deliver { node: dst as u32, objs: scratch.clone() },
                        );
                    }
                }
            }
        }
    }

    // ---- metrics -----------------------------------------------------------
    // Only objects with a full TTL inside the horizon can be fairly judged.
    let cutoff = cfg.horizon.saturating_sub(cfg.ttl);
    let mut lat: Vec<f64> = Vec::new();
    let mut measured = 0usize;
    let mut delivered = 0usize;
    let mut lora_gated = 0usize;
    for i in 0..m {
        if objs[i].created > cutoff {
            continue;
        }
        measured += 1;
        if objs[i].size > LinkKind::Lora.max_object() {
            lora_gated += 1;
        }
        if delivered_at[i] != u64::MAX {
            delivered += 1;
            lat.push((delivered_at[i] - objs[i].created) as f64 / HOUR as f64);
        }
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Corpus coverage at the horizon.
    let lo = created.partition_point(|&c| c + cfg.ttl <= cfg.horizon);
    let hi = created.partition_point(|&c| c <= cfg.horizon);
    let live = (hi - lo) as f64;
    let lw = lo >> 6;
    let hw = ((hi + 63) >> 6).min(store[0].w.len());
    let mut cov: Vec<f64> = (0..cfg.n)
        .map(|u| {
            if live <= 0.0 {
                0.0
            } else {
                store[u].count_range(lw, hw) as f64 / live
            }
        })
        .collect();
    let cov_mean = cov.iter().sum::<f64>() / cov.len() as f64;
    cov.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // ---- audit diagnostics -------------------------------------------------
    // Exact holder counts over the live window, so we can separate three things
    // the published `cover` column conflates: the boundary-word overcount, the
    // count-vs-byte weighting, and the fact that objects created near the
    // horizon have had no time to propagate at all.
    const NB: usize = 8;
    let mut age_hold = vec![0u64; NB];
    let mut age_tot = vec![0u64; NB];
    let mut held_total: u128 = 0;
    let mut bytes_held: u128 = 0;
    let mut bytes_live: u128 = 0;
    let mut settled_hold: u128 = 0;
    let mut settled_tot: u128 = 0;
    for oi in lo..hi {
        let age = cfg.horizon.saturating_sub(created[oi]);
        let b = (((age as f64 / cfg.ttl as f64) * NB as f64) as usize).min(NB - 1);
        let mut holders: u64 = 0;
        for u in 0..cfg.n {
            if store[u].get(oi) {
                holders += 1;
            }
        }
        age_hold[b] += holders;
        age_tot[b] += cfg.n as u64;
        held_total += holders as u128;
        bytes_held += holders as u128 * objs[oi].size as u128;
        bytes_live += cfg.n as u128 * objs[oi].size as u128;
        if age * 4 >= cfg.ttl * 3 {
            settled_hold += holders as u128;
            settled_tot += cfg.n as u128;
        }
    }
    let denom = (hi - lo) as u128 * cfg.n as u128;
    let cov_exact = if denom == 0 { 0.0 } else { held_total as f64 / denom as f64 };
    let cov_bytes = if bytes_live == 0 { 0.0 } else { bytes_held as f64 / bytes_live as f64 };
    let cov_settled =
        if settled_tot == 0 { 0.0 } else { settled_hold as f64 / settled_tot as f64 };
    let cov_by_age: Vec<f64> = (0..NB)
        .map(|b| if age_tot[b] == 0 { 0.0 } else { age_hold[b] as f64 / age_tot[b] as f64 })
        .collect();
    let lora_eligible =
        if measured == 0 { 0.0 } else { (measured - lora_gated) as f64 / measured as f64 };

    let mut smb: Vec<f64> = peak_bytes.iter().map(|&b| b as f64 / 1e6).collect();
    smb.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let days = cfg.horizon as f64 / DAY as f64;
    let mut rmb: Vec<f64> = rx_bytes.iter().map(|&b| b as f64 / 1e6 / days).collect();
    rmb.sort_by(|a, b| a.partial_cmp(b).unwrap());

    Some(RunResult {
        objects_measured: measured,
        delivered,
        lat_p50: pct(&lat, 0.50),
        lat_p90: pct(&lat, 0.90),
        lat_p99: pct(&lat, 0.99),
        coverage_mean: cov_mean,
        coverage_p10: pct(&cov, 0.10),
        store_mb_p50: pct(&smb, 0.50),
        store_mb_p99: pct(&smb, 0.99),
        rx_mb_day_p50: pct(&rmb, 0.50),
        rx_mb_day_p99: pct(&rmb, 0.99),
        lora_gated_objects: lora_gated,
        cov_exact,
        cov_bytes,
        cov_settled,
        cov_by_age,
        store_mb_mean: smb.iter().sum::<f64>() / smb.len().max(1) as f64,
        rx_mb_day_mean: rmb.iter().sum::<f64>() / rmb.len().max(1) as f64,
        lora_eligible,
    })
}
