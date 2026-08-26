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
use std::collections::{BinaryHeap, HashMap};

enum Ev {
    Inject(u32),
    Sync(u32),
    Deliver {
        node: u32,
        objs: Vec<u32>,
    },
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

    // ---- SIM-1 -------------------------------------------------------------
    /// Control bytes (manifests, fingerprints) per link kind: tcp, lora, courier.
    pub ctrl_bytes: [u64; 3],
    /// Payload bytes actually moved, per link kind.
    pub payload_bytes: [u64; 3],
    /// Reconciliations attempted, per link kind.
    pub syncs: [u64; 3],
    /// Reconciliations in which control traffic consumed the whole window, so
    /// no payload moved at all. The failure mode SIM-0 could not see.
    pub starved: [u64; 3],
    /// P(a vantage point holds an object | hop distance from its origin),
    /// indexed `[age_bucket][distance]`. A flat row means no leak.
    pub hold_by_dist: Vec<Vec<f64>>,
    /// Percentile rank of the true origin under a maximum-likelihood attack
    /// using `hold_by_dist`. 0.0 is a perfect identification, 0.5 is chance.
    pub adv_rank_p50: f64,
    /// Probability the true origin lands in the attack's top 10 candidates.
    /// Chance is `10/n`.
    pub adv_top10: f64,
    /// Objects the attack was scored over.
    pub adv_scored: usize,
}

/// Hop distance from `src` to every node. `u16::MAX` where unreachable.
fn bfs(g: &Graph, src: usize, n: usize) -> Vec<u16> {
    let mut d = vec![u16::MAX; n];
    d[src] = 0;
    let mut frontier = vec![src as u32];
    let mut depth = 0u16;
    while !frontier.is_empty() {
        depth += 1;
        let mut next = Vec::new();
        for &u in &frontier {
            for &v in &g.adj[u as usize] {
                if d[v as usize] == u16::MAX {
                    d[v as usize] = depth;
                    next.push(v);
                }
            }
        }
        frontier = next;
    }
    d
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
    match w.binary_search_by(|&(s, _)| {
        if s <= t {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }) {
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
        (0..cfg.n as u32)
            .map(|u| g.within_hops(u, cfg.social_hops))
            .collect()
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
            objs.push(Object {
                size,
                created: t as u64,
                origin: u,
                dest,
            });
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
        for (k, kind) in [LinkKind::Tcp, LinkKind::Lora, LinkKind::Courier]
            .iter()
            .enumerate()
        {
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

    // SIM-1 accounting.
    let mut ctrl_bytes = [0u64; 3];
    let mut payload_bytes = [0u64; 3];
    let mut syncs = [0u64; 3];
    let mut starved = [0u64; 3];
    // Partially transferred objects, keyed (link, destination, object). Only
    // read by lookup, never iterated, so it cannot perturb the RNG stream.
    let mut partial: HashMap<(u32, u32, u32), u64> = HashMap::new();
    let cap_bytes = cfg.store_cap_mb * 1_000_000;

    // ---- event queue -------------------------------------------------------
    let mut q: BinaryHeap<Sched> = BinaryHeap::new();
    let mut seq: u64 = 0;
    let push = |q: &mut BinaryHeap<Sched>, seq: &mut u64, t: u64, ev: Ev| {
        *seq += 1;
        q.push(Sched { t, seq: *seq, ev });
    };
    for (i, o) in objs.iter().enumerate().take(m) {
        push(&mut q, &mut seq, o.created, Ev::Inject(i as u32));
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
                    // SIM-1: capacity-pressure eviction. Oldest-first and
                    // uniform across shards (I-6) — the holding set must not
                    // encode anything but age, since under partial coverage
                    // *which* objects a node holds is the whole question.
                    if cap_bytes > 0 && b > cap_bytes {
                        let mut oi = lo;
                        while b > cap_bytes && oi < hi {
                            if store[u].get(oi) {
                                store[u].w[oi >> 6] &= !(1u64 << (oi & 63));
                                b -= objs[oi].size as u64;
                            }
                            oi += 1;
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
                if l.kind != LinkKind::Courier
                    && (!is_online(&windows[l.a as usize], t)
                        || !is_online(&windows[l.b as usize], t))
                {
                    continue;
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
                let ki = kidx(l.kind);
                let mask = &size_mask[ki];
                let cap = l.kind.capacity_bytes();
                let lat = l.kind.latency_s();
                let bw = cap as f64 / l.kind.sync_mean().max(1.0);

                // Word mask restricting a word to the live window, so counts
                // do not spill into the partial words at either boundary.
                let wmask = |wi: usize| -> u64 {
                    let mut m = !0u64;
                    if wi == lo >> 6 {
                        m &= !0u64 << (lo & 63);
                    }
                    if hi & 63 != 0 && wi == hi >> 6 {
                        m &= (1u64 << (hi & 63)) - 1;
                    }
                    m
                };

                // SIM-1: control traffic is charged against the same window as
                // payload. SIM-0 treated it as free, which is what hid the
                // question of whether a constrained link can reconcile at all.
                let (ctrl, rounds) = if cfg.manifest {
                    let (mut mine, mut theirs, mut diff) = (0u64, 0u64, 0u64);
                    for wi in lw..hw {
                        let w = wmask(wi) & mask.w[wi];
                        let a_w = store[l.a as usize].w[wi] & w;
                        let b_w = store[l.b as usize].w[wi] & w;
                        mine += a_w.count_ones() as u64;
                        theirs += b_w.count_ones() as u64;
                        diff += (a_w ^ b_w).count_ones() as u64;
                    }
                    recon_cost(cfg, mine, theirs, diff)
                } else {
                    (0, 1)
                };
                syncs[ki] += 1;
                let pay_cap = cap.saturating_sub(ctrl);
                ctrl_bytes[ki] += ctrl.min(cap);
                if pay_cap == 0 {
                    starved[ki] += 1;
                    continue;
                }
                // An RBSR descent costs a round trip per level; a full manifest
                // costs one. On a courier link that is the dominant term.
                let lat = lat * (2.0 * rounds as f64 - 1.0);

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
                            if cfg.frag {
                                // Store-and-forward fragmentation: an object
                                // too large for one window resumes in the next.
                                let key = (li, dst as u32, oi as u32);
                                let done = *partial.get(&key).unwrap_or(&0);
                                let take = (sz - done).min(pay_cap - bytes);
                                bytes += take;
                                if done + take == sz {
                                    partial.remove(&key);
                                    scratch.push(oi as u32);
                                } else {
                                    partial.insert(key, done + take);
                                    break 'words;
                                }
                            } else if bytes + sz > pay_cap {
                                // SIM-0 abandons the whole transfer here, which
                                // wedges the link on its oldest oversized
                                // object forever. `hol_fix` skips instead.
                                if cfg.hol_fix {
                                    continue;
                                }
                                break 'words;
                            } else {
                                bytes += sz;
                                scratch.push(oi as u32);
                            }
                        }
                    }
                    payload_bytes[ki] += bytes;
                    if !scratch.is_empty() {
                        let dt = lat + bytes as f64 / bw.max(1.0);
                        push(
                            &mut q,
                            &mut seq,
                            t + dt as u64,
                            Ev::Deliver {
                                node: dst as u32,
                                objs: scratch.clone(),
                            },
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
    let mut age_hold = [0u64; NB];
    let mut age_tot = [0u64; NB];
    let mut held_total: u128 = 0;
    let mut bytes_held: u128 = 0;
    let mut bytes_live: u128 = 0;
    let mut settled_hold: u128 = 0;
    let mut settled_tot: u128 = 0;
    for oi in lo..hi {
        let age = cfg.horizon.saturating_sub(created[oi]);
        let b = (((age as f64 / cfg.ttl as f64) * NB as f64) as usize).min(NB - 1);
        let holders = store
            .iter()
            .take(cfg.n)
            .filter(|s| s.get(oi))
            .count() as u64;
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
    let cov_exact = if denom == 0 {
        0.0
    } else {
        held_total as f64 / denom as f64
    };
    let cov_bytes = if bytes_live == 0 {
        0.0
    } else {
        bytes_held as f64 / bytes_live as f64
    };
    let cov_settled = if settled_tot == 0 {
        0.0
    } else {
        settled_hold as f64 / settled_tot as f64
    };
    let cov_by_age: Vec<f64> = (0..NB)
        .map(|b| {
            if age_tot[b] == 0 {
                0.0
            } else {
                age_hold[b] as f64 / age_tot[b] as f64
            }
        })
        .collect();
    let lora_eligible = if measured == 0 {
        0.0
    } else {
        (measured - lora_gated) as f64 / measured as f64
    };

    // ---- SIM-1: holdings leak and the origin attack ------------------------
    //
    // RFC 0 §7.4 defers to SIM-1 the coverage threshold below which
    // differential holdings analysis becomes practical. The SIM-0 audit
    // showed the threshold is the wrong question: holding probability is a
    // steep function of object *age*, and age is readable from the cleartext
    // `expiry` field that blocking item B2 freezes permanently.
    //
    // So the quantity measured here is not a threshold but a leak: how much
    // does an adversary holding k vantage points sharpen its posterior over a
    // message's injection point, given only what it holds and each object's
    // age? No arrival timestamps, no decryption.
    let mut hold_by_dist: Vec<Vec<f64>> = Vec::new();
    let mut adv_rank_p50 = f64::NAN;
    let mut adv_top10 = f64::NAN;
    let mut adv_scored = 0usize;
    if cfg.adversary > 0 && hi > lo {
        // Placement draws from its own stream, after the main loop, so an
        // adversary can never perturb the simulation it is observing.
        let mut arng = Rng::new(seed ^ 0x00AD_0E12_5A17_9C3B);
        let vantage: Vec<usize> = match cfg.adv_place {
            AdvPlacement::HighDegree => {
                let mut idx: Vec<usize> = (0..cfg.n).collect();
                idx.sort_by_key(|&u| (core::cmp::Reverse(g.adj[u].len()), u));
                idx.truncate(cfg.adversary);
                idx
            }
            AdvPlacement::Random => {
                let mut idx: Vec<usize> = (0..cfg.n).collect();
                for i in 0..cfg.adversary.min(cfg.n) {
                    let j = i + arng.below((cfg.n - i) as u64) as usize;
                    idx.swap(i, j);
                }
                idx.truncate(cfg.adversary);
                idx
            }
        };
        let dists: Vec<Vec<u16>> = vantage.iter().map(|&v| bfs(&g, v, cfg.n)).collect();
        let maxd = dists
            .iter()
            .flatten()
            .copied()
            .filter(|&d| d != u16::MAX)
            .max()
            .unwrap_or(0) as usize;

        // Train the leak table on even-indexed objects and attack the odd ones,
        // so the attack is never scored against the data that calibrated it.
        let mut hit = vec![vec![0u64; maxd + 1]; NB];
        let mut tot = vec![vec![0u64; maxd + 1]; NB];
        for oi in (lo..hi).step_by(2) {
            let age = cfg.horizon.saturating_sub(created[oi]);
            let b = (((age as f64 / cfg.ttl as f64) * NB as f64) as usize).min(NB - 1);
            let origin = objs[oi].origin as usize;
            for (vi, &v) in vantage.iter().enumerate() {
                let d = dists[vi][origin];
                if d == u16::MAX {
                    continue;
                }
                tot[b][d as usize] += 1;
                if store[v].get(oi) {
                    hit[b][d as usize] += 1;
                }
            }
        }
        // Laplace-smoothed, so an unobserved (bucket, distance) cell cannot
        // hand the attack an infinite log-likelihood.
        let rate =
            |b: usize, d: usize| -> f64 { (hit[b][d] as f64 + 0.5) / (tot[b][d] as f64 + 1.0) };
        hold_by_dist = (0..NB)
            .map(|b| {
                (0..=maxd)
                    .map(|d| if tot[b][d] == 0 { f64::NAN } else { rate(b, d) })
                    .collect()
            })
            .collect();

        let mut ranks: Vec<f64> = Vec::new();
        let mut top10 = 0usize;
        for oi in (lo + 1..hi).step_by(2) {
            let age = cfg.horizon.saturating_sub(created[oi]);
            let b = (((age as f64 / cfg.ttl as f64) * NB as f64) as usize).min(NB - 1);
            let obs: Vec<bool> = vantage.iter().map(|&v| store[v].get(oi)).collect();
            // An adversary that holds none of an object learns nothing useful
            // about it beyond "not near us"; score only what it can act on.
            if !obs.iter().any(|&x| x) {
                continue;
            }
            let mut best = 0usize;
            let mut ll: Vec<f64> = Vec::with_capacity(cfg.n);
            // `c` indexes the second axis of `dists`, one column across every
            // row — not a walk over a slice, so there is no iterator to take.
            #[allow(clippy::needless_range_loop)]
            for c in 0..cfg.n {
                let mut s = 0.0f64;
                for (vi, &o) in obs.iter().enumerate() {
                    let d = dists[vi][c];
                    if d == u16::MAX {
                        continue;
                    }
                    let p = rate(b, d as usize);
                    s += if o { p.ln() } else { (1.0 - p).ln() };
                }
                ll.push(s);
                if s > ll[best] {
                    best = c;
                }
            }
            let truth = ll[objs[oi].origin as usize];
            // Mid-rank, because ties are the common case rather than an edge
            // case: where the leak is weak, most candidates share a likelihood
            // and counting only strict betters would report a confident
            // identification that the adversary cannot actually make.
            let better = ll.iter().filter(|&&s| s > truth).count();
            let tied = ll.iter().filter(|&&s| s == truth).count().saturating_sub(1);
            let rank = better as f64 + tied as f64 / 2.0;
            ranks.push(rank / cfg.n as f64);
            if rank < 10.0 {
                top10 += 1;
            }
            adv_scored += 1;
        }
        ranks.sort_by(|a, b| a.partial_cmp(b).unwrap());
        adv_rank_p50 = pct(&ranks, 0.50);
        adv_top10 = if adv_scored == 0 {
            f64::NAN
        } else {
            top10 as f64 / adv_scored as f64
        };
    }

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
        ctrl_bytes,
        payload_bytes,
        syncs,
        starved,
        hold_by_dist,
        adv_rank_p50,
        adv_top10,
        adv_scored,
    })
}
