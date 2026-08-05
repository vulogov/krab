//! Peer-graph topology generation.
//!
//! Krab peer sets are built by hand, out of band, between people who know each
//! other. The resulting graph is therefore a social graph, not a random one:
//! sparse, clustered, with a small number of long-range edges. Watts-Strogatz
//! is the standard model for that shape and is the primary topology here.
//! Barabasi-Albert is included because a real deployment will grow hubs
//! (well-connected operators everyone wants to peer with) whether or not the
//! design intends them, and hubs change convergence substantially.

use crate::rng::Rng;
use std::collections::BTreeSet;

// BTreeSet, not HashSet: HashSet iteration order is randomised per process, and
// the generators below consume the RNG stream in iteration order. Using a hash
// set here makes runs unreproducible across invocations, which would defeat the
// point of a simulator that grounds normative claims.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    /// Ring lattice with `degree` neighbours, each edge rewired with prob `p`.
    WattsStrogatz,
    /// Preferential attachment; each new node attaches `degree/2` edges.
    BarabasiAlbert,
    /// Uniformly random graph of the given mean degree. Baseline only --
    /// no clustering, so it converges optimistically compared to reality.
    RandomRegular,
}

impl Topology {
    pub fn parse(s: &str) -> Option<Topology> {
        match s {
            "ws" | "watts-strogatz" => Some(Topology::WattsStrogatz),
            "ba" | "barabasi-albert" => Some(Topology::BarabasiAlbert),
            "rr" | "random-regular" => Some(Topology::RandomRegular),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Topology::WattsStrogatz => "ws",
            Topology::BarabasiAlbert => "ba",
            Topology::RandomRegular => "rr",
        }
    }
}

pub struct Graph {
    pub n: usize,
    pub edges: Vec<(u32, u32)>,
    pub adj: Vec<Vec<u32>>,
}

impl Graph {
    fn from_edges(n: usize, set: BTreeSet<(u32, u32)>) -> Graph {
        let mut edges: Vec<(u32, u32)> = set.into_iter().collect();
        edges.sort_unstable();
        let mut adj = vec![Vec::new(); n];
        for &(a, b) in &edges {
            adj[a as usize].push(b);
            adj[b as usize].push(a);
        }
        Graph { n, edges, adj }
    }

    pub fn generate(topo: Topology, n: usize, degree: usize, rewire: f64, rng: &mut Rng) -> Graph {
        match topo {
            Topology::WattsStrogatz => watts_strogatz(n, degree, rewire, rng),
            Topology::BarabasiAlbert => barabasi_albert(n, degree, rng),
            Topology::RandomRegular => random_regular(n, degree, rng),
        }
    }

    /// Nodes reachable from `src` within `hops`, excluding `src`.
    /// Used by the "social" destination model: people mostly message people
    /// near them in the trust graph, not uniformly random strangers.
    pub fn within_hops(&self, src: u32, hops: usize) -> Vec<u32> {
        let mut seen = vec![false; self.n];
        seen[src as usize] = true;
        let mut frontier = vec![src];
        let mut out = Vec::new();
        for _ in 0..hops {
            let mut next = Vec::new();
            for &u in &frontier {
                for &v in &self.adj[u as usize] {
                    if !seen[v as usize] {
                        seen[v as usize] = true;
                        out.push(v);
                        next.push(v);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        out
    }

    /// True if every node is reachable from node 0. A disconnected peer graph
    /// cannot converge by definition, so this is checked before every run.
    pub fn is_connected(&self) -> bool {
        if self.n == 0 {
            return true;
        }
        let mut seen = vec![false; self.n];
        seen[0] = true;
        let mut stack = vec![0u32];
        let mut count = 1;
        while let Some(u) = stack.pop() {
            for &v in &self.adj[u as usize] {
                if !seen[v as usize] {
                    seen[v as usize] = true;
                    count += 1;
                    stack.push(v);
                }
            }
        }
        count == self.n
    }

    pub fn mean_degree(&self) -> f64 {
        2.0 * self.edges.len() as f64 / self.n as f64
    }
}

fn norm(a: u32, b: u32) -> (u32, u32) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn watts_strogatz(n: usize, degree: usize, rewire: f64, rng: &mut Rng) -> Graph {
    let k = (degree / 2).max(1);
    let mut set: BTreeSet<(u32, u32)> = BTreeSet::new();
    for i in 0..n {
        for j in 1..=k {
            set.insert(norm(i as u32, ((i + j) % n) as u32));
        }
    }
    let base: Vec<(u32, u32)> = set.iter().copied().collect();
    for &(a, b) in &base {
        if rng.chance(rewire) {
            for _ in 0..32 {
                let c = rng.below(n as u64) as u32;
                if c == a {
                    continue;
                }
                let e = norm(a, c);
                if set.contains(&e) {
                    continue;
                }
                set.remove(&norm(a, b));
                set.insert(e);
                break;
            }
        }
    }
    Graph::from_edges(n, set)
}

fn barabasi_albert(n: usize, degree: usize, rng: &mut Rng) -> Graph {
    let m = (degree / 2).max(1);
    let mut set: BTreeSet<(u32, u32)> = BTreeSet::new();
    // Seed clique.
    let seed = (m + 1).min(n);
    for i in 0..seed {
        for j in (i + 1)..seed {
            set.insert(norm(i as u32, j as u32));
        }
    }
    // Endpoint multiset: sampling from it is preferential attachment.
    let mut targets: Vec<u32> = Vec::new();
    for &(a, b) in set.iter() {
        targets.push(a);
        targets.push(b);
    }
    for v in seed..n {
        let mut picked: BTreeSet<u32> = BTreeSet::new();
        let mut guard = 0;
        while picked.len() < m && guard < 1000 {
            guard += 1;
            let t = if targets.is_empty() {
                rng.below(v as u64) as u32
            } else {
                targets[rng.below(targets.len() as u64) as usize]
            };
            if t != v as u32 {
                picked.insert(t);
            }
        }
        for &t in &picked {
            set.insert(norm(v as u32, t));
            targets.push(v as u32);
            targets.push(t);
        }
    }
    Graph::from_edges(n, set)
}

fn random_regular(n: usize, degree: usize, rng: &mut Rng) -> Graph {
    let target = n * degree / 2;
    let mut set: BTreeSet<(u32, u32)> = BTreeSet::new();
    // Spanning ring first, so the graph is always connected.
    for i in 0..n {
        set.insert(norm(i as u32, ((i + 1) % n) as u32));
    }
    let mut guard = 0;
    while set.len() < target && guard < target * 100 {
        guard += 1;
        let a = rng.below(n as u64) as u32;
        let b = rng.below(n as u64) as u32;
        if a != b {
            set.insert(norm(a, b));
        }
    }
    Graph::from_edges(n, set)
}
