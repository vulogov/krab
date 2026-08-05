//! SIM-0 -- corpus convergence simulator for Krab.
//!
//! Answers the question the whole architecture rests on: does a message
//! reach its recipient, within TTL, across a sparse hand-built peer graph
//! whose edges include day-latency couriers and duty-cycle-limited radio?
//!
//! If the delivery rate here is low, no amount of protocol quality fixes it,
//! and the design has to change before any RFC asserts otherwise.

mod graph;
mod model;
mod rng;
mod sim;

use graph::Topology;
use model::*;
use std::fmt::Write as _;

struct Args {
    cfg: Config,
    json: Option<String>,
    sweep: Option<String>,
    diag: bool,
    recon: bool,
    adv: bool,
}

fn usage() -> ! {
    eprintln!(
        r#"SIM-0 -- Krab corpus convergence simulator

USAGE: krab-sim [OPTIONS]

TOPOLOGY
  --topo <ws|ba|rr>      peer graph model            (default ws)
  --n <int>              nodes                       (default 500)
  --degree <int>         mean peers per node         (default 8)
  --rewire <float>       WS long-range edge prob     (default 0.10)

TRANSPORT MIX (fractions of edges, must sum to 1.0)
  --tcp <float>                                      (default 0.70)
  --lora <float>                                     (default 0.15)
  --courier <float>                                  (default 0.15)

TRAFFIC
  --ttl <days>           object lifetime             (default 14)
  --horizon <days>       simulated span              (default 42)
  --rate <float>         messages/node/day           (default 2.0)
  --dest <social|uniform>                            (default social)
  --hops <int>           social destination radius   (default 3)

AVAILABILITY
  --uptime <float>       fraction of time online     (default 0.85)
  --session <hours>      mean online session         (default 12)

RUN
  --seeds <int>          independent runs            (default 5)
  --sweep <name>         run a predefined sweep
                         (ttl|degree|mix|topo|scale|dest)
  --json <path>          write results as JSON
  --quiet
"#
    );
    std::process::exit(2);
}

fn parse() -> Args {
    let mut cfg = Config::default();
    let mut json = None;
    let mut sweep = None;
    let mut diag = false;
    let mut recon = false;
    let mut adv = false;
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    // Bare flags are matched before any value is read. Reading first (as this
    // did) makes a trailing `--quiet` fail with usage text.
    while i < a.len() {
        match a[i].as_str() {
            "--quiet" => {
                cfg.quiet = true;
                i += 1;
                continue;
            }
            "--diag" => {
                diag = true;
                i += 1;
                continue;
            }
            "--recon" => {
                recon = true;
                cfg.manifest = true;
                i += 1;
                continue;
            }
            "--adv" => {
                adv = true;
                if cfg.adversary == 0 {
                    cfg.adversary = 5;
                }
                i += 1;
                continue;
            }
            "--manifest" => {
                cfg.manifest = true;
                i += 1;
                continue;
            }
            "--frag" => {
                cfg.frag = true;
                i += 1;
                continue;
            }
            "--hol-fix" => {
                cfg.hol_fix = true;
                i += 1;
                continue;
            }
            // SIM-1 model fidelity as a set: charge reconciliation overhead,
            // fragment oversized objects, and stop wedging a link on one.
            "--sim1" => {
                cfg.manifest = true;
                cfg.frag = true;
                cfg.hol_fix = true;
                i += 1;
                continue;
            }
            "-h" | "--help" => usage(),
            _ => {}
        }
        if i + 1 >= a.len() {
            usage();
        }
        let v = a[i + 1].clone();
        match a[i].as_str() {
            "--topo" => cfg.topo = Topology::parse(&v).unwrap_or_else(|| usage()),
            "--n" => cfg.n = v.parse().unwrap_or_else(|_| usage()),
            "--degree" => cfg.degree = v.parse().unwrap_or_else(|_| usage()),
            "--rewire" => cfg.rewire = v.parse().unwrap_or_else(|_| usage()),
            "--tcp" => cfg.mix_tcp = v.parse().unwrap_or_else(|_| usage()),
            "--lora" => cfg.mix_lora = v.parse().unwrap_or_else(|_| usage()),
            "--courier" => cfg.mix_courier = v.parse().unwrap_or_else(|_| usage()),
            "--ttl" => cfg.ttl = v.parse::<u64>().unwrap_or_else(|_| usage()) * DAY,
            "--horizon" => cfg.horizon = v.parse::<u64>().unwrap_or_else(|_| usage()) * DAY,
            "--rate" => cfg.rate_per_day = v.parse().unwrap_or_else(|_| usage()),
            "--dest" => {
                cfg.dest = match v.as_str() {
                    "social" => DestModel::Social,
                    "uniform" => DestModel::Uniform,
                    _ => usage(),
                }
            }
            "--hops" => cfg.social_hops = v.parse().unwrap_or_else(|_| usage()),
            "--uptime" => cfg.uptime = v.parse().unwrap_or_else(|_| usage()),
            "--session" => {
                cfg.mean_session_up = v.parse::<f64>().unwrap_or_else(|_| usage()) * HOUR as f64
            }
            "--seeds" => cfg.seeds = v.parse().unwrap_or_else(|_| usage()),
            "--sweep" => sweep = Some(v),
            "--json" => json = Some(v),
            "--id-len" => cfg.id_len = v.parse().unwrap_or_else(|_| usage()),
            "--sync" => cfg.sync_mode = SyncMode::parse(&v).unwrap_or_else(|| usage()),
            "--rbsr-b" => cfg.rbsr_b = v.parse().unwrap_or_else(|_| usage()),
            "--cap" => cfg.store_cap_mb = v.parse().unwrap_or_else(|_| usage()),
            "--adversary" => cfg.adversary = v.parse().unwrap_or_else(|_| usage()),
            "--adv-place" => cfg.adv_place = AdvPlacement::parse(&v).unwrap_or_else(|| usage()),
            _ => usage(),
        }
        i += 2;
    }
    Args { cfg, json, sweep, diag, recon, adv }
}

#[derive(Clone)]
struct Agg {
    label: String,
    runs: usize,
    delivery: f64,
    lat_p50: f64,
    lat_p90: f64,
    lat_p99: f64,
    coverage: f64,
    coverage_p10: f64,
    store_p50: f64,
    store_p99: f64,
    rx_p50: f64,
    rx_p99: f64,
    cov_exact: f64,
    cov_bytes: f64,
    cov_settled: f64,
    cov_by_age: Vec<f64>,
    store_mean: f64,
    rx_mean: f64,
    lora_eligible: f64,
    ctrl_bytes: [f64; 3],
    payload_bytes: [f64; 3],
    syncs: [f64; 3],
    starved: [f64; 3],
    hold_by_dist: Vec<Vec<f64>>,
    adv_rank_p50: f64,
    adv_top10: f64,
    adv_scored: f64,
}

fn aggregate(label: &str, cfg: &Config) -> Agg {
    // Seeds are independent; run them concurrently.
    let results: Vec<sim::RunResult> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..cfg.seeds)
            .map(|k| {
                let c = cfg.clone();
                s.spawn(move || sim::run(&c, k + 1))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    });

    let n = results.len().max(1) as f64;
    let mean = |f: &dyn Fn(&sim::RunResult) -> f64| -> f64 {
        results.iter().map(|r| f(r)).sum::<f64>() / n
    };
    Agg {
        label: label.to_string(),
        runs: results.len(),
        delivery: mean(&|r| {
            if r.objects_measured == 0 {
                0.0
            } else {
                r.delivered as f64 / r.objects_measured as f64
            }
        }),
        lat_p50: mean(&|r| r.lat_p50),
        lat_p90: mean(&|r| r.lat_p90),
        lat_p99: mean(&|r| r.lat_p99),
        coverage: mean(&|r| r.coverage_mean),
        coverage_p10: mean(&|r| r.coverage_p10),
        store_p50: mean(&|r| r.store_mb_p50),
        store_p99: mean(&|r| r.store_mb_p99),
        rx_p50: mean(&|r| r.rx_mb_day_p50),
        rx_p99: mean(&|r| r.rx_mb_day_p99),
        cov_exact: mean(&|r| r.cov_exact),
        cov_bytes: mean(&|r| r.cov_bytes),
        cov_settled: mean(&|r| r.cov_settled),
        cov_by_age: {
            let nb = results.first().map(|r| r.cov_by_age.len()).unwrap_or(0);
            (0..nb)
                .map(|b| results.iter().map(|r| r.cov_by_age[b]).sum::<f64>() / n)
                .collect()
        },
        store_mean: mean(&|r| r.store_mb_mean),
        rx_mean: mean(&|r| r.rx_mb_day_mean),
        lora_eligible: mean(&|r| r.lora_eligible),
        ctrl_bytes: [0, 1, 2].map(|k| mean(&|r| r.ctrl_bytes[k] as f64)),
        payload_bytes: [0, 1, 2].map(|k| mean(&|r| r.payload_bytes[k] as f64)),
        syncs: [0, 1, 2].map(|k| mean(&|r| r.syncs[k] as f64)),
        starved: [0, 1, 2].map(|k| mean(&|r| r.starved[k] as f64)),
        hold_by_dist: {
            // Elementwise mean across seeds, skipping cells no seed observed.
            let nb = results.iter().map(|r| r.hold_by_dist.len()).max().unwrap_or(0);
            let nd = results.iter().flat_map(|r| r.hold_by_dist.iter()).map(|r| r.len()).max();
            match nd {
                None => Vec::new(),
                Some(nd) => (0..nb)
                    .map(|b| {
                        (0..nd)
                            .map(|d| {
                                let v: Vec<f64> = results
                                    .iter()
                                    .filter_map(|r| r.hold_by_dist.get(b).and_then(|x| x.get(d)))
                                    .copied()
                                    .filter(|x| !x.is_nan())
                                    .collect();
                                if v.is_empty() {
                                    f64::NAN
                                } else {
                                    v.iter().sum::<f64>() / v.len() as f64
                                }
                            })
                            .collect()
                    })
                    .collect(),
            }
        },
        adv_rank_p50: mean(&|r| r.adv_rank_p50),
        adv_top10: mean(&|r| r.adv_top10),
        adv_scored: mean(&|r| r.adv_scored as f64),
    }
}

/// Reconciliation overhead view (SIM-1 priority 1, blocking item B3).
fn recon_header() -> String {
    format!(
        "{:<22} {:>9} {:>10} {:>10} {:>9} {:>10} {:>10} {:>9}",
        "case", "lora ctl%", "lora ctlKB", "lora payKB", "lora strv", "cour ctl%", "tcp ctl%",
        "cour strv"
    )
}

fn recon_row(a: &Agg) -> String {
    let share = |k: usize| -> f64 {
        let t = a.ctrl_bytes[k] + a.payload_bytes[k];
        if t <= 0.0 {
            f64::NAN
        } else {
            100.0 * a.ctrl_bytes[k] / t
        }
    };
    let strv = |k: usize| -> f64 {
        if a.syncs[k] <= 0.0 {
            f64::NAN
        } else {
            100.0 * a.starved[k] / a.syncs[k]
        }
    };
    let per = |v: f64, k: usize| -> f64 {
        if a.syncs[k] <= 0.0 {
            f64::NAN
        } else {
            v / a.syncs[k] / 1000.0
        }
    };
    format!(
        "{:<22} {:>8.1}% {:>10.1} {:>10.1} {:>8.1}% {:>9.1}% {:>9.2}% {:>8.1}%",
        a.label,
        share(1),
        per(a.ctrl_bytes[1], 1),
        per(a.payload_bytes[1], 1),
        strv(1),
        share(2),
        share(0),
        strv(2)
    )
}

/// Holdings-leak view (SIM-1 priority 2, blocking item B2).
fn adv_rows(a: &Agg, n: usize) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "{:<22} origin rank p50 {:>6.1}%  (chance 50.0%)   top-10 {:>6.2}%  (chance {:.2}%)  \
         scored {:.0}",
        a.label,
        a.adv_rank_p50 * 100.0,
        a.adv_top10 * 100.0,
        1000.0 / n as f64,
        a.adv_scored
    ));
    for (b, row) in a.hold_by_dist.iter().enumerate() {
        let cells: Vec<String> = row
            .iter()
            .map(|&p| if p.is_nan() { "   -".into() } else { format!("{:>3.0}%", p * 100.0) })
            .collect();
        out.push(format!("  age bucket {}  P(hold | hops): {}", b, cells.join(" ")));
    }
    out
}

/// Audit view: separates the quantities the standard table conflates.
fn diag_header() -> String {
    format!(
        "{:<22} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "case", "coverPUB", "coverEX", "coverBY", "coverSET", "storeP99", "storeMEAN", "rxP99",
        "rxMEAN"
    )
}

fn diag_row(a: &Agg) -> String {
    format!(
        "{:<22} {:>7.1}% {:>7.1}% {:>7.1}% {:>8.1}% {:>9.1} {:>9.1} {:>9.2} {:>9.2}",
        a.label,
        a.coverage * 100.0,
        a.cov_exact * 100.0,
        a.cov_bytes * 100.0,
        a.cov_settled * 100.0,
        a.store_p99,
        a.store_mean,
        a.rx_p99,
        a.rx_mean
    )
}

fn age_row(a: &Agg) -> String {
    let mut s = format!("{:<22} lora-eligible {:>6.2}%  cover by age: ", a.label, a.lora_eligible * 100.0);
    for (b, c) in a.cov_by_age.iter().enumerate() {
        let _ = write!(s, "{}{:.0}%", if b == 0 { "" } else { " " }, c * 100.0);
    }
    s
}

fn header() -> String {
    format!(
        "{:<22} {:>5} {:>9} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9} {:>9}",
        "case", "runs", "delivery", "lat50h", "lat90h", "lat99h", "cover", "cover10", "storeMB",
        "rxMB/d"
    )
}

fn row(a: &Agg) -> String {
    format!(
        "{:<22} {:>5} {:>8.1}% {:>8.1} {:>8.1} {:>8.1} {:>8.1}% {:>8.1}% {:>9.1} {:>9.2}",
        a.label,
        a.runs,
        a.delivery * 100.0,
        a.lat_p50,
        a.lat_p90,
        a.lat_p99,
        a.coverage * 100.0,
        a.coverage_p10 * 100.0,
        a.store_p99,
        a.rx_p99
    )
}

fn sweep_cases(name: &str, base: &Config) -> Vec<(String, Config)> {
    let mut out = Vec::new();
    match name {
        "ttl" => {
            for d in [3u64, 7, 14, 21, 30, 45] {
                let mut c = base.clone();
                c.ttl = d * DAY;
                c.horizon = (d * 3).max(30) * DAY;
                out.push((format!("ttl={}d", d), c));
            }
        }
        "degree" => {
            for k in [4usize, 6, 8, 12, 16, 20] {
                let mut c = base.clone();
                c.degree = k;
                out.push((format!("degree={}", k), c));
            }
        }
        "mix" => {
            for (t, l, k, n) in [
                (1.00, 0.00, 0.00, "all-tcp"),
                (0.85, 0.15, 0.00, "tcp+lora"),
                (0.70, 0.15, 0.15, "mixed"),
                (0.50, 0.20, 0.30, "courier-heavy"),
                (0.20, 0.30, 0.50, "austere"),
                (0.00, 0.00, 1.00, "all-courier"),
            ] {
                let mut c = base.clone();
                c.mix_tcp = t;
                c.mix_lora = l;
                c.mix_courier = k;
                out.push((n.to_string(), c));
            }
        }
        "topo" => {
            for t in [Topology::WattsStrogatz, Topology::BarabasiAlbert, Topology::RandomRegular] {
                let mut c = base.clone();
                c.topo = t;
                out.push((format!("topo={}", t.name()), c));
            }
        }
        "scale" => {
            for n in [100usize, 250, 500, 1000, 2000] {
                let mut c = base.clone();
                c.n = n;
                out.push((format!("n={}", n), c));
            }
        }
        "dest" => {
            for (d, h, n) in [
                (DestModel::Social, 2, "social h=2"),
                (DestModel::Social, 3, "social h=3"),
                (DestModel::Social, 5, "social h=5"),
                (DestModel::Uniform, 0, "uniform"),
            ] {
                let mut c = base.clone();
                c.dest = d;
                c.social_hops = h;
                out.push((n.to_string(), c));
            }
        }
        // ---- SIM-1 ---------------------------------------------------------
        // Blocking item B3's identifier-length row, measured rather than
        // argued. Manifest cost is linear in id_len under Full and linear in
        // the difference under RBSR, so the two react very differently.
        "idlen" => {
            for (mode, len) in [
                (SyncMode::Full, 32u64),
                (SyncMode::Full, 16),
                (SyncMode::Full, 8),
                (SyncMode::Rbsr, 32),
                (SyncMode::Rbsr, 16),
                (SyncMode::Rbsr, 8),
            ] {
                let mut c = base.clone();
                c.manifest = true;
                c.sync_mode = mode;
                c.id_len = len;
                out.push((format!("{} id={}B", mode.name(), len), c));
            }
        }
        // Does charging reconciliation overhead change the SIM-0 conclusions?
        "recon" => {
            for (t, l, k, n) in [
                (1.00, 0.00, 0.00, "all-tcp"),
                (0.70, 0.15, 0.15, "mixed"),
                (0.50, 0.20, 0.30, "courier-heavy"),
                (0.20, 0.30, 0.50, "austere"),
            ] {
                for (mode, tag) in [(SyncMode::Full, "full"), (SyncMode::Rbsr, "rbsr")] {
                    let mut c = base.clone();
                    c.mix_tcp = t;
                    c.mix_lora = l;
                    c.mix_courier = k;
                    c.manifest = true;
                    c.sync_mode = mode;
                    out.push((format!("{} {}", n, tag), c));
                }
            }
        }
        // How much does an adversary's posterior over the injection point
        // sharpen with vantage count? RFC 0 §7.4's deferred question.
        "adversary" => {
            for k in [1usize, 3, 5, 10, 25, 50] {
                let mut c = base.clone();
                c.adversary = k;
                out.push((format!("vantage={}", k), c));
            }
        }
        // The same, under the transport regimes that produce different
        // coverage ramps. This is where the age gradient should bite hardest.
        "adversary-mix" => {
            for (t, l, k, n) in [
                (1.00, 0.00, 0.00, "all-tcp"),
                (0.70, 0.15, 0.15, "mixed"),
                (0.20, 0.30, 0.50, "austere"),
            ] {
                let mut c = base.clone();
                c.mix_tcp = t;
                c.mix_lora = l;
                c.mix_courier = k;
                c.adversary = 5;
                out.push((n.to_string(), c));
            }
        }
        // Capacity-pressure eviction, which SIM-0 §9 notes will reduce
        // coverage further and which interacts directly with I-6.
        "cap" => {
            for mb in [0u64, 100, 200, 300, 450] {
                let mut c = base.clone();
                c.store_cap_mb = mb;
                out.push((
                    if mb == 0 { "cap=none".into() } else { format!("cap={}MB", mb) },
                    c,
                ));
            }
        }
        _ => usage(),
    }
    out
}

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            c => vec![c],
        })
        .collect()
}

fn to_json(aggs: &[Agg], cfg: &Config) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "{{\n  \"config\": {{\"topo\": \"{}\", \"n\": {}, \"degree\": {}, \"ttl_days\": {}, \
         \"horizon_days\": {}, \"rate_per_day\": {}, \"uptime\": {}, \"seeds\": {}}},\n  \
         \"results\": [\n",
        cfg.topo.name(),
        cfg.n,
        cfg.degree,
        cfg.ttl / DAY,
        cfg.horizon / DAY,
        cfg.rate_per_day,
        cfg.uptime,
        cfg.seeds
    );
    for (i, a) in aggs.iter().enumerate() {
        let _ = write!(
            s,
            "    {{\"case\": \"{}\", \"runs\": {}, \"delivery\": {:.4}, \"lat_p50_h\": {:.2}, \
             \"lat_p90_h\": {:.2}, \"lat_p99_h\": {:.2}, \"coverage\": {:.4}, \
             \"coverage_p10\": {:.4}, \"store_mb_p50\": {:.2}, \"store_mb_p99\": {:.2}, \
             \"rx_mb_day_p50\": {:.3}, \"rx_mb_day_p99\": {:.3}}}{}\n",
            json_escape(&a.label),
            a.runs,
            a.delivery,
            a.lat_p50,
            a.lat_p90,
            a.lat_p99,
            a.coverage,
            a.coverage_p10,
            a.store_p50,
            a.store_p99,
            a.rx_p50,
            a.rx_p99,
            if i + 1 == aggs.len() { "" } else { "," }
        );
    }
    s.push_str("  ]\n}\n");
    s
}

fn main() {
    let args = parse();
    let cfg = args.cfg;

    let cases: Vec<(String, Config)> = match &args.sweep {
        Some(name) => sweep_cases(name, &cfg),
        None => vec![("baseline".to_string(), cfg.clone())],
    };

    if !cfg.quiet {
        println!(
            "SIM-0  topo={} n={} degree={} ttl={}d horizon={}d rate={}/day uptime={} seeds={}",
            cfg.topo.name(),
            cfg.n,
            cfg.degree,
            cfg.ttl / DAY,
            cfg.horizon / DAY,
            cfg.rate_per_day,
            cfg.uptime,
            cfg.seeds
        );
        println!("{}", header());
        println!("{}", "-".repeat(header().len()));
    }

    let mut aggs = Vec::new();
    for (label, c) in &cases {
        let a = aggregate(label, c);
        if !cfg.quiet {
            println!("{}", row(&a));
        }
        aggs.push(a);
    }

    if args.diag && !cfg.quiet {
        println!("\n{}", diag_header());
        println!("{}", "-".repeat(diag_header().len()));
        for a in &aggs {
            println!("{}", diag_row(a));
        }
        println!();
        for a in &aggs {
            println!("{}", age_row(a));
        }
    }

    if args.recon && !cfg.quiet {
        println!("\n{}", recon_header());
        println!("{}", "-".repeat(recon_header().len()));
        for a in &aggs {
            println!("{}", recon_row(a));
        }
        println!("\nctl% is control traffic as a share of all bytes on that link kind.");
        println!("strv is the share of reconciliations where control traffic consumed the");
        println!("whole window, so no payload moved at all.");
    }

    if args.adv && !cfg.quiet {
        println!();
        for a in &aggs {
            for line in adv_rows(a, cfg.n) {
                println!("{}", line);
            }
            println!();
        }
        println!("A flat P(hold | hops) row means holdings leak nothing about the origin.");
        println!("Rank p50 is the true origin's percentile under a maximum-likelihood attack");
        println!("calibrated on a disjoint half of the corpus; 50% is chance.");
    }

    if let Some(p) = args.json {
        let s = to_json(&aggs, &cfg);
        if let Err(e) = std::fs::write(&p, s) {
            eprintln!("write {}: {}", p, e);
            std::process::exit(1);
        }
        if !cfg.quiet {
            println!("\nwrote {}", p);
        }
    }
}
