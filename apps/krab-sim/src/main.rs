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
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let need = |i: usize, a: &Vec<String>| -> String {
        if i + 1 >= a.len() {
            usage();
        }
        a[i + 1].clone()
    };
    while i < a.len() {
        let v = need(i, &a);
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
            "-h" | "--help" => usage(),
            _ => usage(),
        }
        i += 2;
    }
    Args { cfg, json, sweep, diag }
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
    }
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
