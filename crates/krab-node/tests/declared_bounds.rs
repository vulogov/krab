//! Every declared bound is enforced somewhere that is not a test.
//!
//! # What this mechanises, and what it does not
//!
//! Pass 15's method note: *"for every sentence naming a mechanism, grep for
//! its caller."* Three of that pass's seven findings, and one of Pass 14's,
//! were the same shape — a limit that a comment says exists, with nothing in
//! the running program applying it:
//!
//! - `Store::verify_body_padding`, documented as the check a decoder *SHOULD*
//!   also call, with no caller that did.
//! - `MAX_MESSAGES`, whose own comment says "the loop is otherwise unbounded"
//!   while both main loops were `loop {`.
//! - `start_listener`'s cap, argued as satisfied structurally by code that had
//!   since been replaced.
//!
//! The general form is not mechanisable — it needs a reader who can tell that
//! a paragraph has outlived its subject. **This is the narrow, checkable
//! subset**: a `pub const` in a library crate that no non-test line mentions.
//! That is exactly a bound nobody applies, and it is the shape that recurs.
//!
//! It does **not** catch a bound that is applied in one place and missing in
//! another — `MAX_MESSAGES` would have passed this, because the drain loops
//! used it. `no_session_driver_loops_without_a_bound` below is the companion
//! for that, and it is deliberately narrow rather than general: bare `loop {`
//! is legitimate almost everywhere and is a defect in a driver reading from a
//! peer.
//!
//! # Why a test rather than a lint
//!
//! `dead_code` does not fire on `pub` items, and nothing in the toolchain
//! knows that "referenced only from `#[cfg(test)]`" is what this project means
//! by unenforced. An allow-list with a stated reason per entry is also the
//! point: an exception somebody had to write down is an exception somebody
//! considered.

use std::path::{Path, PathBuf};

/// Constants that no running line applies, and why that is correct.
///
/// **Every entry is a claim.** Adding one is asserting that the bound is
/// declared for something other than enforcement — a wire format's own
/// dimensions, a figure quoted by a document, a value a downstream crate is
/// meant to read. If none of those is true, the entry is hiding the defect
/// this test exists to find.
const ALLOWED: &[(&str, &str)] = &[
    // krab-core: the frozen wire format states its own dimensions. These are
    // read by encoders and decoders as part of the format, not applied as
    // limits, and several are quoted by RFC 1's tables.
    ("BUCKETS", "RFC 1 §8.1's table; indexed, not compared against"),
    ("ROUTING_HEADER_LEN", "the frozen header's width"),
    ("TRUNC_LEN", "RFC 1 §9.3's manifest row width"),
    ("EPOCH_WINDOW", "RFC 1 §2's retention, in days; MAX_TTL_MIN derives from it"),
    // krab-fabric: profile dimensions that a carrier declares about itself.
    ("NOISE_PARAMS", "the Noise pattern string"),
    ("NOISE_PARAMS_XX", "the first-contact Noise pattern string"),
];

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Strip `#[cfg(test)]` modules, so a reference from one does not count.
///
/// Brace counting rather than parsing, so it can be fooled — an unbalanced
/// brace inside a string literal ends the scan early and drops the rest of the
/// file.
///
/// **That is why declarations are enumerated from the whole file and only
/// *uses* are counted here.** Getting this wrong then shrinks the set of uses,
/// which flags more constants rather than fewer. The first version enumerated
/// declarations from the stripped text too, and a dropped tail made a
/// deliberately-unenforced probe constant invisible — the check passed by not
/// looking, which is the failure it exists to find.
fn without_tests(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let after = &rest[at..];
        let Some(open) = after.find('{') else { break };
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) => rest = &after[e..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn every_declared_bound_is_enforced_outside_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mut files = Vec::new();
    for crate_dir in std::fs::read_dir(&root).unwrap().flatten() {
        rust_sources(&crate_dir.path().join("src"), &mut files);
    }
    assert!(files.len() > 10, "found {} sources — the walk is wrong", files.len());

    // Declarations come from the whole file; uses from the non-test corpus.
    let bodies: Vec<(PathBuf, String, String)> = files
        .iter()
        .map(|f| {
            let whole = std::fs::read_to_string(f).unwrap();
            let live = without_tests(&whole);
            (f.clone(), whole, live)
        })
        .collect();
    let corpus: String = bodies.iter().map(|(_, _, live)| live.as_str()).collect();

    let mut declared = 0usize;
    let mut unenforced = Vec::new();
    for (path, whole, _) in &bodies {
        for line in whole.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("pub const ") else {
                continue;
            };
            let Some(name) = rest.split([':', ' ']).next().filter(|n| !n.is_empty()) else {
                continue;
            };
            declared += 1;
            if ALLOWED.iter().any(|(a, _)| *a == name) {
                continue;
            }
            // Its declaration is one mention; anything else is a use.
            let uses = corpus.matches(name).count();
            if uses <= 1 {
                unenforced.push(format!("{} — {name}", path.display()));
            }
        }
    }
    // A walk that found nothing would pass silently, which is the shape of
    // failure this whole file is about.
    assert!(
        declared > 20,
        "only {declared} public constants found — the walk is not reading the tree"
    );
    assert!(
        unenforced.is_empty(),
        "these bounds are declared and applied nowhere outside a test:\n  {}\n\n\
         Either apply the bound, or add it to ALLOWED with the reason it is \
         declared for something other than enforcement.",
        unenforced.join("\n  ")
    );
}

/// **A driver reading from a peer must not loop without a bound.**
///
/// The companion to the check above, for the case it cannot see: a limit that
/// is applied in one loop and missing from another. `MAX_MESSAGES` was used by
/// both inner drain loops and by neither main loop, so it had callers and the
/// session was still unbounded — a peer that sends a two-byte message no arm
/// acts on spins the thread for ever.
///
/// Narrow on purpose. Bare `loop {` is ordinary Rust and a defect only here,
/// where every iteration is driven by whatever a peer chose to send.
#[test]
fn no_session_driver_loops_without_a_bound() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/exchange.rs"),
    )
    .unwrap();
    let body = without_tests(&src);
    let bare: Vec<usize> = body
        .lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "loop {")
        .map(|(i, _)| i + 1)
        .collect();
    assert!(
        bare.is_empty(),
        "unbounded loop(s) in the session drivers, at line(s) {bare:?}. \
         Every iteration here is driven by a message a peer chose to send, so \
         the loop needs a count — see MAX_MESSAGES."
    );
}

/// **`unsafe` lives in exactly one crate.**
///
/// RFC 7 §9 needs `mlock`, `mlock` is a foreign function, and there is no safe
/// way to call one — so the workspace has an unsafe boundary. `krab-lock` is
/// it, and the value of putting it in a crate of its own rather than a block
/// inside a larger file is entirely in this test: an auditor who has read that
/// file has read every unsafe line in the tree, and a diff to any other crate
/// cannot quietly add one.
///
/// Checked by reading the sources rather than by trusting the attributes,
/// because an attribute can be removed in the same commit that adds the code
/// it was guarding.
#[test]
fn unsafe_code_lives_only_in_the_crate_that_exists_for_it() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut files = Vec::new();
    for dir in ["crates", "apps"] {
        for entry in std::fs::read_dir(workspace.join(dir)).unwrap().flatten() {
            rust_sources(&entry.path().join("src"), &mut files);
        }
    }
    assert!(files.len() > 30, "found {} sources — the walk is wrong", files.len());

    let mut offenders = Vec::new();
    let mut boundary_seen = false;
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let in_boundary = f.components().any(|c| c.as_os_str() == "krab-lock");
        // `unsafe` as a keyword: a block, an `impl`, an `extern`, or an `fn`.
        // Not the word in prose — every crate here discusses it at length.
        let uses = src.lines().any(|l| {
            let t = l.trim_start();
            !t.starts_with("//")
                && !t.starts_with("///")
                && !t.starts_with("*")
                && (t.contains("unsafe {")
                    || t.starts_with("unsafe impl")
                    || t.starts_with("unsafe extern")
                    || t.starts_with("unsafe fn")
                    || t.contains("= unsafe"))
        });
        if uses && in_boundary {
            boundary_seen = true;
        }
        if uses && !in_boundary {
            offenders.push(f.display().to_string());
        }
    }
    assert!(
        boundary_seen,
        "no unsafe found in krab-lock — the walk is not reading it, and a test \
         that cannot see the boundary cannot police it"
    );
    assert!(
        offenders.is_empty(),
        "unsafe outside `krab-lock`:\n  {}\n\nThe boundary is a whole crate on \
         purpose. If this code genuinely needs it, it belongs there.",
        offenders.join("\n  ")
    );
}
