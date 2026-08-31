//! **RFC 3 §3: every signed document's domain string is unique to it.**
//!
//! > "Every signed document in this series MUST prefix its signing input with
//! > a domain string unique to that document type. A signature produced over
//! > one document type MUST NOT be valid over any other."
//!
//! RFC 3 states the general rule rather than one more constant, and says why:
//!
//! > "Without a prefix, two document types whose encodings coincide are
//! > interchangeable under one signature: the signer consented to one meaning
//! > and is bound to the other."
//!
//! A shared string is a cross-protocol signature forgery, and it is a
//! *silent* one — every signature still verifies, over the wrong document.
//! Nothing in the type system prevents a new signed document being given a
//! string that already exists, and reviewing for it means holding a dozen
//! `const`s in your head at once.
//!
//! Sealing contexts are checked with the signing domains rather than
//! separately. They are the same mechanism — a label that binds a key or a
//! signature to one meaning — and a collision between a seal context and a
//! signing domain is as bad as one between two signing domains.
//!
//! # What this does not check
//!
//! That every signed document *has* a domain. A document written with no
//! prefix at all is invisible here, and the only defence against that is
//! review — RFC 3 §3 exists because the credential was exactly that case
//! until it was noticed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

/// `pub const NAME: &[u8] = b"krab/…/v1";` — the declarations, not the uses.
fn domain_constants(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let Some(open) = tail.find("b\"krab/") else {
            continue;
        };
        let value = &tail[open + 2..];
        let Some(close) = value.find('"') else { continue };
        out.push((name.trim().to_string(), value[..close].to_string()));
    }
    out
}

#[test]
fn no_two_signed_documents_share_a_domain_string() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for dir in ["crates", "apps"] {
        let root = workspace.parent().unwrap().join(dir);
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            rust_sources(&entry.path().join("src"), &mut files);
        }
    }
    assert!(
        files.len() > 30,
        "found {} sources — the walk is wrong, and a walk that finds nothing \
         passes this test by not looking",
        files.len()
    );

    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        for (name, value) in domain_constants(&src) {
            seen.entry(value)
                .or_default()
                .push(format!("{} ({name})", f.display()));
        }
    }

    assert!(
        seen.len() > 10,
        "only {} domain strings found — the parser is not matching",
        seen.len()
    );

    let collisions: Vec<String> = seen
        .iter()
        .filter(|(_, wheres)| wheres.len() > 1)
        .map(|(value, wheres)| format!("{value} — {}", wheres.join(", ")))
        .collect();
    assert!(
        collisions.is_empty(),
        "two document types share a domain string, so a signature over one is \
         valid over the other (RFC 3 §3):\n  {}",
        collisions.join("\n  ")
    );
}
