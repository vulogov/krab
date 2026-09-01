//! **`Documentation/CRYPTO-BOUNDARIES.md`'s check, run instead of documented.**
//!
//! That document ends with two `cargo tree` invocations and the sentence "If
//! `krab-crypto` ever shows two, that is a regression against the rule above
//! and not an acceptable state." Nothing ran them. A shell command in prose is
//! the same shape of bound as a limit that is documented and never called —
//! the defect pattern `PLAN.md` records under three different names.
//!
//! It was found the way such things are: an external reviewer read
//! `krab-crypto/Cargo.toml`'s note about one copy of each primitive, ran
//! `cargo tree` on the *binary*, saw two versions of `curve25519-dalek` and
//! two of `chacha20poly1305`, and reported the check as failing. The check was
//! passing — it is scoped to `krab-crypto`, and the second copies are `snow`'s,
//! which `CRYPTO-BOUNDARIES.md` documents at length as the accepted cost of
//! RFC 4 §4.1's Noise IK. But a check nobody runs cannot distinguish a
//! documented duplicate from a new one, which is the whole reason to run it.
//!
//! # What this asserts, and what it deliberately does not
//!
//! - **`krab-crypto` links exactly one version of each primitive.** This is
//!   the rule. Two copies inside that crate would mean one implementation
//!   deriving tags and a different one running the KEM.
//! - **`krab-fabric` may link two**, and the second must be reachable through
//!   `snow`. A second copy arriving by any other route is a new boundary, and
//!   `CRYPTO-BOUNDARIES.md` says a third "would mean there is no boundary,
//!   only a habit".
//!
//! It does not assert versions. Pinning those here would make every routine
//! dependency bump fail a test about cryptographic boundaries, which teaches
//! people to edit the test.

use std::collections::BTreeSet;
use std::process::Command;

/// The primitives that must not be duplicated inside `krab-crypto`.
const PRIMITIVES: [&str; 3] = ["curve25519-dalek", "chacha20poly1305", "x25519-dalek"];

/// Versions of `crate_name` in `package`'s dependency tree.
fn versions(package: &str, crate_name: &str) -> BTreeSet<String> {
    let out = Command::new(env!("CARGO"))
        .args(["tree", "-p", package, "--all-features", "--prefix", "none"])
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree -p {package} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let version = it.next()?;
            (name == crate_name && version.starts_with('v')).then(|| version.to_string())
        })
        .collect()
}

/// **The rule.** One implementation of each primitive inside `krab-crypto`.
#[test]
fn krab_crypto_links_one_copy_of_each_primitive() {
    for p in PRIMITIVES {
        let found = versions("krab-crypto", p);
        assert!(
            found.len() <= 1,
            "krab-crypto links {} versions of {p}: {found:?}. \
             CRYPTO-BOUNDARIES.md: \"If krab-crypto ever shows two, that is a \
             regression against the rule above and not an acceptable state.\"",
            found.len()
        );
    }
}

/// **The accepted exception, held to its stated cause.**
///
/// `krab-fabric` may link a second copy because `snow` resolves older majors
/// than RFC 1 §6.1's suite requires and no combination satisfies both. That is
/// one boundary with a reason. A third copy, or a second arriving without
/// `snow` in the tree, is a new boundary and not this one.
#[test]
fn the_second_copy_is_snows_and_there_is_no_third() {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "krab-fabric",
            "--all-features",
            "--prefix",
            "none",
        ])
        .output()
        .expect("cargo tree runs");
    let tree = String::from_utf8_lossy(&out.stdout);
    assert!(
        tree.lines().any(|l| l.starts_with("snow ")),
        "krab-fabric no longer depends on snow, so the documented reason for a \
         second copy of anything is gone — CRYPTO-BOUNDARIES.md needs editing \
         before this test does"
    );

    for p in PRIMITIVES {
        let found = versions("krab-fabric", p);
        assert!(
            found.len() <= 2,
            "krab-fabric links {} versions of {p}: {found:?}. Two is the \
             documented boundary — snow's and ours. A third is a boundary \
             nobody argued for, and CRYPTO-BOUNDARIES.md says a third \"would \
             mean there is no boundary, only a habit\"",
            found.len()
        );
    }
}
