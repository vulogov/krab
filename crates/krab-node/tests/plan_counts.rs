//! **`PLAN.md` §30's counts are derived from its own tables.**
//!
//! The document has drifted the same way three times: a tally written beside a
//! table, edited when it was written and never again. §20's summary said 26
//! requirements over a 28-row table; §23's said 167 across the series when the
//! rows come to 171; eleven rows said "unmet" for requirements later sections
//! of the same document record as closed.
//!
//! Marking those superseded fixes the instances. It does not fix the mechanism,
//! and §30 says so: "the durable answer is a test that parses this file and
//! checks the totals against the rows". This is that test.
//!
//! It follows `domain_separation.rs`: read the tree's own documentation as
//! data, and fail on a claim the tree contradicts. What it checks is narrow and
//! deliberately so — **row counts and verdict tallies, not verdicts.** Whether
//! a row's verdict is *true* is a question about the code that no parser can
//! answer; whether the summary agrees with the rows is arithmetic, and
//! arithmetic is exactly what kept going wrong.

use std::collections::BTreeMap;
use std::path::PathBuf;

fn plan() -> String {
    let doc = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("Documentation/PLAN.md");
    std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("{}: {e}", doc.display()))
}

/// The seven per-requirement audit tables, by the section that holds each.
const SECTIONS: [(&str, &str); 7] = [
    ("RFC 1", "## 17."),
    ("RFC 2", "## 18."),
    ("RFC 3", "## 19."),
    ("RFC 4", "## 20."),
    ("RFC 5", "## 21."),
    ("RFC 6", "## 22."),
    ("RFC 7", "## 23."),
];

/// Which bucket a verdict cell falls in.
///
/// The document writes verdicts in prose — "met + tested", "was unmet, now
/// met", "met — errata E-4" — because they are read by people. The order of
/// these tests matters: "was unmet, now met" and "was never unmet" must be
/// counted as met, and only a cell that still says unmet with no such
/// qualifier is unmet.
fn bucket(cell: &str) -> &'static str {
    let v = cell.replace('*', "").to_lowercase();
    let v = v.trim().to_string();
    if v.contains("never unmet")
        || v.contains("now met")
        || v.starts_with("met")
        || v.contains("closed in the body")
        || v.contains("deployment obligation")
    {
        "met"
    } else if v.contains("withdrawn") {
        "withdrawn"
    } else if v == "vacuous" {
        "vacuous"
    } else if v == "unrepresentable" {
        "unrepresentable"
    } else if v == "partly met" {
        "partly met"
    } else if v.contains("unmet") {
        "unmet"
    } else {
        "other"
    }
}

/// Requirement rows in one section: `| § | requirement | verdict | where |`.
///
/// Four columns exactly. The series-wide summary tables in the same sections
/// have a different shape and are skipped by that check rather than by their
/// position, so moving them does not silently change what is counted.
fn rows_of(section: &str) -> Vec<String> {
    section
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("|---"))
        // §23 still carries the superseded series-wide table, whose rows are
        // also four cells wide — `| RFC 1 | 31 | 2 | 1 |`. Excluded by what
        // its first cell says rather than by where it sits, so that moving it
        // does not quietly change what is counted.
        .filter(|l| !l.starts_with("| § ") && !l.starts_with("| document"))
        .filter(|l| !l.starts_with("| RFC ") && !l.starts_with("| **total**"))
        .filter(|l| l.split('|').count() == 6)
        .map(|l| l.split('|').nth(3).unwrap_or("").trim().to_string())
        .collect()
}

fn slice_between<'a>(doc: &'a str, from: &str, to: &str) -> &'a str {
    let a = doc
        .find(from)
        .unwrap_or_else(|| panic!("no section {from}"));
    let b = doc[a..]
        .find(to)
        .map(|i| a + i)
        .unwrap_or_else(|| panic!("no section {to} after {from}"));
    &doc[a..b]
}

/// §30's derived table: `| RFC n | rows | met | vacuous | unrep | partly | withdrawn | unmet |`.
fn declared(doc: &str) -> BTreeMap<String, Vec<usize>> {
    let s = slice_between(
        doc,
        "### The series, recounted from the tables",
        "**171, not 167.**",
    );
    let mut out = BTreeMap::new();
    for line in s.lines() {
        if !line.starts_with("| RFC ") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let name = cells[1].to_string();
        let nums: Vec<usize> = cells[2..9]
            .iter()
            .map(|c| c.replace('*', "").replace('—', "0").parse().unwrap_or(0))
            .collect();
        out.insert(name, nums);
    }
    out
}

/// **The per-document rows in §30 match the tables they summarise.**
#[test]
fn the_recount_matches_the_audit_tables() {
    let doc = plan();
    let declared = declared(&doc);
    assert_eq!(declared.len(), 7, "§30's table lost a row");

    let ends = [
        "## 18.", "## 19.", "## 20.", "## 21.", "## 22.", "## 23.", "## 24.",
    ];
    for (i, (name, start)) in SECTIONS.iter().enumerate() {
        let section = slice_between(&doc, start, ends[i]);
        let verdicts = rows_of(section);
        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for v in &verdicts {
            *tally.entry(bucket(v)).or_default() += 1;
        }
        assert_eq!(
            tally.get("other").copied().unwrap_or(0),
            0,
            "{name}: a verdict this test cannot classify — {:?}",
            verdicts
                .iter()
                .filter(|v| bucket(v) == "other")
                .collect::<Vec<_>>()
        );

        let want = declared
            .get(*name)
            .unwrap_or_else(|| panic!("§30 has no {name} row"));
        let got = [
            verdicts.len(),
            tally.get("met").copied().unwrap_or(0),
            tally.get("vacuous").copied().unwrap_or(0),
            tally.get("unrepresentable").copied().unwrap_or(0),
            tally.get("partly met").copied().unwrap_or(0),
            tally.get("withdrawn").copied().unwrap_or(0),
            tally.get("unmet").copied().unwrap_or(0),
        ];
        assert_eq!(
            &got[..],
            &want[..],
            "{name}: §30 says {want:?}, the table has {got:?} \
             (rows, met, vacuous, unrepresentable, partly met, withdrawn, unmet)"
        );
    }
}

/// **§30's total row is the sum of its own columns.**
///
/// Separate from the check above because they fail for different reasons: that
/// one catches a table edited without its summary, this one catches a summary
/// added up wrongly. The old "167" was the second kind.
#[test]
fn the_total_is_the_sum_of_the_documents() {
    let doc = plan();
    let declared = declared(&doc);
    let mut sum = vec![0usize; 7];
    for nums in declared.values() {
        for (s, n) in sum.iter_mut().zip(nums) {
            *s += n;
        }
    }
    // Scoped to §30: §23 keeps its superseded total row, and matching the
    // first `| **total** |` in the file would check the wrong table.
    let thirty = slice_between(
        &doc,
        "### The series, recounted from the tables",
        "**171, not 167.**",
    );
    let s = slice_between(thirty, "| **total** |", "\n\n");
    let stated: Vec<usize> = s
        .split('|')
        .skip(2)
        .take(7)
        .map(|c| {
            c.replace('*', "")
                .trim()
                .replace('—', "0")
                .parse()
                .unwrap_or(0)
        })
        .collect();
    assert_eq!(
        sum, stated,
        "§30's total row does not add up its own columns"
    );

    // And each column is internally consistent: the buckets partition the rows.
    assert_eq!(
        sum[0],
        sum[1..].iter().sum::<usize>(),
        "the verdict buckets do not account for every row"
    );
}
