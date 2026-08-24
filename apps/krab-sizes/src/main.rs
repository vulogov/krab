//! krab-sizes — RFC 1 reference size encoder.
//!
//! RFC 1 cannot be revised, and every byte count in it is cited from here.
//! This computes those counts from the format RFC 1 specifies, so a reviewer
//! can check the document against arithmetic rather than against assertion.
//!
//! It computes lengths, not bytes: the RFC 1 §4.3 deterministic profile makes
//! an item's encoded length a pure function of its type and magnitude, which
//! is exactly the property that lets a parameter table be frozen.

// **Every figure an RFC publishes is in `--check`.** What remains here is
// arithmetic the RFC series derives from but does not tabulate — intermediate
// steps, and quantities a later revision may cite. Those are kept and are
// unused, which the compiler reports and which is correct: they are
// derivations, not code paths.
//
// The rule is the important part, and it is enforceable by review: if a number
// appears in an RFC and not in `check`, that is a defect. `--check` verifies
// 142 of them.
#![allow(dead_code)]

mod cbor;
mod creds;
mod groups;
mod keys;
mod object;
mod tags;
mod transport;

use object::*;

/// RFC 1 §7.2's worked example address, `dst=<16 hex>`.
const ADDR: usize = 20;
/// `text/plain`.
const CTYPE: usize = 10;

/// LoRa, EU868 SF10 under a 1% duty cycle (RFC 1 §8.3, SIM-0 §1).
const LORA_PAYLOAD: usize = 51;
const LORA_BPS: f64 = 0.85;

fn main() {
    let m = Magnitudes::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("krab-sizes — RFC 1 reference size encoder\n");
        println!("USAGE: krab-sizes [--check]\n");
        println!("  --check   verify every figure RFC 1 publishes, and exit");
        println!("            non-zero on any disagreement");
        return;
    }
    if args.iter().any(|a| a == "--check") {
        std::process::exit(check(m));
    }

    println!("KRAB RFC 1 -- computed size budget\n");

    let floor = sealed(0, 0, 0, Suite::Classical, m);
    println!("frozen routing header ......... {ROUTING_HEADER} bytes (fixed)");
    println!(
        "envelope CBOR (empty ct) ...... {} bytes",
        envelope(X25519, 0, m)
    );
    println!("  of which HPKE enc ........... {X25519} bytes");
    println!(
        "inner plaintext, empty body ... {} bytes",
        inner_plaintext(0, 0, 0, m)
    );
    println!(
        "  + AEAD tag .................. {AEAD_TAG} bytes -> ciphertext {}",
        inner_plaintext(0, 0, 0, m) + AEAD_TAG
    );
    println!();
    println!(
        "MINIMUM sealed object ......... {} bytes  (header {} + body {})",
        floor.on_wire,
        ROUTING_HEADER,
        floor.on_wire - ROUTING_HEADER
    );
    println!(
        "  padded to bucket ............ {} bytes",
        floor.bucket.unwrap()
    );
    println!();
    println!("  Computed with an empty address and empty content type. RFC 1 §8.1");
    println!("  cites a 150-byte floor, which requires 17 bytes of encoded address");
    println!("  and content type; the RFC does not state that composition. Both land");
    println!("  in the 256-byte bucket, so §8.1's conclusion is unaffected either way.");

    println!("\n--- realistic messages (X25519, addr 'dst=<16 hex>', text/plain) ---");
    println!(
        "{:>10} {:>9} {:>9} {:>10} {:>9}",
        "body", "plaintxt", "cipher", "on-wire", "bucket"
    );
    for body in [0usize, 64, 280, 1_200, 4_000, 20_000, 120_000] {
        let s = sealed(body, ADDR, CTYPE, Suite::Classical, m);
        println!(
            "{:>10} {:>9} {:>9} {:>10} {:>9}",
            s.body,
            s.plaintext,
            s.ciphertext,
            s.on_wire,
            s.bucket
                .map(|b| b.to_string())
                .unwrap_or_else(|| "OVER".into())
        );
    }

    println!("\n--- overhead ratio at each bucket ---");
    for b in BUCKETS {
        match max_body_for(b, ADDR, CTYPE, Suite::Classical, m) {
            Some(mb) => println!(
                "bucket {:>7}: max body {:>7} bytes, overhead {:>5.1}%",
                b,
                mb,
                100.0 * (b - mb) as f64 / b as f64
            ),
            None => println!("bucket {b:>7}: no sealed object fits"),
        }
    }

    println!("\n--- post-quantum (suite 0x0002, X25519 + ML-KEM-768) ---");
    let pq_floor = sealed(0, 0, 0, Suite::Hybrid, m);
    println!(
        "MINIMUM sealed object ......... {} bytes (vs {} classical)",
        pq_floor.on_wire, floor.on_wire
    );
    println!(
        "  padded to bucket ............ {} bytes",
        pq_floor.bucket.unwrap()
    );
    let pq = sealed(280, ADDR, CTYPE, Suite::Hybrid, m);
    let cl = sealed(280, ADDR, CTYPE, Suite::Classical, m);
    println!(
        "280-byte message .............. {} bytes -> bucket {}   (classical {} -> {})",
        pq.on_wire,
        pq.bucket.unwrap(),
        cl.on_wire,
        cl.bucket.unwrap()
    );
    println!(
        "inflation, smallest objects .... {:.0}x   ({} -> {} bucket)",
        pq_floor.bucket.unwrap() as f64 / floor.bucket.unwrap() as f64,
        floor.bucket.unwrap(),
        pq_floor.bucket.unwrap()
    );
    println!(
        "inflation, 280-byte message .... {:.0}x   ({} -> {} bucket)",
        pq.bucket.unwrap() as f64 / cl.bucket.unwrap() as f64,
        cl.bucket.unwrap(),
        pq.bucket.unwrap()
    );

    println!("\n--- LoRa fragmentation (EU868 SF10, {LORA_PAYLOAD} B payload, ~{LORA_BPS} B/s sustained) ---");
    for b in [256usize, 1_024, 4_096] {
        let frames = b.div_ceil(LORA_PAYLOAD);
        let airtime = b as f64 / LORA_BPS;
        println!(
            "bucket {:>5}: {:>4} frames, {:>7.0} s airtime ({:.1} h)",
            b,
            frames,
            airtime,
            airtime / 3_600.0
        );
    }

    println!("\n--- manifest cost (expiry u32 + truncated id) ---");
    for id in [8usize, 12, 16, 32] {
        let entry = 4 + id;
        print!("id {id:>2}B -> {entry:>2} B/entry:");
        for corpus in [10_000usize, 100_000, 500_000] {
            print!(
                "  {}k={:>6.1} MB",
                corpus / 1_000,
                (corpus * entry) as f64 / 1e6
            );
        }
        println!();
    }

    println!(
        "\n--- RFC 3 nodelist fragments (peer-link with 1 endpoint = {} B) ---",
        creds::PEER_LINK_1EP
    );
    println!(
        "{:>7} {:>10} {:>12} {:>10} {:>10} {:>12}",
        "peers", "fragment", "all copies", "LoRa rec", "LoRa days", "delta(1 link)"
    );
    for p in [5usize, 8, 12, 20, 25, 50] {
        let f = creds::fragment(p, creds::PEER_LINK_1EP);
        let c = creds::all_copies(p, creds::PEER_LINK_1EP);
        println!(
            "{:>7} {:>9.1}K {:>11.1}K {:>10.1} {:>10.1} {:>11.1}K",
            p,
            f as f64 / 1000.0,
            c as f64 / 1000.0,
            creds::lora_reconciliations(c),
            creds::lora_days(c),
            creds::delta_all_copies(p, 1, creds::PEER_LINK_1EP) as f64 / 1000.0
        );
    }
    println!("\n  Cost is O(P^2): the fragment is encrypted individually to each peer.");
    println!("  A weekly publication fits inside a week of LoRa airtime up to 25 peers");
    println!("  and not beyond, which is what RFC 3 §13's upper bound is made of.");

    println!("\n--- EPOCH_WINDOW vs MAX_TTL (RFC 1 §2, §6.2) ---");
    const EPOCH_S: u64 = 86_400;
    const MAX_TTL_D: u64 = 45;
    let need = MAX_TTL_D * 86_400 / EPOCH_S;
    println!("MAX_TTL {MAX_TTL_D} d, EPOCH {EPOCH_S} s -> an object may arrive {need} epochs late");
    for w in [30u64, 45, 60] {
        let ok = w >= need;
        println!(
            "  EPOCH_WINDOW +/-{:<3} {}  50 correspondents -> {} precomputed tags",
            w,
            if ok { "OK        " } else { "UNDERSIZED" },
            50 * (2 * w + 1)
        );
    }
}

/// Verify every figure RFC 1 publishes. Exit code is the number of mismatches.
fn check(m: Magnitudes) -> i32 {
    let mut bad = 0;
    let mut ok = 0;
    let mut cmp = |what: &str, got: usize, want: usize| {
        if got == want {
            ok += 1;
        } else {
            bad += 1;
            println!("MISMATCH  {what}: computed {got}, RFC 1 says {want}");
        }
    };

    cmp("§4.1 routing header", ROUTING_HEADER, 16);
    cmp("envelope, empty ciphertext", envelope(X25519, 0, m), 46);
    cmp("HPKE enc, suite 0x0001", X25519, 32);

    for (body, pt, ct, wire, bucket) in [
        (0usize, 84usize, 100usize, 163usize, 256usize),
        (64, 149, 165, 228, 256),
        (280, 366, 382, 446, 1_024),
        (1_200, 1_286, 1_302, 1_366, 4_096),
        (4_000, 4_086, 4_102, 4_166, 16_384),
        (20_000, 20_086, 20_102, 20_166, 65_536),
        (120_000, 120_088, 120_104, 120_170, 262_144),
    ] {
        let s = sealed(body, ADDR, CTYPE, Suite::Classical, m);
        cmp(&format!("body {body} plaintext"), s.plaintext, pt);
        cmp(&format!("body {body} ciphertext"), s.ciphertext, ct);
        cmp(&format!("body {body} on-wire"), s.on_wire, wire);
        cmp(
            &format!("body {body} bucket"),
            s.bucket.unwrap_or(0),
            bucket,
        );
    }

    for (b, mb) in [
        (256usize, 92usize),
        (1_024, 858),
        (4_096, 3_930),
        (16_384, 16_218),
        (65_536, 65_370),
        (262_144, 261_974),
    ] {
        cmp(
            &format!("§8.1 bucket {b} max body"),
            max_body_for(b, ADDR, CTYPE, Suite::Classical, m).unwrap_or(0),
            mb,
        );
    }

    let pq = sealed(280, ADDR, CTYPE, Suite::Hybrid, m);
    cmp("§6.5 hybrid 280-byte message", pq.on_wire, 1_535);
    cmp("§6.5 hybrid 280-byte bucket", pq.bucket.unwrap_or(0), 4_096);

    for (b, frames) in [(256usize, 6usize), (1_024, 21), (4_096, 81)] {
        cmp(
            &format!("§8.3 LoRa bucket {b} frames"),
            b.div_ceil(LORA_PAYLOAD),
            frames,
        );
    }

    // RFC 3 §8.1 and §8.2 — derivable from a credential size, and checked.
    for (peers, frag, copies, recons) in [
        (5usize, 2_300usize, 11_000usize, 6usize),
        (8, 3_548, 28_000, 16),
        (12, 5_212, 62_000, 35),
        (20, 8_540, 170_000, 95),
        (50, 21_020, 1_051_000, 584),
    ] {
        cmp(
            &format!("RFC3 §8.1 fragment, {peers} peers"),
            creds::fragment(peers, creds::PEER_LINK_1EP),
            frag,
        );
        // RFC 3 truncates to two significant figures rather than rounding.
        cmp(
            &format!("RFC3 §8.1 all copies, {peers} peers"),
            (creds::all_copies(peers, creds::PEER_LINK_1EP) / 1000) * 1000,
            copies,
        );
        cmp(
            &format!("RFC3 §8.1 LoRa reconciliations, {peers} peers"),
            (creds::lora_reconciliations(creds::all_copies(peers, creds::PEER_LINK_1EP)) * 10.0)
                .round() as usize,
            recons,
        );
    }
    for (peers, delta_tenths) in [(12usize, 74usize), (20, 123), (50, 308)] {
        cmp(
            &format!("RFC3 §8.2 delta, {peers} peers"),
            (creds::delta_all_copies(peers, 1, creds::PEER_LINK_1EP) as f64 / 100.0).round()
                as usize,
            delta_tenths,
        );
    }

    // §9.3 manifest table, in units of 0.1 MB to keep the comparison integral.
    for (id, tenths) in [
        (8usize, [1usize, 12, 60]),
        (12, [2, 16, 80]),
        (16, [2, 20, 100]),
        (32, [4, 36, 180]),
    ] {
        let entry = 4 + id;
        for (i, corpus) in [10_000usize, 100_000, 500_000].iter().enumerate() {
            let mb10 = ((corpus * entry) as f64 / 1e5).round() as usize;
            cmp(
                &format!("§9.3 manifest id {id}B corpus {corpus}"),
                mb10,
                tenths[i],
            );
        }
    }

    // ---- RFC 6 §2 — groups. Every figure the RFC publishes, checked. ----
    //
    // These were computed here and cited there, and then nothing verified
    // them: the module's constants read as dead code because `--check` only
    // covered RFC 1 and RFC 3. A figure nobody checks is an assertion, which
    // is precisely what this program exists to replace.
    for (g, objects, mb, received) in [
        (5usize, 40usize, 0.04f64, 8usize),
        (10, 180, 0.18, 18),
        (20, 760, 0.78, 38),
        (30, 1_740, 1.78, 58),
        (50, 4_900, 5.02, 98),
        (100, 19_800, 20.28, 198),
        (200, 79_600, 81.51, 398),
    ] {
        cmp(
            &format!("RFC6 §2.3 objects/day, G={g}"),
            groups::group_objects_per_day(g),
            objects,
        );
        cmp(
            &format!("RFC6 §2.3 corpus MB/day, G={g}"),
            (groups::group_mb_day(g) * 100.0).round() as usize,
            (mb * 100.0).round() as usize,
        );
        cmp(
            &format!("RFC6 §2.3 received/member/day, G={g}"),
            groups::received_per_day(g),
            received,
        );
    }

    // §2.4's fan-out ratio: (G−1)× a shared-sender-key scheme.
    for (g, ratio) in [(5usize, 4usize), (20, 19), (50, 49), (100, 99)] {
        cmp(
            &format!("RFC6 §2.4 fan-out ratio, G={g}"),
            groups::group_objects_per_day(g) / groups::shared_key_objects_per_day(g),
            ratio,
        );
    }

    // §2.7's stagger window, at a ten percent local rate lift. This is the
    // table `krab-tui`'s `fanout` module reproduces; both derive it from the
    // same formula and neither had checked it against the RFC until now.
    for (n, g, hours_tenths) in [
        (100usize, 10usize, 108usize),
        (100, 20, 228),
        (100, 50, 588),
        (500, 10, 22),
        (500, 20, 46),
        (500, 50, 118),
        (2_000, 10, 5),
        (2_000, 20, 11),
        (2_000, 50, 29),
    ] {
        cmp(
            &format!("RFC6 §2.7 stagger hours, n={n} G={g}"),
            (groups::stagger_hours(g, n, 0.10) * 10.0).round() as usize,
            hours_tenths,
        );
    }

    // §2.8's prekey burn: group size dominates consumption.
    for (g, per_day, seven, thirty) in [
        (5usize, 8usize, 128usize, 512usize),
        (10, 18, 256, 1_024),
        (20, 38, 512, 2_048),
        (50, 98, 2_048, 8_192),
    ] {
        cmp(
            &format!("RFC6 §2.8 received/day, G={g}"),
            groups::received_per_day(g),
            per_day,
        );
        cmp(
            &format!("RFC6 §2.8 batch for 7d, G={g}"),
            keys::batch_for(keys::prekeys_needed(per_day, 7)),
            seven,
        );
        cmp(
            &format!("RFC6 §2.8 batch for 30d, G={g}"),
            keys::batch_for(keys::prekeys_needed(per_day, 30)),
            thirty,
        );
    }
    // And §2.8's conclusion: a 50-member group cannot republish monthly,
    // because the batch would not fit in one object.
    cmp(
        "RFC6 §2.8 G=50 monthly batch does NOT fit one object",
        keys::batch_fits(8_192, object::MAX_OBJECT) as usize,
        0,
    );
    // And the sizes below it do fit, or the conclusion would be about the
    // gate rather than about the group.
    cmp(
        "RFC6 §2.8 G=20 monthly batch fits one object",
        keys::batch_fits(2_048, object::MAX_OBJECT) as usize,
        1,
    );

    // ---- RFC 7 §5.3 — prekey batch wire sizes. ----
    for (n, wire) in [
        (256usize, 8_312usize),
        (1_024, 32_888),
        (2_048, 65_656),
        (8_192, 262_264),
    ] {
        cmp(
            &format!("RFC7 §5.3 batch wire, {n} keys"),
            keys::prekey_batch_wire(n),
            wire,
        );
    }

    // ---- RFC 2 §4.3 — the precomputation table, as published. ----
    for (correspondents, window, entries, kb) in [
        (25usize, 30usize, 1_525usize, 18usize),
        (50, 30, 3_050, 37),
        (50, 45, 4_550, 55),
        (200, 30, 12_200, 146),
        (500, 45, 45_500, 546),
    ] {
        cmp(
            &format!("RFC2 §4.3 entries, {correspondents} at ±{window}"),
            tags::table_entries(correspondents, window),
            entries,
        );
        // **Decimal KB, rounded.** The RFC's figures are bytes ÷ 1000 to the
        // nearest whole — 1 525 entries is 18 300 bytes, printed as "18 KB",
        // which is 17.9 KiB. Checking against 1024 would report five
        // mismatches that are a unit convention rather than an error.
        cmp(
            &format!("RFC2 §4.3 table KB, {correspondents} at ±{window}"),
            (tags::table_bytes(correspondents, window) as f64 / 1000.0).round() as usize,
            kb,
        );
        cmp(
            &format!("RFC2 §4.3 ECDH ms×10, {correspondents}"),
            (tags::ecdh_ms(correspondents) * 10.0).round() as usize,
            (correspondents as f64 * 0.06 * 10.0).round() as usize,
        );
    }

    // ---- RFC 4 — transport. ----
    cmp("RFC4 §4.1 Noise handshake", transport::NOISE_HANDSHAKE, 144);
    cmp(
        "RFC4 §8 largest object spans more than one frame",
        (transport::frames(object::MAX_OBJECT) > 1) as usize,
        1,
    );
    // §5.4's conclusion, and the reason RFC 8 §6 refuses a picture on LoRa:
    // the largest object does not cross the slowest profile in usable time.
    for l in transport::LORA.iter().take(1) {
        cmp(
            "RFC4 §5.4 largest object exceeds an hour on the slowest LoRa",
            (l.elapsed_s(object::MAX_OBJECT) > 3_600.0) as usize,
            1,
        );
    }

    println!("\n{ok} figures verified, {bad} mismatched");

    if bad == 0 {
        println!("RFC 1's published byte counts are reproduced exactly.");
    }
    bad.min(125)
}
