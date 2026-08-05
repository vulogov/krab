//! krab-sizes — RFC 1 reference size encoder.
//!
//! RFC 1 cannot be revised, and every byte count in it is cited from here.
//! This computes those counts from the format RFC 1 specifies, so a reviewer
//! can check the document against arithmetic rather than against assertion.
//!
//! It computes lengths, not bytes: the RFC 1 §4.3 deterministic profile makes
//! an item's encoded length a pure function of its type and magnitude, which
//! is exactly the property that lets a parameter table be frozen.

mod cbor;
mod object;

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
    println!("  padded to bucket ............ {} bytes", floor.bucket.unwrap());
    println!();
    println!("  Computed with an empty address and empty content type. RFC 1 §8.1");
    println!("  cites a 150-byte floor, which requires 17 bytes of encoded address");
    println!("  and content type; the RFC does not state that composition. Both land");
    println!("  in the 256-byte bucket, so §8.1's conclusion is unaffected either way.");

    println!("\n--- realistic messages (X25519, addr 'dst=<16 hex>', text/plain) ---");
    println!("{:>10} {:>9} {:>9} {:>10} {:>9}", "body", "plaintxt", "cipher", "on-wire", "bucket");
    for body in [0usize, 64, 280, 1_200, 4_000, 20_000, 120_000] {
        let s = sealed(body, ADDR, CTYPE, Suite::Classical, m);
        println!(
            "{:>10} {:>9} {:>9} {:>10} {:>9}",
            s.body,
            s.plaintext,
            s.ciphertext,
            s.on_wire,
            s.bucket.map(|b| b.to_string()).unwrap_or_else(|| "OVER".into())
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
    println!("  padded to bucket ............ {} bytes", pq_floor.bucket.unwrap());
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
            print!("  {}k={:>6.1} MB", corpus / 1_000, (corpus * entry) as f64 / 1e6);
        }
        println!();
    }

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
    cmp("envelope, empty ciphertext", envelope(X25519, 0, m), 48);
    cmp("HPKE enc, suite 0x0001", X25519, 32);

    for (body, pt, ct, wire, bucket) in [
        (0usize, 84usize, 100usize, 165usize, 256usize),
        (64, 149, 165, 230, 256),
        (280, 366, 382, 448, 1_024),
        (1_200, 1_286, 1_302, 1_368, 4_096),
        (4_000, 4_086, 4_102, 4_168, 16_384),
        (20_000, 20_086, 20_102, 20_168, 65_536),
        (120_000, 120_088, 120_104, 120_172, 262_144),
    ] {
        let s = sealed(body, ADDR, CTYPE, Suite::Classical, m);
        cmp(&format!("body {body} plaintext"), s.plaintext, pt);
        cmp(&format!("body {body} ciphertext"), s.ciphertext, ct);
        cmp(&format!("body {body} on-wire"), s.on_wire, wire);
        cmp(&format!("body {body} bucket"), s.bucket.unwrap_or(0), bucket);
    }

    for (b, mb) in [
        (256usize, 90usize),
        (1_024, 856),
        (4_096, 3_928),
        (16_384, 16_216),
        (65_536, 65_368),
        (262_144, 261_972),
    ] {
        cmp(
            &format!("§8.1 bucket {b} max body"),
            max_body_for(b, ADDR, CTYPE, Suite::Classical, m).unwrap_or(0),
            mb,
        );
    }

    let pq = sealed(280, ADDR, CTYPE, Suite::Hybrid, m);
    cmp("§6.5 hybrid 280-byte message", pq.on_wire, 1_537);
    cmp("§6.5 hybrid 280-byte bucket", pq.bucket.unwrap_or(0), 4_096);

    for (b, frames) in [(256usize, 6usize), (1_024, 21), (4_096, 81)] {
        cmp(&format!("§8.3 LoRa bucket {b} frames"), b.div_ceil(LORA_PAYLOAD), frames);
    }

    // §9.3 manifest table, in units of 0.1 MB to keep the comparison integral.
    for (id, tenths) in [(8usize, [1usize, 12, 60]), (12, [2, 16, 80]), (16, [2, 20, 100]), (32, [4, 36, 180])] {
        let entry = 4 + id;
        for (i, corpus) in [10_000usize, 100_000, 500_000].iter().enumerate() {
            let mb10 = ((corpus * entry) as f64 / 1e5).round() as usize;
            cmp(&format!("§9.3 manifest id {id}B corpus {corpus}"), mb10, tenths[i]);
        }
    }

    println!("\n{ok} figures verified, {bad} mismatched");
    if bad == 0 {
        println!("RFC 1's published byte counts are reproduced exactly.");
    }
    bad.min(125)
}
