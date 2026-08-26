//! Fingerprints as spoken words — RFC 3 §2, RFC 8 §5.4.
//!
//! > "Display is the first 8 bytes as a word list, not base32. Operators verify
//! > fingerprints aloud, over a phone call, in a language they speak; **a human
//! > cannot reliably read base32 aloud and a human is the verification
//! > mechanism here.**"
//!
//! This is the encoding for RFC 3 §11 step 2 — "the actual security step" —
//! and for RFC 7 §11's identity backup, which is "printable as a word list on
//! paper".
//!
//! # The PGP word list
//!
//! RFC 8 cites it. Two alphabets of 256 words, alternating by byte position:
//! even indices draw from [`EVEN`] (two syllables), odd from [`ODD`] (three).
//! The alternation is the useful part — a transposed or dropped byte changes
//! the *rhythm* of the phrase, so it is audible rather than merely wrong.
//!
//! The words were selected for phonetic distinctness under noise, which is
//! exactly the condition a hurried phone call provides.
//!
//! # ⚠ The table must be checked against the canonical source
//!
//! These 512 words are transcribed, and a transcription error here is
//! security-relevant in a way that is not obvious: two Krab implementations
//! with different tables would render the *same* fingerprint as *different*
//! phrases, and operators would correctly conclude they had been attacked and
//! abandon a sound peering. A duplicate within a table is worse — two distinct
//! fingerprints reading identically is a collision an attacker can aim for.
//!
//! [`tests::the_tables_are_well_formed`] catches duplicates, count errors and
//! cross-table collisions, which are the failures that break the scheme
//! outright. It cannot catch a word that is merely *different from PGP's*.
//! **Verify against the canonical list before release.**

/// Two-syllable words, for even byte positions.
pub const EVEN: [&str; 256] = [
    "aardvark",
    "absurd",
    "accrue",
    "acme",
    "adrift",
    "adult",
    "afflict",
    "ahead",
    "aimless",
    "Algol",
    "allow",
    "alone",
    "ammo",
    "ancient",
    "apple",
    "artist",
    "assume",
    "Athens",
    "atlas",
    "Aztec",
    "baboon",
    "backfield",
    "backward",
    "banjo",
    "beaming",
    "bedlamp",
    "beehive",
    "beeswax",
    "befriend",
    "Belfast",
    "berserk",
    "billiard",
    "bison",
    "blackjack",
    "blockade",
    "blowtorch",
    "bluebird",
    "bombast",
    "bookshelf",
    "brackish",
    "breadline",
    "breakup",
    "brickyard",
    "briefcase",
    "Burbank",
    "button",
    "buzzard",
    "cement",
    "chairlift",
    "chatter",
    "checkup",
    "chisel",
    "choking",
    "chopper",
    "Christmas",
    "clamshell",
    "classic",
    "classroom",
    "cleanup",
    "clockwork",
    "cobra",
    "commence",
    "concert",
    "cowbell",
    "crackdown",
    "cranky",
    "crowfoot",
    "crucial",
    "crumpled",
    "crusade",
    "cubic",
    "dashboard",
    "deadbolt",
    "deckhand",
    "dogsled",
    "dragnet",
    "drainage",
    "dreadful",
    "drifter",
    "dropper",
    "drumbeat",
    "drunken",
    "Dupont",
    "dwelling",
    "eating",
    "edict",
    "egghead",
    "eightball",
    "endorse",
    "endow",
    "enlist",
    "erase",
    "escape",
    "exceed",
    "eyeglass",
    "eyetooth",
    "facial",
    "fallout",
    "flagpole",
    "flatfoot",
    "flytrap",
    "fracture",
    "framework",
    "freedom",
    "frighten",
    "gazelle",
    "Geiger",
    "glitter",
    "glucose",
    "goggles",
    "goldfish",
    "gremlin",
    "guidance",
    "hamlet",
    "highchair",
    "hockey",
    "indoors",
    "indulge",
    "inverse",
    "involve",
    "island",
    "jawbone",
    "keyboard",
    "kickoff",
    "kiwi",
    "klaxon",
    "locale",
    "lockup",
    "merit",
    "minnow",
    "miser",
    "Mohawk",
    "mural",
    "music",
    "necklace",
    "Neptune",
    "newborn",
    "nightbird",
    "Oakland",
    "obtuse",
    "offload",
    "optic",
    "orca",
    "payday",
    "peachy",
    "pheasant",
    "physique",
    "playhouse",
    "Pluto",
    "preclude",
    "prefer",
    "preshrunk",
    "printer",
    "prowler",
    "pupil",
    "puppy",
    "python",
    "quadrant",
    "quiver",
    "quota",
    "ragtime",
    "ratchet",
    "rebirth",
    "reform",
    "regain",
    "reindeer",
    "rematch",
    "repay",
    "retouch",
    "revenge",
    "reward",
    "rhythm",
    "ribcage",
    "ringbolt",
    "robust",
    "rocker",
    "ruffled",
    "sailboat",
    "sawdust",
    "scallion",
    "scenic",
    "scorecard",
    "Scotland",
    "seabird",
    "select",
    "sentence",
    "shadow",
    "shamrock",
    "showgirl",
    "skullcap",
    "skydive",
    "slingshot",
    "slowdown",
    "snapline",
    "snapshot",
    "snowcap",
    "snowslide",
    "solo",
    "southward",
    "soybean",
    "spaniel",
    "spearhead",
    "spellbind",
    "spheroid",
    "spigot",
    "spindle",
    "spyglass",
    "stagehand",
    "stagnate",
    "stairway",
    "standard",
    "stapler",
    "steamship",
    "sterling",
    "stockman",
    "stopwatch",
    "stormy",
    "sugar",
    "surmount",
    "suspense",
    "sweatband",
    "swelter",
    "tactics",
    "talon",
    "tapeworm",
    "tempest",
    "tiger",
    "tissue",
    "tonic",
    "topmost",
    "tracker",
    "transit",
    "trauma",
    "treadmill",
    "Trojan",
    "trouble",
    "tumor",
    "tunnel",
    "tycoon",
    "uncut",
    "unearth",
    "unwind",
    "uproot",
    "upset",
    "upshot",
    "vapor",
    "village",
    "virus",
    "Vulcan",
    "waffle",
    "wallet",
    "watchword",
    "wayside",
    "willow",
    "woodlark",
    "Zulu",
];

/// Three-syllable words, for odd byte positions.
pub const ODD: [&str; 256] = [
    "adroitness",
    "adviser",
    "aftermath",
    "aggregate",
    "alkali",
    "almighty",
    "amulet",
    "amusement",
    "antenna",
    "applicant",
    "Apollo",
    "armistice",
    "article",
    "asteroid",
    "Atlantic",
    "atmosphere",
    "autopsy",
    "Babylon",
    "backwater",
    "barbecue",
    "belowground",
    "bifocals",
    "bodyguard",
    "bookseller",
    "borderline",
    "bottomless",
    "Bradbury",
    "bravado",
    "Brazilian",
    "breakaway",
    "Burlington",
    "businessman",
    "butterfat",
    "Camelot",
    "candidate",
    "cannonball",
    "Capricorn",
    "caravan",
    "caretaker",
    "celebrate",
    "cellulose",
    "certify",
    "chambermaid",
    "Cherokee",
    "Chicago",
    "clergyman",
    "coherence",
    "combustion",
    "commando",
    "company",
    "component",
    "concurrent",
    "confidence",
    "conformist",
    "congregate",
    "consensus",
    "consulting",
    "corporate",
    "corrosion",
    "councilman",
    "crossover",
    "crucifix",
    "cumbersome",
    "customer",
    "Dakota",
    "decadence",
    "December",
    "decimal",
    "designing",
    "detector",
    "detergent",
    "determine",
    "dictator",
    "dinosaur",
    "direction",
    "disable",
    "disbelief",
    "disruptive",
    "distortion",
    "document",
    "embezzle",
    "enchanting",
    "enrollment",
    "enterprise",
    "equation",
    "equipment",
    "escapade",
    "Eskimo",
    "everyday",
    "examine",
    "existence",
    "exodus",
    "fascinate",
    "filament",
    "finicky",
    "forever",
    "fortitude",
    "frequency",
    "gadgetry",
    "Galveston",
    "getaway",
    "glossary",
    "gossamer",
    "graduate",
    "gravity",
    "guitarist",
    "hamburger",
    "Hamilton",
    "handiwork",
    "hazardous",
    "headwaters",
    "hemisphere",
    "hesitate",
    "hideaway",
    "holiness",
    "hurricane",
    "hydraulic",
    "impartial",
    "impetus",
    "inception",
    "indigo",
    "inertia",
    "infancy",
    "inferno",
    "informant",
    "insincere",
    "insurgent",
    "integrate",
    "intention",
    "inventive",
    "Istanbul",
    "Jamaica",
    "Jupiter",
    "leprosy",
    "letterhead",
    "liberty",
    "maritime",
    "matchmaker",
    "maverick",
    "Medusa",
    "megaton",
    "microscope",
    "microwave",
    "midsummer",
    "millionaire",
    "miracle",
    "misnomer",
    "molasses",
    "molecule",
    "Montana",
    "monument",
    "mosquito",
    "narrative",
    "nebula",
    "newsletter",
    "Norwegian",
    "October",
    "Ohio",
    "onlooker",
    "opulent",
    "Orlando",
    "outfielder",
    "Pacific",
    "pandemic",
    "Pandora",
    "paperweight",
    "paragon",
    "paragraph",
    "paramount",
    "passenger",
    "pedigree",
    "Pegasus",
    "penetrate",
    "perceptive",
    "performance",
    "pharmacy",
    "phonetic",
    "photograph",
    "pioneer",
    "pocketful",
    "politeness",
    "positive",
    "potato",
    "processor",
    "provincial",
    "proximate",
    "puberty",
    "publisher",
    "pyramid",
    "quantity",
    "racketeer",
    "rebellion",
    "recipe",
    "recover",
    "repellent",
    "replica",
    "reproduce",
    "resistor",
    "responsive",
    "retraction",
    "retrieval",
    "retrospect",
    "revenue",
    "revival",
    "revolver",
    "sandalwood",
    "sardonic",
    "Saturday",
    "savagery",
    "scavenger",
    "sensation",
    "sociable",
    "souvenir",
    "specialist",
    "speculate",
    "stethoscope",
    "stupendous",
    "supportive",
    "surrender",
    "suspicious",
    "sympathy",
    "tambourine",
    "telephone",
    "therapist",
    "tobacco",
    "tolerance",
    "tomorrow",
    "torpedo",
    "tradition",
    "travesty",
    "trombonist",
    "truncated",
    "typewriter",
    "ultimate",
    "undaunted",
    "underfoot",
    "unicorn",
    "unify",
    "universe",
    "unravel",
    "upcoming",
    "vacancy",
    "vagabond",
    "vertigo",
    "Virginia",
    "visitor",
    "vocalist",
    "voyager",
    "warranty",
    "Waterloo",
    "whimsical",
    "Wichita",
    "Wilmington",
    "Wyoming",
    "yesteryear",
    "Yucatan",
];

/// The word for `byte` at `position`.
pub fn word(position: usize, byte: u8) -> &'static str {
    if position.is_multiple_of(2) {
        EVEN[byte as usize]
    } else {
        ODD[byte as usize]
    }
}

/// Render bytes as a spoken phrase.
///
/// RFC 3 §2 displays the **first 8 bytes** of a fingerprint, so a caller
/// showing an identity passes `&id[..8]`. Longer inputs are accepted for
/// RFC 7 §11's 64-byte backup, which uses the same alphabet.
pub fn phrase(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(word(i, *b));
    }
    out
}

/// Parse a phrase back to bytes, for checking a transcribed backup.
///
/// Case-insensitive, since an operator reading from paper will not reproduce
/// the capitalisation of "Aztec". Position matters: a word from the wrong
/// alphabet is rejected rather than silently accepted, because that is what
/// makes a transposition audible *and* detectable.
pub fn parse(phrase: &str) -> Option<alloc::vec::Vec<u8>> {
    use alloc::vec::Vec;
    let mut out = Vec::new();
    for (i, token) in phrase.split_whitespace().enumerate() {
        let table = if i % 2 == 0 { &EVEN } else { &ODD };
        let found = table.iter().position(|w| w.eq_ignore_ascii_case(token))?;
        out.push(found as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// **The test that guards the transcription.** A duplicate within a table
    /// makes two distinct fingerprints read identically, which is a collision
    /// an attacker can aim for.
    #[test]
    fn the_tables_are_well_formed() {
        for (name, table) in [("EVEN", &EVEN), ("ODD", &ODD)] {
            assert_eq!(table.len(), 256, "{name} must have exactly 256 entries");
            let mut sorted: Vec<&str> = table.to_vec();
            sorted.sort_unstable();
            let before = sorted.len();
            sorted.dedup();
            assert_eq!(sorted.len(), before, "{name} contains a duplicate word");
            for w in table.iter() {
                assert!(
                    !w.is_empty() && w.is_ascii(),
                    "{name}: {w:?} is not speakable ASCII"
                );
            }
        }
        // No word appears in both alphabets: a word must identify its own
        // position, so a dropped byte cannot resynchronise unnoticed.
        let mut all: Vec<&str> = EVEN.iter().chain(ODD.iter()).copied().collect();
        all.sort_unstable();
        let before = all.len();
        all.dedup();
        assert_eq!(all.len(), before, "a word appears in both alphabets");
    }

    /// The alternation RFC 8 §5.4 relies on: even positions are short, odd
    /// positions are long, so a phrase has an audible rhythm.
    #[test]
    fn the_alphabets_alternate_by_position() {
        assert_eq!(word(0, 0), "aardvark");
        assert_eq!(word(1, 0), "adroitness");
        assert_eq!(word(2, 0), "aardvark");
        assert_eq!(word(7, 255), "Yucatan");
        assert_eq!(word(6, 255), "Zulu");
    }

    #[test]
    fn a_phrase_round_trips() {
        let id = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let p = phrase(&id);
        assert_eq!(p.split_whitespace().count(), 8, "RFC 3 §2 — eight bytes");
        assert_eq!(parse(&p).unwrap(), id);
    }

    /// An operator reads from paper; capitalisation will not survive.
    #[test]
    fn parsing_ignores_case_and_extra_space() {
        let id = [0x13u8, 0x9c, 0x00, 0xff];
        let p = phrase(&id);
        let sloppy = alloc::format!("  {}  ", p.to_lowercase().replace(' ', "   "));
        assert_eq!(parse(&sloppy).unwrap(), id);
    }

    /// A transposition moves words into the wrong alphabet, so it fails to
    /// parse rather than decoding to a different valid fingerprint.
    #[test]
    fn a_transposed_phrase_does_not_parse() {
        let id = [0x01u8, 0x02, 0x03, 0x04];
        let words: Vec<&str> = {
            let p: &'static str = alloc::boxed::Box::leak(phrase(&id).into_boxed_str());
            p.split_whitespace().collect()
        };
        let swapped = alloc::format!("{} {} {} {}", words[1], words[0], words[2], words[3]);
        assert!(
            parse(&swapped).is_none(),
            "a swap must be detected, not decoded"
        );
    }

    #[test]
    fn an_unknown_word_is_rejected() {
        assert!(parse("aardvark adroitness notaword").is_none());
        assert!(
            parse("aardvark aardvark").is_none(),
            "right word, wrong alphabet"
        );
    }

    /// Every byte value is reachable, so no fingerprint is unrenderable.
    #[test]
    fn every_byte_renders_and_parses() {
        for b in 0u8..=255 {
            for pos in [0usize, 1] {
                let w = word(pos, b);
                let mut phrase_bytes = alloc::vec![0u8; pos];
                phrase_bytes.push(b);
                let text = phrase(&phrase_bytes);
                assert!(text.ends_with(w));
                assert_eq!(parse(&text).unwrap(), phrase_bytes);
            }
        }
    }

    /// RFC 7 §11 — the 64-byte identity backup uses the same alphabet.
    #[test]
    fn the_identity_backup_renders_as_words() {
        let backup = [0x5Au8; 64];
        let p = phrase(&backup);
        assert_eq!(p.split_whitespace().count(), 64);
        assert_eq!(parse(&p).unwrap(), backup.to_vec());
    }
}
