//! Rendering text this node did not write — RFC 8 §7.
//!
//! > "Channel and node identifiers are keys and cannot be spoofed. **Display
//! > names are attacker-controlled**, and a Cyrillic homoglyph defeats the
//! > strongest cryptographic guarantee in the system with a font."
//!
//! ```text
//! A key fingerprint MUST appear alongside every display name in list views,
//!   not only in a detail pane.
//! The client MUST run Unicode confusable detection against names the user
//!   already follows, and MUST mark matches.
//! ```
//!
//! # What §7 protects, and what this implementation actually has
//!
//! §7 is written for a client with petnames. This one has none: every
//! identifier an operator sees is a **short id**, four bytes of a node
//! identifier in hex, derived from a key. `groups::Group::name` looks like a
//! display name and is not — it is "local only … not in any signature", so it
//! never crosses the wire and no one but the operator can choose it.
//!
//! So §7's first `MUST` is satisfied by construction, and the second has no
//! set of "names the user already follows" to run against. That is a stronger
//! position than §7 asks for and it would be easy, and wrong, to stop there.
//!
//! # Where the attack actually lands
//!
//! Two fields of attacker-chosen **free text** reach list views: the operator
//! note on a `peer-request` (RFC 3 §5.1 key 7) and on a `peer-counter`
//! (§5.2). Both are written by someone this node has never met, and both were
//! rendered verbatim.
//!
//! Because every identifier here *is* a short hex id, the impersonation §7
//! describes has a precise form: a note reading `0797c2c1` where the digits
//! are Cyrillic `о`, `с` and so on. It renders identically, it is a different
//! string, and an operator scanning a list has no way to tell. §7's own
//! sentence is the requirement — "the confusion happens while scanning a
//! list".
//!
//! So [`skeleton`] folds the homoglyphs and [`confusable_with_known`] marks a
//! note that renders like an identifier this node already holds.
//!
//! # And the simpler thing that was also wrong
//!
//! A note went to the pane with its control characters intact. A newline
//! breaks the list's layout; U+202E reverses everything after it; a zero-width
//! joiner hides a difference the skeleton would otherwise catch. [`safe`]
//! removes them and says how many it removed, because silently swallowing an
//! attacker's bytes is its own kind of lie.
//!
//! # What this is not
//!
//! Not a full Unicode TR39 implementation. The confusables table below is the
//! Cyrillic, Greek and fullwidth folds onto ASCII — the ones that matter for
//! text that impersonates a hex identifier — and it is a **subset**, stated
//! rather than implied. A name built from confusables outside it renders
//! unmarked, and the fingerprint beside it is what the operator has left.
//!
//! That is why §7 asks for both and why doing only one would, in its words,
//! "satisfy the letter and miss the point".

/// The most characters of foreign text this node will render in one line.
///
/// A list row is a line; text longer than one is not a name.
pub const MAX_RENDERED: usize = 64;

/// Characters removed before anything is rendered.
///
/// Control characters break the layout of a pane built from lines. The
/// bidirectional and zero-width formatting characters are worse: they change
/// what the *rest* of the line looks like without being visible themselves,
/// which is the whole mechanism of a display-spoofing attack.
///
/// # Why this is a category and not a list
///
/// It was a list: the bidi controls, the zero-width range, the byte-order
/// mark, the invisible mathematical operators. Everything on it was correctly
/// there and the list was the wrong shape, because an invisible character
/// defeats [`skeleton`] whether or not anyone thought of it. `skeleton` drops
/// exactly what this function calls dangerous, so a character that renders as
/// nothing and is *not* named here survives into the skeleton — and two
/// strings that look identical then produce different skeletons, which is the
/// one thing confusable detection must never do. U+00AD, U+061C, U+3164,
/// U+FE00 and the tag characters at U+E0020 all walked through.
///
/// So the rule is now the Unicode general category `Cf` in full, plus the
/// characters that are not `Cf` and still occupy no visible space. That is
/// still a subset of TR39 and still stated rather than implied — see the
/// module header — but it is a subset of a *category* rather than a list of
/// the attacks somebody happened to enumerate.
///
/// # What is deliberately still allowed
///
/// Combining marks. A long run of them stacks glyphs on one base character
/// and can overflow a row, which is a layout problem rather than an
/// impersonation one, and removing them would mangle every script that needs
/// them. Only the invisible ones — the variation selectors — are taken.
fn is_dangerous(c: char) -> bool {
    c.is_control() || is_format(c) || is_invisible(c)
}

/// Unicode general category `Cf`, as of Unicode 15.1.
///
/// Transcribed from `DerivedGeneralCategory.txt` rather than assembled from
/// the characters that had been used against this code, which is the whole
/// point of the change. A future Unicode version may add to it; that is a
/// table to refresh, not a mechanism to redesign.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD                  // soft hyphen
        | 0x0600..=0x0605       // Arabic number signs
        | 0x061C                // Arabic letter mark
        | 0x06DD | 0x070F
        | 0x0890..=0x0891
        | 0x08E2
        | 0x180E                // Mongolian vowel separator
        | 0x200B..=0x200F       // zero-width space, ZWNJ, ZWJ, LRM, RLM
        | 0x202A..=0x202E       // bidi embeddings and overrides
        | 0x2060..=0x206F       // word joiner, invisible operators, isolates
        | 0xFEFF                // byte-order mark, as a zero-width no-break space
        | 0xFFF9..=0xFFFB       // interlinear annotation
        | 0x110BD | 0x110CD
        | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0001               // language tag
        | 0xE0020..=0xE007F     // tag characters: a whole hidden ASCII alphabet
    )
}

/// Characters outside `Cf` that still render as nothing.
///
/// `Cf` is the category for "affects the text around it"; these are in letter,
/// mark and symbol categories and simply have no glyph. A reader cannot see
/// them and a skeleton must not keep them.
fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x034F                  // combining grapheme joiner
        | 0x115F | 0x1160       // Hangul choseong and jungseong fillers
        | 0x17B4 | 0x17B5       // Khmer inherent vowels
        | 0x180B..=0x180D | 0x180F  // Mongolian free variation selectors
        | 0x2800                // braille pattern blank
        | 0x3164                // Hangul filler
        | 0xFE00..=0xFE0F       // variation selectors 1–16
        | 0xFFA0                // halfwidth Hangul filler
        | 0xFFF0..=0xFFF8       // unassigned, reserved as default-ignorable
        | 0xE0100..=0xE01EF     // variation selectors 17–256
    )
}

/// What rendering someone else's text produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Safe to put in a pane.
    pub text: String,
    /// Characters removed because they would have changed the line around
    /// them. **Reported, not swallowed**: an operator whose peer sent
    /// invisible formatting should know that rather than see a tidy string.
    pub removed: usize,
    /// Whether it was cut at [`MAX_RENDERED`].
    pub truncated: bool,
}

impl Rendered {
    /// The line to show, with the marks §7 requires.
    pub fn line(&self) -> String {
        let mut out = format!("\"{}\"", self.text);
        if self.truncated {
            out.push('…');
        }
        if self.removed > 0 {
            out.push_str(&format!(
                "  [{} hidden character(s) removed — formatting that would \
                 have changed how this line reads]",
                self.removed
            ));
        }
        out
    }
}

/// Prepare text this node did not write for a pane.
pub fn safe(text: &str) -> Rendered {
    let mut out = String::new();
    let mut kept = 0usize;
    let mut removed = 0;
    let mut truncated = false;
    for c in text.chars() {
        if is_dangerous(c) {
            removed += 1;
            continue;
        }
        if kept >= MAX_RENDERED {
            truncated = true;
            break;
        }
        out.push(c);
        kept += 1;
    }
    Rendered {
        text: out,
        removed,
        truncated,
    }
}

/// The same sanitising, over a block of text that is allowed to have lines.
///
/// [`safe`] is for a row in a list: it removes every dangerous character —
/// which includes `\n`, correctly, because a newline in a one-line row is a
/// way to push text off the row — and stops at [`MAX_RENDERED`].
///
/// A body is neither of those things. Applying `safe` to one joined its lines
/// into a single run and cut it at 64 characters, so a note typed over two
/// lines came back as one and a long message came back short. This keeps the
/// line structure and the far larger bound, and sanitises within each line
/// exactly as `safe` does.
/// # The length is carried, not recomputed
///
/// Both loops used to ask `out.chars().count() >= MAX` once per character
/// kept, and that walks everything written so far — quadratic in the length of
/// a body somebody else chose. `safe` survived it because [`MAX_RENDERED`] is
/// 64. This did not: [`MAX_BLOCK`] is 512 Ki, and `Ui::show_selected` calls it
/// on the main thread, inside key handling, every time the selection moves.
///
/// Measured on a body of 256 KiB — the largest object RFC 1 §8 defines, so the
/// worst a message can be — that was **960 ms per keypress** while scrolling a
/// list, against 0.3 ms now. A message that froze the interface needed no
/// invalid bytes and no exploit, only length, and the sender pays 256 KiB once
/// for an effect that repeats for as long as the operator keeps pressing a
/// key.
pub fn safe_block(text: &str) -> Rendered {
    // One allocation. The output is never longer than the input, and a body
    // arrives as one owned buffer already.
    let mut out = String::with_capacity(text.len());
    let mut kept = 0usize;
    let mut removed = 0;
    let mut truncated = false;
    'block: for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            if kept >= MAX_BLOCK {
                truncated = true;
                break;
            }
            out.push('\n');
            kept += 1;
        }
        for c in line.chars() {
            if is_dangerous(c) {
                removed += 1;
                continue;
            }
            if kept >= MAX_BLOCK {
                truncated = true;
                break 'block;
            }
            out.push(c);
            kept += 1;
        }
    }
    Rendered {
        text: out,
        removed,
        truncated,
    }
}

/// Characters a body may render to.
///
/// Large enough that no message this protocol can carry hits it — the largest
/// object is 256 KB — and finite so that a hostile body cannot make the
/// renderer walk forever.
pub const MAX_BLOCK: usize = 512 * 1024;

/// Fold a string onto its confusable skeleton — Unicode TR39's idea.
///
/// Case is folded and the confusables below are mapped onto ASCII, so two
/// strings that render alike produce the same skeleton. A **subset**: see the
/// module header on what that costs.
pub fn skeleton(text: &str) -> String {
    text.chars()
        .filter(|c| !is_dangerous(*c))
        .map(fold)
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Confusables that matter for text impersonating a hex identifier.
///
/// Cyrillic and Greek letters that render as Latin ones, plus the fullwidth
/// forms. Hex digits are `0`–`9` and `a`–`f`, so the folds that matter most
/// are the ones producing those.
fn fold(c: char) -> char {
    match c {
        // Cyrillic → Latin.
        'а' | 'А' => 'a',
        'е' | 'Е' | 'ё' | 'Ё' => 'e',
        'о' | 'О' => 'o',
        'с' | 'С' => 'c',
        'р' | 'Р' => 'p',
        'х' | 'Х' => 'x',
        'у' | 'У' => 'y',
        'ѕ' | 'Ѕ' => 's',
        'і' | 'І' | 'ї' | 'Ї' => 'i',
        'ј' | 'Ј' => 'j',
        'һ' | 'Һ' => 'h',
        'ԁ' => 'd',
        'В' => 'b',
        'М' => 'm',
        'Н' => 'h',
        'Т' => 't',
        'К' => 'k',
        'Ѵ' => 'v',
        // Greek → Latin.
        'ο' | 'Ο' => 'o',
        'α' | 'Α' => 'a',
        'ε' | 'Ε' => 'e',
        'ρ' | 'Ρ' => 'p',
        'χ' | 'Χ' => 'x',
        'υ' => 'u',
        'ν' => 'v',
        'Β' => 'b',
        'Ϲ' | 'ϲ' => 'c',
        'Ι' => 'i',
        'Κ' => 'k',
        'Μ' => 'm',
        'Ν' => 'n',
        'Τ' => 't',
        'Υ' => 'y',
        'Ζ' => 'z',
        'Η' => 'h',
        // Letters that render as digits. `l` and `I` are the classic pair;
        // in a hex identifier a `1` is what they imitate.
        'l' => '1',
        'I' => '1',
        'Ⅰ' => '1',
        // Fullwidth forms.
        '\u{ff10}'..='\u{ff19}' => char::from_u32(c as u32 - 0xff10 + 0x30).unwrap_or(c),
        '\u{ff21}'..='\u{ff3a}' => char::from_u32(c as u32 - 0xff21 + 0x61).unwrap_or(c),
        '\u{ff41}'..='\u{ff5a}' => char::from_u32(c as u32 - 0xff41 + 0x61).unwrap_or(c),
        _ => c,
    }
}

/// Whether `text` renders like one of `known` without being it — §7's
/// "confusable detection against names the user already follows".
///
/// Returns the identifier it imitates. Exact matches are **not** flagged: a
/// note that simply says a peer's short id is quoting it, which is ordinary,
/// and marking that would train an operator to ignore the mark.
pub fn confusable_with_known(text: &str, known: &[String]) -> Option<String> {
    // A short id appears inside a sentence, so the comparison is per word
    // rather than over the whole string — and **punctuation is trimmed**,
    // because the first version compared `"асеdfасе,"` against `"acedface"`
    // and found nothing. An attacker writing a full stop would have walked
    // past the check.
    let words: Vec<String> = text.split_whitespace().map(trim_punctuation).collect();
    known.iter().find_map(|k| {
        let target = skeleton(k);
        let imitates = words.iter().any(|w| skeleton(w) == target);
        // An exact quotation is not an impersonation.
        let quotes = words.iter().any(|w| w == k);
        (imitates && !quotes).then(|| k.clone())
    })
}

/// Strip leading and trailing punctuation from a word.
fn trim_punctuation(w: &str) -> String {
    w.trim_matches(|c: char| !c.is_alphanumeric()).to_string()
}

#[cfg(test)]
mod block_tests {
    use super::*;

    /// **A body keeps its lines.** `safe` removes `\n` — correctly, for a
    /// row in a list, where a newline pushes text off the row. Used on a
    /// body it joined a note typed over two lines into one.
    #[test]
    fn a_block_keeps_its_newlines() {
        let r = safe_block("abc\nsdd");
        assert_eq!(r.text, "abc\nsdd", "the newline was eaten");
        assert_eq!(safe("abc\nsdd").text, "abcsdd", "safe still strips it");
    }

    /// And it still removes what `safe` removes, on every line.
    #[test]
    fn a_block_is_still_sanitised_on_every_line() {
        let r = safe_block("one\ntwo\u{202e}three");
        assert!(!r.text.contains('\u{202e}'), "an override survived: {:?}", r.text);
        assert_eq!(r.removed, 1);
        assert_eq!(r.text.lines().count(), 2, "{:?}", r.text);
    }

    /// **A body is not cut at 64 characters.** `safe`'s bound is a row's
    /// width; applying it to a message truncated every line of it.
    #[test]
    fn a_block_is_not_truncated_at_a_rows_width() {
        let long = "x".repeat(MAX_RENDERED * 4);
        let r = safe_block(&long);
        assert_eq!(r.text.chars().count(), long.chars().count());
        assert!(!r.truncated);
        // The row form still is, which is what it is for.
        assert!(safe(&long).truncated);
    }

    /// But it is bounded: a hostile body must not make the renderer walk on
    /// forever.
    #[test]
    fn a_block_is_still_bounded() {
        let huge = "y".repeat(MAX_BLOCK + 1000);
        let r = safe_block(&huge);
        assert!(r.truncated);
        assert_eq!(r.text.chars().count(), MAX_BLOCK);
    }

    /// **And bounded is not the same as cheap.** `show_selected` runs this on
    /// the main thread while handling a keypress, so the cost of a body is a
    /// cost the operator pays per arrow key.
    ///
    /// A wall-clock assertion, which this suite otherwise avoids — but here
    /// the elapsed time *is* the defect, and the two behaviours are three
    /// orders of magnitude apart rather than a percentage: 3.8 s against
    /// 0.5 ms at this size, measured in a release build, and the quadratic
    /// version is no faster in debug because the walk is memory-bound either
    /// way. Any bound between them is safe; two seconds leaves a factor of
    /// four thousand for a slow machine.
    #[test]
    fn a_large_block_does_not_cost_more_than_its_length() {
        let body = "y".repeat(MAX_BLOCK);
        let started = std::time::Instant::now();
        let r = safe_block(&body);
        let took = started.elapsed();
        assert_eq!(r.text.len(), body.len());
        assert!(!r.truncated);
        assert!(
            took < std::time::Duration::from_secs(2),
            "sanitising {} characters took {took:?} — the length is being \
             recomputed per character again",
            body.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A note claiming to be an identifier.** Every identifier this node
    /// shows is four bytes of hex, so the impersonation §7 describes has a
    /// precise form here: Cyrillic letters that render as hex digits.
    #[test]
    fn a_cyrillic_homoglyph_of_a_short_id_is_marked() {
        let real = "0797c2c1".to_string();
        // Cyrillic с (U+0441) for the Latin c, twice.
        let spoof = "from 0797с2с1 — trust me";
        assert!(!spoof.contains(&real), "the fixture is not a spoof");
        assert_eq!(
            confusable_with_known(spoof, std::slice::from_ref(&real)),
            Some(real),
            "a homoglyph of a known identifier went unmarked"
        );
    }

    /// **An invisible character must not change the skeleton.** `skeleton`
    /// drops what `is_dangerous` names, so anything invisible it does not name
    /// survives — and two strings that render identically then fold to
    /// different skeletons, which is the one failure confusable detection
    /// cannot have.
    ///
    /// Every character here rendered as nothing and walked past the old list.
    #[test]
    fn an_invisible_character_does_not_defeat_the_skeleton() {
        let real = "0797c2c1".to_string();
        for (name, hidden) in [
            ("soft hyphen", '\u{00ad}'),
            ("Arabic letter mark", '\u{061c}'),
            ("Hangul filler", '\u{3164}'),
            ("variation selector 1", '\u{fe00}'),
            ("tag latin capital A", '\u{e0041}'),
            ("zero-width joiner", '\u{200d}'),
            ("braille blank", '\u{2800}'),
            ("word joiner", '\u{2060}'),
            ("combining grapheme joiner", '\u{034f}'),
        ] {
            // The spoof: Cyrillic с for Latin c, with the invisible character
            // spliced in to break the fold.
            let spoof = format!("from 0797с2{hidden}с1 — trust me");
            assert_eq!(
                confusable_with_known(&spoof, std::slice::from_ref(&real)),
                Some(real.clone()),
                "{name} (U+{:04X}) carried a homoglyph past the check",
                hidden as u32
            );
            // And it never reaches the pane.
            let shown = safe(&spoof);
            assert!(
                !shown.text.contains(hidden),
                "{name} was rendered"
            );
            assert!(shown.removed > 0, "{name} was dropped without saying so");
        }
    }

    /// The same character must not hide an identifier from the check either:
    /// splicing one into a *known* identifier is the mirror of the attack
    /// above.
    #[test]
    fn an_invisible_character_cannot_disguise_the_target() {
        let real = "acedface".to_string();
        let spoof = "from a\u{00ad}сеdfасе, vouching";
        assert_eq!(
            confusable_with_known(spoof, std::slice::from_ref(&real)),
            Some(real)
        );
    }

    /// **Quoting an identifier is not impersonating one.** Marking it would
    /// train an operator to ignore the mark.
    #[test]
    fn quoting_a_real_identifier_is_not_flagged() {
        let real = "0797c2c1".to_string();
        assert_eq!(confusable_with_known("this is 0797c2c1", &[real]), None);
    }

    /// **Punctuation must not carry a homoglyph past the check.** The first
    /// version compared `"асеdfасе,"` against `"acedface"` and found nothing,
    /// so an attacker writing a full stop walked past it.
    #[test]
    fn punctuation_does_not_hide_a_homoglyph() {
        let real = "acedface".to_string();
        for note in [
            "from асеdfасе, vouching",
            "асеdfасе.",
            "(асеdfасе)",
            "\"асеdfасе\"",
            "асеdfасе!",
        ] {
            assert_eq!(
                confusable_with_known(note, std::slice::from_ref(&real)),
                Some(real.clone()),
                "punctuation hid a homoglyph in {note:?}"
            );
        }
        // And the exact one, punctuated, is still a quotation.
        assert_eq!(confusable_with_known("acedface.", &[real]), None);
    }

    /// Nothing to imitate, nothing marked.
    #[test]
    fn ordinary_text_is_not_flagged() {
        let known = vec!["0797c2c1".to_string(), "deadbeef".to_string()];
        assert_eq!(confusable_with_known("we met at the thing", &known), None);
        assert_eq!(confusable_with_known("", &known), None);
    }

    /// **Bidi overrides change the line around them without being visible.**
    /// That is the whole mechanism, so they go before anything is rendered.
    #[test]
    fn formatting_characters_are_removed_and_reported() {
        let nasty = "alice\u{202e}txt.exe";
        let r = safe(nasty);
        assert!(!r.text.contains('\u{202e}'));
        assert_eq!(r.removed, 1);
        assert!(
            r.line().contains("hidden character(s) removed"),
            "removal was silent: {}",
            r.line()
        );
    }

    /// A newline breaks a pane built from lines; a control character can do
    /// worse on a terminal.
    #[test]
    fn control_characters_cannot_reach_a_pane() {
        let r = safe("first\nsecond\r\u{7}\u{1b}[31mred");
        assert!(!r.text.contains('\n'));
        assert!(!r.text.contains('\r'));
        assert!(!r.text.contains('\u{1b}'), "an escape sequence survived");
        assert_eq!(r.removed, 4);
    }

    /// Zero-width characters hide a difference the skeleton would catch.
    #[test]
    fn zero_width_characters_are_removed() {
        for c in ['\u{200b}', '\u{200d}', '\u{feff}', '\u{2062}'] {
            let s = format!("a{c}b");
            assert_eq!(safe(&s).text, "ab", "{c:?} survived");
            assert_eq!(skeleton(&s), "ab", "{c:?} survived folding");
        }
    }

    /// Long text is a paragraph, not a name, and a list row is a line.
    #[test]
    fn long_text_is_cut_and_says_so() {
        let r = safe(&"x".repeat(MAX_RENDERED * 2));
        assert_eq!(r.text.chars().count(), MAX_RENDERED);
        assert!(r.truncated);
        assert!(r.line().ends_with('…'));
    }

    /// The fold covers Greek and fullwidth as well as Cyrillic, because a
    /// table that stopped at one script would be a table an attacker reads.
    #[test]
    fn the_fold_covers_the_scripts_it_claims_to() {
        assert_eq!(skeleton("ο"), "o", "Greek omicron");
        assert_eq!(skeleton("аеос"), "aeoc", "Cyrillic");
        assert_eq!(skeleton("\u{ff10}\u{ff41}"), "0a", "fullwidth");
        assert_eq!(skeleton("ABC"), "abc", "case is folded");
    }

    /// A skeleton is not a decoder ring: text that is genuinely different
    /// stays different.
    #[test]
    fn distinct_text_keeps_distinct_skeletons() {
        assert_ne!(skeleton("0797c2c1"), skeleton("0797c2c2"));
        assert_ne!(skeleton("alice"), skeleton("bob"));
    }

    /// Nothing here may panic on whatever arrived from a stranger.
    #[test]
    fn arbitrary_input_does_not_panic() {
        for s in [
            "",
            "\u{0}",
            "🙂🙂🙂",
            "\u{202e}\u{202d}\u{feff}",
            &"é".repeat(500),
        ] {
            let r = safe(s);
            let _ = r.line();
            let _ = skeleton(s);
            let _ = confusable_with_known(s, &["0797c2c1".into()]);
        }
    }
}
