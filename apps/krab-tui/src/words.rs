//! Tokenising a command line into strings and numbers.
//!
//! # What was wrong with `split_whitespace`
//!
//! Every argument was `line.split_whitespace().nth(n)`. That cannot express a
//! path containing a space, and it does not fail when given one — it silently
//! truncates. `peer accept /Volumes/My Disk/bob.card` read the card from
//! `/Volumes/My`, and the operator was told the file did not exist.
//!
//! Removable media is where pads and cards travel, and removable media is
//! mounted under names people gave them. This was not a corner case.
//!
//! # Why a tokeniser and not a language
//!
//! The need is quoting and typed values, which is a lexer. `WORDS.md` records
//! why the concatenative VM that could also provide them is not used for it:
//! the composition such a VM adds is a hazard here rather than a feature,
//! because the verbs an operator most wants to loop over are the ones whose
//! value is that they are performed one at a time, deliberately.
//!
//! # Grammar
//!
//! ```text
//! line     := word*
//! word     := bare | quoted
//! bare     := <run of non-space, non-quote>
//! quoted   := '"' ( <any but " or \> | '\' <any> )* '"'
//! ```
//!
//! A word is a number if it parses as one, and a string otherwise. Nothing is
//! coerced silently: [`Word::int`] returns `None` for `"12"` written with
//! quotes, so a caller that wants a count cannot be handed a filename that
//! happens to be digits.

/// One token from a command line.
///
/// **The original text is kept.** An earlier version stored a parsed `i64`
/// and rendered it back for `text()`, which silently rewrote any identifier
/// that happened to be all digits: a short id of `09437082` became
/// `9437082`, and the verb addressed a peer that did not exist — or, worse,
/// a different one. Hex identifiers are digits eight times out of sixteen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    raw: String,
    /// The value, if this was written as a bare number. Never used to
    /// reconstruct the text.
    num: Option<i64>,
}

impl Word {
    /// A bare token, classified.
    fn bare(raw: String) -> Word {
        // A leading zero means the operator wrote an identifier, whatever the
        // characters are. Numbers do not have leading zeros and identifiers
        // do, so this is the one place the distinction is decidable.
        let num = if raw.len() > 1 && raw.starts_with('0') {
            None
        } else {
            raw.parse::<i64>().ok()
        };
        Word { raw, num }
    }

    /// A quoted token. Always text, never a number.
    fn quoted(raw: String) -> Word {
        Word { raw, num: None }
    }

    /// The text exactly as it was typed, minus quoting.
    pub fn text(&self) -> String {
        self.raw.clone()
    }

    /// The value, if this token was written as a bare number.
    ///
    /// A quoted `"40000"` is a string and stays one; so is `040000`, because
    /// a leading zero is how an identifier is written and not how a number is.
    pub fn int(&self) -> Option<i64> {
        self.num
    }
}

/// Why a line could not be tokenised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A quote was opened and never closed.
    ///
    /// Refused rather than assumed closed at end of line: guessing turns a
    /// visible typo into a command that runs against the wrong argument.
    UnterminatedQuote,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnterminatedQuote => f.write_str(
                "unterminated quote — a \" was opened and not closed. \
                 Use \\\" for a literal quote.",
            ),
        }
    }
}

/// Split a line into words.
pub fn split(line: &str) -> Result<Vec<Word>, Error> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '"' {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next() {
                    None => return Err(Error::UnterminatedQuote),
                    Some('"') => break,
                    // A backslash escapes the next character, whatever it is.
                    // Only `\"` and `\\` are meaningful; everything else is
                    // passed through, because a Windows path is full of
                    // backslashes that mean nothing but themselves.
                    Some('\\') => match chars.next() {
                        None => return Err(Error::UnterminatedQuote),
                        Some(n) => {
                            if n != '"' && n != '\\' {
                                s.push('\\');
                            }
                            s.push(n);
                        }
                    },
                    Some(other) => s.push(other),
                }
            }
            // A quoted token is always a string, never a number.
            out.push(Word::quoted(s));
            continue;
        }
        let mut s = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                break;
            }
            s.push(c);
            chars.next();
        }
        out.push(Word::bare(s));
    }
    Ok(out)
}

/// The `n`th word's text, or `None`.
///
/// The shape `arg(line, n)` had, so call sites did not all have to change at
/// once — but reading a tokenised line rather than a whitespace split.
pub fn nth(words: &[Word], n: usize) -> Option<String> {
    words.get(n).map(|w| w.text())
}

/// Everything from word `n` onward, rejoined with single spaces.
///
/// For the one place a command takes free text — a note on a peer-request —
/// where the words were never meant to be separate.
pub fn rest(words: &[Word], n: usize) -> String {
    words
        .iter()
        .skip(n)
        .map(|w| w.text())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(line: &str) -> Vec<String> {
        split(line).unwrap().iter().map(|w| w.text()).collect()
    }

    /// **The bug this exists for.** Removable media is where pads and cards
    /// travel, and it is mounted under names people gave it.
    #[test]
    fn a_path_with_a_space_survives() {
        assert_eq!(
            strs(r#"peer accept "/Volumes/My Disk/bob.card""#),
            vec!["peer", "accept", "/Volumes/My Disk/bob.card"]
        );
    }

    /// Unquoted lines behave exactly as they did, so nothing an operator has
    /// in their fingers changes.
    #[test]
    fn bare_lines_tokenise_as_before() {
        assert_eq!(
            strs("connect fed356f2 tcp 127.0.0.1:40000"),
            vec!["connect", "fed356f2", "tcp", "127.0.0.1:40000"]
        );
        assert_eq!(strs("   peers   "), vec!["peers"]);
        assert_eq!(strs(""), Vec::<String>::new());
    }

    /// Numbers are numbers, and quoted numbers are not.
    ///
    /// A port and a filename are different kinds of thing, and coercing one
    /// into the other is how a caller ends up opening a file called `40000`.
    #[test]
    fn quoting_decides_whether_a_digit_string_is_a_number() {
        let w = split(r#"listen 40000 "40000""#).unwrap();
        assert_eq!(w[1].int(), Some(40_000));
        assert_eq!(w[1].int(), Some(40_000));
        assert_eq!(w[2].text(), "40000");
        assert_eq!(w[2].int(), None, "a quoted number is a string");
        // And both still render the same when only the text is wanted.
        assert_eq!(w[1].text(), w[2].text());
    }

    /// Negative numbers, and things that only look numeric.
    #[test]
    fn numbers_are_recognised_conservatively() {
        assert_eq!(split("-5").unwrap()[0].int(), Some(-5));
        // An address is not a number, and neither is a version.
        assert_eq!(split("127.0.0.1:40000").unwrap()[0].int(), None);
        // Nor is something that would overflow — it stays the text it was,
        // rather than saturating into a different value.
        let big = "99999999999999999999999";
        let w = &split(big).unwrap()[0];
        assert_eq!(w.int(), None);
        assert_eq!(w.text(), big, "an overflowing number lost its digits");
    }

    /// An unclosed quote is refused, not assumed closed at the end of the
    /// line. Guessing turns a visible typo into a command that runs against
    /// the wrong argument.
    #[test]
    fn an_unterminated_quote_is_refused() {
        assert_eq!(split(r#"peer accept "oops"#), Err(Error::UnterminatedQuote));
        assert_eq!(split(r#"a "b\"#), Err(Error::UnterminatedQuote));
    }

    /// Escapes cover a literal quote and a literal backslash, and leave every
    /// other backslash alone — a Windows path is full of them.
    #[test]
    fn escapes_do_not_eat_windows_paths() {
        assert_eq!(
            strs(r#""C:\Users\alice\bob.card""#),
            vec![r"C:\Users\alice\bob.card"]
        );
        assert_eq!(strs(r#""a\"b""#), vec![r#"a"b"#]);
        assert_eq!(strs(r#""a\\b""#), vec![r"a\b"]);
    }

    /// Empty quotes are a word, not nothing. A caller that gets three
    /// arguments where the operator typed three must not silently get two.
    #[test]
    fn an_empty_quoted_word_is_still_a_word() {
        let w = split(r#"a "" b"#).unwrap();
        assert_eq!(w.len(), 3);
        assert_eq!(w[1].text(), "");
    }

    /// Free text keeps its spacing intent, for the one command that takes a
    /// note rather than arguments.
    #[test]
    fn the_rest_of_a_line_can_be_taken_as_text() {
        let w = split(r#"request bob.card it is me "from the cafe""#).unwrap();
        assert_eq!(rest(&w, 2), "it is me from the cafe");
        assert_eq!(nth(&w, 1).as_deref(), Some("bob.card"));
        assert_eq!(nth(&w, 99), None);
    }

    /// Nothing an operator can type causes a panic.
    #[test]
    fn no_input_panics() {
        for line in [
            "\"", "\\", "\"\\", "\"\"\"", "a\"b", "  \t \n ", "\"\\\"", "-", "--",
        ] {
            let _ = split(line);
        }
        // Including a very long unquoted run, which must not be quadratic or
        // recursive.
        let long = "x".repeat(100_000);
        assert_eq!(split(&long).unwrap().len(), 1);
    }

    /// **An identifier that is all digits keeps its leading zeros.**
    ///
    /// A short id is four hex bytes, so eight times in sixteen every
    /// character is a digit. Parsing one as an integer and rendering it back
    /// dropped the leading zero — and the verb then addressed a peer that did
    /// not exist, or a different one, with nothing to say so.
    #[test]
    fn an_identifier_of_digits_survives_intact() {
        for id in ["09437082", "00000001", "0123456789abcdef", "007"] {
            let w = &split(id).unwrap()[0];
            assert_eq!(w.text(), id, "{id} was rewritten");
            assert_eq!(w.int(), None, "{id} was taken for a number");
        }
        // And a genuine number is still a number.
        assert_eq!(split("40000").unwrap()[0].int(), Some(40_000));
        assert_eq!(split("40000").unwrap()[0].text(), "40000");
    }

    /// Every token round-trips to exactly what was typed. A tokeniser that
    /// rewrites its input is one that addresses the wrong thing.
    #[test]
    fn every_token_renders_back_to_what_was_typed() {
        for line in [
            "connect 09437082 tcp 127.0.0.1:40000",
            "peer verified 00ff00ff",
            "message 007 0042",
            "listen bob 40000",
        ] {
            let got: Vec<String> = split(line).unwrap().iter().map(|w| w.text()).collect();
            let want: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(got, want, "{line} was rewritten");
        }
    }
}
