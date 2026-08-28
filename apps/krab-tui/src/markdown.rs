//! A deliberately small subset of Markdown, for message bodies — RFC 8 §7.
//!
//! # What is rendered, and why only this
//!
//! Emphasis, code spans, bullets and headings. Nothing else.
//!
//! RFC 8 §7 exists because displayed text is attacker-controlled: a message
//! body is written by somebody else, and §7's confusable detection is there so
//! that what is shown cannot lie about who wrote it. Markdown's `[text](url)`
//! is a purpose-built mechanism for displayed text lying about its target —
//! the same attack with a specification behind it. `![](url)` is worse: it
//! asks the client to fetch a remote resource when a message is displayed,
//! which is a network callback on read, and RFC 8 §6 already forbids handing
//! received bytes to anything that would do that.
//!
//! So links, images, inline HTML and reference syntax are **not implemented**,
//! which is a stronger guarantee than refusing them: there is no code here
//! that could render one. `[a](b)` and `<b>` arrive as those characters and
//! are displayed as those characters.
//!
//! # What the subset still cannot do
//!
//! The four constructs change weight and colour within the body. None of them
//! can produce a full-width reversed bar, so none can be made to resemble the
//! interface's own banners — which is the residual spoof once links are gone.
//! `Style` is chosen here rather than passed in, so a body cannot select one.
//!
//! # And the raw text is always one keystroke away
//!
//! `Ctrl-Y` shows the bytes. A renderer that consumes syntax makes source text
//! invisible, and "what you see is what is there" is a property RFC 8 §7 leans
//! on. Rendering is a view of the text, never a replacement for it.

/// What a line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An ordinary line.
    Plain,
    /// `#`, `##`, `###`. Deeper markers are not headings and stay literal.
    Heading(u8),
    /// `- ` or `* ` at the start of a line.
    Bullet,
}

/// A run of text with one set of attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The characters, with the markers removed.
    pub text: String,
    /// `**like this**`.
    pub bold: bool,
    /// `*like this*`.
    pub italic: bool,
    /// `` `like this` `` — literal, so nothing inside it is markup.
    pub code: bool,
}

/// One rendered line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Heading, bullet or plain.
    pub kind: Kind,
    /// Its runs, in order.
    pub pieces: Vec<Piece>,
}

/// Longest run of markers considered. A body full of asterisks is a body, not
/// an attack, but it must not be quadratic to render.
const MAX_MARKER: usize = 2;

/// Parse `text` into rows.
///
/// Never fails and never drops characters it does not understand: anything
/// that is not one of the four constructs is text.
pub fn parse(text: &str) -> Vec<Row> {
    text.split('\n').map(parse_line).collect()
}

fn parse_line(line: &str) -> Row {
    // Headings first: the marker is only a marker at the start of a line, and
    // only with a space after it. `#hashtag` is a word.
    let mut kind = Kind::Plain;
    let mut rest = line;
    let hashes = line.chars().take_while(|&c| c == '#').count();
    if (1..=3).contains(&hashes) && line.chars().nth(hashes) == Some(' ') {
        kind = Kind::Heading(hashes as u8);
        rest = &line[hashes + 1..];
    } else if let Some(r) = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
    {
        kind = Kind::Bullet;
        rest = r;
    }
    Row {
        kind,
        pieces: inline(rest),
    }
}

/// Split a line into runs on `**`, `*` and backticks.
fn inline(s: &str) -> Vec<Piece> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<Piece> = Vec::new();
    let mut buf = String::new();
    let (mut bold, mut italic) = (false, false);
    let mut i = 0;

    let flush = |out: &mut Vec<Piece>, buf: &mut String, bold: bool, italic: bool| {
        if !buf.is_empty() {
            out.push(Piece {
                text: std::mem::take(buf),
                bold,
                italic,
                code: false,
            });
        }
    };

    while i < chars.len() {
        let c = chars[i];
        // **Code is literal.** Everything between the backticks is text, which
        // is the construct's whole purpose: a body quoting `*` must not be
        // read as emphasis.
        if c == '`' {
            if let Some(end) = chars[i + 1..].iter().position(|&x| x == '`') {
                flush(&mut out, &mut buf, bold, italic);
                out.push(Piece {
                    text: chars[i + 1..i + 1 + end].iter().collect(),
                    bold: false,
                    italic: false,
                    code: true,
                });
                i += end + 2;
                continue;
            }
            // Unclosed: a lone backtick is a backtick.
            buf.push(c);
            i += 1;
            continue;
        }
        if c == '*' {
            let run = chars[i..].iter().take_while(|&&x| x == '*').count();
            // Only `*` and `**` mean anything; `***` and longer are text.
            //
            // A marker that is already open closes unconditionally. Requiring
            // a *further* match made the closing `**` of `**b** c *d*` look
            // unmatched — there is no second `**` after it — so it stayed
            // literal and the rest of the line was bold.
            let open = if run == 2 { bold } else { italic };
            if run <= MAX_MARKER && (open || closes(&chars[i + run..], run)) {
                flush(&mut out, &mut buf, bold, italic);
                if run == 2 {
                    bold = !bold;
                } else {
                    italic = !italic;
                }
                i += run;
                continue;
            }
            for _ in 0..run {
                buf.push('*');
            }
            i += run;
            continue;
        }
        buf.push(c);
        i += 1;
    }
    // An unclosed marker leaves its text unstyled rather than styling the rest
    // of the line: a body ending in `*` should not turn the pane italic.
    flush(&mut out, &mut buf, bold, italic);
    out
}

/// Whether a matching run of `n` asterisks appears later on the line.
fn closes(rest: &[char], n: usize) -> bool {
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == '*' {
            let run = rest[i..].iter().take_while(|&&x| x == '*').count();
            if run == n {
                return true;
            }
            i += run;
        } else {
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(row: &Row) -> String {
        row.pieces.iter().map(|p| p.text.as_str()).collect()
    }

    #[test]
    fn emphasis_and_code_are_rendered() {
        let rows = parse("a **b** c *d* e `f`");
        assert_eq!(rows.len(), 1);
        let p = &rows[0].pieces;
        assert!(p.iter().any(|x| x.text == "b" && x.bold));
        assert!(p.iter().any(|x| x.text == "d" && x.italic));
        assert!(p.iter().any(|x| x.text == "f" && x.code));
    }

    #[test]
    fn headings_and_bullets_are_rendered() {
        let rows = parse("# one\n## two\n- item\n* item");
        assert_eq!(rows[0].kind, Kind::Heading(1));
        assert_eq!(rows[1].kind, Kind::Heading(2));
        assert_eq!(rows[2].kind, Kind::Bullet);
        assert_eq!(rows[3].kind, Kind::Bullet);
        assert_eq!(plain(&rows[0]), "one");
        assert_eq!(plain(&rows[2]), "item");
    }

    /// **The point of the subset.** A link is not rendered because no code
    /// here renders one — the characters arrive and are displayed.
    #[test]
    fn links_images_and_html_stay_literal() {
        for src in [
            "[bob's key](https://evil.example)",
            "![](https://evil.example/track.png)",
            "<b>bold</b>",
            "<script>x</script>",
            "[ref][1]",
        ] {
            let rows = parse(src);
            assert_eq!(plain(&rows[0]), src, "{src} was transformed");
            assert!(
                rows[0].pieces.iter().all(|p| !p.code),
                "{src} became a code span"
            );
        }
    }

    /// A body quoting a marker must not be read as markup.
    #[test]
    fn a_code_span_is_literal_inside() {
        let rows = parse("`a *b* [c](d)`");
        assert_eq!(rows[0].pieces.len(), 1);
        assert!(rows[0].pieces[0].code);
        assert_eq!(rows[0].pieces[0].text, "a *b* [c](d)");
    }

    /// An unclosed marker is text, not a mode the rest of the body is in.
    #[test]
    fn unclosed_markers_are_text() {
        for src in ["a *b", "a **b", "a `b", "***x***"] {
            let rows = parse(src);
            assert_eq!(plain(&rows[0]), src, "{src} lost characters");
        }
    }

    /// `#hashtag` is a word; `####` is not a heading this subset has.
    #[test]
    fn only_the_marker_forms_are_markers() {
        assert_eq!(parse("#nothash")[0].kind, Kind::Plain);
        assert_eq!(parse("#### four")[0].kind, Kind::Plain);
        assert_eq!(parse("-nospace")[0].kind, Kind::Plain);
        assert_eq!(plain(&parse("#nothash")[0]), "#nothash");
    }

    /// Nothing is ever dropped: what goes in comes out, markers aside.
    #[test]
    fn no_characters_are_lost_on_ordinary_text() {
        let src = "plain line\nsecond line with 100% of it";
        let rows = parse(src);
        assert_eq!(rows.len(), 2);
        assert_eq!(plain(&rows[0]), "plain line");
        assert_eq!(plain(&rows[1]), "second line with 100% of it");
    }
}
