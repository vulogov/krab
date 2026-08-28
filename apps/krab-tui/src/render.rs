//! Drawing, RFC 8 §2.
//!
//! Everything here is a projection of state onto cells. All the decisions —
//! which pane is where, whether a banner shows, what the status line says —
//! were made in [`crate::layout`] and [`crate::activity`] and tested there,
//! headlessly. This module is deliberately thin, because a decision made
//! inside a draw call is a decision no test can reach.

use crate::activity::{status_line_with, NodeState, Spinner};
use crate::layout::{Banner, Level, Mode, Pane, Rect as UiRect, Tab, Ui};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use ratatui::Frame;

fn to_rect(r: UiRect) -> Rect {
    Rect {
        x: r.x,
        y: r.y,
        width: r.w,
        height: r.h,
    }
}

/// What the interface is showing, beyond layout.
pub struct View<'a> {
    /// Pane and tab state.
    pub ui: &'a Ui,
    /// Node state, for the status line.
    pub node: &'a NodeState,
    /// Spinner phase.
    pub spinner: &'a Spinner,
    /// Rows for the list pane.
    pub list: &'a [String],
    /// Body for the view pane, or long command output (RFC 8 §3).
    pub body: &'a str,
    /// The command line's current contents.
    pub command: &'a crate::line::Line,
    /// Command output — the output pane.
    pub output: &'a str,
    /// A picture being shown, as character cells — RFC 8 §6.
    pub showing: Option<&'a [crate::picture::Cell2]>,
    /// This node's short id, or `None` before `init`.
    pub me: Option<&'a str>,
    /// Whether anything is going out, and whether anything is coming in.
    pub sending: bool,
    pub receiving: bool,
    /// Inner width of the output pane at the last frame, and how many rows
    /// its content wrapped to. Written by `draw_output` and read by the
    /// scroll clamp and the auto-reveal, so all three use the same units.
    pub output_width: &'a std::cell::Cell<u16>,
    pub output_rows: &'a std::cell::Cell<usize>,
    /// Rows the pane showed, so the auto-reveal knows what "does not fit"
    /// means in the terminal actually in use.
    pub output_height: &'a std::cell::Cell<u16>,
    /// What the interface is waiting for the operator to do, if anything.
    /// Takes the status rule when set, because nothing else on screen is
    /// more useful than "this is stopped, and here is what unsticks it".
    pub waiting: Option<&'a str>,
    /// Where the caret is in `composer`, as a character index.
    pub composer_at: usize,
    /// Which item the list pane's cursor is on, and how many items there are.
    /// Two numbers because `list` may hold rows that are not items.
    /// Show the body's bytes rather than its rendering.
    pub raw_body: bool,
    pub selected: usize,
    pub items: usize,
    /// Lines the output pane is scrolled back from the newest.
    pub scroll: usize,
    /// Composer contents, shown when `ui.mode()` is `Compose`.
    pub composer: &'a str,
    /// Whether the node is locked. A locked node draws no message content.
    pub locked: bool,
    /// Recent background activity, newest last.
    ///
    /// Bounded and transient — see `crate::activity_log`. It shares the command
    /// pane with the status line, so zooming the pane is what an operator does
    /// to watch a reconciliation (RFC 8 §2, §3).
    pub log: &'a [String],
    /// Whether command-pane input is a passphrase.
    ///
    /// A passphrase must not reach the screen: RFC 7 §4 makes it the only root
    /// of the hierarchy, and it is typed at exactly the moment someone may be
    /// looking over a shoulder — a first-run ceremony is often performed with
    /// company.
    pub masked: bool,
}

/// Draw one frame.
pub fn draw(f: &mut Frame, view: &View) {
    let area = f.area();
    let ui = view.ui;

    let tabs_h = if ui.zoomed().is_some() { 0 } else { 1 };
    let body = UiRect {
        x: area.x,
        y: area.y + tabs_h,
        w: area.width,
        h: area.height.saturating_sub(tabs_h),
    };

    if tabs_h == 1 {
        draw_tabs(
            f,
            Rect {
                x: area.x,
                y: area.y,
                width: area.width,
                height: 1,
            },
            ui,
        );
    }

    for (pane, rect) in ui.layout(body) {
        match pane {
            Pane::List => draw_list(f, to_rect(rect), view),
            Pane::View => draw_view(f, to_rect(rect), view),
            Pane::Output => draw_output(f, to_rect(rect), view),
            Pane::Command => draw_command(f, to_rect(rect), view),
        }
    }
}

fn draw_tabs(f: &mut Frame, area: Rect, ui: &Ui) {
    let sel = Style::default()
        .fg(Color::Black)
        .bg(Color::White)
        .add_modifier(Modifier::BOLD);
    let un = Style::default().fg(Color::DarkGray);
    let (a, b, c) = match ui.tab() {
        Tab::Private => (sel, un, un),
        Tab::Channels => (un, sel, un),
        Tab::Notes => (un, un, sel),
    };
    let line = Line::from(vec![
        Span::styled(" Private messages ", a),
        Span::raw(" "),
        Span::styled(" Channels ", b),
        Span::raw(" "),
        // Named for what it is rather than "Notes" alone: the tab's whole
        // property is that nothing in it is ever offered to a peer.
        Span::styled(" Notes (local) ", c),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

/// Focused panes get a bright border. RFC 8 §2 needs the focused pane to be
/// obvious, since `Tab` cycles and zoom hides the others entirely.
fn frame_for(ui: &Ui, pane: Pane, title: String) -> Block<'static> {
    let focused = ui.focus() == pane;
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused {
            Color::White
        } else {
            Color::DarkGray
        }))
        .title(title)
}

fn draw_list(f: &mut Frame, area: Rect, view: &View) {
    // RFC 8 §2: the channels list is two-level and the client MUST indicate
    // which level is displayed.
    //
    // The node's own short id rides on this frame as well as the output
    // pane's. This is the pane an operator looks at while reading mail, and
    // running two nodes on one host — the ordinary way to test anything — the
    // two windows are otherwise identical. Knowing which node you are typing
    // into is not a nicety when one of the verbs is `wipe`.
    let title = match (view.ui.tab(), view.ui.level()) {
        (Tab::Private, _) => format!(" messages · {} ", view.me.unwrap_or("no identity")),
        (Tab::Channels, Level::Channels) => {
            format!(" channels · {} ", view.me.unwrap_or("no identity"))
        }
        (Tab::Channels, Level::Messages) => " channel ▸ posts ".to_string(),
        (Tab::Notes, _) => format!(" notes · local only · {} ", view.me.unwrap_or("no identity")),
    };
    // **The cursor, drawn.** `selected` indexes items; the list can carry
    // rows above them — first-contact requests sit on top of the mail — so
    // the highlighted row is offset by however many of those there are.
    let offset = view.list.len().saturating_sub(view.items);
    let here = offset + view.selected;
    let cursor = Style::default().add_modifier(Modifier::REVERSED);
    let rows: Vec<Line> = view
        .list
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i == here && view.items > 0 {
                Line::from(Span::styled(s.clone(), cursor))
            } else {
                Line::from(s.as_str())
            }
        })
        .collect();
    f.render_widget(
        Paragraph::new(rows).block(frame_for(view.ui, Pane::List, title)),
        area,
    );
}

/// One body line, styled by the subset in [`crate::markdown`].
///
/// Weight and colour only: none of these can paint a full-width reversed bar,
/// so a body cannot be made to resemble the interface's own banners. The
/// styles are chosen here rather than carried in the text, so a body cannot
/// select one.
fn body_lines(text: &str) -> Vec<Line<'static>> {
    use crate::markdown::{Kind, Row};
    crate::markdown::parse(text)
        .into_iter()
        .map(|Row { kind, pieces }| {
            let mut spans = Vec::new();
            let base = match kind {
                Kind::Heading(_) => Style::default().add_modifier(Modifier::BOLD),
                _ => Style::default(),
            };
            if kind == Kind::Bullet {
                spans.push(Span::raw("  • "));
            }
            for p in pieces {
                let mut st = base;
                if p.bold {
                    st = st.add_modifier(Modifier::BOLD);
                }
                if p.italic {
                    st = st.add_modifier(Modifier::ITALIC);
                }
                if p.code {
                    st = Style::default().fg(Color::Cyan);
                }
                spans.push(Span::styled(p.text, st));
            }
            Line::from(spans)
        })
        .collect()
}

fn draw_view(f: &mut Frame, area: Rect, view: &View) {
    if view.ui.mode() == Mode::Compose {
        return draw_composer(f, area, view);
    }
    // A picture, if one is being shown. Half-blocks: the foreground is the
    // upper pixel and the background the lower, so one cell carries two and
    // the terminal is never handed an image to decode — see `picture::cells`.
    if let Some(rows) = view.showing.filter(|_| !view.locked) {
        let lines: Vec<Line> = rows
            .iter()
            .map(|row| {
                Line::from(
                    row.iter()
                        .map(|(top, bottom)| {
                            Span::styled(
                                "\u{2580}",
                                Style::default()
                                    .fg(Color::Rgb(top[0], top[1], top[2]))
                                    .bg(Color::Rgb(bottom[0], bottom[1], bottom[2])),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(frame_for(view.ui, Pane::View, " picture ".into())),
            area,
        );
        return;
    }
    // RFC 7 §8 and RFC 8 §2.2: plaintext exists only while displayed, and a
    // locked node has no key to produce any.
    let body = if view.locked {
        "locked — no message content"
    } else {
        view.body
    };
    // **Rendered, unless the operator asked for the bytes.** `Ctrl-Y` is not
    // a preference to be set once and forgotten: it is the check that what is
    // displayed is what arrived, so the title says which one this is.
    let title = if view.raw_body {
        " message · raw ".to_string()
    } else {
        " message ".to_string()
    };
    let block = frame_for(view.ui, Pane::View, title);
    if view.raw_body || view.locked {
        f.render_widget(Paragraph::new(body).block(block), area);
    } else {
        f.render_widget(Paragraph::new(body_lines(body)).block(block), area);
    }
}

/// Break `text` into rows no wider than `width`, breaking on whitespace where
/// possible and mid-word only when a single word does not fit.
///
/// Shared with the scroll clamp and the auto-reveal threshold so that all
/// three agree on how tall a given output actually is.
pub fn wrap_rows(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return text.lines().map(str::to_string).collect();
    }
    // **Cells, not characters.** A CJK character is one `char` and two
    // columns, a combining mark is one `char` and none. Counting `chars()`
    // let a row that "fit" overflow the pane, and since this function
    // replaced the widget's own wrapping, the overflow was truncated rather
    // than re-flowed — text silently gone, not merely misplaced.
    let cells = |s: &str| UnicodeWidthStr::width(s);
    let mut out = Vec::new();
    for line in text.lines() {
        if cells(line) <= width {
            out.push(line.to_string());
            continue;
        }
        let mut row = String::new();
        let mut n = 0usize;
        for word in line.split_inclusive(char::is_whitespace) {
            let w = cells(word);
            if n + w > width && n > 0 {
                out.push(std::mem::take(&mut row));
                n = 0;
            }
            // A single word wider than the pane: cut it, rather than let it
            // run off the edge where it cannot be read or scrolled to.
            if w > width {
                for c in word.chars() {
                    let cw = UnicodeWidthChar::width(c).unwrap_or(0);
                    if n + cw > width {
                        out.push(std::mem::take(&mut row));
                        n = 0;
                    }
                    row.push(c);
                    n += cw;
                }
            } else {
                row.push_str(word);
                n += w;
            }
        }
        out.push(row);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Command output.
///
/// Not subject to RFC 8 §2.2's locked-node blanking: this is what the node
/// said about itself, not message content, and blanking it would hide the
/// reason the node is locked from the operator trying to unlock it.
fn draw_output(f: &mut Frame, area: Rect, view: &View) {
    // Scrolled to the end. Output longer than the pane is normal — `help`,
    // `peers`, the backup word list — and the newest line is the one the
    // operator just asked for. Showing the top would mean a verb whose reply
    // runs long appears to have printed nothing.
    let rows = area.height.saturating_sub(2) as usize;
    let width = area.width.saturating_sub(2) as usize;
    // **Window over display rows, not logical lines.**
    //
    // This used to slice `output.lines()` and hand the result to a wrapping
    // Paragraph. A window of `rows` logical lines wraps to more than `rows`
    // rows on screen, and the overflow is clipped off the bottom — so the
    // newest line, the one the verb was run for, could be the invisible one.
    // Scrolling could not reach it either, because PgUp counted the logical
    // lines. Wrapping here first makes the window, the scroll and the
    // ↑n/↓n counts all speak the same unit.
    let lines = wrap_rows(view.output, width);
    // The window ends `scroll` rows above the newest, so a fresh command
    // lands at the bottom and PgUp walks backwards from there. Anchoring to
    // the top instead would put every reply's first line on screen and hide
    // its result, which is the part the operator asked for.
    let end = lines.len().saturating_sub(view.scroll.min(lines.len()));
    let from = end.saturating_sub(rows.max(1));
    let shown = lines[from..end].join("\n");
    let below = lines.len() - end;
    // What the pane is, so the scroll clamp and the auto-reveal threshold can
    // work in the same units this function just used.
    view.output_width.set(width as u16);
    view.output_rows.set(lines.len());
    view.output_height.set(rows as u16);
    // This node's own short id, on the frame of the pane the operator is
    // always looking at. It is public — it is in every card handed out and is
    // the name a peer types into `connect` — and being asked "what is my id"
    // should not require a verb.
    let me = view.me.unwrap_or("no identity");
    // Two directions, so a still glyph means "nothing is moving" rather than
    // "the interface froze".
    let (out, inn) = view.spinner.duplex(view.sending, view.receiving);
    let title = match (from, below) {
        (0, 0) => format!(" {me}  {out}\u{2191} {inn}\u{2193} "),
        (a, 0) => format!(" {me}  {out}\u{2191} {inn}\u{2193}  \u{2191}{a} PgUp "),
        (0, b) => format!(" {me}  {out}\u{2191} {inn}\u{2193}  \u{2193}{b} PgDn "),
        (a, b) => format!(" {me}  {out}\u{2191} {inn}\u{2193}  \u{2191}{a} \u{2193}{b} PgUp/PgDn "),
    };
    f.render_widget(
        // Already wrapped above; wrapping again would re-flow rows that were
        // measured, and the counts in the title would stop being true.
        Paragraph::new(shown).block(frame_for(view.ui, Pane::Output, title)),
        area,
    );
}

/// The draft with the caret drawn on it.
///
/// A composer with editing keys and no visible caret is worse than one
/// without either: the operator can move it and cannot see where it went.
/// The character under the caret is reversed, and at end-of-line a space
/// stands in so the caret has something to sit on.
fn caret_lines(text: &str, at: usize) -> Vec<Line<'static>> {
    let caret = Style::default().add_modifier(Modifier::REVERSED);
    let mut out = Vec::new();
    let mut seen = 0usize;
    for line in text.split('\n') {
        let n = line.chars().count();
        if at >= seen && at <= seen + n {
            let col = at - seen;
            let before: String = line.chars().take(col).collect();
            let under: String = line.chars().skip(col).take(1).collect();
            let after: String = line.chars().skip(col + 1).collect();
            out.push(Line::from(vec![
                Span::raw(before),
                Span::styled(if under.is_empty() { " ".into() } else { under }, caret),
                Span::raw(after),
            ]));
        } else {
            out.push(Line::from(line.to_string()));
        }
        seen += n + 1;
    }
    out
}

/// The composer, and the banner that must always accompany it.
///
/// RFC 8 §2.1: *"A zoomed or overlaid composer MUST render its security
/// banner. The client MUST NOT suppress the banner to reclaim space."*
///
/// [`Ui::banner`] does not take zoom as an input, so this cannot draw a
/// composer without one — the `expect` documents that rather than guarding it.
fn draw_composer(f: &mut Frame, area: Rect, view: &View) {
    let banner = view.ui.banner().expect("composing always yields a banner");
    let (fg, bg) = match banner {
        Banner::Private => (Color::Black, Color::Green),
        // RFC 8 §4.1 — the only unrecoverable user error in Krab.
        Banner::PublicSignedPermanent => (Color::Black, Color::Red),
    };
    let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(bg).add_modifier(Modifier::BOLD))
        .title(Span::styled(format!(" {} ", banner.text()), style));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // The banner is repeated inside the frame, not only in the title: a title
    // is one line at the top of a pane that may be taller than the screen.
    let lines = vec![
        Line::from(Span::styled(format!(" {} ", banner.text()), style)),
        Line::from(""),
    ];
    if inner.height > 0 {
        f.render_widget(
            Paragraph::new(lines),
            Rect {
                height: inner.height.min(2),
                ..inner
            },
        );
    }
    if inner.height > 2 {
        f.render_widget(
            Paragraph::new(caret_lines(view.composer, view.composer_at)),
            Rect {
                y: inner.y + 2,
                height: inner.height - 2,
                ..inner
            },
        );
    }
}

/// Two lines: input, and status. RFC 8 §3 sends anything longer to the view
/// pane or a zoomed command pane rather than scrolling this.
fn draw_command(f: &mut Frame, area: Rect, view: &View) {
    let status = status_line_with(view.node, view.spinner);
    // A quiet node has no status, and an empty rule is a wasted row on the one
    // pane an operator is always looking at. The chords are what they need
    // next and cannot otherwise discover without typing `help` first.
    let status = if status.is_empty() {
        "Ctrl-Q quit  ·  Ctrl-O full screen  ·  Esc back  ·  help".to_string()
    } else {
        status
    };
    // **What the interface is waiting for wins the rule.**
    //
    // A step that needs a keypress used to say so only in the output pane, in
    // prose, next to whatever else the verb printed — so "press Enter" and
    // "the node is doing something, wait" looked identical from the outside.
    // A node mid-ceremony is not a quiet node and its chords are not what the
    // operator needs next.
    let waiting = view.waiting.is_some();
    let status = match view.waiting {
        Some(w) => format!("WAITING \u{2192} {w}"),
        None => status,
    };
    let lock = if view.locked { "  \u{1f512}" } else { "" };
    // The status rides on the rule. It has to live somewhere, and the two rows
    // below are spoken for: RFC 8 §3 gives this pane a prompt and one line of
    // acknowledgement, and a status line stealing one of them leaves no room
    // for the acknowledgement to be read.
    let focused = view.ui.focus() == Pane::Command;
    let block = Block::default()
        .borders(Borders::TOP)
        .title(format!(" {status}{lock} "))
        .title_style(Style::default().fg(if waiting {
            Color::Yellow
        } else {
            Color::DarkGray
        }))
        .border_style(Style::default().fg(if focused {
            Color::White
        } else {
            Color::DarkGray
        }));

    // Everything the rule and the prompt do not take. Unzoomed that is one
    // line; zoomed it is the backlog, which is where RFC 8 §3 sends output
    // too long for two lines.
    let room = area.height.saturating_sub(2) as usize;
    // Length is shown, contents are not: an operator needs to see that keys
    // are registering without the passphrase reaching the screen.
    let shown = if view.masked {
        "\u{2022}".repeat(view.command.len())
    } else {
        view.command.as_string()
    };
    let mut lines: Vec<Line> = view
        .log
        .iter()
        .rev()
        .take(room)
        .rev()
        .map(|l| {
            Line::from(Span::styled(
                l.clone(),
                Style::default().fg(Color::DarkGray),
            ))
        })
        .collect();
    lines.push(Line::from(format!("> {shown}")));
    let rows = lines.len() as u16;
    f.render_widget(Paragraph::new(lines).block(block), area);

    // A visible cursor, because the line editor is only usable if the operator
    // can see where an insertion will land. `+2` clears the `> ` prompt; the
    // row is the last line drawn, which is the one holding it.
    if view.ui.focus() == Pane::Command {
        let col = area.x + 2 + view.command.cursor() as u16;
        let row = area.y + rows;
        if col < area.x + area.width && row < area.y + area.height {
            f.set_cursor_position((col, row));
        }
    }
}
