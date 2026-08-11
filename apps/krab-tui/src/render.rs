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
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
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
    /// This node's short id, or `None` before `init`.
    pub me: Option<&'a str>,
    /// Whether anything is going out, and whether anything is coming in.
    pub sending: bool,
    pub receiving: bool,
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
    let (a, b) = match ui.tab() {
        Tab::Private => (sel, un),
        Tab::Channels => (un, sel),
    };
    let line = Line::from(vec![
        Span::styled(" Private messages ", a),
        Span::raw(" "),
        Span::styled(" Channels ", b),
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
    let title = match (view.ui.tab(), view.ui.level()) {
        (Tab::Private, _) => " messages ".to_string(),
        (Tab::Channels, Level::Channels) => " channels ".to_string(),
        (Tab::Channels, Level::Messages) => " channel ▸ posts ".to_string(),
    };
    let rows: Vec<Line> = view.list.iter().map(|s| Line::from(s.as_str())).collect();
    f.render_widget(
        Paragraph::new(rows).block(frame_for(view.ui, Pane::List, title)),
        area,
    );
}

fn draw_view(f: &mut Frame, area: Rect, view: &View) {
    if view.ui.mode() == Mode::Compose {
        return draw_composer(f, area, view);
    }
    // RFC 7 §8 and RFC 8 §2.2: plaintext exists only while displayed, and a
    // locked node has no key to produce any.
    let body = if view.locked {
        "locked — no message content"
    } else {
        view.body
    };
    f.render_widget(
        Paragraph::new(body).block(frame_for(view.ui, Pane::View, " message ".into())),
        area,
    );
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
    let lines: Vec<&str> = view.output.lines().collect();
    let from = lines.len().saturating_sub(rows.max(1));
    let shown = lines[from..].join("\n");
    // This node's own short id, on the frame of the pane the operator is
    // always looking at. It is public — it is in every card handed out and is
    // the name a peer types into `connect` — and being asked "what is my id"
    // should not require a verb.
    let me = view.me.unwrap_or("no identity");
    // Two directions, so a still glyph means "nothing is moving" rather than
    // "the interface froze".
    let (out, inn) = view.spinner.duplex(view.sending, view.receiving);
    let title = if from > 0 {
        format!(" {me}  {out}\u{2191} {inn}\u{2193}  {from} more above (Ctrl-O) ")
    } else {
        format!(" {me}  {out}\u{2191} {inn}\u{2193} ")
    };
    f.render_widget(
        Paragraph::new(shown)
            .wrap(Wrap { trim: false })
            .block(frame_for(view.ui, Pane::Output, title)),
        area,
    );
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
            Paragraph::new(view.composer),
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
    let lock = if view.locked { "  \u{1f512}" } else { "" };
    // The status rides on the rule. It has to live somewhere, and the two rows
    // below are spoken for: RFC 8 §3 gives this pane a prompt and one line of
    // acknowledgement, and a status line stealing one of them leaves no room
    // for the acknowledgement to be read.
    let focused = view.ui.focus() == Pane::Command;
    let block = Block::default()
        .borders(Borders::TOP)
        .title(format!(" {status}{lock} "))
        .title_style(Style::default().fg(Color::DarkGray))
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
