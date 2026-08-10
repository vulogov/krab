//! Panes, tabs, focus and zoom, RFC 8 §2.
//!
//! ```text
//! ┌ Private messages │ Channels ─────────────────────────────────┐
//! │  LIST PANE        │  MESSAGE VIEW PANE                       │
//! │  40%              │  60%                                     │
//! ├───────────────────┴──────────────────────────────────────────┤
//! │ COMMAND PANE — 2 lines, combined input and output            │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Zoom is why the composer banner is load-bearing
//!
//! Any pane may be zoomed to full screen, and the new-message pane overlays
//! the view. Both mean **the tab header can be absent while the user is
//! composing** — which is RFC 8 §2.1's reason for putting the security context
//! in the composer rather than the tab strip:
//!
//! > "A tab indicator is not merely weaker, it is periodically not on screen."
//!
//! So [`Ui::banner`] is a function of mode and tab, and **zoom is not one of
//! its inputs**. RFC 8 §2.1's "the client MUST NOT suppress the banner to
//! reclaim space" is therefore not a rule to follow but a thing there is no
//! way to do.

/// Rows the command pane occupies: RFC 8 §3's two content lines plus the
/// rule that separates it from the body.
///
/// Two rows was not two lines. The pane drew a full border, so a two-row
/// allocation left zero usable rows inside and the command line had nowhere
/// to render — the interface looked as though typing did nothing.
pub const COMMAND_ROWS: u16 = 3;

/// Rows the output pane occupies, directly above the command pane.
///
/// Four: a border top and bottom, and two lines of output. Enough to read an
/// acknowledgement and the line before it without zooming; anything longer is
/// what `Ctrl-O` and `z` are for.
pub const OUTPUT_ROWS: u16 = 4;

/// What is full-screened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zoom {
    /// One pane, RFC 8 §2.
    One(Pane),
    /// The output pane and the command line together — see
    /// [`Ui::toggle_console`].
    Console,
}

/// The three panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pane {
    /// Messages, or channels. 40% of width, on the left.
    List,
    /// The message body. 60%, on the right.
    ///
    /// No longer "or long command output": operator evidence and decrypted
    /// plaintext in one pane means reading `peers` destroys the message you
    /// were looking at, and RFC 3 §12 wants a disconnect decision one
    /// keystroke from the evidence for it.
    View,
    /// Command output. Between the body and the command line.
    Output,
    /// Two lines at the bottom, combined input and output.
    Command,
}

impl Pane {
    /// Cycle order for `Tab`.
    pub const CYCLE: [Pane; 4] = [Pane::List, Pane::View, Pane::Output, Pane::Command];

    /// The next pane in the cycle, wrapping.
    pub fn next(self) -> Pane {
        let i = Pane::CYCLE.iter().position(|&p| p == self).unwrap_or(0);
        Pane::CYCLE[(i + 1) % Pane::CYCLE.len()]
    }

    /// The previous pane, wrapping.
    pub fn prev(self) -> Pane {
        let i = Pane::CYCLE.iter().position(|&p| p == self).unwrap_or(0);
        Pane::CYCLE[(i + Pane::CYCLE.len() - 1) % Pane::CYCLE.len()]
    }
}

/// The two tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Sealed, deniably authenticated, private. **The default.**
    Private,
    /// Public, signed, permanent.
    Channels,
}

impl Tab {
    /// Switch.
    pub fn other(self) -> Tab {
        match self {
            Tab::Private => Tab::Channels,
            Tab::Channels => Tab::Private,
        }
    }
}

/// Which level the channels list is showing. RFC 8 §2 requires the client
/// indicate this, because a channel list and a message list rendered
/// identically in the same 40% column is a context ambiguity in the tab where
/// context confusion is most costly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// A list of channels.
    Channels,
    /// A list of messages within one channel.
    Messages,
}

/// What the user is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reading.
    Browse,
    /// Composing. The composer overlays the view pane.
    Compose,
}

/// The security banner shown in the composer, RFC 8 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Banner {
    /// Sealed to one recipient, deniable, expires with its epoch key.
    Private,
    /// **`PUBLIC — SIGNED — PERMANENT`.** RFC 8 §4.1: a mistaken channel post
    /// is the only unrecoverable user error in Krab — signed, non-repudiable,
    /// flooded, archived, and unaffected by epoch erasure because it has no
    /// epoch key.
    PublicSignedPermanent,
}

impl Banner {
    /// The text to render.
    pub fn text(&self) -> &'static str {
        match self {
            Banner::Private => "PRIVATE — SEALED — EXPIRES",
            Banner::PublicSignedPermanent => "PUBLIC — SIGNED — PERMANENT",
        }
    }
}

/// A rectangle in cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// Left edge.
    pub x: u16,
    /// Top edge.
    pub y: u16,
    /// Width.
    pub w: u16,
    /// Height.
    pub h: u16,
}

/// Interface state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ui {
    tab: Tab,
    focus: Pane,
    zoomed: Option<Zoom>,
    mode: Mode,
    level: Level,
}

impl Default for Ui {
    /// RFC 8 §2: **secure messaging is the tab the client opens on**, so that
    /// the safe context is the one reached by inattention.
    fn default() -> Ui {
        Ui {
            tab: Tab::Private,
            // The command pane, because that is where every verb in RFC 8 §5 is
            // typed and a node that has just started has nothing else to do.
            // Starting on the list meant `init` went to a pane that treats
            // letters as chords, so the characters were silently dropped and
            // the interface looked broken.
            focus: Pane::Command,
            zoomed: None,
            mode: Mode::Browse,
            level: Level::Channels,
        }
    }
}

impl Ui {
    /// Current tab.
    pub fn tab(&self) -> Tab {
        self.tab
    }
    /// Focused pane.
    /// Focus the command pane directly.
    ///
    /// The command pane is the one destination worth reaching without cycling
    /// — it is where every verb in RFC 8 §5 is typed.
    #[allow(dead_code)] // used by main.rs's tests
    pub fn focus_command(&mut self) {
        self.focus = Pane::Command;
    }

    pub fn focus(&self) -> Pane {
        self.focus
    }
    /// Zoomed pane, if any.
    pub fn zoomed(&self) -> Option<Zoom> {
        self.zoomed
    }
    /// Current mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }
    /// Which level the channels list shows.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Cycle focus. Bound to `Tab`.
    pub fn cycle_focus(&mut self) {
        self.focus = self.focus.next();
        // Focus follows into the zoom: cycling while zoomed moves the zoom,
        // rather than focusing a pane the user cannot see.
        if matches!(self.zoomed, Some(Zoom::One(_))) {
            self.zoomed = Some(Zoom::One(self.focus));
        }
    }

    /// Cycle focus backwards. Bound to `Shift-Tab`.
    pub fn cycle_focus_back(&mut self) {
        self.focus = self.focus.prev();
        if matches!(self.zoomed, Some(Zoom::One(_))) {
            self.zoomed = Some(Zoom::One(self.focus));
        }
    }

    /// Toggle full-screen on the focused pane.
    ///
    /// RFC 8 §2: *any* pane may be zoomed, including the command pane — which
    /// §3 relies on, since `peers`, `reach` and `keys` all exceed two lines.
    pub fn toggle_zoom(&mut self) {
        self.zoomed = match self.zoomed {
            Some(_) => None,
            None => Some(Zoom::One(self.focus)),
        };
    }

    /// Full-screen whatever has focus — `Ctrl-O`.
    ///
    /// The command line and the output pane full-screen **as a pair**, because
    /// separately neither is usable: a zoomed output pane has no prompt to
    /// type the next verb into, and a zoomed command line is a prompt whose
    /// own output is somewhere off-screen. Every other pane full-screens
    /// alone. Composing full-screens the composer, since that is what occupies
    /// the view pane while it is running.
    pub fn toggle_full_screen(&mut self) {
        let want = match self.focus {
            Pane::Command | Pane::Output => Zoom::Console,
            p => Zoom::One(p),
        };
        self.zoomed = if self.zoomed == Some(want) {
            None
        } else {
            Some(want)
        };
    }

    /// Back to the default screen — `Esc`.
    ///
    /// This subsumes what used to be a separate `ascend`: leaving a channel's
    /// message list is one of the things going back to the default screen
    /// does, and two keystrokes that differ only in how far back they go is
    /// two things for an operator to remember under pressure.
    ///
    /// One keystroke, not a stack to unwind: an operator who has zoomed a pane
    /// while composing should not have to remember how many things are open.
    /// The caller zeroizes the draft; this only decides what is on screen.
    pub fn reset(&mut self) {
        self.zoomed = None;
        self.mode = Mode::Browse;
        self.level = Level::Channels;
        self.focus = Pane::Command;
    }

    /// Switch tabs.
    pub fn switch_tab(&mut self) {
        self.select_tab(self.tab.other());
    }

    /// Go to a named tab. Idempotent, which is the point: `Ctrl-1` twice
    /// leaves you on Private, where `m` twice leaves you where you started
    /// without ever telling you where that was.
    pub fn select_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.level = Level::Channels;
    }

    /// Descend into a channel, or back out. RFC 8 §2's two-level list.
    pub fn descend(&mut self) {
        if self.tab == Tab::Channels {
            self.level = Level::Messages;
        }
    }

    /// Begin composing.
    pub fn compose(&mut self) {
        self.mode = Mode::Compose;
    }

    /// Stop composing.
    pub fn end_compose(&mut self) {
        self.mode = Mode::Browse;
    }

    /// The security banner to render, or `None` when not composing.
    ///
    /// **Zoom is not an input.** RFC 8 §2.1 forbids suppressing the banner to
    /// reclaim space; here there is no expression for doing so.
    pub fn banner(&self) -> Option<Banner> {
        match self.mode {
            Mode::Browse => None,
            Mode::Compose => Some(match self.tab {
                Tab::Private => Banner::Private,
                Tab::Channels => Banner::PublicSignedPermanent,
            }),
        }
    }

    /// Lay the panes out. RFC 8 §2's 40/60 split and two-line command pane.
    ///
    /// A zoomed pane takes the whole area and the others are absent.
    pub fn layout(&self, area: Rect) -> Vec<(Pane, Rect)> {
        let cmd_h = COMMAND_ROWS.min(area.h);
        match self.zoomed {
            Some(Zoom::One(z)) => return vec![(z, area)],
            Some(Zoom::Console) => {
                return vec![
                    (
                        Pane::Output,
                        Rect {
                            x: area.x,
                            y: area.y,
                            w: area.w,
                            h: area.h.saturating_sub(cmd_h),
                        },
                    ),
                    (
                        Pane::Command,
                        Rect {
                            x: area.x,
                            y: area.y + area.h.saturating_sub(cmd_h),
                            w: area.w,
                            h: cmd_h,
                        },
                    ),
                ]
            }
            None => {}
        }
        // RFC 8 §3's two lines are two lines *of content*. The pane draws a
        // top rule to separate it from the body, so it needs three rows —
        // allocating two gave a bordered box with zero usable rows inside, and
        // the command line had nowhere to render at all.
        //
        // The output pane sits directly above it, at a fixed height: a body
        // pane that changes size when output arrives is a body pane that
        // moves the line you were reading.
        let rest = area.h.saturating_sub(cmd_h);
        let out_h = OUTPUT_ROWS.min(rest);
        let body_h = rest.saturating_sub(out_h);
        let list_w = (area.w as u32 * 40 / 100) as u16;
        let view_w = area.w.saturating_sub(list_w);
        vec![
            (
                Pane::List,
                Rect {
                    x: area.x,
                    y: area.y,
                    w: list_w,
                    h: body_h,
                },
            ),
            (
                Pane::View,
                Rect {
                    x: area.x + list_w,
                    y: area.y,
                    w: view_w,
                    h: body_h,
                },
            ),
            (
                Pane::Output,
                Rect {
                    x: area.x,
                    y: area.y + body_h,
                    w: area.w,
                    h: out_h,
                },
            ),
            (
                Pane::Command,
                Rect {
                    x: area.x,
                    y: area.y + body_h + out_h,
                    w: area.w,
                    h: cmd_h,
                },
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCREEN: Rect = Rect {
        x: 0,
        y: 0,
        w: 100,
        h: 40,
    };

    /// RFC 8 §2 — the safe context is the one reached by inattention.
    #[test]
    fn the_client_opens_on_private_messages() {
        assert_eq!(Ui::default().tab(), Tab::Private);
        assert_eq!(Ui::default().mode(), Mode::Browse);
        assert_eq!(Ui::default().zoomed(), None);
    }

    /// Tab cycles through every pane and wraps.
    #[test]
    fn tab_cycles_focus_through_all_panes() {
        let mut ui = Ui::default();
        let mut seen = vec![ui.focus()];
        for _ in 0..3 {
            ui.cycle_focus();
            seen.push(ui.focus());
        }
        // Starting on Command, because that is where a fresh node's first verb
        // is typed. The cycle order itself is unchanged.
        assert_eq!(
            seen,
            vec![Pane::Command, Pane::List, Pane::View, Pane::Output]
        );

        ui.cycle_focus();
        assert_eq!(ui.focus(), Pane::Command, "wraps");

        // And backwards.
        ui.cycle_focus_back();
        assert_eq!(ui.focus(), Pane::Output);
    }

    /// RFC 8 §2 — *any* pane may be zoomed to full screen.
    #[test]
    fn any_pane_can_be_zoomed_full_screen() {
        for target in Pane::CYCLE {
            let mut ui = Ui::default();
            while ui.focus() != target {
                ui.cycle_focus();
            }
            ui.toggle_zoom();
            assert_eq!(ui.zoomed(), Some(Zoom::One(target)));

            let panes = ui.layout(SCREEN);
            assert_eq!(panes.len(), 1, "zoomed pane is alone");
            assert_eq!(panes[0], (target, SCREEN), "and takes the whole screen");

            ui.toggle_zoom();
            assert_eq!(ui.zoomed(), None);
            assert_eq!(ui.layout(SCREEN).len(), Pane::CYCLE.len());
        }
    }

    /// Cycling while zoomed moves the zoom, rather than focusing a pane the
    /// user cannot see.
    #[test]
    fn focus_follows_into_the_zoom() {
        let mut ui = Ui::default();
        ui.toggle_zoom();
        assert_eq!(
            ui.zoomed(),
            Some(Zoom::One(Pane::Command)),
            "zoom follows focus"
        );
        ui.cycle_focus();
        assert_eq!(ui.focus(), Pane::List, "Command cycles round to List");
        assert_eq!(
            ui.zoomed(),
            Some(Zoom::One(Pane::List)),
            "the zoom moved with the focus"
        );
    }

    /// RFC 8 §2's 40/60 split and the command pane's rows.
    #[test]
    fn layout_matches_the_specified_proportions() {
        let panes = Ui::default().layout(SCREEN);
        let list = panes.iter().find(|(p, _)| *p == Pane::List).unwrap().1;
        let view = panes.iter().find(|(p, _)| *p == Pane::View).unwrap().1;
        let cmd = panes.iter().find(|(p, _)| *p == Pane::Command).unwrap().1;

        assert_eq!(list.w, 40, "list pane is 40% of width");
        assert_eq!(view.w, 60, "view pane is 60%");
        assert_eq!(
            cmd.h, COMMAND_ROWS,
            "the command pane needs RFC 8 §3's two content lines plus its rule"
        );
        let out = panes.iter().find(|(p, _)| *p == Pane::Output).unwrap().1;
        assert_eq!(out.h, OUTPUT_ROWS, "four rows above the command pane");
        assert_eq!(out.w, SCREEN.w, "spanning the width");
        assert_eq!(list.h + out.h + cmd.h, SCREEN.h, "and they tile the screen");
        assert_eq!(list.y + list.h, out.y, "output sits under the body");
        assert_eq!(out.y + out.h, cmd.y, "and directly above the command line");
        assert_eq!(list.x + list.w, view.x, "no gap between them");
    }

    /// **RFC 8 §2.1's invariant.** The banner is a function of mode and tab;
    /// zoom is not an input, so suppressing it to reclaim space has no
    /// expression. This is the test that fails if someone adds one.
    #[test]
    fn the_composer_banner_survives_every_zoom_and_pane_combination() {
        for tab in [Tab::Private, Tab::Channels] {
            for zoom_target in [
                None,
                Some(Pane::List),
                Some(Pane::View),
                Some(Pane::Output),
                Some(Pane::Command),
            ] {
                let mut ui = Ui::default();
                if tab == Tab::Channels {
                    ui.switch_tab();
                }
                if let Some(t) = zoom_target {
                    while ui.focus() != t {
                        ui.cycle_focus();
                    }
                    ui.toggle_zoom();
                }
                ui.compose();

                let banner = ui.banner().expect("composing always shows a banner");
                match tab {
                    Tab::Private => assert_eq!(banner, Banner::Private),
                    Tab::Channels => {
                        assert_eq!(banner, Banner::PublicSignedPermanent);
                        assert_eq!(banner.text(), "PUBLIC — SIGNED — PERMANENT");
                    }
                }
            }
        }
    }

    #[test]
    fn no_banner_when_not_composing() {
        let mut ui = Ui::default();
        assert_eq!(ui.banner(), None);
        ui.compose();
        assert!(ui.banner().is_some());
        ui.end_compose();
        assert_eq!(ui.banner(), None);
    }

    /// RFC 8 §2 — the channels list is two-level and the level must be
    /// indicated, because two identically-rendered lists in the same column is
    /// a context ambiguity in the tab where confusion is most costly.
    #[test]
    fn the_channels_list_is_two_level_and_the_level_is_observable() {
        let mut ui = Ui::default();
        // Private messages are a flat list; descending does nothing.
        ui.descend();
        assert_eq!(ui.level(), Level::Channels);

        ui.switch_tab();
        assert_eq!(ui.tab(), Tab::Channels);
        assert_eq!(ui.level(), Level::Channels);
        ui.descend();
        assert_eq!(ui.level(), Level::Messages, "inside a channel");
        // Esc is the way back out, and it goes all the way rather than one
        // level: see `reset`.
        ui.reset();
        assert_eq!(ui.level(), Level::Channels);
        ui.select_tab(Tab::Channels);

        // Switching tabs resets the level, so returning never lands somewhere
        // the user did not choose.
        ui.descend();
        ui.switch_tab();
        ui.switch_tab();
        assert_eq!(ui.level(), Level::Channels);
    }

    #[test]
    fn layout_survives_a_tiny_terminal() {
        for (w, h) in [(1u16, 1u16), (2, 2), (10, 3), (0, 0)] {
            let ui = Ui::default();
            let panes = ui.layout(Rect { x: 0, y: 0, w, h });
            // Never panics, never produces a pane wider than the screen.
            for (_, r) in panes {
                assert!(r.w <= w && r.h <= h);
            }
        }
    }
}
