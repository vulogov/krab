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

/// The three panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pane {
    /// Messages, or channels. 40% of width, on the left.
    List,
    /// The message body, or long command output. 60%, on the right.
    View,
    /// Two lines at the bottom, combined input and output.
    Command,
}

impl Pane {
    /// Cycle order for `Tab`.
    pub const CYCLE: [Pane; 3] = [Pane::List, Pane::View, Pane::Command];

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
    zoomed: Option<Pane>,
    mode: Mode,
    level: Level,
}

impl Default for Ui {
    /// RFC 8 §2: **secure messaging is the tab the client opens on**, so that
    /// the safe context is the one reached by inattention.
    fn default() -> Ui {
        Ui {
            tab: Tab::Private,
            focus: Pane::List,
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
    pub fn zoomed(&self) -> Option<Pane> {
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
        if self.zoomed.is_some() {
            self.zoomed = Some(self.focus);
        }
    }

    /// Cycle focus backwards. Bound to `Shift-Tab`.
    pub fn cycle_focus_back(&mut self) {
        self.focus = self.focus.prev();
        if self.zoomed.is_some() {
            self.zoomed = Some(self.focus);
        }
    }

    /// Toggle full-screen on the focused pane.
    ///
    /// RFC 8 §2: *any* pane may be zoomed, including the command pane — which
    /// §3 relies on, since `peers`, `reach` and `keys` all exceed two lines.
    pub fn toggle_zoom(&mut self) {
        self.zoomed = match self.zoomed {
            Some(_) => None,
            None => Some(self.focus),
        };
    }

    /// Switch tabs.
    pub fn switch_tab(&mut self) {
        self.tab = self.tab.other();
        self.level = Level::Channels;
    }

    /// Descend into a channel, or back out. RFC 8 §2's two-level list.
    pub fn descend(&mut self) {
        if self.tab == Tab::Channels {
            self.level = Level::Messages;
        }
    }

    /// Leave the channel's message list.
    pub fn ascend(&mut self) {
        if self.tab == Tab::Channels {
            self.level = Level::Channels;
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
        if let Some(z) = self.zoomed {
            return vec![(z, area)];
        }
        let cmd_h = 2.min(area.h);
        let body_h = area.h.saturating_sub(cmd_h);
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
                Pane::Command,
                Rect {
                    x: area.x,
                    y: area.y + body_h,
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
        for _ in 0..2 {
            ui.cycle_focus();
            seen.push(ui.focus());
        }
        assert_eq!(seen, vec![Pane::List, Pane::View, Pane::Command]);

        ui.cycle_focus();
        assert_eq!(ui.focus(), Pane::List, "wraps");

        // And backwards.
        ui.cycle_focus_back();
        assert_eq!(ui.focus(), Pane::Command);
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
            assert_eq!(ui.zoomed(), Some(target));

            let panes = ui.layout(SCREEN);
            assert_eq!(panes.len(), 1, "zoomed pane is alone");
            assert_eq!(panes[0], (target, SCREEN), "and takes the whole screen");

            ui.toggle_zoom();
            assert_eq!(ui.zoomed(), None);
            assert_eq!(ui.layout(SCREEN).len(), 3);
        }
    }

    /// Cycling while zoomed moves the zoom, rather than focusing a pane the
    /// user cannot see.
    #[test]
    fn focus_follows_into_the_zoom() {
        let mut ui = Ui::default();
        ui.toggle_zoom();
        assert_eq!(ui.zoomed(), Some(Pane::List));
        ui.cycle_focus();
        assert_eq!(ui.focus(), Pane::View);
        assert_eq!(
            ui.zoomed(),
            Some(Pane::View),
            "the zoom moved with the focus"
        );
    }

    /// RFC 8 §2's 40/60 split and two-line command pane.
    #[test]
    fn layout_matches_the_specified_proportions() {
        let panes = Ui::default().layout(SCREEN);
        let list = panes.iter().find(|(p, _)| *p == Pane::List).unwrap().1;
        let view = panes.iter().find(|(p, _)| *p == Pane::View).unwrap().1;
        let cmd = panes.iter().find(|(p, _)| *p == Pane::Command).unwrap().1;

        assert_eq!(list.w, 40, "list pane is 40% of width");
        assert_eq!(view.w, 60, "view pane is 60%");
        assert_eq!(cmd.h, 2, "command pane is two lines");
        assert_eq!(list.h + cmd.h, SCREEN.h, "and they tile the screen");
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
        ui.ascend();
        assert_eq!(ui.level(), Level::Channels);

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
