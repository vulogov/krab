//! Key bindings, and the lock chord.
//!
//! # Lock is dispatched before anything else
//!
//! [`Binding::of`] resolves `Ctrl-L` **first**, before the mode is consulted.
//! Lock is used when someone walks into the room, so it must work while
//! composing, while zoomed, mid-command, and while a confirmation prompt is up
//! — every state in which a mode-aware dispatcher would have swallowed it.
//!
//! No confirmation, and no two-key chord. RFC 7 §10 makes panic wipe "the
//! control that matters at the moment of seizure", and lock is its lesser
//! sibling; a dialogue at that moment is the wrong shape. The cost is a lost
//! draft, which `RFC-8-review.md` §8.6 records as the one open question in the
//! lock design and which is not solved by adding a keystroke.
//!
//! `Ctrl-L` conventionally redraws a terminal, so redraw moves to `Ctrl-R`.

use crate::layout::Mode;

/// A key press, as crossterm reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPress {
    /// The character, or a named key.
    pub code: Key,
    /// Whether Ctrl was held.
    pub ctrl: bool,
    /// Whether Shift was held.
    pub shift: bool,
}

impl KeyPress {
    /// A plain character.
    pub fn char(c: char) -> KeyPress {
        KeyPress { code: Key::Char(c), ctrl: false, shift: false }
    }
    /// A character with Ctrl.
    pub fn ctrl(c: char) -> KeyPress {
        KeyPress { code: Key::Char(c), ctrl: true, shift: false }
    }
    /// A named key.
    pub fn key(k: Key) -> KeyPress {
        KeyPress { code: k, ctrl: false, shift: false }
    }
}

/// Keys the interface distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character.
    Char(char),
    /// Cycle focus.
    Tab,
    /// Confirm, descend, or decrypt.
    Enter,
    /// Leave, ascend, or cancel.
    Esc,
}

/// What a key press means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Binding {
    /// **Lock immediately.** Reachable from every mode.
    Lock,
    /// Redraw. Displaced from `Ctrl-L`.
    Redraw,
    /// Cycle pane focus forwards.
    CycleFocus,
    /// Cycle pane focus backwards.
    CycleFocusBack,
    /// Toggle full-screen on the focused pane.
    ToggleZoom,
    /// Switch between the private and channels tabs.
    SwitchTab,
    /// Decrypt into the view, or descend a level.
    Activate,
    /// Leave, ascend, or cancel a composition.
    Cancel,
    /// Begin composing.
    Compose,
    /// Reply — **always privately**, per RFC 8 §4.2 requirement 3.
    Reply,
    /// Publish to a channel. A separate keystroke from [`Binding::Reply`].
    Publish,
    /// A character typed into the composer or the command line.
    Input(char),
    /// Nothing.
    Ignored,
}

impl Binding {
    /// Resolve a key press in a mode.
    pub fn of(key: KeyPress, mode: Mode) -> Binding {
        // Lock first, unconditionally. Every other branch is below this line,
        // so no mode can shadow it and no future mode can either.
        if key.ctrl && key.code == Key::Char('l') {
            return Binding::Lock;
        }

        match mode {
            Mode::Compose => match key.code {
                // Tab still cycles panes rather than inserting a tab
                // character: the user needs to reach the peers panel to check
                // who they are about to talk to without losing the draft.
                Key::Tab if key.shift => Binding::CycleFocusBack,
                Key::Tab => Binding::CycleFocus,
                Key::Esc => Binding::Cancel,
                // Enter means "commit what is being entered", and what that
                // commits depends on where the text is going: a newline in a
                // composer, a submitted verb on the command line. The caller
                // knows which pane has focus; this layer does not.
                Key::Enter => Binding::Activate,
                Key::Char('r') if key.ctrl => Binding::Redraw,
                Key::Char(c) if !key.ctrl => Binding::Input(c),
                _ => Binding::Ignored,
            },
            Mode::Browse => match key.code {
                Key::Tab if key.shift => Binding::CycleFocusBack,
                Key::Tab => Binding::CycleFocus,
                Key::Enter => Binding::Activate,
                Key::Esc => Binding::Cancel,
                Key::Char('r') if key.ctrl => Binding::Redraw,
                Key::Char('z') if !key.ctrl => Binding::ToggleZoom,
                Key::Char('\t') => Binding::CycleFocus,
                Key::Char('c') if !key.ctrl => Binding::Compose,
                // RFC 8 §4.2 requirement 3: reply defaults to a private sealed
                // message to the author, and publish is a separate keystroke.
                Key::Char('r') if !key.ctrl => Binding::Reply,
                Key::Char('P') => Binding::Publish,
                Key::Char('m') if !key.ctrl => Binding::SwitchTab,
                _ => Binding::Ignored,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The lock chord reaches through every mode.** This is the test that
    /// fails if someone puts lock inside a mode branch.
    #[test]
    fn lock_is_reachable_from_every_mode() {
        for mode in [Mode::Browse, Mode::Compose] {
            assert_eq!(Binding::of(KeyPress::ctrl('l'), mode), Binding::Lock, "{mode:?}");
        }
    }

    /// It must survive a composer that is swallowing every other character.
    #[test]
    fn lock_is_not_swallowed_by_the_composer() {
        // Ordinary characters become input.
        assert_eq!(Binding::of(KeyPress::char('l'), Mode::Compose), Binding::Input('l'));
        // The chord does not.
        assert_eq!(Binding::of(KeyPress::ctrl('l'), Mode::Compose), Binding::Lock);
    }

    /// One motion, no confirmation. Lock is used when someone walks in.
    #[test]
    fn lock_is_a_single_press_not_a_sequence() {
        // There is no intermediate state: one press resolves to Lock outright.
        assert_eq!(Binding::of(KeyPress::ctrl('l'), Mode::Browse), Binding::Lock);
    }

    /// `Ctrl-L` conventionally redraws, so redraw is displaced rather than
    /// shared -- a binding that sometimes locks and sometimes redraws would be
    /// worse than either.
    #[test]
    fn redraw_moved_off_the_lock_chord() {
        assert_eq!(Binding::of(KeyPress::ctrl('r'), Mode::Browse), Binding::Redraw);
        assert_eq!(Binding::of(KeyPress::ctrl('r'), Mode::Compose), Binding::Redraw);
    }

    /// Tab cycles panes in both modes, so the user can reach the peers panel
    /// mid-composition without losing the draft.
    #[test]
    fn tab_cycles_panes_even_while_composing() {
        for mode in [Mode::Browse, Mode::Compose] {
            assert_eq!(Binding::of(KeyPress::key(Key::Tab), mode), Binding::CycleFocus);
            let shift_tab = KeyPress { code: Key::Tab, ctrl: false, shift: true };
            assert_eq!(Binding::of(shift_tab, mode), Binding::CycleFocusBack);
        }
    }

    /// RFC 8 §4.2 requirement 3 — **pressing reply must never publish.**
    #[test]
    fn reply_and_publish_are_different_keys() {
        assert_eq!(Binding::of(KeyPress::char('r'), Mode::Browse), Binding::Reply);
        assert_eq!(Binding::of(KeyPress::char('P'), Mode::Browse), Binding::Publish);
        assert_ne!(Binding::Reply, Binding::Publish);
    }

    #[test]
    fn zoom_is_bound_and_composition_does_not_steal_it() {
        assert_eq!(Binding::of(KeyPress::char('z'), Mode::Browse), Binding::ToggleZoom);
        // While composing, `z` is a character the user is typing.
        assert_eq!(Binding::of(KeyPress::char('z'), Mode::Compose), Binding::Input('z'));
    }

    /// No key press may panic or be silently reinterpreted.
    #[test]
    fn every_key_resolves_in_every_mode() {
        for mode in [Mode::Browse, Mode::Compose] {
            for ctrl in [false, true] {
                for c in ' '..='~' {
                    let k = KeyPress { code: Key::Char(c), ctrl, shift: false };
                    let b = Binding::of(k, mode);
                    if ctrl && c == 'l' {
                        assert_eq!(b, Binding::Lock, "lock must win everywhere");
                    }
                }
            }
        }
    }
}
