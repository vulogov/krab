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
    /// Alt/Option. Only the panic chord uses it, which is why it is here at
    /// all: three modifiers is a chord an operator might reach by accident on
    /// some layout, and four is not.
    pub alt: bool,
    /// The character, or a named key.
    pub code: Key,
    /// Whether Ctrl was held.
    pub ctrl: bool,
    /// Whether Shift was held.
    pub shift: bool,
}

impl KeyPress {
    // Constructors used by this module's tests. `main.rs` builds a `KeyPress`
    // from a crossterm event directly, because `BackTab` needs to set both the
    // code and the shift flag and these would obscure that.
    /// A plain character.
    #[allow(dead_code)]
    pub fn char(c: char) -> KeyPress {
        KeyPress {
            code: Key::Char(c),
            ctrl: false,
            alt: false,
            shift: false,
        }
    }
    /// A character with Ctrl.
    #[allow(dead_code)]
    pub fn ctrl(c: char) -> KeyPress {
        KeyPress {
            code: Key::Char(c),
            ctrl: true,
            alt: false,
            shift: false,
        }
    }
    /// A named key.
    #[allow(dead_code)]
    pub fn key(k: Key) -> KeyPress {
        KeyPress {
            code: k,
            ctrl: false,
            alt: false,
            shift: false,
        }
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
    /// Delete backwards. Its absence is why a typo could not be corrected.
    Backspace,
    /// Delete forwards.
    Delete,
    Left,
    Right,
    Home,
    End,
    Up,
    Down,
    PageUp,
    PageDown,
    /// A function key, `F(1)`..`F(12)`.
    F(u8),
}

/// What a key press means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Binding {
    /// **Leave.** `Ctrl-Q`, reachable from every mode.
    Quit,
    /// **Lock immediately.** Reachable from every mode.
    Lock,
    /// **Destroy the key hierarchy.** `Ctrl-Alt-Shift-W`, twice.
    ///
    /// RFC 7 §10's wipe without the typing. The `wipe` verb asks for
    /// confirmation and that is right for a deliberate decision; it is wrong
    /// when the operator has seconds. `duress` covers being watched. This
    /// covers not having time.
    PanicWipe,
    /// Redraw. Displaced from `Ctrl-L`.
    Redraw,
    /// Cycle pane focus forwards.
    CycleFocus,
    /// Cycle pane focus backwards.
    CycleFocusBack,
    /// Toggle full-screen on the focused pane.
    ToggleZoom,
    /// Full-screen the focused pane — `Ctrl-O`. The command line and output
    /// pane go full-screen together.
    ToggleFullScreen,
    /// Switch between the private and channels tabs.
    SwitchTab,
    /// Select a tab outright, rather than toggling.
    SelectTab(crate::layout::Tab),
    /// Decrypt into the view, or descend a level.
    Activate,
    /// **Back to the default screen** — `Esc`. Not one level of a stack:
    /// see [`crate::layout::Ui::reset`].
    Cancel,
    /// Begin composing.
    Compose,
    /// Reply — **always privately**, per RFC 8 §4.2 requirement 3.
    Reply,
    /// Publish to a channel. A separate keystroke from [`Binding::Reply`].
    Publish,
    /// A character typed into the composer or the command line.
    Input(char),
    /// An edit to the line being typed. See [`crate::line::Line`].
    Edit(Edit),
    /// Walk the command history. Newer is `+1`.
    History(i8),
    /// Scroll the output pane. **`+1` is further back**, toward older
    /// output — the direction PgUp moves, not the direction the eye moves.
    Scroll(i8),
    /// Nothing.
    Ignored,
}

/// A one-line editing operation.
///
/// Separate from [`Binding`] so that the command line and the composer can be
/// given the same editing vocabulary without the pane deciding what `Ctrl-W`
/// means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit {
    Backspace,
    Delete,
    Left,
    Right,
    WordLeft,
    WordRight,
    Home,
    End,
    /// `Ctrl-W`.
    KillWord,
    /// `Ctrl-U`.
    KillToStart,
    /// `Ctrl-K`.
    KillToEnd,
}

impl Binding {
    /// Resolve a key press in a mode.
    pub fn of(key: KeyPress, mode: Mode) -> Binding {
        // The panic chord, before everything — including lock, since locking
        // is recoverable and this is not, and an operator reaching for it has
        // already decided. Four modifiers so it cannot be struck by accident;
        // the caller requires it twice, so a single misfire destroys nothing.
        if key.ctrl && key.alt && key.shift && key.code == Key::Char('W') {
            return Binding::PanicWipe;
        }
        // Lock first, unconditionally. Every other branch is below this line,
        // so no mode can shadow it and no future mode can either.
        if key.ctrl && key.code == Key::Char('l') {
            return Binding::Lock;
        }
        // And quit, for the same reason. There was previously no way to leave
        // at all: `q` resolved to `Ignored` in browse mode, and the branch that
        // set `quit` could only be reached while typing on the command line,
        // where the character went into the command instead. An interface with
        // no exit is not a small defect — an operator who cannot leave cannot
        // stop the node.
        if key.ctrl && key.code == Key::Char('q') {
            return Binding::Quit;
        }
        // Tabs, likewise before any mode. `m` toggles them, but only in browse
        // mode — and focus starts on the command line, where `m` is a letter.
        // A security context this consequential (RFC 8 §4.1: a channel post is
        // irreversible) needs a way to be *selected*, not toggled: an operator
        // who cannot tell which tab they are on cannot toggle their way to
        // certainty, and guessing wrong publishes.
        if key.ctrl && key.code == Key::Char('o') {
            return Binding::ToggleFullScreen;
        }
        // **Ctrl-M for Messages, Ctrl-G for Groups.** Letters, so they have a
        // control encoding every terminal sends. `Ctrl-1` does not: the
        // control range is built from `@` through `_`, and a digit is not in
        // it, so the keystroke arrives as a bare `1` or as nothing at all.
        // F1/F2 and Ctrl-1/Ctrl-2 stay for the terminals that do send them.
        match key.code {
            Key::F(1) => return Binding::SelectTab(crate::layout::Tab::Private),
            Key::F(2) => return Binding::SelectTab(crate::layout::Tab::Channels),
            Key::Char('m' | 'M' | '1') if key.ctrl || key.alt => {
                return Binding::SelectTab(crate::layout::Tab::Private)
            }
            // `Ctrl-T` for channels. Not `Ctrl-G`: Google's terminal apps
            // take it, emacs uses it for abort, and a chord an operator's
            // environment intercepts is a chord that does not exist. Several
            // alternatives are accepted for the same reason — every one of
            // them is stolen by something, somewhere.
            Key::Char('t' | 'T' | 'g' | 'G' | 'c' | 'C' | '2') if key.ctrl || key.alt => {
                return Binding::SelectTab(crate::layout::Tab::Channels)
            }
            _ => {}
        }

        // History and scrolling, before mode, for the same reason as editing:
        // an operator recalling their last command or looking further up the
        // output is doing the same thing whatever pane has focus.
        match key.code {
            Key::Up => return Binding::History(-1),
            Key::Down => return Binding::History(1),
            Key::PageUp => return Binding::Scroll(1),
            Key::PageDown => return Binding::Scroll(-1),
            _ => {}
        }

        // Editing, before mode. A line being typed is a line being typed, and
        // there is no mode in which `Backspace` should mean something else.
        let edit = match key.code {
            Key::Backspace => Some(Edit::Backspace),
            Key::Delete => Some(Edit::Delete),
            Key::Home => Some(Edit::Home),
            Key::End => Some(Edit::End),
            Key::Left if key.ctrl => Some(Edit::WordLeft),
            Key::Right if key.ctrl => Some(Edit::WordRight),
            Key::Left => Some(Edit::Left),
            Key::Right => Some(Edit::Right),
            Key::Char('w') if key.ctrl => Some(Edit::KillWord),
            Key::Char('u') if key.ctrl => Some(Edit::KillToStart),
            Key::Char('k') if key.ctrl => Some(Edit::KillToEnd),
            Key::Char('a') if key.ctrl => Some(Edit::Home),
            Key::Char('e') if key.ctrl => Some(Edit::End),
            _ => None,
        };
        if let Some(e) = edit {
            return Binding::Edit(e);
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
            assert_eq!(
                Binding::of(KeyPress::ctrl('l'), mode),
                Binding::Lock,
                "{mode:?}"
            );
        }
    }

    /// It must survive a composer that is swallowing every other character.
    #[test]
    fn lock_is_not_swallowed_by_the_composer() {
        // Ordinary characters become input.
        assert_eq!(
            Binding::of(KeyPress::char('l'), Mode::Compose),
            Binding::Input('l')
        );
        // The chord does not.
        assert_eq!(
            Binding::of(KeyPress::ctrl('l'), Mode::Compose),
            Binding::Lock
        );
    }

    /// One motion, no confirmation. Lock is used when someone walks in.
    #[test]
    fn lock_is_a_single_press_not_a_sequence() {
        // There is no intermediate state: one press resolves to Lock outright.
        assert_eq!(
            Binding::of(KeyPress::ctrl('l'), Mode::Browse),
            Binding::Lock
        );
    }

    /// `Ctrl-L` conventionally redraws, so redraw is displaced rather than
    /// shared -- a binding that sometimes locks and sometimes redraws would be
    /// worse than either.
    #[test]
    fn redraw_moved_off_the_lock_chord() {
        assert_eq!(
            Binding::of(KeyPress::ctrl('r'), Mode::Browse),
            Binding::Redraw
        );
        assert_eq!(
            Binding::of(KeyPress::ctrl('r'), Mode::Compose),
            Binding::Redraw
        );
    }

    /// Tab cycles panes in both modes, so the user can reach the peers panel
    /// mid-composition without losing the draft.
    #[test]
    fn tab_cycles_panes_even_while_composing() {
        for mode in [Mode::Browse, Mode::Compose] {
            assert_eq!(
                Binding::of(KeyPress::key(Key::Tab), mode),
                Binding::CycleFocus
            );
            let shift_tab = KeyPress {
                code: Key::Tab,
                ctrl: false,
                alt: false,
                shift: true,
            };
            assert_eq!(Binding::of(shift_tab, mode), Binding::CycleFocusBack);
        }
    }

    /// RFC 8 §4.2 requirement 3 — **pressing reply must never publish.**
    #[test]
    fn reply_and_publish_are_different_keys() {
        assert_eq!(
            Binding::of(KeyPress::char('r'), Mode::Browse),
            Binding::Reply
        );
        assert_eq!(
            Binding::of(KeyPress::char('P'), Mode::Browse),
            Binding::Publish
        );
        assert_ne!(Binding::Reply, Binding::Publish);
    }

    #[test]
    fn zoom_is_bound_and_composition_does_not_steal_it() {
        assert_eq!(
            Binding::of(KeyPress::char('z'), Mode::Browse),
            Binding::ToggleZoom
        );
        // While composing, `z` is a character the user is typing.
        assert_eq!(
            Binding::of(KeyPress::char('z'), Mode::Compose),
            Binding::Input('z')
        );
    }

    /// No key press may panic or be silently reinterpreted.
    #[test]
    fn every_key_resolves_in_every_mode() {
        for mode in [Mode::Browse, Mode::Compose] {
            for ctrl in [false, true] {
                for c in ' '..='~' {
                    let k = KeyPress {
                        code: Key::Char(c),
                        ctrl,
                        alt: false,
                        shift: false,
                    };
                    let b = Binding::of(k, mode);
                    if ctrl && c == 'l' {
                        assert_eq!(b, Binding::Lock, "lock must win everywhere");
                    }
                }
            }
        }
    }

    /// **Tabs must be reachable from the command line.** `m` toggles them,
    /// but only in browse mode, and focus starts on the command line where
    /// `m` is a letter — so on a fresh node there was no way to see channels
    /// at all without first knowing to press Tab.
    #[test]
    fn the_tab_chords_resolve_before_any_mode() {
        use crate::layout::Tab;
        for mode in [Mode::Browse, Mode::Compose] {
            for (c, tab) in [('1', Tab::Private), ('2', Tab::Channels)] {
                let press = KeyPress {
                    code: Key::Char(c),
                    ctrl: true,
                    alt: false,
                    shift: false,
                };
                assert_eq!(Binding::of(press, mode), Binding::SelectTab(tab));
                // Without the modifier they are digits, so a channel named
                // `1` can still be typed.
                assert_eq!(
                    Binding::of(KeyPress::key(Key::Char(c)), mode),
                    if mode == Mode::Browse {
                        Binding::Ignored
                    } else {
                        Binding::Input(c)
                    }
                );
            }
        }
    }
}
