//! A one-line editor, for the command pane and the passphrase prompt.
//!
//! There was none. `Key` mapped `Tab`, `Enter`, `Esc` and `Char` and nothing
//! else — no `Backspace`, no arrows — so a mistyped verb could not be
//! corrected and a mistyped passphrase could only be abandoned. That is worse
//! than inconvenient at the passphrase step: the KEK is the only root (RFC 7
//! §4), the passphrase is masked, and an operator who cannot see what they
//! typed and cannot fix it either will produce a store they cannot open.
//!
//! # Why the cursor is a character index
//!
//! Byte indices into a `String` invite a panic on any multi-byte character,
//! and a passphrase is exactly where someone reaches for one. The cost is a
//! `Vec<char>` rather than a `String`; a command line is short enough that
//! nothing about that matters.
//!
//! # Erasure
//!
//! [`Line::take`] and [`Line::clear`] overwrite the buffer before releasing
//! it, the same as [`crate::overwrite`] does for a `String`. The passphrase
//! lives in one of these, and RFC 7 §9 does not want it lingering in a
//! reallocated heap block.

/// An editable line and a cursor position within it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Line {
    chars: Vec<char>,
    /// Character index, `0..=chars.len()`. The upper bound is inclusive: the
    /// cursor sits *after* the last character when appending.
    cursor: usize,
}

impl Line {
    /// The text, as a `String`.
    pub fn as_string(&self) -> String {
        self.chars.iter().collect()
    }

    /// Characters before the cursor — what a renderer needs to place it.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Characters in the line.
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Insert at the cursor and advance past it.
    pub fn insert(&mut self, c: char) {
        self.chars.insert(self.cursor, c);
        self.cursor += 1;
    }

    /// Delete the character before the cursor.
    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }

    /// Delete the character under the cursor.
    pub fn delete(&mut self) {
        if self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        if self.cursor < self.chars.len() {
            self.cursor += 1;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.chars.len();
    }

    /// To the start of the previous word.
    ///
    /// A word is a run of non-space; leading spaces are crossed first, so
    /// pressing this at the end of `connect bob ` lands before `bob` rather
    /// than in the trailing space.
    pub fn word_left(&mut self) {
        while self.cursor > 0 && self.chars[self.cursor - 1].is_whitespace() {
            self.cursor -= 1;
        }
        while self.cursor > 0 && !self.chars[self.cursor - 1].is_whitespace() {
            self.cursor -= 1;
        }
    }

    /// To the start of the next word.
    pub fn word_right(&mut self) {
        let n = self.chars.len();
        while self.cursor < n && !self.chars[self.cursor].is_whitespace() {
            self.cursor += 1;
        }
        while self.cursor < n && self.chars[self.cursor].is_whitespace() {
            self.cursor += 1;
        }
    }

    /// Delete the word before the cursor — `Ctrl-W`.
    pub fn kill_word(&mut self) {
        let to = self.cursor;
        self.word_left();
        self.chars.drain(self.cursor..to);
    }

    /// Delete from the cursor to the start — `Ctrl-U`.
    pub fn kill_to_start(&mut self) {
        self.chars.drain(..self.cursor);
        self.cursor = 0;
    }

    /// Delete from the cursor to the end — `Ctrl-K`.
    pub fn kill_to_end(&mut self) {
        self.chars.truncate(self.cursor);
    }

    /// Empty the line, overwriting what was in it first.
    pub fn clear(&mut self) {
        self.overwrite();
        self.chars.clear();
        self.cursor = 0;
    }

    /// Take the contents, leaving the line empty and the buffer overwritten.
    pub fn take(&mut self) -> String {
        let out = self.as_string();
        self.clear();
        out
    }

    /// Overwrite every character in place.
    ///
    /// The `Vec`'s allocation is reused by `clear`, so this reaches the memory
    /// that actually held the passphrase. It does not reach a block the `Vec`
    /// abandoned during an earlier growth — see `Documentation/SECURE-DELETE.md`
    /// for why that is a bound on this mechanism rather than a defect in it.
    fn overwrite(&mut self) {
        for c in &mut self.chars {
            *c = '\0';
        }
    }
}

impl From<&str> for Line {
    fn from(s: &str) -> Line {
        let chars: Vec<char> = s.chars().collect();
        Line {
            cursor: chars.len(),
            chars,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_and_correcting_a_typo() {
        let mut l = Line::default();
        for c in "inti".chars() {
            l.insert(c);
        }
        // The whole point: a typo at the end can be fixed.
        l.backspace();
        l.backspace();
        l.insert('i');
        l.insert('t');
        assert_eq!(l.as_string(), "init");
    }

    #[test]
    fn the_cursor_moves_and_insertion_follows_it() {
        let mut l = Line::from("connect bob");
        assert_eq!(l.cursor(), 11, "from() puts the cursor at the end");
        l.home();
        for c in "re".chars() {
            l.insert(c);
        }
        assert_eq!(l.as_string(), "reconnect bob");
        l.end();
        l.insert('!');
        assert_eq!(l.as_string(), "reconnect bob!");
    }

    #[test]
    fn delete_takes_the_character_under_the_cursor() {
        let mut l = Line::from("abc");
        l.home();
        l.delete();
        assert_eq!(l.as_string(), "bc");
        // And is a no-op at the end, rather than a panic.
        l.end();
        l.delete();
        assert_eq!(l.as_string(), "bc");
    }

    #[test]
    fn the_cursor_does_not_leave_the_line() {
        let mut l = Line::from("ab");
        for _ in 0..5 {
            l.right();
        }
        assert_eq!(l.cursor(), 2);
        for _ in 0..5 {
            l.left();
        }
        assert_eq!(l.cursor(), 0);
        // And backspace at the start is a no-op.
        l.backspace();
        assert_eq!(l.as_string(), "ab");
    }

    #[test]
    fn word_motion_crosses_spaces_first() {
        let mut l = Line::from("listen bob 127.0.0.1:40000");
        l.word_left();
        assert_eq!(l.cursor(), 11, "before the address");
        l.word_left();
        assert_eq!(l.cursor(), 7, "before bob");
        l.word_right();
        assert_eq!(l.cursor(), 11);
    }

    #[test]
    fn the_kill_operations() {
        let mut l = Line::from("connect bob tcp");
        l.kill_word();
        assert_eq!(l.as_string(), "connect bob ");

        let mut l = Line::from("connect bob");
        l.word_left();
        l.kill_to_start();
        assert_eq!(l.as_string(), "bob");
        assert_eq!(l.cursor(), 0);

        let mut l = Line::from("connect bob");
        l.word_left();
        l.kill_to_end();
        assert_eq!(l.as_string(), "connect ");
    }

    /// Multi-byte characters are where a byte-indexed cursor would panic, and
    /// a passphrase is exactly where someone reaches for one.
    #[test]
    fn multi_byte_characters_do_not_panic() {
        let mut l = Line::default();
        for c in "паssphraseü🦀".chars() {
            l.insert(c);
        }
        let n = l.len();
        l.home();
        for _ in 0..n {
            l.right();
        }
        assert_eq!(l.cursor(), n);
        l.backspace();
        assert_eq!(l.as_string(), "паssphraseü");
        l.home();
        l.delete();
        assert_eq!(l.as_string(), "аssphraseü");
    }

    /// Taking the line overwrites it. The passphrase goes through here.
    #[test]
    fn taking_the_line_overwrites_it() {
        let mut l = Line::from("correct horse battery staple");
        let got = l.take();
        assert_eq!(got, "correct horse battery staple");
        assert!(l.is_empty());
        assert_eq!(l.cursor(), 0);
        // The allocation is reused, and every character in it was overwritten
        // before the length was dropped.
        assert!(l.chars.capacity() >= 28);
        let raw = l.chars.spare_capacity_mut();
        let seen: Vec<char> = unsafe { raw[..28].iter().map(|c| c.assume_init()) }.collect();
        assert!(
            seen.iter().all(|&c| c == '\0'),
            "the buffer still holds the passphrase: {seen:?}"
        );
    }
}
