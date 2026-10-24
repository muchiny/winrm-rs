//! Forward-only substring search shared by the parsers.

/// Forward-only search for one needle in one haystack. It remembers the last
/// hit, or that there is none, so a caller whose start offset only moves
/// forward reads the haystack once per needle.
pub(super) struct NextMatch<'a> {
    hay: &'a str,
    needle: &'static str,
    /// Start offset of the last search and its result.
    last: Option<(usize, Option<usize>)>,
}

impl<'a> NextMatch<'a> {
    pub(super) fn new(hay: &'a str, needle: &'static str) -> Self {
        Self {
            hay,
            needle,
            last: None,
        }
    }

    /// Absolute offset of the first `needle` at or after `from`: always
    /// equal to `hay.get(from..)?.find(needle).and_then(|i| from.checked_add(i))`,
    /// whatever the call order.
    pub(super) fn at_or_after(&mut self, from: usize) -> Option<usize> {
        // A `from` inside a character (or past the end) has no answer, and
        // says nothing about later offsets: leave the memo alone.
        let rest = self.hay.get(from..)?;
        if let Some((start, hit)) = self.last
            && from >= start
        {
            match hit {
                // Nothing at or after `start`, so nothing at or after `from`.
                None => return None,
                // The first hit from `start` is also the first from `from`.
                Some(h) if h >= from => return Some(h),
                Some(_) => {}
            }
        }
        let found = rest.find(self.needle).and_then(|i| from.checked_add(i));
        self.last = Some((from, found));
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An offset inside a multi-byte character has no answer and must not
    /// poison the memo for the offsets after it.
    #[test]
    fn offset_inside_a_character_leaves_the_memo_alone() {
        let hay = "éab<x ";
        let mut next = NextMatch::new(hay, "<x ");
        assert_eq!(next.at_or_after(1), None);
        assert_eq!(next.at_or_after(2), Some(4));
        assert_eq!(next.at_or_after(1), None);
        assert_eq!(next.at_or_after(3), Some(4));
        assert_eq!(next.at_or_after(6), None);
        assert_eq!(next.at_or_after(99), None);
    }

    proptest::proptest! {
        /// Any order of `from`, forwards or backwards, gives `str::find`'s answer.
        #[test]
        fn next_match_agrees_with_find(
            parts in proptest::collection::vec(
                proptest::sample::select(vec!["ab", "a", "b", ";", "é", "<x ", "x"]), 0..32),
            froms in proptest::collection::vec(0usize..80, 0..16),
        ) {
            let hay: String = parts.concat();
            for needle in [";", "ab", "<x "] {
                let mut next = NextMatch::new(&hay, needle);
                for &from in &froms {
                    let expected = hay.get(from..).and_then(|r| r.find(needle)).map(|i| from + i);
                    proptest::prop_assert_eq!(next.at_or_after(from), expected);
                }
            }
        }
    }
}
