//! Shannon entropy over a byte string, used as the tool's last-resort,
//! pattern-free detector.
//!
//! This measures character-frequency randomness only — it has no concept
//! of "looks like a secret" beyond "the character distribution is
//! unusually flat for its length." That's a real, known limitation (the
//! same one trufflehog's original entropy checker has): a short random
//! token doesn't have room to reach a high score (the theoretical max for
//! an N-character string is `log2(N)`, so a 16-char token can never
//! exceed 4 bits/char no matter how random it is), while a sufficiently
//! long, character-diverse *non-secret* (a camelCase identifier with a
//! digit in it, say) can occasionally cross a naive threshold. See the
//! README's Status section for the honest false-positive/false-negative
//! trade-off this implies and why the threshold here was picked
//! empirically rather than copied from a table.

use std::collections::HashMap;

/// Average Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut len = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        len += 1;
    }
    let len = len as f64;
    counts.values().fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn a_single_repeated_character_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
    }

    #[test]
    fn a_uuid_stays_below_the_hex_alphabet_ceiling() {
        // 16 possible symbols -> max achievable entropy is exactly
        // log2(16) == 4.0 bits/char, no matter how the digits fall.
        let e = shannon_entropy("550e8400-e29b-41d4-a716-446655440000");
        assert!(e < 4.0, "uuid entropy {e} unexpectedly reached the hex ceiling");
    }

    #[test]
    fn a_sha256_hex_digest_stays_below_the_hex_alphabet_ceiling() {
        let e = shannon_entropy("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(e < 4.0, "sha256 hex entropy {e} unexpectedly reached the hex ceiling");
    }

    #[test]
    fn a_hand_built_high_diversity_token_scores_clearly_higher() {
        let e = shannon_entropy("Zx9Kq2Lm8Rt5Wp3Nc7Vb1Hy6Ds4Fg0Ja");
        assert!(e > 4.5, "expected a clearly high entropy score, got {e}");
    }

    #[test]
    fn entropy_is_symmetric_under_reordering() {
        // Shannon entropy is a pure frequency measure — it can't see
        // sequence/structure at all, only the character distribution.
        // That's exactly the limitation documented above, demonstrated
        // directly: shuffling the string changes nothing.
        assert_eq!(shannon_entropy("aabbcc"), shannon_entropy("abcabc"));
    }
}
