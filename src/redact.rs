//! Turning a real secret into something safe to print.
//!
//! The one invariant every caller in this crate relies on: the full
//! secret text never reaches `redact`'s return value. Short secrets are
//! fully masked (no head/tail shown at all — a 6-character password
//! leaking even its first and last character is still a leak); longer
//! ones show a fixed-size head and tail so a human reviewing scan output
//! can tell *which* secret was found (e.g. to go rotate it) without the
//! tool ever echoing enough of it to be useful to an attacker reading a
//! CI log.

/// Chars of head/tail kept visible for secrets long enough to afford it.
const VISIBLE: usize = 4;
/// Below this length, nothing is shown at all — just asterisks.
const FULLY_MASKED_BELOW: usize = VISIBLE * 2 + 1;
/// The masked middle is capped so redacting a 4KB private key body (if
/// one ever made it this far) doesn't dump a 4KB line of asterisks.
const MAX_MASK_CHARS: usize = 24;

pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let n = chars.len();
    if n == 0 {
        return String::new();
    }
    if n < FULLY_MASKED_BELOW {
        return "*".repeat(n.max(4));
    }
    let head: String = chars[..VISIBLE].iter().collect();
    let tail: String = chars[n - VISIBLE..].iter().collect();
    let mask_len = (n - VISIBLE * 2).min(MAX_MASK_CHARS);
    format!("{head}{}{tail}", "*".repeat(mask_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_secrets_are_fully_masked_no_head_or_tail() {
        let r = redact("hunter2");
        assert!(!r.contains("hunter") && !r.contains('2'));
        assert!(r.chars().all(|c| c == '*'));
    }

    #[test]
    fn long_secrets_show_a_head_and_tail_but_never_the_middle() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let r = redact(secret);
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("MPLE"));
        assert!(!r.contains("OSFODNN7EXA"), "middle of the secret leaked: {r}");
        assert_ne!(r, secret);
    }

    #[test]
    fn never_reproduces_the_original_secret_verbatim() {
        // Empty input is deliberately excluded: there's no secret content
        // to leak, and `redact("") == ""` is the documented, intentional
        // behavior covered separately by `empty_input_redacts_to_empty`.
        for secret in [
            "hunter2",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
            "a",
        ] {
            assert_ne!(redact(secret), secret);
        }
    }

    #[test]
    fn empty_input_redacts_to_empty() {
        assert_eq!(redact(""), "");
    }

    #[test]
    fn very_long_secrets_cap_the_masked_middle_length() {
        let secret = "x".repeat(500);
        let r = redact(&secret);
        assert!(r.len() < 100, "redacted preview should stay short, got {} chars", r.len());
    }
}
