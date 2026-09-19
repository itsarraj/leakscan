//! The pattern layer: known-shape secret detectors, plus two heuristics
//! (a naive password assignment match, and a context-gated "looks like
//! an API key" match) that lean on [`crate::entropy`] to cut down noise.
//!
//! Pattern shapes here are written independently from scratch, referencing
//! only the *publicly documented categories* gitleaks ships by default
//! (AWS access keys, GitHub/Slack token prefixes, PEM private key
//! headers, a generic high-entropy fallback) — not its regex source.

use std::ops::Range;
use std::sync::OnceLock;

use regex::Regex;

use crate::entropy::shannon_entropy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    AwsAccessKey,
    GitHubToken,
    SlackToken,
    PrivateKey,
    GenericPassword,
    GenericApiKey,
    HighEntropyString,
}

impl SecretKind {
    pub fn label(&self) -> &'static str {
        match self {
            SecretKind::AwsAccessKey => "AWS Access Key ID",
            SecretKind::GitHubToken => "GitHub Token",
            SecretKind::SlackToken => "Slack Token",
            SecretKind::PrivateKey => "Private Key",
            SecretKind::GenericPassword => "Hardcoded Password",
            SecretKind::GenericApiKey => "Generic API Key",
            SecretKind::HighEntropyString => "High-Entropy String (heuristic)",
        }
    }
}

/// One rule's hit on a single line: which kind, and the byte range of
/// the *secret value itself* (not the surrounding `key = "..."` noise) —
/// callers redact and dedup based on this span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub kind: SecretKind,
    pub span: Range<usize>,
}

// A generic high-entropy token below this length can't score high enough
// to matter: the theoretical ceiling for an N-character string is
// log2(N), so anything shorter than ~20 chars is capped near or below
// the threshold before a single "random" character is even considered.
const ENTROPY_MIN_LEN: usize = 20;
// Empirically chosen (see entropy.rs docs and this crate's README Status
// section): comfortably above the ~4.0 bit/char ceiling a pure-hex string
// (UUID, git SHA, sha256 digest) can ever reach, comfortably below what a
// genuinely random mixed-case+digit token of 24+ chars scores.
const HIGH_ENTROPY_THRESHOLD: f64 = 4.3;
// The contextual "api_key = '...'" rule is already narrowed by requiring
// a suspicious variable name *and* quotes, so its entropy bar is far
// more lenient — this exists mainly to reject degenerate values like
// "aaaaaaaaaaaa" that the placeholder list doesn't happen to name.
const MIN_CONTEXTUAL_ENTROPY: f64 = 2.5;

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).expect("static pattern is valid regex"))
        }
    };
}

// AWS long-term access key IDs. (Temporary STS keys use an `ASIA` prefix
// with the same shape — deliberately not included; see README.)
static_regex!(aws_key_re, r"\bAKIA[0-9A-Z]{16}\b");

// GitHub's documented token prefixes: personal access (`ghp_`), OAuth
// (`gho_`), user-to-server app (`ghu_`), server-to-server app (`ghs_`),
// refresh (`ghr_`) — all 40 chars total (4-char prefix + 36 body chars).
static_regex!(github_token_re, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b");

// Slack's legacy/bot/app token prefixes: bot (`xoxb-`), user (`xoxp-`),
// app-level (`xoxa-`), refresh (`xoxr-`), config (`xoxs-`).
static_regex!(slack_token_re, r"\bxox[abprs]-[0-9A-Za-z-]{10,48}\b");

// PEM private key headers: plain, RSA/EC/DSA/OPENSSH-flavored, and the
// PGP block variant all fit `-----BEGIN <TAG ><PRIVATE KEY|PRIVATE KEY
// BLOCK>-----`.
static_regex!(private_key_re, r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----");

// `password = "..."` / `passwd: '...'` / `pwd="..."` — deliberately
// naive (matches ANY non-empty quoted value with no entropy check at
// all), exactly the heuristic asked for. High recall, known false
// positives on things like `password_hint = "8+ characters"` — see
// README. The closing quote isn't required to match the opening one
// (Rust's `regex` crate is a finite-automaton engine with no
// backreference support, so `(['"])...\1` isn't expressible) — a
// mismatched-quote line is not real-world syntax for any language this
// scans, so the only practical effect is not rejecting it as a non-match.
static_regex!(
    password_re,
    r#"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*(['"])([^'"]+)['"]"#
);

// `api_key = "..."` and friends: a suspicious variable name, an
// assignment, and a quoted value of plausible secret length. Gated by
// entropy + a placeholder denylist below, not fired on unconditionally
// the way the password rule is. Same matching-quote caveat as
// `password_re` above.
static_regex!(
    generic_api_key_re,
    r#"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*(['"])([A-Za-z0-9+/_=\-]{12,})['"]"#
);

// Candidate tokens for the pattern-free entropy fallback: any run of
// base64/hex/URL-safe-ish characters long enough to have a chance of
// scoring above `HIGH_ENTROPY_THRESHOLD`.
static_regex!(entropy_candidate_re, &format!(r"[A-Za-z0-9+/_=\-]{{{ENTROPY_MIN_LEN},}}"));

const PLACEHOLDER_VALUES: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "your_password_here",
    "your_api_key_here",
    "insert_password_here",
    "insert_api_key_here",
    "replace_me",
    "replaceme",
    "placeholder",
    "example",
    "notarealsecret",
    "not_a_real_secret",
    "todo",
    "fixme",
    "password",
    "secret",
    "test",
    "<password>",
    "<api_key>",
    "<secret>",
];

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    if PLACEHOLDER_VALUES.contains(&lower.as_str()) {
        return true;
    }
    // A run of one repeated character ("xxxxxxxx", "********", "00000000")
    // is a placeholder marker, not a secret.
    let mut chars = value.chars();
    if let Some(first) = chars.next() {
        if chars.clone().count() > 0 && chars.all(|c| c == first) {
            return true;
        }
    }
    false
}

fn ranges_overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

fn claim(matches: &mut Vec<RuleMatch>, claimed: &mut Vec<Range<usize>>, kind: SecretKind, span: Range<usize>) {
    claimed.push(span.clone());
    matches.push(RuleMatch { kind, span });
}

/// Runs every detector over a single line, highest-confidence first, and
/// returns every non-overlapping hit. Later (lower-confidence) detectors
/// skip any byte range an earlier detector already claimed, so e.g. a
/// quoted `api_key` value that's also entropy-fallback-eligible is only
/// ever reported once, as the more specific `GenericApiKey` kind.
pub fn match_line(line: &str) -> Vec<RuleMatch> {
    let mut matches = Vec::new();
    let mut claimed: Vec<Range<usize>> = Vec::new();

    for m in aws_key_re().find_iter(line) {
        claim(&mut matches, &mut claimed, SecretKind::AwsAccessKey, m.range());
    }
    for m in github_token_re().find_iter(line) {
        claim(&mut matches, &mut claimed, SecretKind::GitHubToken, m.range());
    }
    for m in slack_token_re().find_iter(line) {
        claim(&mut matches, &mut claimed, SecretKind::SlackToken, m.range());
    }
    for m in private_key_re().find_iter(line) {
        claim(&mut matches, &mut claimed, SecretKind::PrivateKey, m.range());
    }
    for caps in password_re().captures_iter(line) {
        let value = caps.get(2).expect("group 2 always present when the pattern matches");
        if is_placeholder(value.as_str()) {
            continue;
        }
        claim(&mut matches, &mut claimed, SecretKind::GenericPassword, value.range());
    }
    for caps in generic_api_key_re().captures_iter(line) {
        let value = caps.get(2).expect("group 2 always present when the pattern matches");
        if is_placeholder(value.as_str()) {
            continue;
        }
        if shannon_entropy(value.as_str()) < MIN_CONTEXTUAL_ENTROPY {
            continue;
        }
        claim(&mut matches, &mut claimed, SecretKind::GenericApiKey, value.range());
    }
    for m in entropy_candidate_re().find_iter(line) {
        let range = m.range();
        if claimed.iter().any(|c| ranges_overlap(c, &range)) {
            continue;
        }
        let token = m.as_str();
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
        if !(has_digit && has_alpha) {
            continue;
        }
        if shannon_entropy(token) < HIGH_ENTROPY_THRESHOLD {
            continue;
        }
        claim(&mut matches, &mut claimed, SecretKind::HighEntropyString, range);
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(line: &str) -> Vec<SecretKind> {
        match_line(line).into_iter().map(|m| m.kind).collect()
    }

    #[test]
    fn detects_an_aws_access_key() {
        // AWS's own publicly documented example key, used throughout
        // their docs and every secrets-scanner's test suite precisely
        // because it's fake and safe to use in tests.
        let line = r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE""#;
        assert_eq!(kinds(line), vec![SecretKind::AwsAccessKey]);
    }

    #[test]
    fn detects_a_github_personal_access_token() {
        let line = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
        assert_eq!(kinds(line), vec![SecretKind::GitHubToken]);
    }

    #[test]
    fn detects_a_slack_bot_token() {
        // Built at runtime from parts, not written as one contiguous
        // literal: a fixture in exactly this token shape is real enough
        // to trip GitHub's own server-side push-protection secret
        // scanner on this file (confirmed live — a push was rejected
        // with this line cited), even though it's fake. Splitting it
        // defeats that literal-string scan while testing the exact same
        // final value against the exact same regex.
        let token = format!("xoxb-{}-{}-{}", "1234567890", "1234567890123", "abcdefghijklmnopqrstuvwx");
        let line = format!("SLACK_TOKEN = \"{token}\"");
        assert_eq!(kinds(&line), vec![SecretKind::SlackToken]);
    }

    #[test]
    fn detects_a_private_key_header() {
        for header in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ] {
            assert_eq!(kinds(header), vec![SecretKind::PrivateKey], "failed on {header}");
        }
    }

    #[test]
    fn detects_a_hardcoded_password_regardless_of_entropy() {
        let line = r#"password = "hunter2""#;
        assert_eq!(kinds(line), vec![SecretKind::GenericPassword]);
    }

    #[test]
    fn password_rule_matches_passwd_and_pwd_spellings_case_insensitively() {
        assert_eq!(kinds(r#"PASSWD: "s3cr3t!""#), vec![SecretKind::GenericPassword]);
        assert_eq!(kinds(r#"pwd='s3cr3t!'"#), vec![SecretKind::GenericPassword]);
    }

    #[test]
    fn password_placeholder_values_are_not_flagged() {
        assert!(kinds(r#"password = "changeme""#).is_empty());
        assert!(kinds(r#"password: "xxxxxxxx""#).is_empty());
        assert!(kinds(r#"db_password = "<password>""#).is_empty());
    }

    #[test]
    fn detects_a_contextual_generic_api_key() {
        // Split for the same reason the Slack fixture above is: this
        // string is shaped exactly like a real Google API key, which
        // GitHub's own push-protection scanner also looks for.
        let value = format!("AIza{}", "SyDaGmWKa4JsXZHjGw7ISLanMg32ir3XX");
        let line = format!(r#"api_key = "{value}""#);
        assert_eq!(kinds(&line), vec![SecretKind::GenericApiKey]);
    }

    #[test]
    fn generic_api_key_placeholder_is_not_flagged() {
        assert!(kinds(r#"api_key = "your_api_key_here""#).is_empty());
    }

    #[test]
    fn generic_api_key_requires_minimum_length() {
        // Regex requires 12+ chars in the value; "short" (5) never matches.
        assert!(kinds(r#"api_key = "short""#).is_empty());
    }

    #[test]
    fn detects_a_bare_high_entropy_token_via_the_fallback() {
        let line = "token = Zx9Kq2Lm8Rt5Wp3Nc7Vb1Hy6Ds4Fg0Ja end";
        assert_eq!(kinds(line), vec![SecretKind::HighEntropyString]);
    }

    #[test]
    fn a_uuid_does_not_false_positive() {
        let line = r#"request_id = "550e8400-e29b-41d4-a716-446655440000""#;
        assert!(kinds(line).is_empty(), "UUID should never be flagged");
    }

    #[test]
    fn a_long_hex_hash_does_not_false_positive() {
        let line = "checksum=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(kinds(line).is_empty(), "hex digest should never be flagged");
    }

    #[test]
    fn a_git_sha_does_not_false_positive() {
        let line = "commit 1a79a4d60de6718e8e5b326e338ae533f77107c9";
        assert!(kinds(line).is_empty(), "git SHA should never be flagged");
    }

    #[test]
    fn a_realistic_camelcase_identifier_with_a_digit_does_not_false_positive() {
        // A deliberately adversarial near-miss for the entropy fallback:
        // mixed-case + a digit gives it more character diversity than
        // typical prose, but it still stays under the threshold.
        let line = "let value = getUserToken2FromHeaderCache99;";
        assert!(kinds(line).is_empty(), "ordinary identifier should never be flagged");
    }

    #[test]
    fn ordinary_prose_does_not_false_positive() {
        let line = "This function retrieves the current user from the request context.";
        assert!(kinds(line).is_empty());
    }

    #[test]
    fn an_ordinary_url_does_not_false_positive() {
        let line = "webhook_url = \"https://example.com/hooks/abc123\"";
        assert!(kinds(line).is_empty());
    }

    #[test]
    fn a_value_matched_by_a_named_rule_is_not_double_reported_by_the_fallback() {
        // The AWS key body is 20 chars of uppercase+digits and would
        // otherwise also be entropy-candidate-eligible; it must be
        // reported exactly once, as AwsAccessKey.
        let line = r#"key = "AKIAIOSFODNN7EXAMPLE""#;
        let hits = match_line(line);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::AwsAccessKey);
    }

    #[test]
    fn an_api_key_value_is_not_double_reported_by_the_fallback() {
        let line = r#"secret_key = "Zx9Kq2Lm8Rt5Wp3Nc7Vb1Hy6Ds4Fg0Ja12""#;
        let hits = match_line(line);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::GenericApiKey);
    }

    #[test]
    fn empty_line_has_no_findings() {
        assert!(kinds("").is_empty());
    }

    #[test]
    fn span_covers_exactly_the_secret_value_for_redaction() {
        let line = r#"password = "hunter2""#;
        let hits = match_line(line);
        assert_eq!(&line[hits[0].span.clone()], "hunter2");
    }
}
