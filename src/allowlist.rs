//! `.leakscanignore` — every real secrets scanner needs a way to say "I
//! know, it's fine": a vendored fixture full of fake-but-real-shaped
//! keys, a `testdata/` directory, one specific line that's a documented
//! false positive.
//!
//! Two independent mechanisms, matching how gitleaks/trufflehog's own
//! ignore files work:
//!
//! - **Path globs** — a line like `testdata/*` or `*.lock` skips whole
//!   files by relative path, checked before the file is even read.
//! - **Line hashes** — a bare 64-hex-character line is a SHA-256 digest
//!   of one specific offending line's trimmed text. Print one with
//!   `leakscan scan --print-hashes` (or read it off a finding) and paste
//!   it in to allow that exact line without silencing the whole file or
//!   the whole rule.
//!
//! A third, inline mechanism lives in `scanner.rs` instead of here: a
//! trailing `leakscan:allow` comment on the offending line itself, the
//! same convention `gitleaks:allow` / `pragma: allowlist secret` use in
//! their respective tools — no `.leakscanignore` entry needed at all for
//! a one-off, self-documenting exception.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub const IGNORE_FILE_NAME: &str = ".leakscanignore";

#[derive(Debug, Default, Clone)]
pub struct Allowlist {
    path_globs: Vec<String>,
    line_hashes: Vec<String>,
}

/// SHA-256 hex digest of a line's trimmed text — the same normalization
/// used both when building the allowlist and when checking a finding
/// against it, so trailing-whitespace differences between someone's
/// editor and the repo's don't silently break an allow entry.
pub fn hash_line(raw_line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_line.trim().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn looks_like_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Translates a small glob subset (`*` = any run of non-slash chars,
/// `**` = any run of chars including slashes, `?` = one char) into a
/// regex anchored to the whole path. Anything not one of those
/// metacharacters is matched literally.
fn glob_to_regex(pattern: &str) -> Option<regex::Regex> {
    let mut out = String::from("(?i)^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                if chars.get(i + 1) == Some(&'*') {
                    out.push_str(".*");
                    i += 2;
                } else {
                    out.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                out.push('.');
                i += 1;
            }
            c => {
                if regex_syntax_needs_escape(c) {
                    out.push('\\');
                }
                out.push(c);
                i += 1;
            }
        }
    }
    out.push('$');
    regex::Regex::new(&out).ok()
}

fn regex_syntax_needs_escape(c: char) -> bool {
    matches!(
        c,
        '.' | '+' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\'
    )
}

impl Allowlist {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Loads `.leakscanignore` from `dir` if present; a missing file is
    /// not an error — an unconfigured allowlist is just an empty one.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(IGNORE_FILE_NAME);
        if !path.exists() {
            return Ok(Self::empty());
        }
        let content = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        Ok(Self::parse(&content))
    }

    pub fn parse(content: &str) -> Self {
        let mut path_globs = Vec::new();
        let mut line_hashes = Vec::new();
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if looks_like_sha256_hex(line) {
                line_hashes.push(line.to_lowercase());
            } else {
                path_globs.push(line.to_string());
            }
        }
        Allowlist { path_globs, line_hashes }
    }

    /// `rel_path` should use forward slashes regardless of host OS, to
    /// match how patterns are written in `.leakscanignore`.
    pub fn is_path_ignored(&self, rel_path: &str) -> bool {
        self.path_globs
            .iter()
            .filter_map(|g| glob_to_regex(g))
            .any(|re| re.is_match(rel_path))
    }

    pub fn is_line_ignored(&self, raw_line: &str) -> bool {
        let digest = hash_line(raw_line);
        self.line_hashes.iter().any(|h| h == &digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_ignores_nothing() {
        let a = Allowlist::empty();
        assert!(!a.is_path_ignored("src/main.rs"));
        assert!(!a.is_line_ignored("password = \"hunter2\""));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let a = Allowlist::parse("# a comment\n\n  \n*.lock\n");
        assert!(a.is_path_ignored("Cargo.lock"));
    }

    #[test]
    fn star_glob_matches_within_one_path_segment_only() {
        let a = Allowlist::parse("testdata/*\n");
        assert!(a.is_path_ignored("testdata/fake_key.pem"));
        assert!(
            !a.is_path_ignored("testdata/nested/fake_key.pem"),
            "single `*` must not cross a `/` boundary"
        );
    }

    #[test]
    fn double_star_glob_crosses_directory_boundaries() {
        let a = Allowlist::parse("vendor/**\n");
        assert!(a.is_path_ignored("vendor/nested/deep/file.go"));
    }

    #[test]
    fn extension_glob_matches_anywhere_in_the_tree() {
        let a = Allowlist::parse("*.lock\n");
        assert!(a.is_path_ignored("Cargo.lock"));
        assert!(!a.is_path_ignored("Cargo.lock.bak"));
    }

    #[test]
    fn line_hash_allows_one_specific_line() {
        let line = r#"password = "hunter2""#;
        let digest = hash_line(line);
        assert!(looks_like_sha256_hex(&digest));

        let a = Allowlist::parse(&digest);
        assert!(a.is_line_ignored(line));
        assert!(!a.is_line_ignored(r#"password = "different""#));
    }

    #[test]
    fn line_hash_is_insensitive_to_surrounding_whitespace() {
        let digest = hash_line("password = \"hunter2\"");
        let a = Allowlist::parse(&digest);
        assert!(a.is_line_ignored("   password = \"hunter2\"   "));
    }

    #[test]
    fn a_non_hash_non_glob_looking_line_is_still_treated_as_a_path_glob() {
        // 63 hex chars (one short) must not be mistaken for a line hash.
        let a = Allowlist::parse(&"a".repeat(63));
        assert!(a.is_path_ignored(&"a".repeat(63)));
    }
}
