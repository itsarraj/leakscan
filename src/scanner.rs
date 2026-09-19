//! Wires the pure detection layer (`rules`, `entropy`) up to a file
//! path, an allowlist, and the inline `leakscan:allow` marker — the
//! orchestration layer `scan --staged` and `scan <path>` both go
//! through.

use serde::Serialize;

use crate::allowlist::Allowlist;
use crate::redact::redact;
use crate::rules::{self, SecretKind};

/// A trailing comment marker that allows one specific line inline,
/// without needing a `.leakscanignore` entry — e.g.
/// `token = "abc..." # leakscan:allow known test fixture`.
const INLINE_ALLOW_MARKER: &str = "leakscan:allow";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub kind_label: String,
    pub redacted: String,
}

/// Pure text -> findings, with no path/allowlist awareness at all. This
/// is the function the unit tests in `rules.rs` exercise indirectly and
/// what a caller with an in-memory string (a diff hunk, a clipboard
/// paste) can use directly.
pub fn scan_text(text: &str) -> Vec<(usize, SecretKind, String)> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.to_lowercase().contains(INLINE_ALLOW_MARKER) {
            continue;
        }
        for m in rules::match_line(line) {
            let secret = &line[m.span.clone()];
            out.push((idx + 1, m.kind, redact(secret)));
        }
    }
    out
}

/// Scans one file's already-read `content`, attributing every finding to
/// `display_path`. `rel_path` (forward-slash, relative to the scan root)
/// is what's checked against the allowlist's path globs — kept separate
/// from `display_path` so callers can show an absolute or `--staged`
/// diff-relative path while still matching globs written relative to the
/// repo root.
pub fn scan_file_content(
    display_path: &str,
    rel_path: &str,
    content: &str,
    allowlist: &Allowlist,
) -> Vec<Finding> {
    if allowlist.is_path_ignored(rel_path) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        if allowlist.is_line_ignored(line) {
            continue;
        }
        if line.to_lowercase().contains(INLINE_ALLOW_MARKER) {
            continue;
        }
        for m in rules::match_line(line) {
            let secret = &line[m.span.clone()];
            findings.push(Finding {
                path: display_path.to_string(),
                line: line_no + 1,
                kind_label: m.kind.label().to_string(),
                redacted: redact(secret),
            });
        }
    }
    findings
}

/// Same as [`scan_file_content`] but only checks the specific `(line_no,
/// content)` pairs given — what `--staged` mode needs, since a diff only
/// tells us about the lines that actually changed, not the whole file.
pub fn scan_added_lines(
    display_path: &str,
    rel_path: &str,
    added_lines: &[(usize, String)],
    allowlist: &Allowlist,
) -> Vec<Finding> {
    if allowlist.is_path_ignored(rel_path) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (line_no, line) in added_lines {
        if allowlist.is_line_ignored(line) {
            continue;
        }
        if line.to_lowercase().contains(INLINE_ALLOW_MARKER) {
            continue;
        }
        for m in rules::match_line(line) {
            let secret = &line[m.span.clone()];
            findings.push(Finding {
                path: display_path.to_string(),
                line: *line_no,
                kind_label: m.kind.label().to_string(),
                redacted: redact(secret),
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_text_finds_a_secret_and_reports_the_right_line_number() {
        // Split (not one contiguous literal) so this Google-API-key-shaped
        // fixture doesn't trip GitHub's own push-protection scanner on
        // this file, the same reason the Slack fixture in rules.rs is.
        let key = format!("AIza{}", "SyDaGmWKa4JsXZHjGw7ISLanMg32ir3XX");
        let text = format!("line one\nline two\napi_key = \"{key}\"\nline four");
        let hits = scan_text(&text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 3);
        assert_eq!(hits[0].1, SecretKind::GenericApiKey);
        assert!(!hits[0].2.contains(&key));
    }

    #[test]
    fn scan_text_respects_the_inline_allow_marker() {
        let text = r#"password = "hunter2" # leakscan:allow this is a test fixture"#;
        assert!(scan_text(text).is_empty());
    }

    #[test]
    fn scan_file_content_skips_allowlisted_paths_entirely() {
        let allowlist = crate::allowlist::Allowlist::parse("testdata/*\n");
        let content = r#"password = "hunter2""#;
        let findings = scan_file_content("testdata/fixture.txt", "testdata/fixture.txt", content, &allowlist);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_file_content_skips_an_allowlisted_line_hash_but_not_others() {
        let secret_line = r#"password = "hunter2""#;
        let digest = crate::allowlist::hash_line(secret_line);
        let allowlist = crate::allowlist::Allowlist::parse(&digest);

        let key = format!("AIza{}", "SyDaGmWKa4JsXZHjGw7ISLanMg32ir3XX");
        let content = format!("{secret_line}\napi_key = \"{key}\"\n");
        let findings = scan_file_content("f.txt", "f.txt", &content, &allowlist);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn scan_file_content_never_includes_the_raw_secret_in_output() {
        let content = r#"aws_secret = "AKIAIOSFODNN7EXAMPLE""#;
        let findings = scan_file_content("f.txt", "f.txt", content, &crate::allowlist::Allowlist::empty());
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].redacted.contains("IOSFODNN7EXAMPLE"));
    }

    #[test]
    fn scan_added_lines_only_looks_at_given_lines_and_keeps_their_line_numbers() {
        let added = vec![
            (12usize, r#"password = "hunter2""#.to_string()),
            (13usize, "no secret here".to_string()),
        ];
        let findings = scan_added_lines("f.txt", "f.txt", &added, &crate::allowlist::Allowlist::empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 12);
    }

    #[test]
    fn clean_content_produces_no_findings() {
        let content = "fn main() {\n    println!(\"hello, world\");\n}\n";
        let findings = scan_file_content("f.rs", "f.rs", content, &crate::allowlist::Allowlist::empty());
        assert!(findings.is_empty());
    }
}
