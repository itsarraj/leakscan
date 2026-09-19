//! Parses `git diff --cached` output into, per file, exactly the
//! `(new-file line number, added line content)` pairs — what `scan
//! --staged` needs to only flag secrets the commit is actually
//! *introducing*, not every secret that happens to already live
//! unchanged elsewhere in a staged file.
//!
//! Run with `--unified=0` deliberately: with zero context lines, every
//! hunk contains only `+`/`-` lines, never a context (` `-prefixed) line.
//! That means line-number bookkeeping only has to handle one case — each
//! `+` line takes the next sequential new-file line number, starting
//! from the hunk header's `+start` — instead of also threading context
//! lines through the counter.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

pub struct StagedFile {
    pub path: String,
    pub added_lines: Vec<(usize, String)>,
}

/// Runs `git diff --cached` in `repo_dir` and returns the raw diff text.
pub fn staged_diff_text(repo_dir: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["diff", "--cached", "--no-color", "--unified=0", "--"])
        .output()
        .with_context(|| format!("running git diff --cached in {}", repo_dir.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git diff --cached failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parses unified diff text (as produced by `staged_diff_text`, `-U0`)
/// into per-file added-line lists. A binary file ("Binary files ...
/// differ") or a deleted file (`+++ /dev/null`) contributes no added
/// lines — there's no new text content to scan.
pub fn parse_added_lines(diff_text: &str) -> Vec<StagedFile> {
    let mut files: Vec<StagedFile> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_new_line: usize = 0;

    for raw in diff_text.lines() {
        if let Some(path) = raw.strip_prefix("+++ ") {
            current_new_line = 0;
            if path == "/dev/null" {
                current_path = None;
            } else {
                let path = path.strip_prefix("b/").unwrap_or(path);
                current_path = Some(path.to_string());
                files.push(StagedFile {
                    path: path.to_string(),
                    added_lines: Vec::new(),
                });
            }
            continue;
        }
        if raw.starts_with("--- ") {
            continue;
        }
        if let Some(hunk) = raw.strip_prefix("@@ ") {
            if let Some(new_start) = parse_hunk_new_start(hunk) {
                current_new_line = new_start;
            }
            continue;
        }
        if raw.starts_with("Binary files ") {
            current_path = None;
            continue;
        }
        if current_path.is_none() {
            continue;
        }
        if let Some(content) = raw.strip_prefix('+') {
            let file = files.last_mut().expect("current_path implies a pushed file");
            file.added_lines.push((current_new_line, content.to_string()));
            current_new_line += 1;
        }
        // '-' lines (removed) and anything else don't advance the
        // new-file line counter and aren't scanned — this tool only
        // cares about lines the commit is introducing.
    }

    files
}

/// Extracts the new-file start line from a hunk header body, e.g.
/// `-12,0 +13,3 @@` -> `13`. Returns `None` on anything unparseable
/// rather than panicking — a hunk header this tool doesn't understand
/// should degrade to "don't scan," not crash the hook.
fn parse_hunk_new_start(hunk_body: &str) -> Option<usize> {
    let plus_pos = hunk_body.find('+')?;
    let rest = &hunk_body[plus_pos + 1..];
    let end = rest.find([',', ' '])?;
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_single_hunk_single_file_diff() {
        let diff = "\
diff --git a/config.py b/config.py
index 1234567..89abcde 100644
--- a/config.py
+++ b/config.py
@@ -10,0 +11,2 @@ def setup():
+    api_key = \"abc123\"
+    debug = True
";
        let files = parse_added_lines(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "config.py");
        assert_eq!(
            files[0].added_lines,
            vec![
                (11, "    api_key = \"abc123\"".to_string()),
                (12, "    debug = True".to_string()),
            ]
        );
    }

    #[test]
    fn a_pure_deletion_hunk_contributes_no_added_lines() {
        let diff = "\
diff --git a/old.py b/old.py
index 1234567..89abcde 100644
--- a/old.py
+++ b/old.py
@@ -5,2 +4,0 @@ def setup():
-    old_line_one = 1
-    old_line_two = 2
";
        let files = parse_added_lines(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].added_lines.is_empty());
    }

    #[test]
    fn multiple_hunks_in_one_file_each_get_correct_line_numbers() {
        let diff = "\
diff --git a/f.py b/f.py
--- a/f.py
+++ b/f.py
@@ -1,0 +2 @@
+first added line
@@ -20,0 +22 @@
+second added line
";
        let files = parse_added_lines(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].added_lines,
            vec![
                (2, "first added line".to_string()),
                (22, "second added line".to_string()),
            ]
        );
    }

    #[test]
    fn multiple_files_are_each_tracked_independently() {
        let diff = "\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -0,0 +1 @@
+line in a
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -0,0 +1 @@
+line in b
";
        let files = parse_added_lines(diff);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "a.py");
        assert_eq!(files[1].path, "b.py");
    }

    #[test]
    fn a_deleted_file_dev_null_target_contributes_nothing() {
        let diff = "\
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-old = 1
-old2 = 2
";
        let files = parse_added_lines(diff);
        assert!(files.is_empty());
    }

    #[test]
    fn a_binary_file_is_skipped_without_crashing() {
        let diff = "\
diff --git a/image.png b/image.png
index 1234567..89abcde 100644
Binary files a/image.png and b/image.png differ
";
        let files = parse_added_lines(diff);
        assert!(files.is_empty());
    }

    #[test]
    fn empty_diff_produces_no_files() {
        assert!(parse_added_lines("").is_empty());
    }

    #[test]
    fn hunk_header_with_no_comma_count_is_parsed() {
        // Git omits the ",count" part entirely when it's 1.
        assert_eq!(parse_hunk_new_start("-3 +5 @@"), Some(5));
        assert_eq!(parse_hunk_new_start("-3,2 +5,7 @@"), Some(5));
    }
}
