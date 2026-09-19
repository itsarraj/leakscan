//! `leakscan install-hook` — writes (or safely extends) a real
//! `.git/hooks/pre-commit`.
//!
//! `pre-commit` (unlike `commit-msg`) gets no arguments and runs before
//! git even opens an editor for the message, so it's the right hook for
//! "block the commit outright if the staged diff contains a secret."
//! git only treats it as installed if it's executable — this sets that
//! bit itself rather than relying on the caller's umask.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const MARKER_START: &str = "# >>> leakscan pre-commit hook >>>";
const MARKER_END: &str = "# <<< leakscan pre-commit hook <<<";

fn hook_block() -> String {
    format!(
        "{MARKER_START}\n\
# Installed by `leakscan install-hook`. Safe to re-run to update this\n\
# block in place; do not hand-edit between the markers.\n\
if command -v leakscan >/dev/null 2>&1; then\n\
    leakscan scan --staged || exit 1\n\
else\n\
    echo \"leakscan: not found on PATH, skipping secret scan\" >&2\n\
fi\n\
{MARKER_END}\n"
    )
}

/// Installs (or updates) the pre-commit hook in `repo_dir/.git/hooks`.
///
/// - No existing hook: writes a fresh `#!/bin/sh` script.
/// - An existing hook that's already ours (contains the marker):
///   replaces just the marked block in place — re-running this after an
///   upgrade doesn't duplicate it.
/// - An existing hook that's someone else's (Husky, a hand-written
///   script, another tool's install-hook): appended to, never
///   overwritten — this is the "don't clobber" case the tool has to get
///   right, since destroying an existing hook silently is a much worse
///   failure mode than a scan getting skipped.
pub fn install_hook(repo_dir: &Path) -> Result<PathBuf> {
    let hooks_dir = repo_dir.join(".git").join("hooks");
    fs::create_dir_all(&hooks_dir).with_context(|| format!("creating {}", hooks_dir.display()))?;
    let hook_path = hooks_dir.join("pre-commit");
    let block = hook_block();

    let new_contents = if hook_path.exists() {
        let existing =
            fs::read_to_string(&hook_path).with_context(|| format!("reading {}", hook_path.display()))?;
        if let Some(replaced) = replace_marked_block(&existing, &block) {
            replaced
        } else {
            let mut updated = existing;
            if !updated.starts_with("#!") {
                updated = format!("#!/bin/sh\n{updated}");
            }
            if !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push('\n');
            updated.push_str(&block);
            updated
        }
    } else {
        format!("#!/bin/sh\n{block}")
    };

    fs::write(&hook_path, new_contents).with_context(|| format!("writing {}", hook_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("making {} executable", hook_path.display()))?;
    }

    Ok(hook_path)
}

/// If `existing` already contains a leakscan block (from a previous
/// `install-hook` run), returns `existing` with that block swapped for
/// `new_block` — an idempotent re-install instead of a duplicated block.
fn replace_marked_block(existing: &str, new_block: &str) -> Option<String> {
    let start = existing.find(MARKER_START)?;
    let end_marker_pos = existing[start..].find(MARKER_END)? + start;
    let end = end_marker_pos + MARKER_END.len();
    let mut out = String::with_capacity(existing.len());
    out.push_str(&existing[..start]);
    out.push_str(new_block.trim_end_matches('\n'));
    out.push('\n');
    // Skip the trailing newline right after the old marker, if any, so
    // we don't accumulate a blank line on every re-install.
    let mut rest = &existing[end..];
    if let Some(stripped) = rest.strip_prefix('\n') {
        rest = stripped;
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("leakscan-test-hook-{}-{}", std::process::id(), name));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_a_fresh_executable_pre_commit_hook() {
        let repo = temp_repo("fresh");
        let hook_path = install_hook(&repo).unwrap();

        assert_eq!(hook_path.file_name().unwrap(), "pre-commit");
        let contents = fs::read_to_string(&hook_path).unwrap();
        assert!(contents.starts_with("#!/bin/sh"));
        assert!(contents.contains("leakscan scan --staged"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&hook_path).unwrap().permissions().mode();
            assert!(mode & 0o111 != 0, "hook must be executable");
        }

        fs::remove_dir_all(&repo).ok();
    }

    #[test]
    fn appends_to_an_existing_unrelated_hook_without_destroying_it() {
        let repo = temp_repo("append");
        let hooks_dir = repo.join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let hook_path = hooks_dir.join("pre-commit");
        fs::write(&hook_path, "#!/bin/sh\necho 'run by husky'\n").unwrap();

        install_hook(&repo).unwrap();
        let contents = fs::read_to_string(&hook_path).unwrap();

        assert!(contents.contains("run by husky"), "pre-existing hook content was destroyed");
        assert!(contents.contains("leakscan scan --staged"));

        fs::remove_dir_all(&repo).ok();
    }

    #[test]
    fn adds_a_missing_shebang_when_appending_to_a_shebang_less_hook() {
        let repo = temp_repo("noshebang");
        let hooks_dir = repo.join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let hook_path = hooks_dir.join("pre-commit");
        fs::write(&hook_path, "echo 'no shebang here'\n").unwrap();

        install_hook(&repo).unwrap();
        let contents = fs::read_to_string(&hook_path).unwrap();
        assert!(contents.starts_with("#!/bin/sh"));
        assert!(contents.contains("no shebang here"));

        fs::remove_dir_all(&repo).ok();
    }

    #[test]
    fn re_running_install_hook_is_idempotent_not_duplicated() {
        let repo = temp_repo("idempotent");
        install_hook(&repo).unwrap();
        install_hook(&repo).unwrap();
        install_hook(&repo).unwrap();

        let hook_path = repo.join(".git").join("hooks").join("pre-commit");
        let contents = fs::read_to_string(&hook_path).unwrap();
        assert_eq!(
            contents.matches("leakscan scan --staged").count(),
            1,
            "re-running install-hook must not duplicate the block"
        );
        assert_eq!(contents.matches(MARKER_START).count(), 1);

        fs::remove_dir_all(&repo).ok();
    }

    #[test]
    fn reinstalling_preserves_unrelated_content_added_around_it() {
        let repo = temp_repo("preserve-around");
        install_hook(&repo).unwrap();

        let hook_path = repo.join(".git").join("hooks").join("pre-commit");
        let mut contents = fs::read_to_string(&hook_path).unwrap();
        contents.push_str("echo 'added by someone else after install'\n");
        fs::write(&hook_path, &contents).unwrap();

        install_hook(&repo).unwrap();
        let final_contents = fs::read_to_string(&hook_path).unwrap();
        assert!(final_contents.contains("added by someone else after install"));
        assert_eq!(final_contents.matches(MARKER_START).count(), 1);

        fs::remove_dir_all(&repo).ok();
    }
}
