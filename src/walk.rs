//! Recursively lists files under a directory for `scan <path>` when
//! `<path>` is a directory rather than a single file.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Directory names never worth descending into for a secrets scan: VCS
/// internals and generated/vendored trees that are either enormous, not
/// meaningfully "yours," or (for `.git`) full of every historical blob
/// this tool has no business reading line-by-line.
const SKIP_DIR_NAMES: &[&str] = &[".git", "target", "node_modules", "vendor", "dist", "build"];

/// Every regular file under `root`, paired with its path relative to
/// `root` using forward slashes (for consistent `.leakscanignore` glob
/// matching regardless of host OS).
pub fn walk_files(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    walk_into(root, root, &mut out)?;
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

fn walk_into(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let name = entry.file_name();
            if SKIP_DIR_NAMES.iter().any(|skip| name == *skip) {
                continue;
            }
            walk_into(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("walked path is always under root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((path, rel));
        }
        // Symlinks are skipped (neither is_dir() nor is_file() under
        // DirEntry::file_type, which doesn't follow them) — a symlink
        // loop can't hang the walk.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("leakscan-test-walk-{}-{}", std::process::id(), name))
    }

    #[test]
    fn walks_nested_directories() {
        let root = unique_temp_dir("nested");
        fs::create_dir_all(root.join("sub/dir")).unwrap();
        fs::write(root.join("top.txt"), b"top").unwrap();
        fs::write(root.join("sub/dir/deep.txt"), b"deep").unwrap();

        let files = walk_files(&root).unwrap();
        let rels: Vec<_> = files.iter().map(|(_, r)| r.clone()).collect();
        assert!(rels.contains(&"top.txt".to_string()));
        assert!(rels.contains(&"sub/dir/deep.txt".to_string()));

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn skips_dot_git_and_target_and_node_modules() {
        let root = unique_temp_dir("skips");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), b"secret stuff").unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("target/debug/bin"), b"binary").unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("node_modules/pkg/index.js"), b"js").unwrap();
        fs::write(root.join("real.rs"), b"fn main() {}").unwrap();

        let files = walk_files(&root).unwrap();
        let rels: Vec<_> = files.iter().map(|(_, r)| r.clone()).collect();
        assert_eq!(rels, vec!["real.rs".to_string()]);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn empty_directory_produces_no_files() {
        let root = unique_temp_dir("empty");
        fs::create_dir_all(&root).unwrap();
        assert!(walk_files(&root).unwrap().is_empty());
        fs::remove_dir_all(&root).ok();
    }
}
