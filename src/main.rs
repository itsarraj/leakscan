use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use leakscan::allowlist::Allowlist;
use leakscan::{diff, hook, scanner, walk};

#[derive(Parser)]
#[command(
    name = "leakscan",
    about = "A secrets scanner + pre-commit hook — gitleaks/trufflehog without the Go runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file, a directory tree, or (with --staged) what's staged for commit.
    Scan {
        /// File or directory to scan. Omit (and pass --staged instead) to scan
        /// what's staged in git.
        path: Option<PathBuf>,
        /// Scan only what's staged for commit (`git diff --cached`) — the mode
        /// a pre-commit hook actually needs.
        #[arg(long)]
        staged: bool,
        /// Repo root to run `git diff --cached` in and to load
        /// `.leakscanignore` from, when --staged is given.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Emit findings as a JSON array instead of human-readable lines.
        #[arg(long)]
        json: bool,
    },
    /// Install (or safely update) a pre-commit hook that runs `leakscan scan --staged`.
    InstallHook {
        /// Repo whose `.git/hooks/pre-commit` should be installed/updated.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(found_secrets) => {
            if found_secrets {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("leakscan: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Returns `Ok(true)` if any (non-allowlisted) secret was found — the
/// caller turns that into the process exit code a pre-commit hook relies
/// on to actually block a commit.
fn run(cli: Cli) -> anyhow::Result<bool> {
    match cli.command {
        Command::Scan { path, staged, repo, json } => {
            let findings = if staged {
                scan_staged(&repo)?
            } else {
                let path =
                    path.ok_or_else(|| anyhow::anyhow!("PATH is required unless --staged is given"))?;
                scan_path(&path)?
            };
            report(&findings, json);
            Ok(!findings.is_empty())
        }
        Command::InstallHook { repo } => {
            let path = hook::install_hook(&repo)?;
            println!("installed pre-commit hook at {}", path.display());
            Ok(false)
        }
    }
}

fn scan_path(path: &Path) -> anyhow::Result<Vec<scanner::Finding>> {
    let mut findings = Vec::new();
    if path.is_file() {
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        let allowlist = Allowlist::load(root)?;
        let content = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let rel = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        findings.extend(scanner::scan_file_content(
            &path.display().to_string(),
            &rel,
            &content,
            &allowlist,
        ));
    } else if path.is_dir() {
        let allowlist = Allowlist::load(path)?;
        for (full_path, rel) in walk::walk_files(path)? {
            // A file that isn't valid UTF-8 text (a binary, most likely)
            // is skipped rather than erroring the whole scan out — see
            // README for this as a documented, deliberate limitation.
            let Ok(content) = fs::read_to_string(&full_path) else {
                continue;
            };
            findings.extend(scanner::scan_file_content(
                &full_path.display().to_string(),
                &rel,
                &content,
                &allowlist,
            ));
        }
    } else {
        anyhow::bail!("{} is not a file or directory", path.display());
    }
    Ok(findings)
}

fn scan_staged(repo: &Path) -> anyhow::Result<Vec<scanner::Finding>> {
    let allowlist = Allowlist::load(repo)?;
    let diff_text = diff::staged_diff_text(repo)?;
    let files = diff::parse_added_lines(&diff_text);
    let mut findings = Vec::new();
    for file in files {
        findings.extend(scanner::scan_added_lines(
            &file.path,
            &file.path,
            &file.added_lines,
            &allowlist,
        ));
    }
    Ok(findings)
}

fn report(findings: &[scanner::Finding], json: bool) {
    if json {
        let out = serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string());
        println!("{out}");
        return;
    }
    if findings.is_empty() {
        println!("leakscan: no secrets found");
        return;
    }
    for f in findings {
        println!("{}:{}: {} - {}", f.path, f.line, f.kind_label, f.redacted);
    }
    eprintln!("\nleakscan: {} potential secret(s) found", findings.len());
}
