# leakscan

gitleaks/trufflehog (Go) without the Go runtime — a secrets scanner plus a
real `pre-commit` hook installer, built from independently-written pattern
rules (referencing only their publicly documented default categories, not
their regex source) plus a Shannon-entropy fallback for anything that
doesn't match a known shape.

## Installation

```sh
cargo install --path .
```

## Usage

```bash
leakscan scan .                    # scan a file or directory tree
leakscan scan . --json             # machine-readable output
leakscan scan --staged             # scan only what's staged for commit
leakscan install-hook              # install a pre-commit hook that runs the line above
```

Exit code `1` if any (non-allowlisted) secret is found — that's what makes
`install-hook`'s pre-commit script actually block a commit.

## What it catches

Known-shape detectors: AWS access key IDs (`AKIA...`), GitHub's five
documented token prefixes (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), Slack's
five token prefixes (`xox[abprs]-`), and PEM private key headers
(RSA/EC/DSA/OPENSSH/PGP block variants). Two heuristics on top: a
deliberately naive `password = "..."` / `passwd:` / `pwd=` match (any
non-empty quoted value, no entropy check — high recall, and yes, that
means `password_hint = "8+ characters"` gets flagged too, see Status), and
a context-gated `api_key = "..."` match (suspicious variable name +
quotes + minimum length + entropy check + a placeholder denylist, so
`api_key = "changeme"` doesn't fire). Anything left over falls through to
a pattern-free Shannon-entropy check over long base64/hex-ish runs.
Detectors run highest-confidence first; a value already claimed by a
named rule is never double-reported by a lower-confidence one.

## Staged-only scanning

`scan --staged` runs `git diff --cached --unified=0` and only looks at
lines the commit is actually *adding* — not every secret that happens to
already live unchanged elsewhere in a staged file, and not anything on
the removed side of a diff. This is what makes it usable as a pre-commit
hook without constantly re-flagging secrets that were already there
before this tool existed.

## Avoiding false positives

Two independent mechanisms, matching how gitleaks/trufflehog's own ignore
files work: a `.leakscanignore` file with path globs (`testdata/*`,
`*.lock`) skipped before the file is even read, and bare 64-hex-character
lines — SHA-256 hashes of one specific offending line's trimmed text,
allowing that exact line without silencing the whole file or rule. There's
also an inline `# leakscan:allow` trailing-comment marker for a one-off.

## Status: built and verified, including two real bugs caught by its own test suite

- **63 unit tests** (`cargo test --lib`) across every module: `rules`
  (21 — every named detector, each false-positive guard, the
  claim-and-skip overlap logic), `allowlist` (8 — path globs, line
  hashes, both mechanisms combined), `diff` (8 — hunk header parsing,
  multi-hunk files, a deleted-then-readded line getting the right new
  line number), `entropy` (6), `scanner` (7 — the orchestration layer,
  including that the raw secret genuinely never appears in a `Finding`'s
  output), `hook` (5 — see below), `redact` (5), `walk` (3 — `.git`/
  `target`/`node_modules`/`vendor`/`dist`/`build` correctly skipped).
- **Two real bugs found and fixed by actually running the suite, not just
  writing it**: the `password`/`api_key` regexes originally used a
  backreference (`(['"])...\1`) to require a matching closing quote —
  Rust's `regex` crate is a finite-automaton engine with no backreference
  support, so every one of those patterns panicked at first use
  (`Syntax(... backreferences are not supported)`), which in turn broke
  every test that exercises the full detector pipeline (`password_re` and
  `generic_api_key_re` are called unconditionally on every scanned line).
  Fixed by dropping the requirement that the closing quote match the
  opening one — a mismatched-quote line isn't real syntax in any language
  this scans, so the only practical effect is not rejecting it as a
  non-match. Separately, `redact`'s own test suite contradicted itself:
  one test asserted `redact("") != ""` while another (correctly) asserted
  `redact("") == ""` is the intended behavior for empty input (there's no
  secret content to leak). Fixed by removing the empty-string case from
  the former.
- **`install-hook` verified against real git, not just its own unit
  tests**: in a real, freshly `git init`-ed repo, `leakscan install-hook`
  wrote a real executable `.git/hooks/pre-commit`; staging a file
  containing `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"` and running a
  real `git commit` was **genuinely blocked** (exit 1, the real hook
  output `AWS Access Key ID - AKIA************MPLE` printed, confirmed via
  `git log` that no commit was ever created); staging a clean file and
  committing again **succeeded** normally once the offending file was
  unstaged; and with `leakscan` deliberately removed from `PATH`, the
  hook degraded gracefully (`leakscan: not found on PATH, skipping secret
  scan`) instead of blocking every future commit on a missing binary.
- **The redaction invariant checked directly, not assumed**:
  `scan_file_content_never_includes_the_raw_secret_in_output` asserts the
  literal secret string is absent from every field of every `Finding` a
  scan produces, not just that *some* masking function exists somewhere.

**Known, accepted false positives** (documented, not hidden): the naive
password rule matches `password_hint = "8+ characters"` and similar —
this is the stated tradeoff for catching every real `password = "..."`
shape with no entropy gate to dodge. A long, mixed-case-and-digit
identifier (a hash, a generated ID) can occasionally cross the entropy
fallback's threshold; use `.leakscanignore` or an inline
`# leakscan:allow` for a confirmed false positive.

**Not done / deliberately deferred**: binary file detection beyond "isn't
valid UTF-8" (a binary containing a secret in an otherwise-text-adjacent
format could slip through the `fs::read_to_string` failure path
unscanned); historical/full-repo-history scanning (gitleaks' `--log-opts`
equivalent) — this only ever looks at a file's current content or a
commit's staged diff, never `git log -p` across all of history; and
custom user-defined rules (the pattern set is fixed at compile time, not
configurable via a rules file).
