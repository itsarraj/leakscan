//! `leakscan` — a secrets scanner + pre-commit hook: gitleaks/trufflehog
//! filled with a set of independently-written pattern rules plus a
//! Shannon-entropy fallback. See the README for scope, what's caught,
//! and honest false-positive/false-negative behavior.

pub mod allowlist;
pub mod diff;
pub mod entropy;
pub mod hook;
pub mod redact;
pub mod rules;
pub mod scanner;
pub mod walk;
