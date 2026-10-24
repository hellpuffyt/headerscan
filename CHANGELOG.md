# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Updated `rustls` 0.23.43 → 0.23.46, `rustls-webpki` 0.103.15 → 0.103.16
  and `webpki-roots` 1.0.9 → 1.0.10 (RUSTSEC-2026-0285, -0346, -0348,
  -0349, -0381, -0382).
- Server-controlled text (cookie names, CSP directive names, the final URL)
  is escaped before printing, so control characters and bidi overrides
  cannot alter the terminal or disguise output.

### Fixed

- A header repeated N times had every value collected N times, so N
  cookies produced N² findings and a deflated score (3 cookies scored 0).
- `'unsafe-inline'` was graded by directive *name*: in `default-src`
  without a `script-src` it was Low although inline scripts run; with a
  nonce, hash or `'strict-dynamic'` (which make browsers ignore it) it was
  High. Severity now follows the effective script policy.
- Header values with non-ASCII bytes were dropped silently by the HTTP
  client; they are now reported as `header-unreadable` (info).

### Changed

- README: install with `cargo install --git` (the crate is not on
  crates.io); example output replaced with a real run against a local
  server; findings table lists the two informational codes.

### Added

- `tests/cli_end_to_end.rs` (binary against local servers only);
  `SECURITY.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`.

## [0.1.0] - 2026-08-30

First release.

### Added

- 29 security-header checks covering HSTS, Content-Security-Policy,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
  Cross-Origin-Opener-Policy, clickjacking, CORS, cookie attributes, and
  software version disclosure.
- Scheme-aware verdicts: HSTS on a plain HTTP response is reported as
  ineffective rather than present, and `Secure` is only required of cookies on
  responses that arrived over TLS.
- Severity that reflects real risk: `'unsafe-inline'` is high in `script-src`
  and low in `style-src`; `max-age=0` is high rather than "HSTS present"; a
  report-only CSP is distinguished from no CSP; a bare `Server: nginx` is not
  flagged while `Server: nginx/1.18.0` is.
- A Content-Security-Policy parser with `default-src` fallback as specified.
- Every `Set-Cookie` header audited, not only the first — the fetch layer
  collects all values for a repeated header name rather than the first.
- Score out of 100 with severity-weighted deductions, and an A–F grade.
- Text and JSON output, plus `--min-score` for use as a CI gate.
- Library API (`headerscan::analyze::analyze`) taking a header set rather than
  a URL, so the rule set is usable and testable without a network.

### Notes

- Minimum supported Rust version is 1.88. That floor comes from the `icu_*`
  crates reached through `ureq` → `url` → `idna`, not from this crate's own
  code, and is enforced by a dedicated CI job.

### Security

- `unsafe_code = "forbid"` at the crate level.
- No response body is retained; only headers are read.
- TLS through rustls rather than OpenSSL.

[0.1.0]: https://github.com/hellpuffyt/headerscan/releases/tag/v0.1.0
