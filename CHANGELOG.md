# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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

### Security

- `unsafe_code = "forbid"` at the crate level.
- No response body is retained; only headers are read.
- TLS through rustls rather than OpenSSL.

[0.1.0]: https://github.com/hellpuffyt/headerscan/releases/tag/v0.1.0
