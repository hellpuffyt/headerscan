# headerscan

Audit HTTP response security headers, grade them, and explain the actual risk —
not just which headers are absent.

[![CI](https://github.com/hellpuffyt/headerscan/actions/workflows/ci.yml/badge.svg)](https://github.com/hellpuffyt/headerscan/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## What is it?

A single static binary that fetches a URL and reports what its security headers
actually protect against.

```console
$ headerscan example.com
https://example.com/  200 grade C (74/100)
  high     Content-Security-Policy: not set, so the page has no script-injection defence in depth [csp-missing]
           fix: Start with: default-src 'self'; object-src 'none'; frame-ancestors 'none'
  medium   X-Content-Type-Options: not set, so browsers may MIME-sniff responses into a different type [nosniff-missing]
           fix: Add: X-Content-Type-Options: nosniff
  low      Permissions-Policy: not set, so powerful features are governed only by browser defaults [permissions-policy-missing]
           fix: Add a policy disabling what you do not use, e.g. camera=(), geolocation=()
```

## Why does it exist?

Most header scanners produce a checklist: header present, header absent, done.
That misses the cases where a header is present and still useless, which is
where real deployments actually go wrong.

headerscan understands context:

- **HSTS on a plain HTTP response is reported as ineffective**, because browsers
  ignore it there. A checklist scanner ticks it off as present.
- **`max-age=0` is flagged as high severity**, not as "HSTS present" — it tells
  browsers to *forget* the policy.
- **`'unsafe-inline'` in `script-src` is high; in `style-src` it is low.**
  Grading them identically buries the finding that matters.
- **A report-only CSP is distinguished from no CSP**, because it is a real
  deployment stage rather than an equivalent failure.
- **`Server: nginx` is not flagged; `Server: nginx/1.18.0` is.** A bare product
  name tells an attacker little. A version maps onto a CVE list.
- **`Secure` on cookies is only required over HTTPS**, so scanning a local dev
  server does not produce noise you learn to ignore.

Every finding carries a stable code, a description of the actual risk, and the
remediation — because "add this header" without "here is what it stops" is how
security advice gets ignored.

## Features

- **29 checks** across HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, COOP, clickjacking, CORS, cookie attributes, and version
  disclosure.
- **Scheme-aware**: several verdicts change between HTTP and HTTPS rather than
  only their wording.
- **A real CSP parser**, with `default-src` fallback exactly as the
  specification defines it.
- **All cookies audited**, not just the first `Set-Cookie`.
- **Grade out of 100** with severity-weighted deductions.
- **Text and JSON output**, and `--min-score` for use as a CI gate.
- **No `unsafe` code** (`unsafe_code = "forbid"`), clippy pedantic clean.

## Architecture

```
main.rs      CLI, exit codes
  └─ fetch.rs    URL → headers          (the only module doing I/O)
  └─ analyze.rs  headers → findings     (pure; every rule lives here)
  └─ headers.rs  case-insensitive access, HSTS/CSP/cookie parsers
  └─ report.rs   findings → text / JSON
```

`analyze` takes a header set and a scheme flag rather than a URL. That is the
design decision the rest follows from: it means the entire rule set is testable
without a network, which is why the checks here have real tests rather than the
handful that live scanning permits.

## Installation

```bash
cargo install headerscan
```

From source:

```bash
git clone https://github.com/hellpuffyt/headerscan
cd headerscan
cargo build --release
./target/release/headerscan example.com
```

Requires Rust 1.74 or newer.

## Usage

```bash
headerscan example.com                      # scheme defaults to https
headerscan https://a.com https://b.com      # several targets
headerscan --format json example.com        # machine-readable
headerscan --min-score 80 example.com       # non-zero exit below 80
headerscan --no-redirects example.com       # audit the first response
headerscan --timeout 30 slow.example.com
```

| Option | Description |
| --- | --- |
| `-f`, `--format <text\|json>` | Output format (default `text`) |
| `-t`, `--timeout <secs>` | Request timeout (default `10`) |
| `--min-score <n>` | Exit non-zero if any target scores below `n` |
| `--no-redirects` | Do not follow redirects |
| `--no-colour` | Disable ANSI colour |

Exit codes: `0` all targets met the threshold, `1` a target scored below
`--min-score` or a request failed, `2` internal error.

An unreachable host does not abandon the remaining targets — it is reported and
the scan continues.

## Examples

**As a CI gate:**

```yaml
- name: Security headers must not regress
  run: |
    cargo install headerscan
    headerscan --min-score 85 https://staging.example.com
```

**JSON for further processing:**

```console
$ headerscan --format json example.com | jq '.summary'
{
  "targets": 1,
  "lowest_score": 74,
  "lowest_grade": "C",
  "findings": 4
}
```

**As a library:**

```rust
use headerscan::analyze::analyze;
use headerscan::headers::Headers;

let headers = Headers::from_pairs([
    ("strict-transport-security", "max-age=31536000; includeSubDomains"),
    ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
]);
let report = analyze("https://example.com", 200, &headers, true);
println!("{} ({}/100)", report.grade, report.score);
```

## Findings reference

| Code | Severity | Meaning |
| --- | --- | --- |
| `hsts-missing` | high | No HSTS on an HTTPS response |
| `hsts-zero-max-age` | high | `max-age=0` tells browsers to forget the policy |
| `hsts-no-max-age` | high | No parseable `max-age`, so nothing is stored |
| `hsts-over-http` | medium | Set on plain HTTP, where it is ignored |
| `hsts-short-max-age` | low | Below the six-month floor |
| `hsts-no-subdomains` | low | `includeSubDomains` omitted |
| `csp-missing` | high | No Content-Security-Policy |
| `csp-empty` | high | Header present but declares nothing |
| `csp-unsafe-inline` | high / low | High in `script-src`, low elsewhere |
| `csp-wildcard-script-src` | high | Scripts allowed from any origin |
| `csp-unsafe-eval` | medium | String-to-code evaluation permitted |
| `csp-report-only` | medium | Only a report-only policy; nothing is blocked |
| `csp-no-default-src` | medium | No backstop for undeclared resource types |
| `csp-no-object-src` | low | Plugin content unrestricted |
| `clickjacking-unprotected` | medium | Neither `frame-ancestors` nor `X-Frame-Options` is set |
| `nosniff-missing` / `nosniff-invalid` | medium | MIME sniffing not prevented |
| `referrer-policy-unsafe` | medium | `unsafe-url` leaks full URLs cross-origin |
| `referrer-policy-missing` | low | Browser default governs referrer leakage |
| `cors-wildcard-with-credentials` | high | `*` with credentials; origin check not being done |
| `cookie-samesite-none-insecure` | high | `SameSite=None` without `Secure`; browsers reject it |
| `cookie-no-httponly` | medium | Cookie readable from JavaScript |
| `cookie-no-secure` | medium | Cookie may travel over plain HTTP |
| `cookie-no-samesite` | low | Relies on the browser default |
| `permissions-policy-missing` | low | Powerful features ungoverned |
| `coop-missing` | low | Shares a browsing context group with openers |
| `version-disclosure` | low | A header discloses a software version |

Scoring deducts 15 per high, 8 per medium, 3 per low, from 100.
Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, E ≥ 50, F below.

## Testing

```bash
cargo test              # unit + integration
cargo clippy --all-targets
cargo fmt --check
```

The suite has two layers. Unit tests cover every rule as a pure function,
including the false-positive guards — the `Server: nginx` case, `unsafe-inline`
severity by directive, `Secure` not required over HTTP. Integration tests run a
real local HTTP server, which is what catches the things rules cannot see:
mixed-case header names surviving the wire, repeated `Set-Cookie` lines all
being audited, and a 404 still being scanned rather than treated as a failure.

The hand-rolled test server is deliberate — it lets a test emit duplicated or
malformed headers that a real framework would refuse to send.

## Deployment

Static binary, no runtime dependencies:

```bash
cargo build --release   # ./target/release/headerscan
```

Release builds enable LTO and strip symbols.

## Security

- **`unsafe_code = "forbid"`** at the crate level.
- **Read-only.** It issues one GET per target and never sends credentials,
  follows at most five redirects, and writes nothing anywhere.
- **No response body is retained** — only headers are read, so scanning a page
  cannot spill its content into your logs.
- **TLS via rustls**, not OpenSSL.
- Scan only hosts you are authorised to test. It is a passive audit of one
  response, but that is still a request to someone else's server.

## Roadmap

- Concurrent scanning for large target lists.
- `Cache-Control` checks for responses that look authenticated.
- SARIF output for GitHub code scanning.

## License

MIT — see [LICENSE](LICENSE).
