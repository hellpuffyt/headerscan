# Production readiness — headerscan

Audit date: 2026-10-22. Branch: `audit/production-readiness`.
Tested commit: `b186492` (the final commit adds only this file).

## Scope

`headerscan` fetches each target URL once (GET, `ureq` + rustls, at most
5 redirects, configurable timeout), reads only the response headers, and
grades them with 29 finding codes (27 graded, 2 informational) across
HSTS, CSP, nosniff, Referrer-Policy, Permissions-Policy, COOP,
clickjacking, CORS, cookies and version disclosure. `analyze` is a pure
function of headers + scheme; `fetch` is the only I/O. Text and JSON
output; `--min-score` exit-code gate.

## Platforms and prerequisites

- Rust 1.88+ (forced by `ureq` → `url` → `idna` → `icu_*`).
  `cargo +1.88 check --all-targets --locked` passed on the audit host
  after the dependency updates.
- Verified on macOS 27 (Apple M5). CI covers Linux, macOS, Windows.
- **No test contacts the internet.** All network tests use servers bound
  to `127.0.0.1` inside the test process. HTTPS behaviour is covered at
  the unit level only (the client trusts only public web PKI roots, so a
  local TLS test server would need a public certificate).

## Clean-clone verification (literal README steps)

```
git clone -b audit/production-readiness <repo> headerscan && cd headerscan
cargo build --release                      # exit 0
cargo test                                 # exit 0 — 70 passed (54 lib, 7 end_to_end, 8 cli_end_to_end, 1 doctest), 0 failed, 0 ignored
cargo clippy --all-targets                 # exit 0, no warnings
cargo fmt --check                          # exit 0
cargo install --locked --path . --root <scratch>/inst   # exit 0
./target/release/headerscan http://127.0.0.1:<local server>/   # exit 0, grade A (100/100), 1 info finding
./target/release/headerscan --min-score 80 http://127.0.0.1:<local server>/   # exit 0
```

The README's `headerscan example.com` line was replaced by a local
target because this audit does not scan third-party hosts.

## Commands and results (audit host)

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | 0 | clean (pedantic + `missing_docs`) |
| `cargo test --all-targets --locked` (baseline) | 0 | 55 passed, 0 failed, 0 ignored (+1 doctest) |
| `cargo test --all-targets --locked` (after) | 0 | 69 passed, 0 failed, 0 ignored (+1 doctest) |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` | 0 | clean |
| `cargo audit --db <local advisory-db> --no-fetch` (baseline) | 1 | **6 vulnerabilities** in `rustls` 0.23.43, `rustls-webpki` 0.103.15, `webpki-roots` 1.0.9 |
| same (after `cargo update -p rustls -p rustls-webpki -p webpki-roots@1.0.9`) | 0 | 0 vulnerabilities in 94 crates |
| `cargo +1.88 check --all-targets --locked` | 0 | MSRV still holds |
| `cargo deny check` | — | not configured |

## CI status

Default branch: `success` (run on `f391624`, 2026-08-30).
Audit branch: pending until pushed. Actions pinned by tag; unchanged.

## Bugs found and fixed (each with a regression test)

| # | Severity | Defect | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | High (dependencies) | RUSTSEC-2026-0285/-0346/-0348/-0349 (rustls), -0382 (rustls-webpki), -0381 (webpki-roots). | Lockfile updates within semver. | `cargo audit` exit 0 |
| 2 | High (wrong grade) | Repeated headers were collected once per header line: 3 `Set-Cookie` lines → each cookie finding reported 3×, score 0 instead of 61. | Iterate distinct names. | `end_to_end::each_repeated_cookie_is_audited_exactly_once` |
| 3 | Medium (false negative / false positive) | `csp-unsafe-inline` severity used the directive *name*: `default-src 'self' 'unsafe-inline'` (inline scripts run) was Low; `script-src 'nonce-…' 'unsafe-inline'` (ignored by browsers) was High. | Severity from effective `script-src`/`-elem`/`-attr`, honouring nonce/hash/`'strict-dynamic'`. | `analyze::tests::csp::{unsafe_inline_in_default_src_without_script_src_is_high, unsafe_inline_ignored_because_of_a_nonce_or_hash_is_low, script_src_without_unsafe_inline_overrides_default_src}` |
| 4 | Medium (silent false negative) | `ureq` withholds header values with non-ASCII bytes; such a cookie was neither audited nor mentioned. | Counted and reported as `header-unreadable` (info). | `end_to_end::a_header_value_with_non_ascii_bytes_is_reported_not_silently_skipped` |
| 5 | Low (hardening) | Server-controlled strings (cookie names, CSP directive names, URL) printed raw to the terminal. | `sanitize_for_terminal` escapes control and bidi characters. | `report::tests::server_controlled_text_cannot_inject_terminal_escapes`, `cli_end_to_end::hostile_header_values_cannot_inject_terminal_escapes` |
| 6 | Docs | `cargo install headerscan` cannot work (not on crates.io); README example output and JSON summary (3 findings shown, "findings: 4") could not be reproduced; "29 checks" matched no count in the code. | Install from git; examples replaced with real local runs; count stated precisely; info codes added to the table. | clean-clone run |

New coverage without a code change: `--min-score` exit codes, JSON
summary consistency, redirects (followed / `--no-redirects` / chain of 7
stops before the final 200), timeout against a silent server (<5 s with
`--timeout 1`), unreachable + reachable targets in one run.

## Security review

- `unsafe_code = "forbid"`; only GET requests; no credentials sent; the
  body is never read (ureq drops it); bounded redirects and timeout.
- TLS: rustls with webpki roots, updated past six advisories.
- Output: escaped as above; JSON output is serde-escaped.
- SSRF: not applicable (operator-supplied URLs, CLI only).
- Secret scan of the tree and full history: no hits.
- Workflow permissions: `contents: read`.

## Known limitations

- Only the first `Content-Security-Policy` header is evaluated; multiple
  policies (which browsers intersect) can produce false positives, never
  false negatives.
- `https:`/`http:` scheme sources in `script-src` are not treated as
  wildcards; `X-Frame-Options` values are not validated.
- No local HTTPS test (see above).
- `cargo deny` not configured.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
| --- | --- | --- | --- | --- | --- |
| Rule set | Each rule incl. false-positive guards | `cargo test --lib` | pass | 54/54 | `src/analyze.rs` |
| Headers over the wire | Case-insensitive; repeated cookies audited once each | `cargo test --test end_to_end` | pass (dup case failed before) | 7/7 | `src/fetch.rs` |
| CLI behaviour | exit codes, JSON, redirects, timeout, multiple targets | `cargo test --test cli_end_to_end` | pass | 8/8 | `src/main.rs` |
| Dependency hygiene | No known advisories | `cargo audit` | pass (failed before) | 0 | `Cargo.lock` |
| Terminal safety | No raw control/bidi characters from servers | unit + e2e tests | pass | escaped | `src/report.rs` |
| Local-only testing | No internet access in tests | test sources | pass | 127.0.0.1 only | `tests/` |
| Lint/docs | fmt, clippy, rustdoc `-D warnings`, MSRV check | table above | pass | clean | — |

## Classification proposal

**Partially Verified** — the documented scope is tested against local
servers on macOS with real grading and dependency defects fixed; not yet
verified: HTTPS fetches end-to-end (no local trusted TLS endpoint), and
the audit branch's CI on Linux/Windows.
