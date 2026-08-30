# Contributing

## Getting set up

```bash
git clone https://github.com/hellpuffyt/headerscan
cd headerscan
cargo test
```

## Before opening a pull request

CI runs exactly these:

```bash
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
```

## Adding a check

Checks live in `src/analyze.rs` and are pure functions of a `Headers` set plus
an `is_https` flag. Keep them that way — `analyze` never performs I/O, and that
is the reason this project has a real test suite instead of the handful of
tests live scanning permits.

1. Give the finding a **stable kebab-case code**. Codes are a public interface;
   people grep for them in CI logs, so renaming one is a breaking change.
2. Write the `message` as *what the risk is*, not *which header is absent*.
   "not set, so browsers may MIME-sniff responses into a different type" is
   useful; "X-Content-Type-Options missing" is not.
3. Always provide `remediation` with the literal header to add.
4. Pick severity by consequence, not by header importance in the abstract. The
   `csp-unsafe-inline` rule grades `script-src` high and `style-src` low for
   precisely this reason.
5. Add tests in both directions. **A check without a false-positive test will
   not be merged** — a noisy scanner is one people stop running, which is worse
   than no scanner.
6. Document the code in the findings table in `README.md`, and add a changelog
   entry.

## Severity guidance

| Severity | Use when |
| --- | --- |
| high | A control is absent or actively defeated |
| medium | A control is missing or misconfigured |
| low | A defence is weakened but not defeated |
| info | Worth knowing; no action implied |

## Reporting a bug

Include the response headers that reproduce it. `curl -sI https://example.com`
is usually enough. Redact anything sensitive — cookie *values* are never needed
to reproduce a cookie finding, only the attributes.
