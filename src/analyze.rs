//! The checks.
//!
//! Every check is a pure function of a [`Headers`] set plus the scheme the
//! response was served over, so the whole rule set is testable without a
//! network. That matters here more than usual: a security scanner whose rules
//! can only be exercised against live sites is a scanner whose rules are never
//! exercised.

use serde::Serialize;

use crate::headers::{parse_cookie, parse_hsts, Csp, Headers};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, no action implied.
    Info,
    /// Weakens a defence.
    Low,
    /// A missing or misconfigured control.
    Medium,
    /// A control that is absent or actively defeated.
    High,
}

impl Severity {
    /// Points deducted from the score.
    const fn weight(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 3,
            Self::Medium => 8,
            Self::High => 15,
        }
    }

    /// Lowercase label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One thing worth reporting about a response.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier, safe to grep for in CI logs.
    pub code: String,
    /// How serious it is.
    pub severity: Severity,
    /// The header the finding concerns, if any.
    pub header: Option<String>,
    /// What is wrong.
    pub message: String,
    /// What to do about it.
    pub remediation: String,
}

impl Finding {
    fn new(
        code: &str,
        severity: Severity,
        header: Option<&str>,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code: code.to_owned(),
            severity,
            header: header.map(str::to_owned),
            message: message.into(),
            remediation: remediation.into(),
        }
    }
}

/// The result of auditing one response.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The URL audited.
    pub url: String,
    /// The HTTP status observed.
    pub status: u16,
    /// Score out of 100.
    pub score: u32,
    /// Letter grade derived from the score.
    pub grade: char,
    /// Everything found, most severe first.
    pub findings: Vec<Finding>,
}

/// Six months, the minimum `max-age` the HSTS preload list requires is a year,
/// but six months is the widely used floor below which the header buys little.
const HSTS_MIN_MAX_AGE: u64 = 15_552_000;

/// Headers that disclose software versions to no benefit.
const DISCLOSURE_HEADERS: [&str; 4] = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
];

fn check_hsts(headers: &Headers, is_https: bool, findings: &mut Vec<Finding>) {
    let Some(value) = headers.get("strict-transport-security") else {
        if is_https {
            findings.push(Finding::new(
                "hsts-missing",
                Severity::High,
                Some("Strict-Transport-Security"),
                "not set, so a browser will still try plain HTTP on the next visit",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            ));
        } else {
            findings.push(Finding::new(
                "hsts-not-applicable",
                Severity::Info,
                Some("Strict-Transport-Security"),
                "not set, and would be ignored over plain HTTP anyway",
                "Serve this origin over HTTPS, then set HSTS on the HTTPS response",
            ));
        }
        return;
    };

    // A browser ignores HSTS delivered over plain HTTP, so a site that sets it
    // there has a control that does nothing.
    if !is_https {
        findings.push(Finding::new(
            "hsts-over-http",
            Severity::Medium,
            Some("Strict-Transport-Security"),
            "set on a plain HTTP response, where browsers ignore it entirely",
            "Set HSTS on the HTTPS response instead; it has no effect here",
        ));
        return;
    }

    let hsts = parse_hsts(value);
    match hsts.max_age {
        None => findings.push(Finding::new(
            "hsts-no-max-age",
            Severity::High,
            Some("Strict-Transport-Security"),
            "has no parseable max-age, so the policy is not stored",
            "Add a max-age directive, for example max-age=31536000",
        )),
        Some(0) => findings.push(Finding::new(
            "hsts-zero-max-age",
            Severity::High,
            Some("Strict-Transport-Security"),
            "uses max-age=0, which instructs browsers to forget the policy",
            "Set max-age=31536000 unless you are deliberately rolling HSTS back",
        )),
        Some(age) if age < HSTS_MIN_MAX_AGE => findings.push(Finding::new(
            "hsts-short-max-age",
            Severity::Low,
            Some("Strict-Transport-Security"),
            format!("max-age is {age}s, below the six-month floor most guidance uses"),
            "Raise max-age to at least 15552000, ideally 31536000",
        )),
        Some(_) => {}
    }

    if !hsts.include_subdomains {
        findings.push(Finding::new(
            "hsts-no-subdomains",
            Severity::Low,
            Some("Strict-Transport-Security"),
            "omits includeSubDomains, leaving subdomains reachable over HTTP",
            "Add includeSubDomains once every subdomain is HTTPS-ready",
        ));
    }
}

fn check_csp(headers: &Headers, findings: &mut Vec<Finding>) {
    let Some(value) = headers.get("content-security-policy") else {
        // Report-only is a real deployment stage, so say something useful
        // rather than treating it as equivalent to nothing.
        if headers.has("content-security-policy-report-only") {
            findings.push(Finding::new(
                "csp-report-only",
                Severity::Medium,
                Some("Content-Security-Policy"),
                "only a report-only policy is set, so nothing is actually blocked",
                "Promote the tested policy to Content-Security-Policy to enforce it",
            ));
        } else {
            findings.push(Finding::new(
                "csp-missing",
                Severity::High,
                Some("Content-Security-Policy"),
                "not set, so the page has no script-injection defence in depth",
                "Start with: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            ));
        }
        return;
    };

    let csp = Csp::parse(value);
    if csp.is_empty() {
        findings.push(Finding::new(
            "csp-empty",
            Severity::High,
            Some("Content-Security-Policy"),
            "is present but declares no directives",
            "Set a real policy, or remove the header so its absence is honest",
        ));
        return;
    }

    if !csp.has("default-src") {
        findings.push(Finding::new(
            "csp-no-default-src",
            Severity::Medium,
            Some("Content-Security-Policy"),
            "has no default-src, so undeclared resource types are unrestricted",
            "Add default-src 'self' (or 'none') as a backstop",
        ));
    }

    let unsafe_inline = csp.directives_containing("'unsafe-inline'");
    if !unsafe_inline.is_empty() {
        // Only script-src matters much; 'unsafe-inline' in style-src is a far
        // smaller problem and reporting both at High would be noise.
        let severity = if unsafe_inline.iter().any(|d| d.starts_with("script")) {
            Severity::High
        } else {
            Severity::Low
        };
        findings.push(Finding::new(
            "csp-unsafe-inline",
            severity,
            Some("Content-Security-Policy"),
            format!("allows 'unsafe-inline' in: {}", unsafe_inline.join(", ")),
            "Replace inline code with nonces or hashes, then drop 'unsafe-inline'",
        ));
    }

    if !csp.directives_containing("'unsafe-eval'").is_empty() {
        findings.push(Finding::new(
            "csp-unsafe-eval",
            Severity::Medium,
            Some("Content-Security-Policy"),
            "allows 'unsafe-eval', which permits string-to-code evaluation",
            "Remove 'unsafe-eval'; most frameworks no longer need it",
        ));
    }

    if let Some(sources) = csp.effective("script-src") {
        if sources.iter().any(|s| s == "*") {
            findings.push(Finding::new(
                "csp-wildcard-script-src",
                Severity::High,
                Some("Content-Security-Policy"),
                "allows scripts from any origin via a wildcard source",
                "Name the origins you actually load scripts from",
            ));
        }
    }

    if !csp.has("object-src") && !csp.has("default-src") {
        findings.push(Finding::new(
            "csp-no-object-src",
            Severity::Low,
            Some("Content-Security-Policy"),
            "does not restrict object-src, leaving plugin content unrestricted",
            "Add object-src 'none'",
        ));
    }
}

/// Clickjacking is covered by either `frame-ancestors` or `X-Frame-Options`.
///
/// This deliberately lives outside [`check_csp`], which returns early when no
/// policy is present at all. Keeping it there meant the worst case — no CSP and
/// no `X-Frame-Options` — was the one case that produced no finding.
fn check_clickjacking(headers: &Headers, findings: &mut Vec<Finding>) {
    let framed_by_csp = headers
        .get("content-security-policy")
        .is_some_and(|value| Csp::parse(value).has("frame-ancestors"));

    if framed_by_csp || headers.has("x-frame-options") {
        return;
    }

    findings.push(Finding::new(
        "clickjacking-unprotected",
        Severity::Medium,
        Some("Content-Security-Policy"),
        "neither frame-ancestors nor X-Frame-Options is set, so the page may be framed",
        "Add frame-ancestors 'none' (or 'self') to the policy, or set X-Frame-Options: DENY",
    ));
}

fn check_simple_headers(headers: &Headers, findings: &mut Vec<Finding>) {
    match headers.get("x-content-type-options") {
        None => findings.push(Finding::new(
            "nosniff-missing",
            Severity::Medium,
            Some("X-Content-Type-Options"),
            "not set, so browsers may MIME-sniff responses into a different type",
            "Add: X-Content-Type-Options: nosniff",
        )),
        Some(value) if !value.trim().eq_ignore_ascii_case("nosniff") => {
            findings.push(Finding::new(
                "nosniff-invalid",
                Severity::Medium,
                Some("X-Content-Type-Options"),
                format!("is {value:?}, but nosniff is the only valid value"),
                "Set exactly: X-Content-Type-Options: nosniff",
            ));
        }
        Some(_) => {}
    }

    match headers.get("referrer-policy") {
        None => findings.push(Finding::new(
            "referrer-policy-missing",
            Severity::Low,
            Some("Referrer-Policy"),
            "not set, so the browser default governs what leaks in the Referer header",
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
        )),
        Some(value) if value.to_ascii_lowercase().contains("unsafe-url") => {
            findings.push(Finding::new(
                "referrer-policy-unsafe",
                Severity::Medium,
                Some("Referrer-Policy"),
                "is unsafe-url, which sends full URLs including paths to other origins",
                "Use strict-origin-when-cross-origin instead",
            ));
        }
        Some(_) => {}
    }

    if !headers.has("permissions-policy") {
        findings.push(Finding::new(
            "permissions-policy-missing",
            Severity::Low,
            Some("Permissions-Policy"),
            "not set, so powerful features are governed only by browser defaults",
            "Add a policy disabling what you do not use, e.g. camera=(), geolocation=()",
        ));
    }

    if !headers.has("cross-origin-opener-policy") {
        findings.push(Finding::new(
            "coop-missing",
            Severity::Low,
            Some("Cross-Origin-Opener-Policy"),
            "not set, so the page shares a browsing context group with openers",
            "Add: Cross-Origin-Opener-Policy: same-origin",
        ));
    }

    for name in DISCLOSURE_HEADERS {
        if let Some(value) = headers.get(name) {
            // A bare product name tells an attacker little; a version string
            // maps directly onto a CVE list, so only that is worth flagging.
            if value.chars().any(|c| c.is_ascii_digit()) {
                findings.push(Finding::new(
                    "version-disclosure",
                    Severity::Low,
                    Some(name),
                    format!("discloses a version: {value:?}"),
                    "Suppress the version, or remove the header entirely",
                ));
            }
        }
    }
}

fn check_cors(headers: &Headers, findings: &mut Vec<Finding>) {
    if let Some(origin) = headers.get("access-control-allow-origin") {
        let credentials = headers
            .get("access-control-allow-credentials")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
        if origin.trim() == "*" && credentials {
            findings.push(Finding::new(
                "cors-wildcard-with-credentials",
                Severity::High,
                Some("Access-Control-Allow-Origin"),
                "is * while credentials are allowed, which browsers reject and which \
                 signals the origin check is not being done",
                "Echo a specific allowed origin instead of *, from an allowlist",
            ));
        }
    }
}

fn check_cookies(headers: &Headers, is_https: bool, findings: &mut Vec<Finding>) {
    for raw in headers.get_all("set-cookie") {
        let cookie = parse_cookie(raw);
        let name = if cookie.name.is_empty() {
            "<unnamed>".to_owned()
        } else {
            cookie.name.clone()
        };

        if !cookie.http_only {
            findings.push(Finding::new(
                "cookie-no-httponly",
                Severity::Medium,
                Some("Set-Cookie"),
                format!("cookie {name} is readable from JavaScript (no HttpOnly)"),
                "Add HttpOnly unless a script genuinely needs to read it",
            ));
        }
        if !cookie.secure && is_https {
            findings.push(Finding::new(
                "cookie-no-secure",
                Severity::Medium,
                Some("Set-Cookie"),
                format!("cookie {name} may be sent over plain HTTP (no Secure)"),
                "Add Secure so the cookie is HTTPS-only",
            ));
        }
        match cookie.same_site.as_deref() {
            None => findings.push(Finding::new(
                "cookie-no-samesite",
                Severity::Low,
                Some("Set-Cookie"),
                format!("cookie {name} sets no SameSite, relying on the browser default"),
                "Set SameSite=Lax, or Strict for session cookies",
            )),
            Some("none") if !cookie.secure => findings.push(Finding::new(
                "cookie-samesite-none-insecure",
                Severity::High,
                Some("Set-Cookie"),
                format!("cookie {name} is SameSite=None without Secure, so browsers reject it"),
                "Add Secure alongside SameSite=None",
            )),
            Some(_) => {}
        }
    }
}

/// Audit a response.
///
/// `is_https` changes several verdicts rather than only the wording: HSTS is
/// meaningless over plain HTTP, and a missing `Secure` cookie attribute is only
/// a finding when the response arrived over TLS.
#[must_use]
pub fn analyze(url: &str, status: u16, headers: &Headers, is_https: bool) -> Report {
    let mut findings = Vec::new();

    check_hsts(headers, is_https, &mut findings);
    check_csp(headers, &mut findings);
    check_clickjacking(headers, &mut findings);
    check_simple_headers(headers, &mut findings);
    check_cors(headers, &mut findings);
    check_cookies(headers, is_https, &mut findings);

    // Most severe first, then by code so output is stable run to run.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.cmp(&b.code))
    });

    let deductions: u32 = findings.iter().map(|f| f.severity.weight()).sum();
    let score = 100_u32.saturating_sub(deductions);

    Report {
        url: url.to_owned(),
        status,
        score,
        grade: grade_for(score),
        findings,
    }
}

/// Letter grade for a score.
#[must_use]
pub const fn grade_for(score: u32) -> char {
    match score {
        90..=u32::MAX => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        50..=59 => 'E',
        _ => 'F',
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a failing expect in a test is the test failure we want"
)]
mod tests {
    use super::*;

    fn codes(report: &Report) -> Vec<&str> {
        report.findings.iter().map(|f| f.code.as_str()).collect()
    }

    /// A response that should pass every check.
    fn hardened() -> Headers {
        Headers::from_pairs([
            (
                "strict-transport-security",
                "max-age=31536000; includeSubDomains",
            ),
            (
                "content-security-policy",
                "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            ),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            ("permissions-policy", "camera=(), geolocation=()"),
            ("cross-origin-opener-policy", "same-origin"),
        ])
    }

    #[test]
    fn a_hardened_response_scores_full_marks() {
        let report = analyze("https://x.test", 200, &hardened(), true);
        assert_eq!(report.findings.len(), 0, "unexpected: {:?}", codes(&report));
        assert_eq!(report.score, 100);
        assert_eq!(report.grade, 'A');
    }

    #[test]
    fn a_bare_response_fails_badly() {
        let report = analyze("https://x.test", 200, &Headers::new(), true);
        assert!(codes(&report).contains(&"hsts-missing"));
        assert!(codes(&report).contains(&"csp-missing"));
        assert!(codes(&report).contains(&"nosniff-missing"));
        assert_eq!(report.grade, 'F');
    }

    #[test]
    fn clickjacking_is_reported_when_there_is_no_csp_at_all() {
        // Regression: this check used to live inside the CSP check, which
        // returns early when no policy is present — so the worst case, no CSP
        // and no X-Frame-Options, was the one case that produced no finding.
        let report = analyze("https://x.test", 200, &Headers::new(), true);
        assert!(
            codes(&report).contains(&"clickjacking-unprotected"),
            "got {:?}",
            codes(&report)
        );
    }

    #[test]
    fn clickjacking_is_satisfied_by_x_frame_options_without_any_csp() {
        let headers = Headers::from_pairs([("x-frame-options", "DENY")]);
        let report = analyze("https://x.test", 200, &headers, true);
        assert!(!codes(&report).contains(&"clickjacking-unprotected"));
    }

    #[test]
    fn clickjacking_is_satisfied_by_frame_ancestors() {
        let headers = Headers::from_pairs([(
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'",
        )]);
        let report = analyze("https://x.test", 200, &headers, true);
        assert!(!codes(&report).contains(&"clickjacking-unprotected"));
    }

    #[test]
    fn findings_are_ordered_most_severe_first() {
        let report = analyze("https://x.test", 200, &Headers::new(), true);
        let severities: Vec<_> = report.findings.iter().map(|f| f.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(severities, sorted);
    }

    mod hsts {
        use super::*;

        #[test]
        fn missing_over_http_is_only_informational() {
            let report = analyze("http://x.test", 200, &Headers::new(), false);
            assert!(codes(&report).contains(&"hsts-not-applicable"));
            assert!(!codes(&report).contains(&"hsts-missing"));
        }

        #[test]
        fn set_over_http_is_flagged_as_ineffective() {
            let headers = Headers::from_pairs([("strict-transport-security", "max-age=31536000")]);
            let report = analyze("http://x.test", 200, &headers, false);
            assert!(codes(&report).contains(&"hsts-over-http"));
        }

        #[test]
        fn zero_max_age_is_high_severity() {
            let headers = Headers::from_pairs([("strict-transport-security", "max-age=0")]);
            let report = analyze("https://x.test", 200, &headers, true);
            let finding = report
                .findings
                .iter()
                .find(|f| f.code == "hsts-zero-max-age")
                .expect("finding");
            assert_eq!(finding.severity, Severity::High);
        }

        #[test]
        fn short_max_age_is_low_severity() {
            let headers = Headers::from_pairs([(
                "strict-transport-security",
                "max-age=600; includeSubDomains",
            )]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"hsts-short-max-age"));
        }

        #[test]
        fn unparseable_max_age_is_reported() {
            let headers = Headers::from_pairs([("strict-transport-security", "includeSubDomains")]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"hsts-no-max-age"));
        }
    }

    mod csp {
        use super::*;

        #[test]
        fn report_only_is_distinguished_from_absent() {
            let headers = Headers::from_pairs([(
                "content-security-policy-report-only",
                "default-src 'self'",
            )]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"csp-report-only"));
            assert!(!codes(&report).contains(&"csp-missing"));
        }

        #[test]
        fn unsafe_inline_in_script_src_is_high() {
            let headers = Headers::from_pairs([(
                "content-security-policy",
                "default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'",
            )]);
            let report = analyze("https://x.test", 200, &headers, true);
            let finding = report
                .findings
                .iter()
                .find(|f| f.code == "csp-unsafe-inline")
                .expect("finding");
            assert_eq!(finding.severity, Severity::High);
        }

        #[test]
        fn unsafe_inline_in_style_src_only_is_low() {
            // Inline styles are a much smaller problem than inline scripts;
            // grading them the same would drown the real finding in noise.
            let headers = Headers::from_pairs([(
                "content-security-policy",
                "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            )]);
            let report = analyze("https://x.test", 200, &headers, true);
            let finding = report
                .findings
                .iter()
                .find(|f| f.code == "csp-unsafe-inline")
                .expect("finding");
            assert_eq!(finding.severity, Severity::Low);
        }

        #[test]
        fn wildcard_script_src_is_flagged() {
            let headers = Headers::from_pairs([(
                "content-security-policy",
                "default-src 'self'; script-src *; frame-ancestors 'none'",
            )]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"csp-wildcard-script-src"));
        }

        #[test]
        fn x_frame_options_satisfies_the_clickjacking_check() {
            let headers = Headers::from_pairs([
                ("content-security-policy", "default-src 'self'"),
                ("x-frame-options", "DENY"),
            ]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(!codes(&report).contains(&"clickjacking-unprotected"));
        }

        #[test]
        fn an_empty_policy_is_worse_than_a_partial_one() {
            let headers = Headers::from_pairs([("content-security-policy", "   ")]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"csp-empty"));
        }
    }

    mod misc {
        use super::*;

        #[test]
        fn invalid_nosniff_value_is_flagged() {
            let headers = Headers::from_pairs([("x-content-type-options", "sniff")]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"nosniff-invalid"));
        }

        #[test]
        fn unsafe_referrer_policy_is_flagged() {
            let headers = Headers::from_pairs([("referrer-policy", "unsafe-url")]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"referrer-policy-unsafe"));
        }

        #[test]
        fn a_versionless_server_header_is_not_flagged() {
            // "nginx" tells an attacker little; "nginx/1.18.0" maps to a CVE list.
            let bare = Headers::from_pairs([("server", "nginx")]);
            let versioned = Headers::from_pairs([("server", "nginx/1.18.0")]);
            assert!(!codes(&analyze("https://x.test", 200, &bare, true))
                .contains(&"version-disclosure"));
            assert!(codes(&analyze("https://x.test", 200, &versioned, true))
                .contains(&"version-disclosure"));
        }

        #[test]
        fn wildcard_cors_with_credentials_is_high() {
            let headers = Headers::from_pairs([
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true"),
            ]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(codes(&report).contains(&"cors-wildcard-with-credentials"));
        }

        #[test]
        fn wildcard_cors_without_credentials_is_fine() {
            let headers = Headers::from_pairs([("access-control-allow-origin", "*")]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(!codes(&report).contains(&"cors-wildcard-with-credentials"));
        }
    }

    mod cookies {
        use super::*;

        #[test]
        fn a_bare_cookie_trips_every_attribute_check() {
            let headers = Headers::from_pairs([("set-cookie", "session=abc")]);
            let report = analyze("https://x.test", 200, &headers, true);
            let found = codes(&report);
            assert!(found.contains(&"cookie-no-httponly"));
            assert!(found.contains(&"cookie-no-secure"));
            assert!(found.contains(&"cookie-no-samesite"));
        }

        #[test]
        fn a_hardened_cookie_passes() {
            let headers = Headers::from_pairs([(
                "set-cookie",
                "session=abc; Secure; HttpOnly; SameSite=Lax",
            )]);
            let report = analyze("https://x.test", 200, &headers, true);
            assert!(!codes(&report).iter().any(|c| c.starts_with("cookie-")));
        }

        #[test]
        fn samesite_none_without_secure_is_high() {
            let headers = Headers::from_pairs([("set-cookie", "s=1; HttpOnly; SameSite=None")]);
            let report = analyze("https://x.test", 200, &headers, true);
            let finding = report
                .findings
                .iter()
                .find(|f| f.code == "cookie-samesite-none-insecure")
                .expect("finding");
            assert_eq!(finding.severity, Severity::High);
        }

        #[test]
        fn missing_secure_is_not_flagged_over_plain_http() {
            let headers = Headers::from_pairs([("set-cookie", "s=1; HttpOnly; SameSite=Lax")]);
            let report = analyze("http://x.test", 200, &headers, false);
            assert!(!codes(&report).contains(&"cookie-no-secure"));
        }

        #[test]
        fn every_cookie_is_checked_not_just_the_first() {
            let headers = Headers::from_pairs([
                ("set-cookie", "a=1; Secure; HttpOnly; SameSite=Lax"),
                ("set-cookie", "b=2"),
            ]);
            let report = analyze("https://x.test", 200, &headers, true);
            let messages: Vec<_> = report.findings.iter().map(|f| f.message.as_str()).collect();
            assert!(messages.iter().any(|m| m.contains("cookie b")));
        }
    }

    mod grading {
        use super::*;

        #[test]
        fn grade_boundaries_are_exact() {
            assert_eq!(grade_for(100), 'A');
            assert_eq!(grade_for(90), 'A');
            assert_eq!(grade_for(89), 'B');
            assert_eq!(grade_for(80), 'B');
            assert_eq!(grade_for(79), 'C');
            assert_eq!(grade_for(70), 'C');
            assert_eq!(grade_for(69), 'D');
            assert_eq!(grade_for(60), 'D');
            assert_eq!(grade_for(59), 'E');
            assert_eq!(grade_for(50), 'E');
            assert_eq!(grade_for(49), 'F');
            assert_eq!(grade_for(0), 'F');
        }

        #[test]
        fn the_score_never_underflows() {
            // Many High findings must saturate at zero, not wrap around.
            let report = analyze("https://x.test", 200, &Headers::new(), true);
            assert!(report.score <= 100);
        }
    }
}
