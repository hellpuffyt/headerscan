//! Rendering reports.

use std::fmt::Write as _;

use crate::analyze::{Report, Severity};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

const fn severity_colour(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "\x1b[31m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[36m",
        Severity::Info => "\x1b[2m",
    }
}

const fn grade_colour(grade: char) -> &'static str {
    match grade {
        'A' | 'B' => "\x1b[32m",
        'C' | 'D' => "\x1b[33m",
        _ => "\x1b[31m",
    }
}

/// Make server-controlled text safe to print to a terminal.
///
/// Cookie names, CSP directive names and the final URL come from the
/// scanned server. Control characters (including ESC, which starts terminal
/// escape sequences) and Unicode bidirectional overrides, which can make a
/// line display differently from what it contains, are shown escaped.
#[must_use]
pub fn sanitize_for_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let bidi = matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}');
        if c.is_control() || bidi {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Render a report as human-readable text.
#[must_use]
pub fn render_text(report: &Report, colour: bool) -> String {
    let paint = |text: &str, code: &str| -> String {
        if colour {
            format!("{code}{text}{RESET}")
        } else {
            text.to_owned()
        }
    };

    let mut out = String::new();
    let heading = format!(
        "{}  {} {}",
        sanitize_for_terminal(&report.url),
        report.status,
        {
            let grade = format!("grade {} ({}/100)", report.grade, report.score);
            paint(&grade, grade_colour(report.grade))
        }
    );
    out.push_str(&paint(&heading, BOLD));
    out.push('\n');

    if report.findings.is_empty() {
        out.push_str("  no findings\n");
        return out;
    }

    for finding in &report.findings {
        let label = paint(finding.severity.label(), severity_colour(finding.severity));
        let header = sanitize_for_terminal(finding.header.as_deref().unwrap_or("-"));
        let code = paint(&format!("[{}]", finding.code), DIM);
        let _ = writeln!(
            out,
            "  {label:<8} {header}: {} {code}",
            sanitize_for_terminal(&finding.message)
        );
        let _ = writeln!(
            out,
            "           {} {}",
            paint("fix:", DIM),
            sanitize_for_terminal(&finding.remediation)
        );
    }
    out
}

/// Render many reports as one JSON document.
///
/// # Errors
///
/// Returns an error only if serialisation fails, which cannot happen for these
/// types but is surfaced rather than hidden.
pub fn render_json(reports: &[Report]) -> Result<String, serde_json::Error> {
    let worst = reports.iter().map(|r| r.score).min().unwrap_or(100);
    let payload = serde_json::json!({
        "summary": {
            "targets": reports.len(),
            "lowest_score": worst,
            "lowest_grade": crate::analyze::grade_for(worst).to_string(),
            "findings": reports.iter().map(|r| r.findings.len()).sum::<usize>(),
        },
        "results": reports,
    });
    serde_json::to_string_pretty(&payload)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "a failing expect in a test is the test failure we want"
)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::headers::Headers;

    fn clean_report() -> Report {
        let headers = Headers::from_pairs([
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
            ("permissions-policy", "camera=()"),
            ("cross-origin-opener-policy", "same-origin"),
        ]);
        analyze("https://x.test", 200, &headers, true)
    }

    #[test]
    fn server_controlled_text_cannot_inject_terminal_escapes() {
        // A cookie name is taken verbatim from the server's Set-Cookie.
        let headers = Headers::from_pairs([("set-cookie", "a\u{1b}[2Jb\u{202e}c=1")]);
        let report = analyze("http://x.test/\u{1b}]0;t\u{7}", 200, &headers, false);
        let text = render_text(&report, false);
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(!text.contains('\u{202e}'), "{text:?}");
        assert!(!text.contains('\u{7}'), "{text:?}");
        assert!(text.contains("a\\u{001b}[2Jb\\u{202e}c"), "{text:?}");
    }

    #[test]
    fn a_clean_report_says_so() {
        let text = render_text(&clean_report(), false);
        assert!(text.contains("no findings"));
        assert!(text.contains("grade A"));
    }

    #[test]
    fn findings_include_code_and_remediation() {
        let report = analyze("https://x.test", 200, &Headers::new(), true);
        let text = render_text(&report, false);
        assert!(text.contains("[hsts-missing]"));
        assert!(text.contains("fix:"));
    }

    #[test]
    fn colour_is_opt_in() {
        let report = clean_report();
        assert!(!render_text(&report, false).contains('\x1b'));
        assert!(render_text(&report, true).contains('\x1b'));
    }

    #[test]
    fn json_reports_the_worst_score_across_targets() {
        let good = clean_report();
        let bad = analyze("https://y.test", 200, &Headers::new(), true);
        let worst = bad.score;
        let worst_grade = bad.grade.to_string();
        let json = render_json(&[good, bad]).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

        assert_eq!(parsed["summary"]["targets"], 2);
        // The summary must report the *worst* target, not the first or the mean.
        assert_eq!(parsed["summary"]["lowest_score"], worst);
        assert_eq!(parsed["summary"]["lowest_grade"], worst_grade);
        assert_eq!(parsed["summary"]["lowest_grade"], "F");
    }

    #[test]
    fn json_of_no_targets_is_still_valid() {
        let json = render_json(&[]).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["summary"]["targets"], 0);
        assert_eq!(parsed["summary"]["lowest_score"], 100);
    }
}
