//! End-to-end tests against a real local HTTP server.
//!
//! The unit tests cover the rules; these cover the parts the rules cannot see —
//! that headers survive the wire, that repeated `Set-Cookie` lines are all
//! collected, and that a non-2xx status is audited rather than treated as a
//! failure. A hand-rolled server keeps this dependency-free and, more usefully,
//! lets a test send malformed or duplicated headers a real framework would
//! refuse to emit.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use headerscan::analyze::analyze;
use headerscan::fetch::fetch;

/// Serve exactly one request with the given status line and headers.
fn serve_once(status_line: &'static str, headers: &'static [&'static str]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        handle(stream, status_line, headers);
    });

    port
}

fn handle(mut stream: TcpStream, status_line: &str, headers: &[&str]) {
    // Consume the request head so the client does not see a reset connection.
    let peek = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(peek);
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let body = "ok";
    let mut response = format!("HTTP/1.1 {status_line}\r\n");
    for header in headers {
        response.push_str(header);
        response.push_str("\r\n");
    }
    let _ = write!(response, "Content-Length: {}\r\n", body.len());
    // Without this the client waits for more data on a kept-alive connection.
    response.push_str("Connection: close\r\n\r\n");
    response.push_str(body);

    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn scan(port: u16) -> headerscan::analyze::Report {
    let url = format!("http://127.0.0.1:{port}/");
    let response = fetch(&url, Duration::from_secs(5), true).expect("fetch");
    analyze(
        &response.url,
        response.status,
        &response.headers,
        response.is_https,
    )
}

fn codes(report: &headerscan::analyze::Report) -> Vec<String> {
    report.findings.iter().map(|f| f.code.clone()).collect()
}

#[test]
fn headers_survive_the_wire_and_are_matched_case_insensitively() {
    // Sent in mixed case on purpose: real servers do this and a scanner that
    // lowercases only its own table reports these as missing.
    let port = serve_once(
        "200 OK",
        &[
            "X-Content-Type-Options: nosniff",
            "REFERRER-POLICY: strict-origin-when-cross-origin",
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
        ],
    );
    let report = scan(port);
    let found = codes(&report);

    assert!(
        !found.contains(&"nosniff-missing".to_owned()),
        "got {found:?}"
    );
    assert!(!found.contains(&"referrer-policy-missing".to_owned()));
    assert!(!found.contains(&"csp-missing".to_owned()));
}

#[test]
fn a_bare_response_is_graded_badly() {
    let port = serve_once("200 OK", &[]);
    let report = scan(port);

    assert_eq!(report.status, 200);
    assert!(codes(&report).contains(&"csp-missing".to_owned()));
    // Served over plain HTTP, so HSTS is informational rather than a failure.
    assert!(codes(&report).contains(&"hsts-not-applicable".to_owned()));
}

#[test]
fn repeated_set_cookie_headers_are_all_audited() {
    let port = serve_once(
        "200 OK",
        &["Set-Cookie: a=1; HttpOnly; SameSite=Lax", "Set-Cookie: b=2"],
    );
    let report = scan(port);
    let messages: Vec<_> = report.findings.iter().map(|f| f.message.clone()).collect();

    assert!(
        messages.iter().any(|m| m.contains("cookie b")),
        "second cookie was not audited: {messages:?}"
    );
}

#[test]
fn an_error_status_is_still_audited() {
    // A 404 has headers worth auditing; treating the status as a failure would
    // silently skip them.
    let port = serve_once("404 Not Found", &["X-Content-Type-Options: nosniff"]);
    let report = scan(port);

    assert_eq!(report.status, 404);
    assert!(!codes(&report).contains(&"nosniff-missing".to_owned()));
}

#[test]
fn an_unreachable_host_is_an_error_not_a_panic() {
    // Port 1 on loopback is reliably closed.
    let result = fetch("http://127.0.0.1:1/", Duration::from_secs(2), true);
    assert!(result.is_err());
}
