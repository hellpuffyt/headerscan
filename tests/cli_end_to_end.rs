//! End-to-end tests of the `headerscan` binary against local servers only:
//! exit codes, JSON output, redirects, timeouts, several targets, and
//! hostile header values. Nothing here touches the internet.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

/// Serve up to `count` requests, each with the same status line and headers.
fn serve(count: usize, status_line: String, headers: Vec<String>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for _ in 0..count {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            respond(stream, &status_line, &headers);
        }
    });
    port
}

fn respond(mut stream: TcpStream, status_line: &str, headers: &[String]) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }
    let mut response = format!("HTTP/1.1 {status_line}\r\n");
    for header in headers {
        response.push_str(header);
        response.push_str("\r\n");
    }
    response.push_str("Content-Length: 2\r\nConnection: close\r\n\r\nok");
    let _ = stream.write_all(response.as_bytes());
}

fn headerscan(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_headerscan"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run headerscan")
}

fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/")
}

fn strong_headers() -> Vec<String> {
    [
        "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy: camera=()",
        "Cross-Origin-Opener-Policy: same-origin",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

#[test]
fn min_score_gates_the_exit_code() {
    let good = serve(2, "200 OK".into(), strong_headers());
    let out = headerscan(&["--min-score", "90", &url(good)]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let out = headerscan(&["--min-score", "101", &url(good)]);
    assert_eq!(out.status.code(), Some(1));

    let bare = serve(1, "200 OK".into(), vec![]);
    let out = headerscan(&["--min-score", "80", &url(bare)]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn json_output_has_the_documented_summary() {
    let port = serve(1, "200 OK".into(), vec![]);
    let out = headerscan(&["--format", "json", &url(port)]);
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["summary"]["targets"], 1);
    assert!(v["summary"]["lowest_score"].as_u64().is_some());
    assert_eq!(
        v["summary"]["findings"].as_u64().unwrap(),
        v["results"][0]["findings"].as_array().unwrap().len() as u64
    );
}

#[test]
fn an_unreachable_target_does_not_stop_the_others() {
    // Bind then drop, so the port is very likely closed.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let good = serve(1, "200 OK".into(), strong_headers());
    let out = headerscan(&[&url(closed), &url(good)]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a failed target makes the run fail"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains(&format!("127.0.0.1:{good}")), "{stdout}");
    assert!(stderr.contains(&format!("127.0.0.1:{closed}")), "{stderr}");
}

#[test]
fn redirects_are_followed_and_the_final_response_is_audited() {
    let target = serve(1, "200 OK".into(), strong_headers());
    let hop = serve(
        1,
        "301 Moved Permanently".into(),
        vec![format!("Location: {}", url(target))],
    );
    let out = headerscan(&["--format", "json", &url(hop)]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["results"][0]["url"], url(target));
    assert_eq!(v["results"][0]["status"], 200);
}

#[test]
fn no_redirects_audits_the_first_response() {
    let hop = serve(
        1,
        "301 Moved Permanently".into(),
        vec!["Location: http://127.0.0.1:9/".into()],
    );
    let out = headerscan(&["--no-redirects", "--format", "json", &url(hop)]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["results"][0]["status"], 301);
}

#[test]
fn redirect_chains_longer_than_five_are_not_followed_forever() {
    // Seven hops in a chain; the documented limit is five.
    let mut next = serve(1, "200 OK".into(), strong_headers());
    for _ in 0..7 {
        next = serve(
            1,
            "302 Found".into(),
            vec![format!("Location: {}", url(next))],
        );
    }
    let start = Instant::now();
    let out = headerscan(&["--format", "json", &url(next)]);
    assert!(start.elapsed() < Duration::from_secs(10));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    // Either refused or stopped at a 3xx - never reached the 200 at hop 8.
    let results = v["results"].as_array().unwrap();
    assert!(results.iter().all(|r| r["status"] != 200), "{v}");
}

#[test]
fn a_silent_server_hits_the_timeout_instead_of_hanging() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        // Accept and hold the connection open without answering.
        let held: Vec<_> = listener.incoming().take(1).collect();
        thread::sleep(Duration::from_secs(10));
        drop(held);
    });
    let start = Instant::now();
    let out = headerscan(&["--timeout", "1", &url(port)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn hostile_header_values_cannot_inject_terminal_escapes() {
    // A Unicode bidi override in a cookie name. The HTTP client withholds
    // non-ASCII header values, so it never reaches the terminal raw and is
    // reported as unreadable instead (escaping of server-controlled text in
    // the renderer is unit-tested in `report.rs`).
    let port = serve(1, "200 OK".into(), vec!["Set-Cookie: a\u{202e}b=1".into()]);
    let out = headerscan(&[&url(port)]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains('\u{202e}'), "{stdout}");
    assert!(stdout.contains("[header-unreadable]"), "{stdout}");
}
