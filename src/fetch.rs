//! Fetching a response's headers.
//!
//! Kept deliberately thin. Everything interesting happens in
//! [`crate::analyze`], which takes headers rather than a URL, so the rules stay
//! testable without a network.

use std::time::Duration;

use crate::headers::Headers;

/// Something that stopped a scan.
#[derive(Debug)]
pub enum FetchError {
    /// The URL could not be used.
    InvalidUrl(String),
    /// The request failed at the transport level.
    Transport(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(message) | Self::Transport(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// One fetched response, reduced to what the checks need.
pub struct Response {
    /// The final URL, after redirects.
    pub url: String,
    /// The HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Headers,
    /// Whether the final URL used TLS.
    pub is_https: bool,
}

/// Add a scheme when the user omitted one, as they usually do.
#[must_use]
pub fn normalize_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    }
}

/// Whether a URL is HTTPS.
#[must_use]
pub fn is_https(url: &str) -> bool {
    url.starts_with("https://")
}

/// Fetch a URL and collect its response headers.
///
/// # Errors
///
/// Returns [`FetchError`] when the URL is unusable or the request fails.
/// An HTTP error status is *not* an error: a 404 still has headers worth
/// auditing, and reporting it as a failure would hide them.
pub fn fetch(url: &str, timeout: Duration, follow_redirects: bool) -> Result<Response, FetchError> {
    let url = normalize_url(url);
    if url.len() <= "https://".len() {
        return Err(FetchError::InvalidUrl(format!("not a usable URL: {url}")));
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(if follow_redirects { 5 } else { 0 })
        .user_agent(concat!("headerscan/", env!("CARGO_PKG_VERSION")))
        .build();

    // A non-2xx status is a normal outcome here: a 404 still has headers worth
    // auditing. Both it and a successful call yield the same response value.
    let response = match agent.get(&url).call() {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => return Err(FetchError::Transport(error.to_string())),
    };

    let final_url = response.get_url().to_owned();
    let mut headers = Headers::new();
    for name in response.headers_names() {
        // `header()` returns only the first value for a name. `Set-Cookie` is
        // routinely repeated, and using `header()` here silently dropped every
        // cookie after the first — so every one of them went unaudited.
        for value in response.all(&name) {
            headers.insert(&name, value);
        }
    }

    Ok(Response {
        status: response.status(),
        is_https: is_https(&final_url),
        url: final_url,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_gains_https() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
    }

    #[test]
    fn an_explicit_scheme_is_preserved() {
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
        assert_eq!(normalize_url("https://example.com"), "https://example.com");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(normalize_url("  example.com  "), "https://example.com");
    }

    #[test]
    fn https_detection_matches_the_scheme() {
        assert!(is_https("https://example.com"));
        assert!(!is_https("http://example.com"));
    }
}
