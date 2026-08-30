//! Case-insensitive header access and the small parsers the checks need.
//!
//! HTTP field names are case-insensitive (RFC 9110 §5.1) and may repeat.
//! Getting that wrong is the usual reason a scanner reports a header missing
//! when it is present, so it is handled once, here, rather than in each check.

use std::collections::BTreeMap;

/// A response's headers, stored under lowercase names.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    fields: BTreeMap<String, Vec<String>>,
}

impl Headers {
    /// An empty header set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one header value, preserving earlier values of the same name.
    pub fn insert(&mut self, name: &str, value: &str) {
        self.fields
            .entry(name.trim().to_ascii_lowercase())
            .or_default()
            .push(value.trim().to_owned());
    }

    /// The first value for a header, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .get(&name.to_ascii_lowercase())
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    /// Every value for a header, in the order received.
    #[must_use]
    pub fn get_all(&self, name: &str) -> &[String] {
        self.fields
            .get(&name.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    /// Whether a header is present at all.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.fields.contains_key(&name.to_ascii_lowercase())
    }

    /// How many distinct header names are present.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no headers are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Build from name/value pairs. Convenient in tests and for the fetcher.
    pub fn from_pairs<'a, I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut headers = Self::new();
        for (name, value) in pairs {
            headers.insert(name, value);
        }
        headers
    }
}

/// A `Strict-Transport-Security` value, parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hsts {
    /// `max-age` in seconds. `None` when the directive is absent or unparseable.
    pub max_age: Option<u64>,
    /// Whether `includeSubDomains` is present.
    pub include_subdomains: bool,
    /// Whether `preload` is present.
    pub preload: bool,
}

/// Parse a `Strict-Transport-Security` header value.
#[must_use]
pub fn parse_hsts(value: &str) -> Hsts {
    let mut hsts = Hsts {
        max_age: None,
        include_subdomains: false,
        preload: false,
    };
    for directive in value.split(';') {
        let directive = directive.trim();
        let lower = directive.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("max-age") {
            let rest = rest.trim_start();
            if let Some(number) = rest.strip_prefix('=') {
                // Quoted forms are legal in the wild even though the grammar
                // does not require them.
                hsts.max_age = number.trim().trim_matches('"').parse().ok();
            }
        } else if lower == "includesubdomains" {
            hsts.include_subdomains = true;
        } else if lower == "preload" {
            hsts.preload = true;
        }
    }
    hsts
}

/// A `Content-Security-Policy` split into directives.
#[derive(Debug, Clone, Default)]
pub struct Csp {
    directives: BTreeMap<String, Vec<String>>,
}

impl Csp {
    /// Parse a policy string.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        let mut directives = BTreeMap::new();
        for part in value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut tokens = part.split_whitespace();
            let Some(name) = tokens.next() else { continue };
            directives.insert(
                name.to_ascii_lowercase(),
                tokens.map(str::to_ascii_lowercase).collect(),
            );
        }
        Self { directives }
    }

    /// Source list for a directive, if declared.
    #[must_use]
    pub fn directive(&self, name: &str) -> Option<&[String]> {
        self.directives.get(name).map(Vec::as_slice)
    }

    /// Whether a directive is declared.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.directives.contains_key(name)
    }

    /// Whether the policy declared no directives at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// Directives whose source list contains a given token.
    #[must_use]
    pub fn directives_containing(&self, token: &str) -> Vec<&str> {
        self.directives
            .iter()
            .filter(|(_, sources)| sources.iter().any(|s| s == token))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// The effective source list for fetch directives, falling back to
    /// `default-src` exactly as the specification does.
    #[must_use]
    pub fn effective(&self, name: &str) -> Option<&[String]> {
        self.directive(name).or(self.directive("default-src"))
    }
}

/// The security-relevant attributes of one `Set-Cookie` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// The cookie name.
    pub name: String,
    /// Whether `Secure` is set.
    pub secure: bool,
    /// Whether `HttpOnly` is set.
    pub http_only: bool,
    /// The `SameSite` value, lowercased.
    pub same_site: Option<String>,
}

/// Parse a `Set-Cookie` header value.
#[must_use]
pub fn parse_cookie(value: &str) -> Cookie {
    let mut parts = value.split(';');
    let name = parts
        .next()
        .and_then(|pair| pair.split('=').next())
        .unwrap_or("")
        .trim()
        .to_owned();

    let mut cookie = Cookie {
        name,
        secure: false,
        http_only: false,
        same_site: None,
    };

    for attribute in parts {
        let attribute = attribute.trim();
        let lower = attribute.to_ascii_lowercase();
        if lower == "secure" {
            cookie.secure = true;
        } else if lower == "httponly" {
            cookie.http_only = true;
        } else if let Some(rest) = lower.strip_prefix("samesite=") {
            cookie.same_site = Some(rest.trim().to_owned());
        }
    }
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_ignores_case() {
        let headers = Headers::from_pairs([("Content-Type", "text/html")]);
        assert_eq!(headers.get("content-type"), Some("text/html"));
        assert_eq!(headers.get("CONTENT-TYPE"), Some("text/html"));
        assert!(headers.has("Content-Type"));
    }

    #[test]
    fn repeated_headers_are_all_kept() {
        let headers = Headers::from_pairs([("Set-Cookie", "a=1"), ("set-cookie", "b=2")]);
        assert_eq!(headers.get_all("Set-Cookie").len(), 2);
        assert_eq!(headers.get("set-cookie"), Some("a=1"));
    }

    #[test]
    fn missing_header_yields_nothing() {
        let headers = Headers::new();
        assert!(headers.is_empty());
        assert_eq!(headers.get("x-nope"), None);
        assert!(headers.get_all("x-nope").is_empty());
    }

    #[test]
    fn hsts_directives_are_parsed() {
        let hsts = parse_hsts("max-age=31536000; includeSubDomains; preload");
        assert_eq!(hsts.max_age, Some(31_536_000));
        assert!(hsts.include_subdomains);
        assert!(hsts.preload);
    }

    #[test]
    fn hsts_parsing_is_case_insensitive_and_tolerates_quotes() {
        let hsts = parse_hsts("MAX-AGE=\"600\"; INCLUDESUBDOMAINS");
        assert_eq!(hsts.max_age, Some(600));
        assert!(hsts.include_subdomains);
    }

    #[test]
    fn hsts_without_max_age_reports_none() {
        assert_eq!(parse_hsts("includeSubDomains").max_age, None);
        assert_eq!(parse_hsts("max-age=abc").max_age, None);
    }

    #[test]
    fn csp_directives_are_split() {
        let csp = Csp::parse("default-src 'self'; script-src 'self' 'unsafe-inline'");
        assert_eq!(
            csp.directive("default-src"),
            Some(["'self'".to_owned()].as_slice())
        );
        assert!(csp.has("script-src"));
        assert!(!csp.has("object-src"));
    }

    #[test]
    fn csp_finds_directives_containing_a_token() {
        let csp = Csp::parse("script-src 'unsafe-inline'; style-src 'unsafe-inline'");
        let mut found = csp.directives_containing("'unsafe-inline'");
        found.sort_unstable();
        assert_eq!(found, ["script-src", "style-src"]);
    }

    #[test]
    fn csp_falls_back_to_default_src() {
        let csp = Csp::parse("default-src 'none'");
        assert_eq!(
            csp.effective("script-src"),
            Some(["'none'".to_owned()].as_slice())
        );
    }

    #[test]
    fn empty_csp_is_detected() {
        assert!(Csp::parse("   ").is_empty());
        assert!(Csp::parse(";;").is_empty());
    }

    #[test]
    fn cookie_attributes_are_parsed() {
        let cookie = parse_cookie("session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
        assert_eq!(cookie.name, "session");
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site.as_deref(), Some("lax"));
    }

    #[test]
    fn cookie_without_attributes_is_bare() {
        let cookie = parse_cookie("plain=1");
        assert_eq!(cookie.name, "plain");
        assert!(!cookie.secure);
        assert!(!cookie.http_only);
        assert_eq!(cookie.same_site, None);
    }
}
