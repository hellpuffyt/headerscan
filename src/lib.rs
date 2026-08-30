//! Audit HTTP response security headers and grade them.
//!
//! The rule set in [`analyze`] is a pure function of a header set, so it can be
//! exercised without a network — which is why the checks here have real tests
//! rather than the handful that live scanning usually permits.
//!
//! ```
//! use headerscan::analyze::analyze;
//! use headerscan::headers::Headers;
//!
//! let headers = Headers::from_pairs([("x-content-type-options", "nosniff")]);
//! let report = analyze("https://example.com", 200, &headers, true);
//! assert!(report.score < 100);
//! ```

pub mod analyze;
pub mod fetch;
pub mod headers;
pub mod report;
