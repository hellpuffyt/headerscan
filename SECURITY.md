# Security policy

## Supported versions

Only the latest release on the default branch receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability.
Report it privately through GitHub's advisory form:

https://github.com/hellpuffyt/headerscan/security/advisories/new

Include the version or commit, a description of the issue, and steps or
input that reproduce it. You should receive an acknowledgement within a
few days; once a fix is available it will be released and credited in
the advisory unless you prefer otherwise.

## Scope

headerscan connects to servers it is pointed at and parses their responses, so the responses are untrusted input. Relevant reports include crashes or hangs triggered by a response, terminal-escape or output injection, findings that are wrong in a way that hides a real weakness, and TLS verification weaknesses.
