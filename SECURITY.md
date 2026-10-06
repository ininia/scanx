# Security policy

scanX processes other people's source code; we treat every vulnerability as serious.

## Reporting
Please **do not** open public issues for security problems. Report privately via GitHub Security
Advisories ("Report a vulnerability") on this repository. Include affected version, impact and
reproduction steps. We aim to acknowledge within 3 business days and to ship a fix or mitigation
within 30 days for high/critical issues, coordinating disclosure with you.

## Scope
In scope: the scanX server, worker, CLI, container images, install scripts and default configs.
Out of scope: vulnerabilities in third-party scanners themselves (report upstream; tell us if
scanX's isolation fails to contain them — that *is* in scope).

## Supported versions
Until 1.0, only the latest release receives fixes.
