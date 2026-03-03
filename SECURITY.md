# Security Policy

## Supported Versions

Security fixes are applied to the latest release series.

| Version | Supported |
| --- | --- |
| Latest | Yes |
| Older releases | No |

## Reporting a Vulnerability

Do not open public issues for security vulnerabilities.

Preferred reporting path:

1. Use GitHub Security Advisories in this repository (Security tab).
2. Provide reproduction details, impact, and affected version/tag.
3. Include any logs with secrets redacted.

## Secret Handling Guidelines

- Do not commit `.env-inspector-state/` data.
- Do not commit `.env` files or credentials.
- Keep token-like values masked in shared screenshots/logs.
- If credentials are exposed, rotate them immediately and report exposure context.
