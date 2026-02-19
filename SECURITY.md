# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Leash, please report it responsibly:

**Email:** security@meridianhouse.tech

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

Leash is a security monitoring tool. We take vulnerabilities seriously, especially:

- **Bypass of monitoring** — Ways for monitored processes to evade detection
- **Tamper resistance** — Ways to disable Leash without triggering alerts
- **Privilege escalation** — Ways Leash could be exploited to gain elevated privileges
- **Information disclosure** — Ways Leash could leak sensitive information it monitors
- **Alert injection** — Ways to inject false alerts

## Out of Scope

- Known limitations documented in README (e.g., /proc polling limitations in v0.1)
- Denial of service against the monitoring tool itself
- Issues requiring physical access to the machine

## Design Decisions

- **SIGSTOP is opt-in** — Response actions are disabled by default to prevent misuse
- **No network listener** — Leash does not open any inbound ports
- **Minimal privileges** — Leash needs read access to /proc and monitored paths, not root
- **No data exfiltration** — Alert webhooks only send detection metadata, never file contents
