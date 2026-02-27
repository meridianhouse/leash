# Leash Threat Model (v0.2)

## What Leash Defends Against
Leash is an **observability + detection** tool for AI-agent activity on endpoints.

Primary goals:
- Detect suspicious process chains from AI tools
- Detect sensitive credential/file access
- Detect persistence attempts (cron/launchd/service changes)
- Detect suspicious egress patterns
- Preserve forensic history for incident response

## Trust Boundaries
1. Host OS / kernel (trusted baseline)
2. Leash binary + config (trusted with integrity monitoring)
3. Monitored AI/tool processes (untrusted)
4. External alert sinks (webhooks/chats; semi-trusted)

## In-Scope Threats
- AI agent executes unexpected shell commands
- AI agent reads/writes sensitive files
- AI agent attempts persistence
- AI agent makes suspicious outbound connections
- Basic tampering with Leash binary/config

## Out-of-Scope (current)
- Full malware prevention/EDR replacement
- Kernel rootkits / privileged kernel compromise
- Memory-only attacks beyond observable telemetry
- Guaranteed blocking of all malicious behavior

## Assumptions
- Leash runs with sufficient host visibility
- Alert channels are configured correctly
- Defender reviews alerts and acts
- Host is not already fully compromised at kernel level

## Evasion Risks
Potential attacker behaviors:
- Living-off-the-land binaries to blend in
- Slow/low-and-slow operations to reduce alert volume
- Abuse of trusted network destinations
- Process name masquerading

Mitigations in place:
- Rule bundles (GTFOBins/LOLC2/LOT tunnels etc.)
- Process tree + context correlation
- Integrity drift checks
- Configurable high-signal sensitive paths

## Response Philosophy
Leash is **observation-first**:
- Default: alert/visibility
- Optional: response actions (e.g., SIGSTOP)

This reduces false positive blast radius while preserving operator control.
