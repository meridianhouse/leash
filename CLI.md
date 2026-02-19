# Leash CLI Quick Reference

```
leash init              Generate config ~/.config/leash/config.yaml
leash watch             Live monitoring (colored output, press Ctrl+C to stop)
leash watch --dry-run   Detect only; print would-be alerts, do not send
leash scan              One-time snapshot of active agents
leash status            Show daemon status + statistics
leash history           Show stored events from SQLite
leash history --last 1h Events from the last hour
leash history --severity red   Only red events
leash test              Send test events to verify alerting
leash start             Start daemon in background
leash start --dry-run   Daemon mode detect-only (no outbound alerts)
leash stop              Stop daemon
leash --help            Show all options
```

## Configuration

Config file: `~/.config/leash/config.yaml`

```yaml
monitored_agents:      # AI tools to watch
  - claude, codex, cursor, aider, cline, copilot-agent

sensitive_paths:        # Alert when accessed
  - ~/.ssh, ~/.gnupg, ~/.config/secrets

allow_list:            # Expected behavior - no alerts
  - name: git
    reason: Version control
```

## Output Colors

| Color | Meaning |
|-------|---------|
| 🟢 GREEN | Normal monitoring |
| 🟡 YELLOW | Notable activity |
| 🟠 ORANGE | Suspicious |
| 🔴 RED | Critical (credential access, file modification) |

## Examples

```bash
# Watch with JSON output
leash watch --json | jq .

# Tune detections without sending alerts
leash watch --dry-run

# Export last 24h to CSV
leash history --last 24h --format csv > events.csv

# Scan and show JSON
leash scan --json | jq .

# Test Slack integration
leash test
```

## Files

- Config: `~/.config/leash/config.yaml`
- Events: `~/.local/share/leash/events.db`
- Logs: `~/.local/state/leash/alerts.jsonl`
