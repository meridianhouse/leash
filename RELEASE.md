# Release Checklist

## Pre-Release (Technical Gate)

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all --quiet`
- [ ] `cargo build --release` succeeds
- [ ] Binary stripped (`strip target/release/leash`)
- [ ] `leash test` generates events on all severity levels
- [ ] `leash scan` shows active agents
- [ ] `leash watch --json` produces valid NDJSON
- [ ] README/CLI flags match current behavior
- [ ] Platform support matrix in README matches actual runtime capabilities
- [ ] `THREAT_MODEL.md` reviewed for current scope
- [ ] Issue templates present (`.github/ISSUE_TEMPLATE/*`)
- [ ] Build release artifact + checksum:
      `scripts/release_artifacts.sh vX.Y.Z`

## Pre-Release (Launch Assets)

- [ ] Landing page deployed to meridianhouse.tech/leash
- [ ] Twitter thread drafted and approved
- [ ] HN post drafted and approved
- [ ] r/netsec post drafted and approved
- [ ] SSH key configured for colo deployment

## Release Day

- [ ] Tag release: `git tag v0.1.0`
- [ ] Push tag: `git push origin v0.1.0`
- [ ] Publish landing page to meridianhouse.tech/leash
- [ ] Post HN Show HN
- [ ] Post r/netsec
- [ ] Tweet thread from @Meridianhousehq
- [ ] Monitor GitHub for stars and issues

## Post-Release

- [ ] Watch for bug reports
- [ ] Respond to issues within 24 hours
- [ ] Plan v0.2 roadmap
- [ ] Begin eBPF implementation

## v0.2 Roadmap

- [ ] eBPF kernel hooks via `aya`
- [ ] Anti-tamper watchdog
- [ ] macOS support
- [ ] Web dashboard
- [ ] More MITRE ATLAS mappings

## Potential Enhancements (Future)
- Apple Watch alerts via OpenClaw integration
- iOS companion app for monitoring AI agents from phone
- Voice integration ("Hey Siri, is Claude doing anything suspicious?")
- Native iOS push notifications for critical alerts
- Leash HTTP API endpoint for remote status queries
