# Contributing to Leash

Thanks for your interest in Leash! We welcome contributions.

## Getting Started

```bash
git clone https://github.com/meridianhouse/leash.git
cd leash
cargo build
cargo test
```

## What We Need Help With

- **New detections** — Process behaviors that indicate AI agent misuse
- **MITRE mappings** — More ATT&CK and ATLAS technique coverage
- **Platform support** — macOS support (currently Linux-only)
- **eBPF hooks** — Moving from /proc polling to kernel-level monitoring
- **Tests** — Unit and integration tests for detection logic
- **Documentation** — Examples, tutorials, blog posts

## Pull Request Guidelines

1. Fork the repo and create a feature branch
2. Write clean, documented Rust code
3. Ensure `cargo build --release` passes with no warnings
4. Ensure `cargo clippy` passes
5. Add tests for new detection logic
6. Update README if adding user-facing features
7. Submit a PR with a clear description

## Detection Contributions

If you're adding a new detection:

1. Add the detection logic to the appropriate module (collector, fim, egress)
2. Map it to MITRE ATT&CK/ATLAS in `src/mitre.rs`
3. Add it to the README detection coverage table
4. Include example events in your PR description

## Code of Conduct

Be respectful. We're all here to make AI agents safer to run.

## License

By contributing, you agree your contributions will be licensed under MIT.
