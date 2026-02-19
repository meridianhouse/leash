# Fuzzing

This project uses `cargo-fuzz` with libFuzzer.

## Targets

- `scrub_secrets`: random input through secret redaction
- `escape_html`: random string escaping for Telegram HTML payloads
- `config_parsing`: malformed/random YAML against config parser
- `mitre_mapping`: random event types and narrative content through MITRE mapping

## Run

```bash
cargo install cargo-fuzz
cargo fuzz run scrub_secrets
cargo fuzz run escape_html
cargo fuzz run config_parsing
cargo fuzz run mitre_mapping
```

## Corpus

Corpus directories live under `fuzz/corpus/<target>/`.
