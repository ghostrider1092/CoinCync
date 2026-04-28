# Contributing to CoinCync

## Code

1. Fork the repo
2. Create a feature branch
3. Write tests for your changes
4. Run `cargo test --release` — all 947+ tests must pass
5. Submit a pull request

## Requirements

- All code changes must have tests
- No `unsafe` without justification
- No external network calls in tests
- Consensus-critical changes require `critical_files.lock` update

## Style

- Rust 2021 edition
- No `unwrap()` in production code (use `?` or handle errors)
- Comments explain "why" not "what"
- Security-critical code gets `// SECURITY:` comment prefix

## Consensus Changes

Changes to consensus-critical files require:
1. Update the code
2. Update `critical_files.lock` hashes
3. Update `docs/src/protocol/consensus.md`
4. Add regression tests
5. Review by at least one other contributor

## Security Issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
