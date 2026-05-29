# Contributing to PQ-RASCV

Thank you for your interest in contributing to PQ-RASCV. This document covers how to get started,
coding standards, and the review process.

## Before You Start

- For **bug fixes and small improvements**: open a PR directly.
- For **new features or significant refactors**: open an issue first to discuss scope and approach.
- For **security vulnerabilities**: see [SECURITY.md](SECURITY.md). Do not open a public issue.

## Development Setup

```bash
# Clone and enter the repo
git clone https://github.com/comwanga/pqrascv-core.git
cd pqrascv-core

# Run the full test suite
cargo test --workspace

# Run the linter (must pass with zero warnings)
cargo clippy --workspace -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Run Miri (memory-safety checker) for the core crate
MIRIFLAGS="-Zmiri-strict-provenance" cargo +nightly miri test -p pqrascv-core --no-default-features
```

## Coding Standards

### Tests first (TDD)

Every functional change must include tests. Write the failing test before writing the implementation:

```
1. Write a failing test that specifies the desired behavior.
2. Run the test and confirm it fails for the right reason.
3. Write the minimal implementation to make the test pass.
4. Refactor if needed, keeping tests green.
```

### No panics on external input

Any code that processes externally-supplied data (quotes, certificates, CBOR, policy configs)
must return `Result`, never `panic!`, `unwrap()`, `expect()`, or `assert!()` on that data.

### No `Co-Authored-By` in commit messages

Do not add `Co-Authored-By` attribution lines to commit messages.

### Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
fix(pki): <short imperative description>
feat(policy): <short imperative description>
docs(readme): <short imperative description>
test(verifier): <short imperative description>
```

First line ≤ 72 characters. If the body is needed, separate it from the subject with a blank line.

### Formatting and linting

All PRs must pass:

```bash
cargo fmt --all -- --check   # no diff
cargo clippy --workspace -- -D warnings   # zero warnings
cargo test --workspace   # all tests green
```

### SAFETY comments for `unsafe`

Any `unsafe` block must have a `// SAFETY:` comment above it that explains why each invariant
required by the unsafe operation is upheld. Five-point justification is expected for `libc::ioctl`
calls (valid fd, stable ioctl number, correct struct layout, pointer validity, no data races).

### Feature gate discipline

- Code that requires heap allocation must be gated `#[cfg(feature = "alloc")]`.
- Code that uses system APIs (file I/O, threads) must be gated `#[cfg(feature = "std")]`.
- Hardware backends must be gated behind their specific feature flag (`hardware-tpm`, `dice`, `intel-tdx`, `amd-sev-snp`).

## Pull Request Process

1. Fork the repository and create a branch: `git checkout -b feat/your-feature-name`.
2. Make your changes with tests.
3. Ensure `cargo fmt`, `cargo clippy`, and `cargo test --workspace` all pass locally.
4. Push and open a PR against `main`.
5. Fill in the PR template: summary bullets and a test plan checklist.
6. A maintainer will review within 5 business days.

PRs are squash-merged. The maintainer may edit the commit message for clarity.

## Areas Where Contributions Are Most Valuable

- **Platform backends** — SEV-SNP and TDX production hardening, OP-TEE, Apple Secure Enclave
- **Transport** — Noise\_PQX integration, COSE/CBOR signing (RFC 9052)
- **Provenance** — Sigstore / Rekor / Fulcio client integration (end-to-end, not just parsing)
- **Fuzzing** — `cargo-fuzz` targets for CBOR parsing, PKI validation, policy evaluation
- **Kani verification** — Formal proofs for the crypto-path invariants
- **Tooling** — Hardware provisioning scripts, key management daemons
- **Bindings** — Python (PyO3), C FFI for embedded integration

## License

By contributing, you agree that your contributions are licensed under the same terms as the
project: MIT OR Apache-2.0, at the recipient's option.
