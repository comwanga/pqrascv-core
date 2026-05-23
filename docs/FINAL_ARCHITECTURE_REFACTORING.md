# Architecture Stabilization & Simplification

This document captures the stabilization direction for PQ-RASCV following Phase 3.6.

## Principles

1. **Feature Freeze**: No new consensus variants or layers will be added.
2. **Comment Reduction**: Self-documenting types are heavily favored over verbose line comments. Only cryptographic invariants or Byzantine threat-models require extensive inline explanation.
3. **Module Splitting**: Large files (e.g., `policy.rs`) will be strictly separated by Trust Domains.
4. **Deterministic Isolation**: Hashing, canonicalization, and bounds checking logic reside strictly in `hashing.rs` and `invariants.rs`.

This marks the transition from Architectural Expansion to Operational Hardening.
