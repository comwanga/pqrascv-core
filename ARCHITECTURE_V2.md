# PQ-RASCV v2 Architecture
## Bitcoin-Anchored Post-Quantum Remote Attestation for Sovereign Infrastructure

---

## 1. Executive Summary

PQ-RASCV v2 is a ground-up redesign of the attestation platform following a
critical security audit that identified ten architectural failures in v0.1.
The new system is built on three independently verifiable pillars:

```
Hardware proves execution reality.
CI proves software origin.
Bitcoin proves historical existence.
```

No component is trusted unless independently verifiable. Every trust
relationship is explicit, typed, and enforced at compile time where possible.

---

## 2. Strategic Positioning

PQ-RASCV v2 targets sovereign infrastructure operators — Bitcoin node
operators, critical national infrastructure, air-gapped government systems,
and high-assurance IoT deployments — who require:

- Cryptographic proof of *what* is running (hardware attestation)
- Cryptographic proof of *how* it was built (external CI provenance)
- Cryptographic proof of *when* it existed (Bitcoin timestamping)
- Post-quantum resistance for 20+ year operational lifetimes
- Offline verifiability without centralized trust anchors

---

## 3. Threat Model

### Adversary Capabilities

| Adversary | Capability |
|-----------|-----------|
| Nation-state | Quantum computer (Shor's algorithm), supply-chain compromise |
| Insider | Firmware modification, key exfiltration, CI pipeline compromise |
| Network attacker | MITM, replay, downgrade attacks |
| Physical attacker | Cold-boot, bus probing, fault injection |

### Assets Under Protection

1. Device signing key (ML-DSA-65 seed)
2. Firmware integrity (what is running)
3. Build provenance (how it was built)
4. Attestation history (when it ran, immutable audit trail)
5. Device identity (PKI certificate chain)

### Out of Scope

- Physical destruction of hardware
- Compromise of the Bitcoin network itself (>51% attack)
- Compromise of the offline root CA private key

---

## 4. Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUST HIERARCHY                               │
│                                                                  │
│  Bitcoin Network (decentralized, immutable history)             │
│       ↑ anchors                                                  │
│  Offline Root CA (air-gapped, ceremony-generated)               │
│       ↓ signs                                                    │
│  Manufacturer Intermediate CA                                    │
│       ↓ signs                                                    │
│  Device Certificate (binds: pubkey + hw_id + fw_policy)         │
│       ↓ signs                                                    │
│  AttestationQuote (hardware-measured, nonce-bound)              │
│       ↑ independently signed by                                  │
│  CI/CD Sigstore Bundle (external provenance, not self-asserted) │
└─────────────────────────────────────────────────────────────────┘
```

### Trust Axioms

1. The TPM/DICE hardware executes before and outside attacker-controlled code
2. The offline root CA private key never touches a networked machine
3. Bitcoin's proof-of-work provides objective time ordering
4. Sigstore's transparency log is independently auditable
5. Nonces are single-use and verifier-generated

---

## 5. System Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║                    PQ-RASCV v2 SYSTEM                               ║
╠══════════════════════════════════════════════════════════════════════╣
║  PROVER SIDE (device)          VERIFIER SIDE (server/offline)       ║
║  ┌─────────────────────┐       ┌──────────────────────────────┐     ║
║  │ Hardware RoT        │       │ PKI Validator                │     ║
║  │ (TPM/DICE/TDX/SEV)  │       │ (cert chain + CRL)           │     ║
║  ├─────────────────────┤       ├──────────────────────────────┤     ║
║  │ Measurement Layer   │       │ Nonce Ledger                 │     ║
║  │ (PCRs, fw_hash)     │       │ (single-use enforcement)     │     ║
║  ├─────────────────────┤       ├──────────────────────────────┤     ║
║  │ PKI Identity        │       │ Sigstore Verifier            │     ║
║  │ (device cert chain) │       │ (external provenance)        │     ║
║  ├─────────────────────┤       ├──────────────────────────────┤     ║
║  │ Quote Assembly      │       │ Policy Engine v2             │     ║
║  │ (CBOR + ML-DSA-65)  │       │ (typed, composable rules)    │     ║
║  └─────────────────────┘       ├──────────────────────────────┤     ║
║           │                    │ Bitcoin Anchor Verifier       │     ║
║           │ AttestationQuote   │ (SPV / Merkle proof)         │     ║
║           └───────────────────►└──────────────────────────────┘     ║
║                                         │                           ║
║                              ┌──────────▼──────────┐               ║
║                              │ Bitcoin Anchor Layer │               ║
║                              │ (OP_RETURN + Merkle) │               ║
║                              └─────────────────────┘               ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 6. Crate Structure

```
pqrascv-core/
├── crates/
│   ├── pqrascv-core/          # Core prover library (no_std + alloc)
│   │   └── src/
│   │       ├── measurement.rs      # RoT trait + PCR bank
│   │       ├── crypto.rs           # ML-DSA-65 backend
│   │       ├── quote.rs            # AttestationQuote assembly
│   │       ├── error.rs            # PqRascvError
│   │       ├── config.rs           # PolicyConfig (legacy, kept for compat)
│   │       ├── provenance.rs       # InTotoAttestation (self-asserted, test only)
│   │       ├── pki/
│   │       │   ├── mod.rs          # DeviceCertificate, CertChain
│   │       │   └── revocation.rs   # CRL types
│   │       ├── nonce/
│   │       │   └── mod.rs          # NonceHandle, ClockEvidence
│   │       ├── policy/
│   │       │   └── mod.rs          # PolicyEngineV2, typed rules
│   │       ├── provenance_v2/
│   │       │   └── mod.rs          # ExternalProvenanceBundle (Sigstore)
│   │       └── backends/
│   │           ├── mod.rs
│   │           ├── dice.rs         # DICE CDI derivation
│   │           ├── tpm.rs          # TPM 2.0 (hardware-tpm feature)
│   │           └── software.rs     # TEST ONLY (software-rot-unsafe feature)
│   ├── verifier/              # Reference verifier (std only)
│   ├── bitcoin-anchor/        # Bitcoin anchoring layer
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── merkle.rs      # Merkle tree batching
│   │       ├── anchor.rs      # OP_RETURN transaction builder
│   │       └── proof.rs       # SPV inclusion proof verification
│   └── cli/                   # CLI tooling
```

---

## 7. Attestation Flow (v2)

```
Verifier                                    Prover (device)
   │                                              │
   │── Challenge { nonce_handle, policy_id } ───►│
   │   (nonce registered in ledger)               │
   │                                              ├── TPM/DICE measure() → PCRs
   │                                              ├── load device certificate chain
   │                                              ├── load external provenance bundle
   │                                              │   (signed by CI, not device)
   │                                              └── sign QuoteBody → ML-DSA-65
   │                                              │
   │◄── AttestationQuote (CBOR) ─────────────────│
   │                                              │
   ├── verify protocol version (reject downgrade)
   ├── verify nonce is in ledger + mark consumed
   ├── verify device cert chain → root CA
   ├── verify cert not revoked (CRL check)
   ├── verify ML-DSA-65 signature
   ├── verify pub_key_id matches cert subject key
   ├── verify external provenance bundle (Sigstore)
   ├── verify builder identity in transparency log
   ├── evaluate PolicyEngineV2 rules
   └── optionally: verify Bitcoin anchor inclusion proof
```

---

## 8. Cryptographic Design

### Algorithm Selection

| Role | Algorithm | Standard | Rationale |
|------|-----------|----------|-----------|
| Device signatures | ML-DSA-65 | FIPS 204 | NIST PQC standard, 128-bit PQ security |
| Key encapsulation | ML-KEM-768 | FIPS 203 | For future PQ transport layer |
| Hashing | SHA3-256 | FIPS 202 | Consistent across all backends |
| Wire encoding | CBOR | RFC 8949 | Compact, no_std-friendly |
| Bitcoin anchoring | SHA-256d | Bitcoin | Double-SHA256 for Merkle roots |

### Dependency Pinning Strategy

```toml
# Pin to exact version; update only after security review
ml-dsa = { version = "=0.1.0-rc.8", ... }
```

All cryptographic dependencies are pinned to exact versions in `Cargo.lock`
and audited via `cargo audit` in CI. The `deny.toml` enforces no unmaintained
or yanked crates.

---

## 9. PKI Design

### Certificate Hierarchy

```
Offline Root CA (air-gapped)
  └── Manufacturer Intermediate CA (HSM-protected)
        └── Device Certificate
              ├── Subject: device serial / hardware ID
              ├── SubjectPublicKey: ML-DSA-65 verifying key
              ├── Extensions:
              │     ├── FirmwarePolicyConstraint (allowed fw hash set)
              │     ├── HardwareIdentityBinding (TPM EK cert hash)
              │     └── KeyUsage: digitalSignature
              └── Validity: 10 years (device lifetime)
```

### Certificate Format

Certificates use a CBOR-native format (not X.509) to remain no_std-compatible
and avoid ASN.1 parsing complexity on embedded targets. The format is defined
in `pki/mod.rs` as `DeviceCertificate`.

### Revocation

CRLs are distributed as signed CBOR lists. Verifiers cache the CRL locally
and refresh on a configurable schedule. For offline operation, the last known
CRL is used with a staleness warning.

---

## 10. Provenance Design (v2)

### The Problem with v1

In v1, the device self-asserts its SLSA provenance. This is cryptographically
meaningless — a compromised device can claim any SLSA level.

### v2 Solution: External Provenance Bundle

```
CI/CD Pipeline
  ├── builds firmware
  ├── generates in-toto provenance statement
  ├── signs with Sigstore (OIDC + Rekor transparency log)
  └── exports: ExternalProvenanceBundle {
        predicate: InTotoAttestation,
        sigstore_bundle: SigstoreBundle {
            signature: <CI key sig>,
            rekor_entry: <transparency log inclusion proof>,
            cert: <Fulcio-issued short-lived cert>,
        }
      }

Device
  └── embeds ExternalProvenanceBundle in AttestationQuote
      (device does NOT sign the provenance — CI already did)

Verifier
  ├── extracts ExternalProvenanceBundle from quote
  ├── verifies Sigstore bundle (cert chain + Rekor proof)
  ├── verifies builder identity matches policy allowlist
  └── verifies firmware hash in provenance matches measured hash
```

---

## 11. Bitcoin Layer Design

### Architecture

```
Attestation Quotes
      │
      ▼
MerkleAggregator (batch N quotes per block)
      │ SHA3-256 Merkle root
      ▼
BitcoinAnchor::commit(merkle_root)
      │ OP_RETURN output: "PQRASCV" || version || merkle_root[0..20]
      ▼
Bitcoin Transaction (broadcast)
      │
      ▼
Block confirmation (6 blocks = ~1 hour finality)
      │
      ▼
InclusionProof { txid, block_height, merkle_path, ... }
      │
      ▼
SPVVerifier::verify(proof, quote_hash) → Ok(BlockHeight)
```

### OP_RETURN Format

```
OP_RETURN <magic: 7 bytes "PQRASCV"> <version: 1 byte> <merkle_root: 20 bytes>
Total: 28 bytes (well within 80-byte OP_RETURN limit)
```

### Security Properties

- Immutable: Bitcoin's proof-of-work makes rewriting history computationally
  infeasible
- Decentralized: No single party controls the audit log
- Offline-verifiable: SPV proofs can be verified without a full node
- Sovereign: Operators can run their own Bitcoin node for full verification

---

## 12. Hardware Attestation Layer

### Backend Abstraction

```rust
pub trait RoT {
    fn measure(&self) -> Result<Measurements, PqRascvError>;
    fn hw_identity(&self) -> Option<HardwareIdentity>;
}
```

### Backend Security Properties

| Backend | Measurement Root | Attacker Boundary | Production? |
|---------|-----------------|-------------------|-------------|
| TPM 2.0 | TPM firmware | Below OS | ✅ Yes |
| DICE | Hardware UDS | Below bootloader | ✅ Yes |
| Intel TDX | CPU microcode | Below VMM | ✅ Yes (planned) |
| AMD SEV-SNP | CPU microcode | Below hypervisor | ✅ Yes (planned) |
| SoftwareRoT | None | None | ❌ Test only |

### TPM Hash Normalization (fixes audit finding #5)

The TPM backend reads SHA-256 PCRs from hardware, then wraps each value
through `SHA3-256(raw_pcr)` before storing in `PcrBank`. This ensures
cross-backend policy consistency: all PCR values in `PcrBank` are always
SHA3-256 digests, regardless of the underlying hardware algorithm.

---

## 13. Verifier Design (v2)

### Verification Pipeline

```rust
pub struct VerifierV2 {
    root_ca: TrustAnchor,
    crl: RevocationList,
    nonce_ledger: Box<dyn NonceLedger>,
    policy: PolicyEngineV2,
    sigstore_config: Option<SigstoreConfig>,
    bitcoin_config: Option<BitcoinVerifyConfig>,
}
```

### Verification Steps (ordered, fail-fast)

1. Size check (CBOR bounds)
2. Protocol version check (reject downgrade)
3. Nonce consumption (single-use enforcement)
4. Certificate chain validation (root CA → device cert)
5. Certificate revocation check (CRL)
6. Signature verification (ML-DSA-65)
7. pub_key_id ↔ certificate subject key binding
8. External provenance bundle verification (Sigstore)
9. Firmware hash cross-check (provenance ↔ measurement)
10. Policy engine evaluation
11. Bitcoin anchor verification (optional, for audit)

---

## 14. Policy Engine Design (v2)

### Typed Rule Composition

```rust
pub enum PolicyRule {
    MinSlsaLevel(u8),
    RequireFirmwareHash,
    AllowedBuilders(Vec<String>),
    AllowedFirmwareHashes(Vec<[u8; 32]>),
    RequireHardwareBackend(HardwareBackendKind),
    RequireCertificateChain,
    RequireExternalProvenance,
    MaxQuoteAgeSecs(u64),
    RequireBitcoinAnchor { min_confirmations: u32 },
    AllowRtclessDevices,
}
```

Rules are evaluated in order; the first failure short-circuits. Rules are
serializable so policies can be distributed and audited.

---

## 15. Storage & Persistence

### Nonce Ledger

```
Interface: trait NonceLedger { fn consume(&mut self, nonce: &[u8;32]) -> Result<()>; }
Implementations:
  - InMemoryNonceLedger (tests, single-process)
  - SqliteNonceLedger (production, single-node)
  - RedisNonceLedger (production, distributed)
```

### Certificate Store

Certificates and CRLs are stored as CBOR files on disk, loaded at startup.
The verifier holds them in memory during operation.

### Bitcoin Anchor Store

Anchor records (txid, block_height, merkle_root, inclusion_proofs) are stored
in a local SQLite database. The store is append-only; records are never deleted.

---

## 16. APIs & SDKs

### Rust SDK (this crate)

Primary interface. All other SDKs are thin wrappers.

### Python SDK (planned)

PyO3 bindings exposing:
- `generate_quote()` (prover)
- `verify_quote()` (verifier)
- `anchor_quotes()` (Bitcoin anchoring)

### CLI (crates/cli)

```
pqrascv-cli
  ├── prover attest [--backend tpm|dice] [--provenance <bundle.json>]
  ├── verifier verify <quote.cbor> [--policy <policy.json>]
  ├── pki issue-device-cert [--ca-key <key>] [--hw-id <id>]
  ├── pki verify-chain <cert.cbor>
  ├── bitcoin anchor <quotes...>
  ├── bitcoin verify-proof <proof.json> <quote_hash>
  └── nonce generate
```

---

## 17. Deployment Architecture

### Sovereign / Air-Gapped

```
[Offline Root CA machine] ──signs──► [Manufacturer CA HSM]
                                              │
                                    [Device provisioning station]
                                              │ issues device certs
                                    [Deployed devices]
                                              │ attestation quotes
                                    [Verifier (local network)]
                                              │ optional
                                    [Bitcoin full node (local)]
```

### Cloud / Enterprise

```
[Devices] ──quotes──► [Verifier Service (k8s)]
                              │
                    [Nonce Ledger (Redis)]
                    [CRL Cache (S3)]
                    [Bitcoin Anchor Service]
                              │
                    [Bitcoin Node (or Electrum)]
```

---

## 18. Security Hardening

### Phase 1 Emergency Fixes (implemented in this PR)

1. **SoftwareRoT removed from production paths** — gated behind
   `software-rot-unsafe` feature, rejected by `PolicyEngineV2` by default
2. **Replay bypass fixed** — `ClockEvidence::NoRtc` is explicit; `timestamp=0`
   is no longer a valid bypass; nonce ledger enforces single-use
3. **Protocol version enforced** — verifier rejects any version ≠ current
4. **CBOR bounds** — `MAX_QUOTE_CBOR_SIZE = 65536` enforced before allocation
5. **Crypto dependency pinned** — `ml-dsa = "=0.1.0-rc.8"` exact version
6. **pub_key_id bound to PKI** — certificate chain validation replaces
   arbitrary key trust

### Ongoing Hardening

- `cargo audit` in CI (deny.toml)
- `cargo deny` for license and advisory checks
- Fuzz targets for CBOR deserialization paths
- Kani harnesses for crypto paths (planned)
- Memory-safe Rust throughout; no `unsafe` in security-critical paths

---

## 19. Attack Resistance

| Attack | v1 Status | v2 Mitigation |
|--------|-----------|---------------|
| Compromised firmware self-attests | ❌ Trivial | ✅ Hardware RoT measures below attacker code |
| Forged SLSA provenance | ❌ Trivial | ✅ External Sigstore bundle, CI-signed |
| Replay attack (timestamp=0) | ❌ Trivial | ✅ Nonce ledger + ClockEvidence enum |
| Arbitrary key trust | ❌ No PKI | ✅ Certificate chain to offline root CA |
| TPM/SHA-256 confusion | ❌ Present | ✅ SHA3-256 normalization layer |
| Caller-controlled counters | ❌ Present | ✅ Hardware monotonic counter (TPM NV) |
| Pre-release crypto crate | ❌ Present | ✅ Exact version pin + audit |
| CBOR DoS/OOM | ❌ Present | ✅ Size limit before allocation |
| Downgrade attack | ❌ Present | ✅ Version field enforced, reject unknown |
| Harvest-now-decrypt-later | ⚠️ Partial | ✅ ML-DSA-65 PQ signatures throughout |
| Supply chain (build time) | ❌ None | ✅ Sigstore + Rekor transparency log |
| Historical audit tampering | ❌ None | ✅ Bitcoin OP_RETURN anchoring |

---

## 20. Implementation Roadmap

### Phase 1 — Emergency Security Corrections (this PR)
- [x] `pki/mod.rs` — DeviceCertificate, CertChain, TrustAnchor
- [x] `pki/revocation.rs` — RevocationList, CRL
- [x] `nonce/mod.rs` — NonceHandle, ClockEvidence, NonceLedger trait
- [x] `policy/mod.rs` — PolicyEngineV2, PolicyRule enum
- [x] `provenance_v2/mod.rs` — ExternalProvenanceBundle, SigstoreBundle
- [x] `bitcoin-anchor/` — MerkleAggregator, InclusionProof, SPVVerifier

### Phase 2 — PKI Infrastructure
- [ ] Certificate issuance tooling (CLI)
- [ ] CRL distribution service
- [ ] HSM integration for manufacturer CA

### Phase 3 — Supply Chain Security
- [ ] Sigstore/Rekor client integration
- [ ] GitHub Actions provenance generation workflow
- [ ] Builder identity allowlist management

### Phase 4 — Hardware Attestation
- [ ] TPM 2.0 backend (stable tss-esapi)
- [ ] Intel TDX backend
- [ ] AMD SEV-SNP backend

### Phase 5 — Bitcoin Integration
- [ ] Bitcoin node RPC client
- [ ] Electrum SPV client
- [ ] Anchor batching service

### Phase 6 — Ecosystem
- [ ] Python SDK (PyO3)
- [ ] Kubernetes admission webhook
- [ ] Prometheus metrics
