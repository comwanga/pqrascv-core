//! # pqrascv-cli
//!
//! Command-line interface for the [PQ-RASCV](https://crates.io/crates/pqrascv-core)
//! hardware attestation protocol.
//!
//! ## Installation
//!
//! ```text
//! cargo install pqrascv-cli
//! ```
//!
//! ## Usage
//!
//! ```text
//! # Generate a post-quantum keypair
//! pqrascv keygen --out-seed seed.bin --out-vk vk.bin
//!
//! # Generate an attestation quote (prover side)
//! pqrascv attest \
//!   --seed seed.bin --vk vk.bin \
//!   --firmware firmware.bin \
//!   --slsa-level 2 \
//!   --out quote.cbor \
//!   --software-rot-acknowledged
//!
//! # Verify the quote (verifier side)
//! pqrascv verify \
//!   --vk vk.bin \
//!   --quote quote.cbor \
//!   --nonce <64-HEX-NONCE> \
//!   --json
//! ```
//!
//! This crate is a binary. For the library API see
//! [`pqrascv-core`](https://docs.rs/pqrascv-core) and
//! [`pqrascv-verifier`](https://docs.rs/pqrascv-verifier).
