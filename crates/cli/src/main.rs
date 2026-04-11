//! pqrascv — CLI prover and verifier for the PQ-RASCV attestation protocol.
//!
//! # Commands
//!
//! ```text
//! pqrascv keygen   --out-seed seed.bin --out-vk vk.bin
//! pqrascv prove    --seed seed.bin --vk vk.bin --firmware fw.bin [--model model.bin]
//!                  [--builder <url>] [--slsa-level <1-4>] [--out quote.cbor]
//! pqrascv verify   --vk vk.bin --quote quote.cbor --nonce <hex32>
//! ```

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use pqrascv_core::{
    config::PolicyConfig,
    crypto::{generate_ml_dsa_keypair, MlDsaBackend, ML_DSA_65_VERIFYING_KEY_SIZE},
    measurement::SoftwareRoT,
    provenance::SlsaPredicateBuilder,
    quote::generate_quote,
};
use pqrascv_verifier::Verifier;

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "pqrascv",
    about = "Post-Quantum Remote Attestation & Supply-Chain Verification",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh ML-DSA-65 keypair.
    Keygen {
        /// Output path for the 32-byte signing seed (keep secret).
        #[arg(long, default_value = "seed.bin")]
        out_seed: PathBuf,

        /// Output path for the 1952-byte verifying key (distribute to verifiers).
        #[arg(long, default_value = "vk.bin")]
        out_vk: PathBuf,
    },

    /// Generate an attestation quote for a firmware image.
    Prove {
        /// Path to the 32-byte signing seed produced by `keygen`.
        #[arg(long)]
        seed: PathBuf,

        /// Path to the verifying key produced by `keygen`.
        #[arg(long)]
        vk: PathBuf,

        /// Firmware image to measure (SHA3-256 hashed).
        #[arg(long)]
        firmware: PathBuf,

        /// Optional AI model weights to measure.
        #[arg(long)]
        model: Option<PathBuf>,

        /// SLSA builder ID (URI identifying the CI pipeline).
        #[arg(long, default_value = "https://github.com/comwanga/pqrascv-core")]
        builder: String,

        /// SLSA level (1–4).
        #[arg(long, default_value_t = 1)]
        slsa_level: u8,

        /// 32-byte nonce from the verifier, as 64 hex chars. Defaults to all zeros —
        /// fine for demos, but use a real nonce in production.
        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        nonce: String,

        /// Output path for the CBOR-encoded quote.
        #[arg(long, default_value = "quote.cbor")]
        out: PathBuf,
    },

    /// Verify a quote against a trusted verifying key.
    Verify {
        /// Path to the trusted 1952-byte verifying key.
        #[arg(long)]
        vk: PathBuf,

        /// Path to the CBOR-encoded quote produced by `prove`.
        #[arg(long)]
        quote: PathBuf,

        /// Expected 32-byte nonce as 64 hex chars.
        #[arg(long)]
        nonce: String,

        /// Minimum SLSA level to accept (default: 1).
        #[arg(long, default_value_t = 1)]
        min_slsa_level: u8,

        /// Maximum quote age in seconds (0 = no check).
        #[arg(long, default_value_t = 300)]
        max_age: u64,
    },
}

// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen { out_seed, out_vk } => cmd_keygen(out_seed, out_vk),
        Command::Prove {
            seed,
            vk,
            firmware,
            model,
            builder,
            slsa_level,
            nonce,
            out,
        } => cmd_prove(seed, vk, firmware, model, builder, slsa_level, nonce, out),
        Command::Verify {
            vk,
            quote,
            nonce,
            min_slsa_level,
            max_age,
        } => cmd_verify(vk, quote, nonce, min_slsa_level, max_age),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// keygen
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_keygen(out_seed: PathBuf, out_vk: PathBuf) -> anyhow::Result<()> {
    let (seed, vk) = generate_ml_dsa_keypair()?;

    fs::write(&out_seed, seed.as_bytes())?;
    fs::write(&out_vk, vk)?;

    println!("Keypair generated.");
    println!("  Seed (secret): {}", out_seed.display());
    println!("  Verifying key: {}", out_vk.display());
    println!();
    println!("  Keep the seed private. Distribute the verifying key to verifiers.");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// prove
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_prove(
    seed_path: PathBuf,
    vk_path: PathBuf,
    fw_path: PathBuf,
    model_path: Option<PathBuf>,
    builder: String,
    slsa_level: u8,
    nonce_hex: String,
    out: PathBuf,
) -> anyhow::Result<()> {
    let seed_bytes = fs::read(&seed_path)?;
    let vk_bytes = fs::read(&vk_path)?;
    let firmware = fs::read(&fw_path)?;
    let model: Option<Vec<u8>> = model_path.map(fs::read).transpose()?;

    let nonce = parse_nonce(&nonce_hex)?;

    let vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] =
        vk_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("verifying key must be exactly {ML_DSA_65_VERIFYING_KEY_SIZE} bytes")
        })?;

    let rot = SoftwareRoT::new(&firmware, model.as_deref(), 0);

    // Hash the firmware and register it as a provenance subject.
    let fw_digest = sha3_256(&firmware);
    let mut builder_obj = SlsaPredicateBuilder::new(&builder)
        .add_subject(
            fw_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .as_ref(),
            &fw_digest,
        )
        .with_slsa_level(slsa_level);

    if let Some(ref m) = model {
        let model_digest = sha3_256(m);
        builder_obj = builder_obj.add_subject("model", &model_digest);
    }

    let provenance = builder_obj.build()?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let quote = generate_quote(
        &rot,
        &MlDsaBackend,
        &seed_bytes,
        &vk_array,
        &nonce,
        provenance,
        timestamp,
    )?;
    let cbor = quote.to_cbor()?;

    fs::write(&out, &cbor)?;

    println!("Quote generated ({} bytes) → {}", cbor.len(), out.display());
    println!(
        "  Firmware:  {} (SHA3-256: {})",
        fw_path.display(),
        hex::encode(fw_digest)
    );
    println!("  Nonce:     {nonce_hex}");
    println!("  SLSA:      level {slsa_level}");
    println!("  Timestamp: {timestamp}");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// verify
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_verify(
    vk_path: PathBuf,
    quote_path: PathBuf,
    nonce_hex: String,
    min_slsa_level: u8,
    max_age: u64,
) -> anyhow::Result<()> {
    let vk_bytes = fs::read(&vk_path)?;
    let quote_bytes = fs::read(&quote_path)?;
    let nonce = parse_nonce(&nonce_hex)?;

    let vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] =
        vk_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("verifying key must be exactly {ML_DSA_65_VERIFYING_KEY_SIZE} bytes")
        })?;

    let policy = PolicyConfig {
        min_slsa_level,
        max_quote_age_secs: max_age,
        require_firmware_hash: true,
        require_event_counter: false,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let verifier = Verifier::new(policy);

    match verifier.verify_cbor(&quote_bytes, &vk_array, &nonce, now) {
        Ok(_) => {
            println!("✓  Quote verified successfully.");
            println!("   Quote: {}", quote_path.display());
            println!("   SLSA level ≥ {min_slsa_level}: satisfied");
        }
        Err(e) => {
            println!("✗  Verification FAILED: {e}");
            std::process::exit(2);
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_nonce(hex: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex)
        .map_err(|_| anyhow::anyhow!("nonce must be 64 hex characters (32 bytes)"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be exactly 32 bytes (64 hex chars)"))
}

fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}
