//! pqrascv — CLI prover and verifier for the PQ-RASCV attestation protocol.
//!
//! # Commands
//!
//! ```text
//! pqrascv keygen   --out-seed seed.bin --out-vk vk.bin
//! pqrascv attest   --seed seed.bin --vk vk.bin --firmware fw.bin [--model model.bin]
//!                  [--builder <url>] [--slsa-level <1-4>] [--out quote.cbor]
//! pqrascv verify   --vk vk.bin --quote quote.cbor --nonce <hex32> [--expected-hash <hex>]
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
    quote::{generate_quote, QuoteTimestamp},
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
    #[command(name = "attest")]
    Attest {
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

        /// 32-byte nonce from the verifier, as 64 hex chars.
        /// If omitted, a cryptographically random nonce is generated and printed —
        /// copy it to use with `verify --nonce`.
        #[arg(long)]
        nonce: Option<String>,

        /// Output path for the CBOR-encoded quote.
        #[arg(long, default_value = "quote.cbor")]
        out: PathBuf,
    },

    /// Verify a quote against a trusted verifying key.
    Verify {
        /// Path to the trusted 1952-byte verifying key.
        #[arg(long)]
        vk: PathBuf,

        /// Path to the CBOR-encoded quote produced by `attest`.
        #[arg(long)]
        quote: PathBuf,

        /// Expected 32-byte nonce as 64 hex chars.
        #[arg(long)]
        nonce: String,

        /// Expected firmware hash (SHA3-256 hex).
        #[arg(long)]
        expected_hash: Option<String>,

        /// Output results in JSON format.
        #[arg(long)]
        json: bool,

        /// Minimum SLSA level to accept (default: 1).
        #[arg(long, default_value_t = 1)]
        min_slsa_level: u8,

        /// Maximum quote age in seconds (0 = no check).
        #[arg(long, default_value_t = 300)]
        max_age: u64,

        /// Accept quotes from devices that have no real-time clock.
        /// Without this flag, NoRtc quotes are rejected.
        #[arg(long, default_value_t = false)]
        allow_rtcless: bool,
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
        Command::Attest {
            seed,
            vk,
            firmware,
            model,
            builder,
            slsa_level,
            nonce,
            out,
        } => cmd_attest(seed, vk, firmware, model, builder, slsa_level, nonce.as_deref(), out),
        Command::Verify {
            vk,
            quote,
            nonce,
            expected_hash,
            json,
            min_slsa_level,
            max_age,
            allow_rtcless,
        } => cmd_verify(vk, quote, &nonce, expected_hash.as_deref(), json, min_slsa_level, max_age, allow_rtcless),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// keygen
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_keygen(out_seed: PathBuf, out_vk: PathBuf) -> anyhow::Result<()> {
    println!("Keypair generated.");
    let (seed, vk) = generate_ml_dsa_keypair()?;
    fs::write(&out_seed, seed.as_bytes())?;
    fs::write(&out_vk, vk)?;

    println!("  Seed (secret): {}", out_seed.display());
    println!("  Verifying key: {}", out_vk.display());
    println!("\n  Keep the seed private. Distribute the verifying key to verifiers.");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// attest
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_attest(
    seed_path: PathBuf,
    vk_path: PathBuf,
    fw_path: PathBuf,
    model_path: Option<PathBuf>,
    builder: String,
    slsa_level: u8,
    nonce_hex: Option<&str>,
    out: PathBuf,
) -> anyhow::Result<()> {
    eprintln!(
        "WARNING: Using SoftwareRoT — no hardware attestation boundary.\n\
         Measurements are derived from caller-supplied bytes, not hardware.\n\
         For production, use a build with `hardware-tpm` or `dice` feature.\n"
    );
    let seed_bytes = fs::read(&seed_path)?;
    let vk_bytes = fs::read(&vk_path)?;
    let firmware = fs::read(&fw_path)?;
    let model: Option<Vec<u8>> = model_path.map(fs::read).transpose()?;

    let nonce = match nonce_hex {
        Some(hex) => parse_nonce(hex)?,
        None => random_nonce()?,
    };

    let vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] =
        vk_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("verifying key must be exactly {ML_DSA_65_VERIFYING_KEY_SIZE} bytes")
        })?;

    let rot = SoftwareRoT::new(&firmware, model.as_deref(), 0);

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

    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => QuoteTimestamp::Rtc(d.as_secs()),
        Err(_) => QuoteTimestamp::NoRtc,
    };

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

    let nonce_display = hex::encode(nonce);
    println!(
        "Attestation Quote generated ({} bytes) → {}",
        cbor.len(),
        out.display()
    );
    println!(
        "  Firmware:  {} (SHA3-256: {})",
        fw_path.display(),
        hex::encode(fw_digest)
    );
    println!("  Nonce:     {nonce_display}  ← pass this to `verify --nonce`");
    println!("  SLSA:      level {slsa_level}");
    println!("  Timestamp: {:?}", timestamp);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// verify
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_verify(
    vk_path: PathBuf,
    quote_path: PathBuf,
    nonce_hex: &str,
    expected_hash_hex: Option<&str>,
    json: bool,
    min_slsa_level: u8,
    max_age: u64,
    allow_rtcless: bool,
) -> anyhow::Result<()> {
    let vk_bytes = fs::read(&vk_path)?;
    if vk_bytes.len() != ML_DSA_65_VERIFYING_KEY_SIZE {
        anyhow::bail!("Invalid verifying key size: expected {ML_DSA_65_VERIFYING_KEY_SIZE}");
    }
    let mut vk_array = [0u8; ML_DSA_65_VERIFYING_KEY_SIZE];
    vk_array.copy_from_slice(&vk_bytes);

    let quote_bytes = fs::read(&quote_path)?;
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(nonce_hex, &mut nonce)
        .map_err(|_| anyhow::anyhow!("Invalid nonce format: must be 64 hex chars"))?;

    // Validate expected_hash_hex is safe hex before any interpolation into JSON
    if let Some(expected) = expected_hash_hex {
        if !expected.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("--expected-hash must be a hex string");
        }
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let policy = PolicyConfig {
        min_slsa_level,
        max_quote_age_secs: max_age,
        require_firmware_hash: true,
        require_event_counter: false,
        allow_rtcless_devices: allow_rtcless,
    };
    let verifier = Verifier::new(policy);

    match verifier.verify_cbor(&quote_bytes, &vk_array, &nonce, now) {
        Ok(result) => {
            let actual_hash = hex::encode(result.firmware_hash());

            if let Some(expected) = expected_hash_hex {
                if actual_hash != expected {
                    if json {
                        println!(r#"{{"verification":"FAILED","reason":"Firmware hash mismatch","expected":"{}","actual":"{}"}}"#, expected, actual_hash);
                    } else {
                        println!("✗  Verification FAILED: Firmware hash mismatch");
                        println!("   Expected: {expected}");
                        println!("   Actual:   {actual_hash}");
                    }
                    std::process::exit(2);
                }
            }

            if json {
                println!(
                    r#"{{
  "verification": "VALID",
  "replay_protection": "PASSED",
  "firmware_hash": "{}",
  "nonce": "{}",
  "slsa_level": {},
  "slsa_level_note": "self-reported; independent CI verification NOT_IMPLEMENTED",
  "bitcoin_anchoring": "NOT_IMPLEMENTED",
  "external_provenance": "NOT_IMPLEMENTED"
}}"#,
                    actual_hash,
                    hex::encode(result.nonce()),
                    result.slsa_level(),
                );
            } else {
                println!("✓  Attestation Quote signature verified.\n");
                println!("   Verification:      VALID (ML-DSA-65 post-quantum signature)");
                println!("   Replay Protection: PASSED (32-byte nonce matched)");
                println!("   Firmware Hash:     {actual_hash}");
                println!("   Nonce:             {}", hex::encode(result.nonce()));
                println!(
                    "   SLSA Level:        {} (self-reported; CI verification NOT_IMPLEMENTED)",
                    result.slsa_level()
                );
                println!("\n   Payload: {}", quote_path.display());
                println!("\n   NOTE: Bitcoin anchoring, consensus verification, and external");
                println!("   provenance validation are NOT YET IMPLEMENTED.");
                println!("   The above confirms ML-DSA-65 signature validity only.");
            }
        }
        Err(e) => {
            if json {
                println!(r#"{{"verification":"FAILED","reason":"{e}"}}"#);
            } else {
                println!("✗  Verification FAILED: {e}");
            }
            std::process::exit(2);
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn random_nonce() -> anyhow::Result<[u8; 32]> {
    use getrandom::rand_core::{Rng, UnwrapErr};
    use getrandom::SysRng;
    let mut nonce = [0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    Ok(nonce)
}

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
