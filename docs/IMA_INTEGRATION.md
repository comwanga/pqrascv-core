# Linux IMA/Appraisal Subsystem Integration

The Integrity Measurement Architecture (IMA) is a Linux kernel subsystem that measures files before they are read or executed. It can also appraise/enforce their integrity against locally stored signatures (EVM/Appraisal). 

PQ-RASCV v2 parses binary IMA logs on the verifier side to continuously verify post-boot file integrity.

## IMA Data Structures

The integration defines the following structures in `ima_integration.rs`:

```rust
pub struct ImaMeasurement {
    /// PCR index where the measurement was extended (typically PCR 10).
    pub pcr: u32,
    /// The template hash recorded in the IMA log.
    pub template_hash: [u8; 20],
    /// The IMA template name (e.g., "ima", "ima-ng", "ima-sig").
    pub template_name: String,
    /// Normalized cryptographic hash of the measured file.
    pub file_hash: TypedDigest,
    /// Absolute or relative path of the measured file.
    pub file_path: String,
}

pub struct ImaEvidence {
    /// Indicates whether IMA measurement is active.
    pub ima_enabled: bool,
    /// Indicates whether Appraisal/EVM enforcement is active.
    pub appraisal_enabled: bool,
    /// Parsed measurements from the binary runtime log.
    pub measurements: Vec<ImaMeasurement>,
}
```

## Bounded Binary Parser

IMA logs can be extremely large, presenting a potential Denial of Service (DoS) vector via memory exhaustion. To prevent this, the parser implements strict safety bounds:

1. **Max Event Count Limit**: The parser accepts a `max_events` argument to stop parsing if the log length exceeds the configured threshold.
2. **Field Length Bounds**:
   - The template name length is capped at `64` bytes.
   - The file path length is capped at `1024` bytes.
   - The file hash length is capped at `256` bytes.
   - The signature length (for `ima-sig`) is capped at `1024` bytes.
3. **Unexpected EOF Handling**: The parser checks buffer lengths before any slice access, returning `ImaParseError::UnexpectedEof` instead of panicking on truncated streams.

## Supported Templates

The parser supports three major Linux IMA template formats:

- **`ima`**: The legacy format, containing a 20-byte file SHA-1 digest and a variable-length file path.
- **`ima-ng`**: The modern default format, containing a hash algorithm identifier (e.g., `sha256\0`), a variable-length hash, and a variable-length path.
- **`ima-sig`**: Similar to `ima-ng`, but appends a signature field containing the file signature (RSA or ECDSA).

## Example Parsing Usage

```rust
let binary_log: &[u8] = fetch_ima_log();
let max_allowed_events = 10_000;

match ImaEvidence::parse_binary(binary_log, max_allowed_events) {
    Ok(evidence) => {
        println!("Successfully parsed {} measurements", evidence.measurements.len());
    }
    Err(e) => {
        eprintln!("Failed to parse IMA log: {e}");
    }
}
```
