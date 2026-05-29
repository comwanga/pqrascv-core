#![no_main]

extern crate alloc;

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::{
    bitcoin_node_identity::{BitcoinNetwork, BitcoinNodeIdentity},
    bitcoin_workload_integrity::BitcoinWorkloadEvidence,
    digest::{DigestAlgorithm, TypedDigest},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let pid = u32::from(data[0]);
    let network = match data[1] % 4 {
        0 => BitcoinNetwork::Mainnet,
        1 => BitcoinNetwork::Testnet,
        2 => BitcoinNetwork::Signet,
        _ => BitcoinNetwork::Regtest,
    };

    let mut hash_bytes = [0u8; 32];
    if data.len() >= 34 {
        hash_bytes.copy_from_slice(&data[2..34]);
    }
    let digest = TypedDigest::new(DigestAlgorithm::Sha3_256, hash_bytes);

    // Exercise BitcoinWorkloadEvidence construction — must not panic.
    let _evidence = BitcoinWorkloadEvidence::new(
        pid,
        digest.clone(),
        digest.clone(),
        None,
        alloc::vec![],
    );

    // Exercise BitcoinNodeIdentity construction — must not panic.
    let _identity = BitcoinNodeIdentity::new(
        "fuzz-node".into(),
        network,
        "26.0.0".into(),
        digest.clone(),
        digest,
    );
});
