# Bitcoin Workload Integrity

Workload integrity guarantees that the exact expected version of Bitcoin Core is running with the exact expected configuration.

## `BitcoinWorkloadEvidence`

This data structure captures:
- `bitcoind_pid`: The process ID.
- `executable_hash`: The hardware-measured hash of the `bitcoind` binary.
- `config_hash`: The measured hash of the `bitcoin.conf` file.
- `chainstate_hash`: Optional integrity measurements for the chainstate.

## Verification

The policy engine checks `BitcoinWorkloadEvidence` against the `BitcoinNodeIdentity` established by the node operator. If the hashes mismatch, the verification fails with `BitcoinBinaryMismatch` or `UnauthorizedConfigMutation`.
