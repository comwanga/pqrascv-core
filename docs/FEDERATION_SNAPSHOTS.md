# Federation Snapshots

Snapshots are cryptographic continuity checkpoints, NOT simple backups. They provide an append-only lineage of the federation's evolution.
By referencing `previous_snapshot_hash`, the federation maintains a tamper-evident recovery chain.

See `crates/pqrascv-hardware/src/federation_snapshot.rs`.
