# Byzantine Quorums

## Safety vs. Liveness
PQ-RASCV explicitly separates the Byzantine state of the federation into Safety and Liveness matrices. 

- A federation may be **Safe but Stalled** (failing to reach consensus, but no malicious action detected).
- A federation may be **Partitioned** (multiple sub-quorums operating independently, compromising liveness).
- A federation may be **Unsafe** due to detected equivocation.

## Intersection Rules
Assuming standard BFT limits (`N >= 3f + 1`):
- **Convergence**: Requires `2f + 1` valid, non-equivocating votes.
- **Partition**: Detected when multiple, disjoint subsets of verifiers accumulate `>= f + 1` votes for differing states. Because no subset can legally reach `2f + 1`, the system halts securely instead of merging conflicts.

## Quorum Certificates
Valid consensus outcomes generate a `QuorumCertificate`. This structure acts as a portable proof that `2f + 1` valid authorities agreed upon a canonical state hash, reducing verification complexity for downstream Observers.
