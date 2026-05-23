# Anti-Equivocation Model

## The Equivocation Problem
Equivocation occurs when a single verifier issues conflicting, signed trust assertions for the exact same point in time. This is a fundamental Byzantine attack intended to fragment the federation's state convergence.

## Canonical Contradiction Semantics
PQ-RASCV formally defines an equivocation as two `SignedStateCommitment`s that share:
1. The identical `verifier_id`
2. The identical monotonic `sequence`
3. A differing `state_hash`

## Minimal Forensic Proof
PQ-RASCV intentionally avoids transmitting full, divergent delta histories to prove equivocation. Doing so would risk transport amplification (DoS). 

Instead, the minimal proof (`EquivocationEvidence`) requires only the two conflicting commitments. Once generated, this evidence is immediately anchorable and triggers automatic revocation propagation.
