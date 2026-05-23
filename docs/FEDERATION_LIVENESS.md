# Federation Liveness

This document differentiates protocol correctness from synchronization liveness.

## Separation of Concerns

A verifier's operational status consists of two axes:
1. Correctness: Cryptographic validity (Policy Rules).
2. Liveness: Synchronization health (Availability).

## Failure Detection

The `FederationLivenessState` tracking isolates network starvation from malicious Byzantine behavior. Stagnating quorums or persistent partitions affect liveness independently of the cryptographic integrity enforced by trust domains.
