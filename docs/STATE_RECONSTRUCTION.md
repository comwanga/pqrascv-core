# State Reconstruction

This document describes bounded state reconstruction.

## Overview

When recovering a federation from snapshot chunks, the verifier must verify that the state lineage maps exactly to the previous verified cryptographic state without gaps.

## Constraints

Reconstruction guarantees deterministic ordering and rejects ambiguous paths. If the timeline diverges or if multiple inconsistent snapshots exist, the system enforces a strict fail-closed policy, requiring out-of-band operator recovery or Bitcoin-anchored governance overrides.
