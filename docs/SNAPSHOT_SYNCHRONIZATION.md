# Snapshot Synchronization

This document outlines deterministic snapshot distribution in Phase 3.6.

## Overview

Sending large unbounded replay histories over the network creates significant bandwidth and memory exhaustion risks. The solution is chunked snapshot synchronization.

## Merkle-Verified Chunking

1. A snapshot is bounded by a root `SnapshotManifest`.
2. The snapshot data is deterministically split into `SnapshotChunk`s.
3. Each chunk contains a Merkle proof tying it to the manifest root.
4. As chunks arrive, they are verified independently and cached.
5. Reassembly occurs deterministically once all expected chunks arrive.
