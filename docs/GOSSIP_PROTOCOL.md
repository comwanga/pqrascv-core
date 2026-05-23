# Gossip Protocol

This document explains the bounded sovereign gossip dissemination implemented in Phase 3.6.

## Overview

The gossip protocol ensures that state updates and topology events propagate deterministically without risking memory exhaustion or infinite routing loops.

## Bounded Dissemination

- All envelopes (`GossipEnvelope`) carry an `hlc_timestamp` and `federation_epoch`.
- Deduplication bounds are enforced using a FIFO buffer (`GossipDeduplication`) capped at a static maximum capacity to prevent exhaustion.
- Replayed signatures or previously seen hashes are dropped immediately.
