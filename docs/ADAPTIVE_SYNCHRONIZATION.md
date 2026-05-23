# Adaptive Synchronization

This document explains the adaptive federation synchronization schedule implemented in Phase 3.6.

## Overview

To prevent malicious synchronization amplification and ensure fairness during federation sync, the `AdaptiveSyncEngine` implements exponential backoff for peers failing to synchronize properly.

## Threat Model

- **Sync Amplification**: Attackers repeatedly request large historical ranges.
- **Starvation**: Slow peers consume all available connection slots.
- **Topology Deadlock**: Partitions cause rapid, wasteful retry storms.

## Defense

Peers are throttled exponentially based on consecutive failures. Synchronization health evaluates the overall active fraction of peers, degrading status when a majority are failing.
