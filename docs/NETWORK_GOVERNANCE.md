# Network Governance

This document describes the operational governance of the synchronization layer.

## Overview

While consensus handles verifier identity and policy state, the operational network layer requires its own governance for managing topology.

## Governance Actions

- `UpdateSyncPolicy`: Tuning message caches or chunk sizes.
- `IsolatePeer`: Formalizing a peer penalty into persistent network quarantine.
- `ScheduleRecovery`: Directing the federation to pivot to a disaster recovery checkpoint.

All actions are epoch-bound and signature-verified.
