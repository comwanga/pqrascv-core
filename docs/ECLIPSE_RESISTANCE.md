# Eclipse Resistance

This document explains the anti-eclipse protections implemented in Phase 3.6.

## Overview

An eclipse attack occurs when a malicious entity isolates a verifier from the honest network by monopolizing all of its connections. To prevent this, the federation mandates topological diversity.

## Defenses

1. **Active Peer Thresholds**: A verifier must maintain a minimum number of active peer connections.
2. **Regional Spread Requirements**: Connections must span multiple logical network regions to prevent localized isolation.
3. **Fail-Closed Execution**: If a verifier detects its connectivity spread has fallen below safe thresholds, it enters a fail-closed state, refusing to authorize consensus operations until connectivity is restored.
