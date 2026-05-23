# Operational Peer Scoring

This document describes the distinction between cryptographic trust and synchronization scoring.

## Scope

`PeerOperationalScore` tracks compliance with synchronization protocols. It does not map to consensus authority.

## Penalty Model

- Invalid signatures, malformed syntax: High penalty.
- Replay attacks: Instant isolation.
- Missing heartbeats, stalls: Low penalty.

Once a peer hits maximum penalty bounds, the connection is throttled or isolated, preventing network exhaustion attacks.
