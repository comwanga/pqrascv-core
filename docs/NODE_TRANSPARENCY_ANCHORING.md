# Node Transparency Anchoring

To prevent verifiers from colluding or presenting a split-brain view of the node's trust state, the final `AttestedNodeReport` must be anchored.

## The Anchor

A `NodeAttestationAnchor` embeds:
- The session ID.
- The block height.
- The hash of the `AttestedNodeReport`.

## OP_RETURN Anchoring

This anchor can be serialized into a Bitcoin `OP_RETURN` transaction, committing the node's attestation history into the very blockchain it validates. This provides an immutable audit trail of the node's operational integrity.
