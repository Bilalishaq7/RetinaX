# Audit Contract Architectural Deep-Dive

## Overview

The `audit` contract provides a production-grade, distributed, and tamper-evident audit logging system tailored for the RetinaX health data ecosystem. It is designed to run in a `no_std` environment suitable for Soroban smart contracts.

The architecture is built on four core pillars:
1. **Hash Chains**: Every log entry is cryptographically linked to its predecessor via a `prev_hash`. This ensures that any retroactive modification to the log is detectable.
2. **Merkle Trees**: Entries are committed to an append-only Merkle log. The root of this tree serves as a compact, tamper-evident beacon that can be published on-chain or across chains.
3. **Consistency Proofs**: Following RFC 6962 §2.1.2, the contract can prove that any two Merkle roots are consistent (i.e., the newer root is an extension of the older one) without needing to replay the entire log.
4. **Searchable Symmetric Encryption (SSE-1)**: Allows for encrypted keyword searches without exposing the plaintext keywords to the underlying index store, preserving privacy while maintaining auditability.

## Module Layout

| Module | Purpose |
| ------ | ------- |
| `types` | Defines the core domain types used throughout the contract (`LogEntry`, `AuditError`, `LogSegmentId`). |
| `merkle_log` | Implements the `MerkleLog` structure, representing an append-only log for a specific segment. Handles inclusion proofs. |
| `consistency` | Provides `ConsistencyProver` and `ConsistencyProof` for RFC 6962 compliance, allowing $O(\log n)$ consistency checks between tree states. |
| `search` | Contains the `SearchEngine` and `ForwardIndex` for SSE-1 keyword search over encrypted log metadata (actor, action, target, result). |

## Key Flows

### 1. Appending to the Log
When a new audit event occurs (e.g., a doctor accesses a patient record), it is appended to the `MerkleLog` for a given segment (e.g., `healthcare.access`). 
- The event is hashed with the `prev_hash` to maintain the chain.
- The Merkle tree is updated, producing a new `current_root`.
- An inclusion proof can be generated immediately to prove the event is part of the state.

### 2. Consistency Verification
To ensure that an auditor's view of the log hasn't been maliciously truncated or altered, they can request a `ConsistencyProof` between their known root and the latest root. The proof verifies that the new tree strictly extends the old tree.

### 3. Private Auditing
Using `SearchEngine` with a specific `SearchKey`, authorized auditors can index and query specific events (like all actions by `alice`) without exposing the query terms or log contents to unauthorized observers on the ledger.
