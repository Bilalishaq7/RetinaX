# Identity Contract Architectural Deep-Dive

## 1. Overview
The **Identity Contract** (`contracts/identity`) serves as the core decentralized identity and access registry for the RetinaX system. It manages identity registration, verifiable credential lifecycles, and identity recovery protocols on-chain.

## 2. Core Architecture & Module Breakdown

The identity contract is structured into four primary Rust modules:

| Module | Location | Description |
| :--- | :--- | :--- |
| `lib.rs` | `contracts/identity/src/lib.rs` | Main contract logic, storage definitions, entry points, and access control checks. |
| `credential.rs` | `contracts/identity/src/credential.rs` | Verifiable Credential management, issuance, revocation, and proof verification routines. |
| `recovery.rs` | `contracts/identity/src/recovery.rs` | Multi-sig / social identity recovery mechanisms and key rotation workflows. |
| `events.rs` | `contracts/identity/src/events.rs` | Structured event emissions for indexing identity lifecycle state changes. |

## 3. Data Model & Key Concepts

### Identity Registration & State
- **Identity Identifier (DID)**: Each actor (patient, provider, or system node) is bound to a unique decentralized identifier.
- **Attributes & Metadata**: Key-value pairs store essential, non-PII identity claims and operational state flags.

### Credential Lifecycle Management (`credential.rs`)
- **Issuance**: Authorized entities issue cryptographic credentials bound to a target DID.
- **Revocation List**: On-chain tracking of revoked credential IDs with cryptographic verification support.
- **Expiration & Validation**: Expiration timestamps and status checks are evaluated on-chain prior to grant execution.

### Identity Recovery Protocol (`recovery.rs`)
- **Recovery Guardians**: Users define designated recovery guardians or secondary keys.
- **Quorum Verification**: Key recovery operations require N-of-M threshold signatures before updating an identity's primary controlling address.
- **Cooldown & Timelock**: Timelocks prevent hostile recovery takeovers by providing a window for the original controller to veto unauthorized recovery attempts.

## 4. Interaction & Data Flow

[ User / Provider ]
|
v
+-------------------------------------------------------+
|                 Identity Contract                     |
|                                                       |
|  +-------------------------------------------------+  |
|  |                     lib.rs                      |  |
|  |   - Identity Registration                       |  |
|  |   - Main Access & Controller Entrypoints        |  |
|  +------------------------+------------------------+  |
|                           |                           |
|         +-----------------+-----------------+         |
|         v                                   v         |
|  +--------------+                   +---------------+ |
|  |credential.rs |                   |  recovery.rs  | |
|  | - Issuance   |                   | - Guardians   | |
|  | - Revocation |                   | - Timelocks   | |
|  +--------------+                   +---------------+ |
|         |                                   |         |
|         +-----------------+-----------------+         |
|                           |                           |
|                           v                           |
|                  +-----------------+                  |
|                  |    events.rs    |                  |
|                  +-----------------+                  |
+-------------------------------------------------------+
|
v
[ On-Chain Event Logs / Indexer ]


## 5. Security & Access Control
- **Controller Permissions**: Direct updates to identity parameters require valid signature authentication from the registered identity controller.
- **Guardian Quorum Isolation**: Recovery execution is strictly bounded by guardian consensus logic in `recovery.rs`.
- **Event Auditing**: All credential status transitions (issuance, revocation, recovery initiation) emit structured events via `events.rs`.
