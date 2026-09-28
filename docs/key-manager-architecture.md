# Key Manager Contract: Architectural Deep-Dive

## Table of Contents

- [Overview](#overview)
- [Core Concepts](#core-concepts)
- [Hierarchical Key Structure](#hierarchical-key-structure)
- [Key Lifecycle Management](#key-lifecycle-management)
- [Security Model](#security-model)
- [Storage Architecture](#storage-architecture)
- [Cross-Contract Integration](#cross-contract-integration)
- [Audit Trail & Integrity](#audit-trail--integrity)
- [Social Recovery System](#social-recovery-system)
- [Policy Enforcement](#policy-enforcement)
- [Implementation Details](#implementation-details)
- [Gas Optimization Strategies](#gas-optimization-strategies)
- [Security Considerations](#security-considerations)
- [Future Enhancements](#future-enhancements)

---

## Overview

The **Key Manager Contract** is a critical cryptographic infrastructure component of the RetinaX ecosystem that implements hierarchical deterministic (HD) key management with policy enforcement, social recovery, and comprehensive audit trails. It enables secure generation, derivation, rotation, and recovery of cryptographic keys while maintaining verifiable lineage and tamper-proof audit logs.

### Purpose

In a blockchain-based healthcare system like RetinaX, key management is paramount. Patient records, provider credentials, and access control all depend on secure cryptographic keys. The Key Manager contract provides:

- **Deterministic key derivation** for generating keys from a master seed
- **Hierarchical structure** to isolate keys by purpose and scope
- **Automatic rotation** to limit exposure from compromised keys
- **Social recovery** to prevent permanent loss of access
- **Policy-based constraints** to enforce usage limits and time windows
- **Immutable audit trail** for compliance and forensic analysis

### Design Philosophy

The contract follows several key principles:

1. **Defense in depth**: Multiple layers of security (authentication, authorization, policy enforcement, audit)
2. **Principle of least privilege**: Keys are scoped to minimum necessary capabilities
3. **Cryptographic accountability**: Every operation is logged in a chained audit trail
4. **Fail-safe recovery**: Guardian-based recovery prevents catastrophic key loss
5. **Gas efficiency**: Optimized storage and computation patterns for Soroban

---

## Core Concepts

### What is Hierarchical Deterministic (HD) Key Derivation?

HD key derivation, originally defined in BIP-32 for Bitcoin, allows generating a tree of cryptographic keys from a single master seed. Key advantages:

- **Deterministic**: Same inputs always produce same outputs (reproducible)
- **Derivable**: Child keys derived from parent without exposing parent
- **Isolated**: Compromise of child key doesn't compromise parent
- **Recoverable**: Entire key tree reconstructable from master seed + derivation paths

The Key Manager adapts HD concepts for healthcare data management on Soroban.

### Key Components

| Component | Description |
|-----------|-------------|
| **KeyRecord** | On-chain metadata representing a managed key |
| **KeyVersion** | Historical versions of key material for rotation |
| **KeyPolicy** | Usage constraints (max uses, time windows, allowed operations) |
| **AuditEntry** | Tamper-evident log of key lifecycle events |
| **RecoveryRequest** | Multisig guardian recovery proposal |

### Key Types

The contract supports four functional key types, each serving distinct cryptographic purposes:

```rust
pub enum KeyType {
    Signing,          // Digital signatures for transactions, records, attestations
    Encryption,       // Symmetric/asymmetric encryption for sensitive PHI data
    Authentication,   // Identity verification and session management
    Delegation,       // Proxy capabilities without exposing master credentials
}
```

### Key Levels

Keys are organized in a four-tier hierarchy:

```rust
pub enum KeyLevel {
    Master,      // Root key - highest privilege (admin-controlled)
    Contract,    // Scoped to specific contract interactions
    Operation,   // Scoped to specific operations (read, write, sign)
    Session,     // Ephemeral keys for short-lived interactions
}
```

**Valid parent-child relationships:**
- Master → Contract
- Contract → Operation
- Operation → Session


---

## Hierarchical Key Structure

### The Key Tree

```
                    ┌──────────────┐
                    │ Master Key   │
                    │ (Admin-owned)│
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
      ┌────▼────┐     ┌────▼────┐    ┌────▼────┐
      │Contract │     │Contract │    │Contract │
      │  Key A  │     │  Key B  │    │  Key C  │
      └────┬────┘     └────┬────┘    └─────────┘
           │               │
      ┌────┼────┐     ┌────┼────┐
      │    │    │     │    │    │
   ┌──▼─┐┌▼──┐┌▼──┐ ┌▼──┐┌▼──┐┌▼──┐
   │Op  ││Op ││Op │ │Op ││Op ││Op │
   │Key ││Key││Key│ │Key││Key││Key│
   └──┬─┘└───┘└───┘ └───┘└───┘└───┘
      │
   ┌──┴──┐
   │     │
┌──▼─┐┌──▼─┐
│Sess││Sess│
│Key ││Key │
└────┘└────┘
```

### Derivation Mechanism

Child keys are derived using cryptographic hashing:

```rust
// Pseudocode representation
child_key = SHA256(parent_key || parent_chain || index || hardened_flag)
child_chain = SHA256(parent_chain || index || hardened_flag || "chain")
```

**Key derivation properties:**
- **Deterministic**: Same parent + index always yields same child
- **One-way**: Cannot derive parent from child (pre-image resistance)
- **Collision-resistant**: Infeasible to find two inputs producing same output
- **Hardened option**: Uses parent private key for stronger isolation

### Record Key Derivation

Beyond hierarchical child keys, the contract supports deriving record-specific encryption keys:

```rust
record_key = SHA256(key_bytes || record_id || "record")
```

This enables:
- **Per-record encryption**: Each vision record encrypted with unique key
- **Deterministic**: Same key + record_id always produces same encryption key
- **Rotation-compatible**: Old key versions can decrypt old records

---

## Key Lifecycle Management

### 1. Creation (Master Keys Only)

Master keys are created by the contract admin:

```rust
pub fn create_master_key(
    env: Env,
    caller: Address,        // Must be admin
    key_type: KeyType,      // Signing, Encryption, Authentication, Delegation
    policy: KeyPolicy,      // Usage constraints
    rotation_interval: u64, // Seconds between rotations (0 = manual)
    key_bytes: BytesN<32>,  // Initial key material
) -> Result<BytesN<32>, ContractError>
```

**Process:**
1. Validate caller is admin
2. Validate policy parameters
3. Generate unique key ID from inputs + timestamp
4. Derive chain code for future child derivation
5. Create KeyRecord with initial metadata
6. Store version 1 of key material
7. Publish audit event

### 2. Derivation

Child keys are derived from parent keys:

```rust
pub fn derive_key(
    env: Env,
    caller: Address,        // Must be key owner or admin
    parent_id: BytesN<32>,  // Parent key ID
    child_level: KeyLevel,  // Must be one level below parent
    index: u32,             // Derivation index (for multiple children)
    hardened: bool,         // Use hardened derivation
    key_type: KeyType,      // Child key type
    policy: KeyPolicy,      // Child key policy
    rotation_interval: u64, // Child key rotation interval
) -> Result<BytesN<32>, ContractError>
```

**Process:**
1. Authenticate caller
2. Load parent key record
3. Verify parent is active (not revoked)
4. Validate hierarchy (child one level below parent)
5. Validate policy
6. Load current parent key version
7. Derive child key and chain code using HD algorithm
8. Generate child key ID
9. Create child KeyRecord
10. Store child version 1
11. Increment parent use counter
12. Publish audit event

### 3. Usage

Keys are used for cryptographic operations:

```rust
pub fn use_key(
    env: Env,
    caller: Address,        // Must be key owner or admin
    key_id: BytesN<32>,     // Key to use
    operation: Symbol,      // Operation symbol (e.g., "SIGN", "ENC", "AUTH")
) -> Result<BytesN<32>, ContractError>
```

**Process:**
1. Authenticate caller
2. Load key record
3. Verify key is active
4. Enforce policy (max_uses, time windows, allowed_ops)
5. Increment use counter
6. Return current key material
7. Publish audit event

### 4. Rotation

Keys are periodically rotated to limit exposure:

```rust
pub fn rotate_key(
    env: Env,
    caller: Address,        // Must be key owner or admin
    key_id: BytesN<32>,     // Key to rotate
) -> Result<u32, ContractError>
```

**Process:**
1. Authenticate caller
2. Load key record
3. Verify key is active
4. Check rotation interval elapsed (if set)
5. Load current key version
6. Derive new key material: `SHA256(current_key || timestamp || "rotate")`
7. Increment version number
8. Update last_rotated timestamp
9. Store new key version
10. Publish audit event

**Why rotate keys?**
- **Limit exposure window**: If key compromised, only data encrypted during that period is at risk
- **Forward secrecy**: New keys can't decrypt old data
- **Compliance**: HIPAA and GDPR encourage regular key rotation

### 5. Revocation

Keys can be permanently disabled:

```rust
pub fn revoke_key(
    env: Env,
    caller: Address,        // Must be key owner or admin
    key_id: BytesN<32>,     // Key to revoke
) -> Result<(), ContractError>
```

**Process:**
1. Authenticate caller
2. Load key record
3. Set status to Revoked
4. Store updated record
5. Publish audit event

**Note**: Revocation is permanent and cannot be undone (by design).


---

## Security Model

### Authentication & Authorization

The contract implements multi-level access control:

| Role | Capabilities |
|------|--------------|
| **Admin** | Create master keys, set identity contract, full access to all keys |
| **Key Owner** | Use, rotate, and revoke owned keys, derive child keys |
| **Guardian** | Initiate and approve recovery for owner's keys |
| **Anyone** | Read public key metadata, generate attestations, execute recovery (if conditions met) |

**Authentication flow:**
1. All state-changing functions require `caller.require_auth()`
2. Soroban SDK verifies caller signature
3. Contract checks role-specific authorization
4. Operation proceeds or reverts with `Unauthorized` error

### Cryptographic Guarantees

| Property | Implementation |
|----------|----------------|
| **Confidentiality** | Key material stored as opaque 32-byte hashes on-chain; actual keys managed off-chain |
| **Integrity** | Audit trail uses SHA-256 chaining to detect tampering |
| **Non-repudiation** | All operations signed by caller; audit log proves who did what when |
| **Forward secrecy** | Key rotation + versioning ensures old keys can't decrypt new data |
| **Availability** | Social recovery prevents permanent key loss |

### Threat Model

**Threats mitigated:**
- ✅ **Key compromise**: Rotation limits exposure; recovery enables replacement
- ✅ **Key loss**: Social recovery with M-of-N guardians
- ✅ **Unauthorized access**: Authentication + authorization checks
- ✅ **Policy bypass**: Enforced at contract level, not client side
- ✅ **Audit tampering**: Cryptographic chaining detects modifications
- ✅ **Guardian collusion**: Threshold + cooldown prevents instant takeover

**Threats NOT mitigated:**
- ❌ **Admin compromise**: Admin has full control (consider multisig admin)
- ❌ **All guardians compromised**: If M-of-N guardians collude, they can recover keys
- ❌ **Side-channel attacks**: Contract doesn't protect against timing attacks on off-chain key usage
- ❌ **Quantum attacks**: SHA-256 and current curves vulnerable to quantum computers

---

## Storage Architecture

The contract uses Soroban's three-tier storage system strategically:

### Instance Storage

**Purpose**: Contract-level configuration and singleton state

```rust
ADMIN           → Address           // Contract administrator
IDENTITY        → Address           // Identity contract address
AUDIT_SEQ       → u64               // Audit log sequence counter
AUDIT_TAIL      → BytesN<32>        // Hash of latest audit entry
```

**Characteristics:**
- Persists across contract upgrades
- Lower storage costs than persistent
- Used for global state

### Persistent Storage

**Purpose**: Long-lived data that must survive TTL expiration

```rust
(KEY, key_id)                 → KeyRecord           // Key metadata
(KEY_VER, key_id, version)    → KeyVersion          // Historical key versions
(RECOVERY, key_id)            → RecoveryRequest     // Active recovery requests
(AUDIT, sequence)             → AuditEntry          // Audit log entries
```

**Characteristics:**
- Requires rent payment to maintain
- Critical for audit trail integrity
- TTL extension needed for long-term storage

### Storage Key Design

The contract uses composite keys for efficient lookups:

```rust
// Primary key: Direct key record access
(KEY, key_id: BytesN<32>) → KeyRecord

// Composite key: Version history
(KEY_VER, key_id: BytesN<32>, version: u32) → KeyVersion

// Composite key: Active recovery
(RECOVERY, key_id: BytesN<32>) → RecoveryRequest

// Sequential key: Audit trail
(AUDIT, seq: u64) → AuditEntry
```

**Benefits:**
- O(1) lookups by key ID
- Efficient version access without iteration
- Single recovery per key (overwrite semantics)
- Sequential audit log for integrity verification

---

## Cross-Contract Integration

### Identity Contract Dependency

The Key Manager integrates tightly with the Identity contract for guardian management:

```rust
use identity::IdentityContractClient;

fn load_guardians(env: &Env, owner: &Address) -> Result<(Vec<Address>, u32), ContractError> {
    let identity_addr: Address = env
        .storage()
        .instance()
        .get(&IDENTITY)
        .ok_or(ContractError::NotInitialized)?;
    
    let client = IdentityContractClient::new(env, &identity_addr);
    let guardians = client.get_guardians(owner);
    let threshold = client.get_recovery_threshold(owner);
    
    Ok((guardians, threshold))
}
```

**Integration points:**
1. **Guardian verification**: Check if address is registered guardian
2. **Threshold retrieval**: Get M-of-N recovery threshold
3. **Dynamic updates**: Guardian changes in Identity contract immediately affect Key Manager

**Design benefits:**
- Single source of truth for guardian data
- No duplication of guardian management logic
- Identity contract can be upgraded without Key Manager changes

### Vision Records Integration

The Vision Records contract uses Key Manager for encryption keys:

```rust
// Derive record-specific encryption key
let derived = key_manager.derive_record_key(key_id, record_id);

// Encrypt vision record with derived key
let encrypted_record = encrypt(record_data, derived.key);

// Store encrypted record (off-chain)
```

**Benefits:**
- Each vision record encrypted with unique key
- Key derivation is deterministic and reproducible
- Key rotation doesn't require re-encrypting all old records
- Old key versions can still decrypt historical records

---

## Audit Trail & Integrity

### Chained Audit Log

The contract implements a tamper-evident audit log using cryptographic chaining:

```
Entry 1                Entry 2                Entry 3
┌─────────┐           ┌─────────┐           ┌─────────┐
│ seq: 1  │           │ seq: 2  │           │ seq: 3  │
│ prev: 0 ├──────────>│ prev: H1├──────────>│ prev: H2│
│ hash: H1│           │ hash: H2│           │ hash: H3│
└─────────┘           └─────────┘           └─────────┘
```

### AuditEntry Structure

```rust
pub struct AuditEntry {
    pub seq: u64,                  // Monotonic sequence number
    pub actor: Address,            // Who performed the action
    pub action: Symbol,            // What action (KEY_NEW, KEY_ROT, KEY_RVK, etc.)
    pub key_id: Option<BytesN<32>>,// Which key was affected
    pub timestamp: u64,            // When it happened
    pub details_hash: BytesN<32>,  // Hash of operation-specific details
    pub prev_hash: BytesN<32>,     // Hash of previous entry
    pub entry_hash: BytesN<32>,    // Hash of this entry
}
```

### Audit Event Types

| Action Symbol | Meaning |
|---------------|---------|
| `KEY_NEW` | Master key created |
| `KEY_DER` | Child key derived |
| `KEY_USE` | Key used for operation |
| `KEY_ROT` | Key rotated to new version |
| `KEY_RVK` | Key revoked |
| `REC_NEW` | Recovery initiated |
| `REC_APP` | Recovery approved by guardian |
| `REC_EXE` | Recovery executed |

### Integrity Verification

The chained structure enables verification:

```rust
// Verify audit log integrity
fn verify_audit_chain(env: &Env, from: u64, to: u64) -> bool {
    let mut prev_hash = get_audit_entry(env, from).entry_hash;
    
    for seq in (from + 1)..=to {
        let entry = get_audit_entry(env, seq);
        if entry.prev_hash != prev_hash {
            return false; // Chain broken - tampering detected
        }
        prev_hash = entry.entry_hash;
    }
    true
}
```

**Properties:**
- **Append-only**: Entries can't be deleted without breaking chain
- **Tamper-evident**: Modifying any entry changes its hash and breaks subsequent links
- **Verifiable**: Anyone can verify chain integrity
- **Timestamped**: Ledger timestamp provides temporal ordering


---

## Social Recovery System

### Problem Statement

In blockchain systems, losing your private key means losing access forever. For healthcare data, this is unacceptable - patients must not lose access to their medical records due to key loss.

### Solution: M-of-N Guardian Recovery

The Key Manager implements social recovery where a key owner designates M guardians, and any M of them can collectively recover a lost key.

### Recovery Flow

```
1. Initiation                2. Approval                    3. Execution
   (Guardian 1)                 (Guardians 2-M)               (Anyone)

┌──────────────┐             ┌──────────────┐             ┌──────────────┐
│  initiate_   │             │   approve_   │             │   execute_   │
│  recovery()  │             │  recovery()  │             │  recovery()  │
└──────┬───────┘             └──────┬───────┘             └──────┬───────┘
       │                            │                            │
       ├─> Create request           ├─> Add approval            ├─> Check threshold
       ├─> Add self as approval     │                           ├─> Check cooldown
       ├─> Start 24h cooldown       ├─> (Repeat M-1 times)      ├─> Replace key
       └─> Log REC_NEW              └─> Log REC_APP             └─> Log REC_EXE
```

### Implementation Details

**Step 1: Initiation**

- Guardian authenticates
- Verifies guardian status via Identity contract
- Creates RecoveryRequest with proposed new key
- Sets execute_after = now + 24 hours
- Adds initiating guardian as first approval
- Stores request in persistent storage

**Step 2: Approval**

- Guardian authenticates
- Verifies guardian status
- Loads active recovery request
- Checks guardian hasn't already approved
- Adds guardian to approvals list
- Updates stored request

**Step 3: Execution**

- Anyone can call (auth required but not role-checked)
- Loads recovery request
- Revalidates approvals against *current* guardian set
- Checks threshold met: `valid_approvals >= threshold`
- Checks cooldown expired: `now >= execute_after`
- Replaces key with new version
- Removes recovery request
- Returns new version number

### Security Properties

| Property | Implementation |
|----------|----------------|
| **Threshold enforcement** | Requires M-of-N valid guardian approvals |
| **Cooldown protection** | 24-hour delay prevents instant takeover |
| **Approval revalidation** | Checks approvals against current guardian set at execution time |
| **One recovery at a time** | Only one active RecoveryRequest per key |
| **Audit trail** | All recovery actions logged in audit chain |

### Edge Cases

**Guardian set changes during recovery:**
- Recovery request stores approvals, not guardian set snapshot
- At execution, approvals are re-checked against *current* guardians
- If guardian removed from set, their approval doesn't count
- Prevents attack: collude with M guardians, then owner removes them

**Threshold changes during recovery:**
- Threshold retrieved from Identity contract at execution time
- If owner increases threshold, existing approvals may no longer be sufficient
- Protects against: owner suspects compromise, increases threshold to block recovery

**Multiple recovery attempts:**
- Only one active recovery per key
- Must wait for first to expire or execute before initiating second
- Prevents: spam attacks or confusion from parallel recovery flows

---

## Policy Enforcement

### KeyPolicy Structure

```rust
pub struct KeyPolicy {
    pub max_uses: u32,              // Max operations before key expires (0 = unlimited)
    pub not_before: u64,            // Key invalid before this timestamp (0 = no bound)
    pub not_after: u64,             // Key invalid after this timestamp (0 = no bound)
    pub allowed_ops: Vec<Symbol>,   // Whitelist of permitted operations (empty = all)
}
```

### Policy Validation

Policies are validated at key creation/derivation:

```rust
fn validate_policy(policy: &KeyPolicy) -> Result<(), ContractError> {
    // Time window must be valid
    if policy.not_after > 0 
        && policy.not_before > 0 
        && policy.not_after <= policy.not_before 
    {
        return Err(ContractError::InvalidPolicy);
    }
    Ok(())
}
```

### Example Policies

**Session key (short-lived, limited use):**
```rust
KeyPolicy {
    max_uses: 100,
    not_before: 0,
    not_after: now + 3600,  // Expires in 1 hour
    allowed_ops: vec![symbol_short!("AUTH")],
}
```

**Signing key (unlimited, specific operation):**
```rust
KeyPolicy {
    max_uses: 0,  // Unlimited
    not_before: 0,
    not_after: 0,  // Never expires
    allowed_ops: vec![symbol_short!("SIGN")],
}
```

**Time-locked delegation key:**
```rust
KeyPolicy {
    max_uses: 0,
    not_before: now + 86400,  // Active tomorrow
    not_after: now + 172800,   // Expires in 2 days
    allowed_ops: vec![],        // All operations allowed
}
```

**Benefits:**
- Limits blast radius of key compromise
- Enforces principle of least privilege
- Enables time-based access control
- Supports audit and compliance requirements

---

## Implementation Details

### Cryptographic Primitives

The contract relies on Soroban SDK cryptographic functions:

```rust
// SHA-256 hashing
let hash: BytesN<32> = env.crypto().sha256(&data).into();

// Key derivation uses repeated SHA-256
child_key = SHA256(parent_key || parent_chain || index || hardened)
child_chain = SHA256(parent_chain || index || hardened || "chain")

// Rotation uses hash with timestamp
new_key = SHA256(current_key || timestamp || "rotate")
```

**Why SHA-256?**
- Widely studied and trusted
- Native support in Soroban SDK
- Sufficient security for deterministic derivation
- Not vulnerable to length-extension attacks (when used properly)

---

## Gas Optimization Strategies

### 1. Composite Storage Keys

Using composite keys avoids expensive map iterations:

```rust
// Efficient: O(1) lookup
(KEY_VER, key_id, version) → KeyVersion

// Inefficient: Would require iterating all versions
KEY_VER → Map<(KeyId, Version), KeyVersion>
```

### 2. Instance vs. Persistent Storage

Contract configuration in instance storage (cheaper):

```rust
ADMIN       → Address      // Instance storage
IDENTITY    → Address      // Instance storage
AUDIT_SEQ   → u64          // Instance storage
```

### 3. Saturating Arithmetic

Prevents overflow panics and retry costs:

```rust
record.uses = record.uses.saturating_add(1);
seq = seq.saturating_add(1);
next_version = record.current_version.saturating_add(1);
```

### 4. Early Returns

Fail fast on authorization checks:

```rust
pub fn use_key(...) -> Result<BytesN<32>, ContractError> {
    caller.require_auth();  // Fail early if auth fails
    let mut record = Self::load_key_record(&env, &key_id)?;
    Self::require_owner_or_admin(&env, &caller, &record.owner)?;
    Self::ensure_active(&record)?;
    // ... expensive operations only if checks pass
}
```

---

## Security Considerations

### Current Strengths

✅ **Authentication**: All state changes require cryptographic signatures  
✅ **Authorization**: Role-based access control enforced at contract level  
✅ **Audit trail**: Tamper-evident chained logging of all operations  
✅ **Key rotation**: Automatic and manual rotation limits exposure  
✅ **Social recovery**: Guardian-based recovery prevents permanent key loss  
✅ **Policy enforcement**: Usage limits and time windows enforced on-chain  
✅ **Revocation**: Keys can be permanently disabled  

### Known Limitations

⚠️ **Admin trust**: Contract admin has full control (no multisig yet)  
⚠️ **Guardian collusion**: M compromised guardians can recover keys  
⚠️ **Quantum vulnerability**: SHA-256 and current curves not quantum-resistant  
⚠️ **No rate limiting**: High-frequency operations not restricted  

### Recommended Practices

**For Admin:**
- Use multisig wallet for admin key
- Regularly audit key creation patterns
- Monitor for suspicious guardian changes
- Implement key ceremony for master key generation

**For Key Owners:**
- Choose guardians carefully (trusted, distributed, independent)
- Set appropriate M-of-N threshold (recommend M = ceil(N/2) + 1)
- Regularly verify guardian set is still valid
- Use strong policies on high-value keys
- Rotate keys proactively, not reactively

**For Guardians:**
- Protect guardian keys with hardware wallets
- Verify recovery requests through out-of-band channels
- Understand the 24-hour cooldown is protection, not hindrance
- Monitor for unauthorized recovery attempts

---

## Future Enhancements

### 1. Post-Quantum Cryptography

**Problem**: SHA-256 and elliptic curves vulnerable to quantum computers

**Solution**: Integrate post-quantum algorithms like NIST-approved lattice-based schemes (Kyber, Dilithium) or hash-based signatures (SPHINCS+)

### 2. Zero-Knowledge Key Proofs

**Problem**: Key usage reveals which key is being used

**Solution**: ZK proofs of key ownership - prove "I own a valid key" without revealing which key

### 3. Multi-Party Computation (MPC)

**Problem**: Single point of compromise for key material

**Solution**: Split keys across multiple parties - threshold signatures require M-of-N parties

### 4. Automated Policy Management

**Problem**: Static policies don't adapt to context

**Solution**: Dynamic, context-aware policies with time-of-day restrictions, risk-based authentication, and AI anomaly detection

### 5. Formal Verification

**Problem**: Complex contract logic hard to audit manually

**Solution**: Formally verify critical properties - prove key hierarchy invariants hold, verify audit chain can't be broken

---

## Conclusion

The Key Manager contract provides a robust, auditable, and recoverable key management system tailored for healthcare data on the blockchain. Its hierarchical deterministic design, policy enforcement, social recovery, and tamper-evident audit trails address the unique challenges of managing cryptographic keys in a high-security, high-compliance environment like vision care records.

---

## Related Documentation

- [GLOSSARY.md](GLOSSARY.md) - Technical terms and definitions
- [architecture.md](architecture.md) - Overall RetinaX system architecture
- [security.md](security.md) - Comprehensive security model
- [zk-integration-guide.md](zk-integration-guide.md) - Zero-knowledge proof integration
- [api.md](api.md) - Complete API reference

---

**Document Version**: 1.0.0  
**Last Updated**: 2025  
**Author**: RetinaX Core Team  
**Status**: Production

For questions or clarifications, open an issue or join our Discord community.
