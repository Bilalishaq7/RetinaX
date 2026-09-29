//! # Cryptographic Audit Trail Module
//!
//! This module provides tamper-evident audit logging for Zero-Knowledge proof
//! verifications. Every successful access verification is appended to a cryptographic
//! hash chain (blockchain-within-a-contract pattern), guaranteeing non-repudiation
//! and compliance with HIPAA and healthcare regulatory standards.
//!
//! ## Hash-Chained Integrity
//!
//! Audit records for each `(user, resource_id)` pair form a sequentially linked list
//! where each record contains `prev_hash = Keccak256(Record_{i-1})`:
//! $$H_i = \text{Keccak256}(\text{proof\_hash}_i \mathbin{\Vert} \text{resource\_id}_i \mathbin{\Vert} H_{i-1} \mathbin{\Vert} \text{timestamp}_i \mathbin{\Vert} \text{expires\_at}_i)$$
//!
//! The genesis record for any resource access starts with $H_0 = 0^{32}$.

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

/// Represents an immutable, hash-linked log entry of a successful ZK verification.
///
/// # Memory Layout & Storage
/// - **Storage Key**: Persistent tuple `(Address, BytesN<32>)` mapping to `Vec<AuditRecord>`.
/// - **Payload Footprint**: Address (32B) + resource_id (32B) + proof_hash (32B) + timestamp (8B) + expires_at (8B) + prev_hash (32B) = **144 bytes**.
/// - **Space Complexity**: $\mathcal{O}(1)$ per record, $\mathcal{O}(K)$ total storage for $K$ access events.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    /// The address of the authenticated user whose proof was verified.
    pub user: Address,
    /// The unique 32-byte identifier of the protected medical or vision resource.
    pub resource_id: BytesN<32>,
    /// The 32-byte Poseidon hash of the public inputs associated with the verified proof.
    pub proof_hash: BytesN<32>,
    /// The ledger timestamp (in seconds) when the verification occurred.
    pub timestamp: u64,
    /// The expiration timestamp of the granted access authorization window.
    pub expires_at: u64,
    /// 32-byte Keccak-256 hash of the preceding audit record in the chain ($0^{32}$ for initial access).
    pub prev_hash: BytesN<32>,
}

/// Standalone verification log entry for tracking proof submission outcomes.
///
/// # Complexity Design
/// - **Space Complexity**: $\mathcal{O}(1)$ fixed size per proof ID.
/// - **Time Complexity**: $\mathcal{O}(1)$ persistent storage access.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRecord {
    /// The address that submitted the proof for verification.
    pub submitter: Address,
    /// Monotonically increasing unique proof submission identifier.
    pub proof_id: u64,
    /// Boolean flag indicating whether proof verification succeeded.
    pub verified: bool,
    /// Ledger timestamp when the proof was processed.
    pub timestamp: u64,
}

/// Computes the cryptographic Keccak-256 hash of an audit record for chain linking.
///
/// Serializes `proof_hash`, `resource_id`, `prev_hash`, `timestamp`, and `expires_at`
/// into a contiguous byte stream before hashing.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$ fixed byte buffer manipulation (112 bytes hashed).
/// - **Space Complexity**: $\mathcal{O}(1)$ temporary buffer.
fn hash_record(env: &Env, record: &AuditRecord) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.extend_from_array(&record.proof_hash.to_array());
    buf.extend_from_array(&record.resource_id.to_array());
    buf.extend_from_array(&record.prev_hash.to_array());
    buf.extend_from_array(&record.timestamp.to_be_bytes());
    buf.extend_from_array(&record.expires_at.to_be_bytes());
    env.crypto().keccak256(&buf).into()
}

/// Audit trail management engine providing logging, retrieval, and chain integrity verification.
pub struct AuditTrail;

impl AuditTrail {
    /// Appends a new verified access record to persistent storage and publishes a contract event.
    ///
    /// Computes the forward hash link from the previous record in the user/resource chain.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `user` - Authenticated user address.
    /// * `resource_id` - Identifier of the accessed resource.
    /// * `proof_hash` - Poseidon digest of the verified proof's public inputs.
    /// * `expires_at` - Access expiration timestamp.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$ amortized append to persistent storage vector.
    /// - **Space Complexity**: $\mathcal{O}(1)$ per log invocation.
    pub fn log_access(
        env: &Env,
        user: Address,
        resource_id: BytesN<32>,
        proof_hash: BytesN<32>,
        expires_at: u64,
    ) {
        let key = (&user, &resource_id);
        let mut chain: Vec<AuditRecord> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));

        let prev_hash = if chain.is_empty() {
            BytesN::from_array(env, &[0u8; 32])
        } else {
            match chain.last() {
                Some(last) => hash_record(env, &last),
                None => BytesN::from_array(env, &[0u8; 32]),
            }
        };

        let record = AuditRecord {
            user: user.clone(),
            resource_id: resource_id.clone(),
            proof_hash,
            timestamp: env.ledger().timestamp(),
            expires_at,
            prev_hash,
        };

        chain.push_back(record.clone());
        env.storage().persistent().set(&key, &chain);
        #[allow(deprecated)]
        env.events().publish((user, resource_id), record);
    }

    /// Fetches the most recent `AuditRecord` for a given user and resource pair.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `user` - User address.
    /// * `resource_id` - Resource identifier.
    ///
    /// # Returns
    /// `Some(AuditRecord)` if at least one access event exists, otherwise `None`.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn get_record(env: &Env, user: Address, resource_id: BytesN<32>) -> Option<AuditRecord> {
        let chain: Option<Vec<AuditRecord>> =
            env.storage().persistent().get(&(&user, &resource_id));
        chain.and_then(|c| {
            if c.is_empty() {
                None
            } else {
                Some(c.get(c.len() - 1).unwrap())
            }
        })
    }

    /// Fetches the entire audit chain history for a given user and resource pair.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `user` - User address.
    /// * `resource_id` - Resource identifier.
    ///
    /// # Returns
    /// Vector of all historical [`AuditRecord`] entries.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(K)$ where $K$ is the length of the audit chain.
    /// - **Space Complexity**: $\mathcal{O}(K)$ return vector allocation.
    pub fn get_chain(env: &Env, user: Address, resource_id: BytesN<32>) -> Vec<AuditRecord> {
        env.storage()
            .persistent()
            .get(&(&user, &resource_id))
            .unwrap_or_else(|| Vec::new(env))
    }

    /// Verifies the cryptographic continuity of the audit chain for a user/resource pair.
    ///
    /// Iterates through every record and asserts that `record[i].prev_hash == Keccak256(record[i-1])`
    /// and that `record[0].prev_hash == 0^{32}`.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `user` - User address.
    /// * `resource_id` - Resource identifier.
    ///
    /// # Returns
    /// * `true` if the audit chain is valid or empty.
    /// * `false` if any record has been modified, reordered, or deleted.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(K)$ hash computations where $K$ is the chain length.
    /// - **Space Complexity**: $\mathcal{O}(1)$ auxiliary working memory.
    pub fn verify_chain(env: &Env, user: Address, resource_id: BytesN<32>) -> bool {
        let chain = Self::get_chain(env, user, resource_id);
        if chain.is_empty() {
            return true;
        }

        let zero = BytesN::from_array(env, &[0u8; 32]);
        let first = match chain.first() {
            Some(item) => item,
            None => return true,
        };
        if first.prev_hash != zero {
            return false;
        }

        let mut i: u32 = 1;
        while i < chain.len() {
            let prev = match chain.get(i - 1) {
                Some(item) => item,
                None => return false,
            };
            let current = match chain.get(i) {
                Some(item) => item,
                None => return false,
            };
            if current.prev_hash != hash_record(env, &prev) {
                return false;
            }
            i += 1;
        }

        true
    }

    /// Logs an individual verification submission into persistent storage and emits an event.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `submitter` - Submitter address.
    /// * `proof_id` - Unique proof identifier.
    /// * `verified` - Verification outcome.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    #[allow(deprecated)]
    pub fn log_verification(env: &Env, submitter: &Address, proof_id: u64, verified: bool) {
        let record = VerificationRecord {
            submitter: submitter.clone(),
            proof_id,
            verified,
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&("verification", proof_id), &record);
        #[allow(deprecated)]
        env.events()
            .publish(("verification", proof_id), (submitter, verified));
    }
}
