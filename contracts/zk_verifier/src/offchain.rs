use crate::audit::AuditTrail;
use crate::ContractError;
use soroban_sdk::{
    contracttype, symbol_short, Address, Bytes, BytesN, Env, Symbol,
};

/// Storage key prefix for trusted off-chain verifier public keys: `(TRUST_V, BytesN<32>)`.
pub const TRUST_V: Symbol = symbol_short!("TRUST_V");

/// Nonce storage prefix for anti-replay protection.
pub const NONCE: Symbol = symbol_short!("NONCE");

/// Off-chain Zero-Knowledge verification payload signed by an authorized verifier node.
///
/// This structure encapsulates the results of an off-chain Groth16 / PLONK proof verification
/// performed over the BN254 curve by an off-chain prover/verifier node, bypassing Soroban's
/// 64KB WASM code size limit while preserving cryptographic verification integrity on-chain.
///
/// # Complexity Design
/// - **Memory Footprint**:
///   `user` (32B) + `resource_id` (32B) + `public_inputs_hash` (32B) + `proof_hash` (32B)
///   + `verifier_pubkey` (32B) + `expires_at` (8B) + `nonce` (8B) + `signature` (64B)
///   = **240 bytes** total fixed-size payload.
/// - **Time Complexity**: $\mathcal{O}(1)$ deserialization and on-chain signature verification.
/// - **Space Complexity**: $\mathcal{O}(1)$ working memory.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OffChainVerificationPayload {
    /// The authenticated Stellar address of the user or patient requesting access.
    pub user: Address,
    /// 32-byte cryptographic identifier for the protected vision record or resource.
    pub resource_id: BytesN<32>,
    /// Cryptographic commitment (e.g. Poseidon or SHA-256) of the public inputs vector.
    pub public_inputs_hash: BytesN<32>,
    /// Cryptographic commitment (e.g. Poseidon or SHA-256) of the proof elements (A, B, C).
    pub proof_hash: BytesN<32>,
    /// Ed25519 public key of the trusted off-chain verifier node that evaluated the proof.
    pub verifier_pubkey: BytesN<32>,
    /// Ledger timestamp (in seconds) after which this verification attestation is invalid.
    pub expires_at: u64,
    /// Strictly-monotonic anti-replay nonce for the user.
    pub nonce: u64,
    /// Ed25519 signature over the canonical attestation message by `verifier_pubkey`.
    pub signature: BytesN<64>,
}

/// Constructs a canonical, domain-separated binary message for off-chain ZK verification attestation.
///
/// Canonical Format:
/// `"retinax_zk_offchain_v1"` || `user_str` || `resource_id(32)` || `public_inputs_hash(32)`
/// || `proof_hash(32)` || `expires_at(8 BE)` || `nonce(8 BE)`
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$ (fixed 22 + 32 + 32 + 32 + 8 + 8 = 134 bytes approx).
/// - **Space Complexity**: $\mathcal{O}(1)$ byte buffer.
pub fn build_offchain_verification_message(
    env: &Env,
    user: &Address,
    resource_id: &BytesN<32>,
    public_inputs_hash: &BytesN<32>,
    proof_hash: &BytesN<32>,
    expires_at: u64,
    nonce: u64,
) -> Bytes {
    let mut msg = Bytes::new(env);
    // Domain separation tag preventing cross-protocol signature replay
    msg.append(&Bytes::from_slice(env, b"retinax_zk_offchain_v1:"));
    
    // User string representation (or serialized address)
    msg.append(&user.to_string().to_bytes());
    msg.append(&Bytes::from_slice(env, &resource_id.to_array()));
    msg.append(&Bytes::from_slice(env, &public_inputs_hash.to_array()));
    msg.append(&Bytes::from_slice(env, &proof_hash.to_array()));
    msg.append(&Bytes::from_slice(env, &expires_at.to_be_bytes()));
    msg.append(&Bytes::from_slice(env, &nonce.to_be_bytes()));
    msg
}

/// Registers or unregisters a trusted off-chain verifier node public key.
pub fn set_trusted_verifier(
    env: &Env,
    verifier_pubkey: &BytesN<32>,
    enabled: bool,
) {
    let key = (TRUST_V, verifier_pubkey.clone());
    if enabled {
        env.storage().persistent().set(&key, &true);
    } else {
        env.storage().persistent().remove(&key);
    }
}

/// Checks whether an off-chain verifier public key is registered and active.
pub fn is_trusted_verifier(env: &Env, verifier_pubkey: &BytesN<32>) -> bool {
    let key = (TRUST_V, verifier_pubkey.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Validates an off-chain verification payload and executes on-chain signature verification.
///
/// # Pipeline
/// 1. Assert contract is not paused.
/// 2. User authentication via `payload.user.require_auth()`.
/// 3. Verify anti-replay nonce `payload.nonce == current_nonce`.
/// 4. Assert attestation has not expired (`now <= payload.expires_at`).
/// 5. Assert `payload.verifier_pubkey` is a registered trusted verifier.
/// 6. Construct canonical attestation message and verify signature via `env.crypto().ed25519_verify`.
/// 7. Log audit trail and increment user nonce.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$ native host Ed25519 cryptographic evaluation.
/// - **Space Complexity**: $\mathcal{O}(1)$ heap allocation.
pub fn verify_offchain_attestation(
    env: &Env,
    payload: &OffChainVerificationPayload,
) -> Result<bool, ContractError> {
    common::pausable::require_not_paused(env).map_err(|_| ContractError::Paused)?;
    payload.user.require_auth();

    // Check expiration timestamp
    let now = env.ledger().timestamp();
    if now > payload.expires_at {
        return Err(ContractError::MalformedProofData);
    }

    // Check anti-replay nonce
    let nonce_key = (NONCE, payload.user.clone());
    let current_nonce: u64 = env.storage().persistent().get(&nonce_key).unwrap_or(0);
    if payload.nonce != current_nonce {
        return Err(ContractError::MalformedProofData);
    }

    // Check verifier node authorization
    if !is_trusted_verifier(env, &payload.verifier_pubkey) {
        return Err(ContractError::Unauthorized);
    }

    // Construct canonical attestation message
    let msg = build_offchain_verification_message(
        env,
        &payload.user,
        &payload.resource_id,
        &payload.public_inputs_hash,
        &payload.proof_hash,
        payload.expires_at,
        payload.nonce,
    );

    // Verify Ed25519 signature natively via Soroban host crypto
    env.crypto().ed25519_verify(
        &payload.verifier_pubkey,
        &msg,
        &payload.signature,
    );

    // Log to HIPAA-compliant cryptographic audit trail
    AuditTrail::log_access(
        env,
        payload.user.clone(),
        payload.resource_id.clone(),
        payload.proof_hash.clone(),
        payload.expires_at,
    );

    // Increment strictly-monotonic nonce
    env.storage()
        .persistent()
        .set(&nonce_key, &current_nonce.saturating_add(1));

    Ok(true)
}
