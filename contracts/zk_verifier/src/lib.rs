#![no_std]
#![allow(dead_code, clippy::manual_inspect, clippy::arithmetic_side_effects)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! # Zero-Knowledge Verifier Smart Contract Module
//!
//! This crate provides an on-chain Zero-Knowledge (ZK) proof verification engine
//! and privacy-preserving access control system for the **RetinaX** vision care ecosystem
//! on the **Stellar** blockchain using the **Soroban** SDK.
//!
//! ## Core Architecture & Capabilities
//! - **Groth16 on BN254**: Verifies pairing-based zero-knowledge proofs over the BN254 elliptic curve.
//! - **PLONK Compatibility**: Universal SNARK support via [`crate::plonk::PlonkVerifier`].
//! - **Poseidon Sponge Hashing**: Zero-knowledge friendly algebraic hashing over $\mathbb{F}_r$.
//! - **Cryptographic Audit Chaining**: Tamper-evident Keccak-256 hash chains for HIPAA compliance.
//! - **Access Control & Defense-in-Depth**:
//!   - Monotonic per-user nonces for replay prevention.
//!   - Sliding window rate limiting.
//!   - Two-step administrative role handover (`propose_admin` / `accept_admin`).
//!   - Emergency pausable mechanism.
//!   - Role-based address whitelisting.

mod audit;
pub mod events;
mod helpers;
pub mod plonk;
pub mod verifier;
pub mod vk;

pub use crate::audit::{AuditRecord, AuditTrail};
pub use crate::events::AccessRejectedEvent;
pub use crate::helpers::{MerkleVerifier, ZkAccessHelper};
pub use crate::plonk::PlonkVerifier;
pub use crate::verifier::{Bn254Verifier, PoseidonHasher, Proof, ProofValidationError, ZkVerifier};
pub use crate::vk::{G1Point, G2Point, VerificationKey};

use common::whitelist;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, BytesN, Env,
    String, Symbol, Vec,
};

/// Storage key for contract administrator address in instance storage.
const ADMIN: Symbol = symbol_short!("ADMIN");
/// Storage key for nominated administrator address in instance storage during two-step transfer.
const PENDING_ADMIN: Symbol = symbol_short!("PEND_ADM");
/// Storage key for rate-limiting configuration `(max_requests, window_duration_seconds)`.
const RATE_CFG: Symbol = symbol_short!("RATECFG");
/// Storage key prefix for persistent rate limit tracking per user: `(RATE_TRACK, Address)`.
const RATE_TRACK: Symbol = symbol_short!("RLTRK");
/// Storage key prefix for persistent monotonic replay protection nonce per user: `(NONCE, Address)`.
const NONCE: Symbol = symbol_short!("NONCE");

/// Maximum number of public inputs accepted per proof verification to bound host CPU consumption.
const MAX_PUBLIC_INPUTS: u32 = 16;

/// Primary envelope for submitting a Zero-Knowledge proof access request to the contract.
///
/// Encapsulates the user identity, targeted medical resource, cryptographic proof points,
/// public inputs vector, validity window, and anti-replay nonce.
///
/// # Complexity Design
/// - **Memory Footprint**:
///   - Base envelope: `user` (32B) + `resource_id` (32B) + `proof` (256B) + `expires_at` (8B) + `nonce` (8B) = **336 bytes**.
///   - Public inputs: $L \times 32$ bytes where $L \le 16$.
///   - Maximum Total Payload: $336 + 512 = \mathbf{848\text{ bytes}}$.
/// - **Space Complexity**: $\mathcal{O}(L)$ where $L = \text{len}(public\_inputs)$.
/// - **Time Complexity**: $\mathcal{O}(L)$ serialization across the Soroban host boundary.
// TODO: post-quantum migration - This struct currently hardcodes a Groth16 `Proof`.
// Future PQ systems (like STARKs) will require an `enum ProofType` or dynamically sized bytes
// to encapsulate changing proof shapes and public inputs matrices.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// The authenticated Stellar address of the user or provider requesting resource access.
    pub user: Address,
    /// Unique 32-byte cryptographic identifier for the targeted vision care record or dataset.
    pub resource_id: BytesN<32>,
    /// The Groth16 proof points $(A \in G_1, B \in G_2, C \in G_1)$ or structural equivalent.
    pub proof: Proof,
    /// Vector of 32-byte public input elements $(x_1, \dots, x_l) \in \mathbb{F}_r^l$ ($l \le 16$).
    pub public_inputs: Vec<BytesN<32>>,
    /// Ledger timestamp (in seconds) after which this access authorization is considered expired.
    pub expires_at: u64,
    /// Strictly-monotonic per-user transaction counter preventing proof replay attacks.
    pub nonce: u64,
}

/// Comprehensive error codes emitted by the `ZkVerifierContract`.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    /// Caller is not authorized to invoke the privileged administrative or verification method.
    Unauthorized = 1,
    /// Caller has exceeded their allotted request quota within the active rate limiting window.
    RateLimited = 2,
    /// Contract configuration is invalid (e.g. zero-valued rate limit parameters or missing verification key).
    InvalidConfig = 3,
    /// Verification was invoked with an empty public input vector (at least one input required).
    EmptyPublicInputs = 4,
    /// Public input count exceeds `MAX_PUBLIC_INPUTS` (16), exceeding compute budget.
    TooManyPublicInputs = 5,
    /// A required proof component is degenerate (all zero coordinates / point at infinity).
    DegenerateProof = 6,
    /// A proof component coordinate is saturated (`0xFF`), violating canonical field modulus encoding.
    OversizedProofComponent = 7,
    /// $G_1$ point $A$ or $C$ contains an inconsistent zero/non-zero coordinate structure.
    MalformedG1Point = 8,
    /// $G_2$ point $B$ contains an inconsistent limb structure in $\mathbb{F}_{p^2}$.
    MalformedG2Point = 9,
    /// A public input element consists entirely of zero bytes.
    ZeroedPublicInput = 10,
    /// Submitted proof data or anti-replay nonce does not match current state.
    MalformedProofData = 11,
    /// The contract is paused and cannot process state-mutating access requests.
    Paused = 12,
    /// The specified authentication level is outside the supported range (1 to 4).
    InvalidAuthLevel = 13,
    /// Public inputs are insufficient for the required authentication level (e.g. Level 4 requires $\ge 2$ inputs).
    ProofRequiredForAuthLevel = 14,
}

/// Maps low-level proof structural validation errors into contract-level [`ContractError`] variants.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$.
/// - **Space Complexity**: $\mathcal{O}(1)$.
fn map_proof_validation_error(e: ProofValidationError) -> ContractError {
    match e {
        ProofValidationError::ZeroedComponent => ContractError::DegenerateProof,
        ProofValidationError::OversizedComponent => ContractError::OversizedProofComponent,
        ProofValidationError::MalformedG1PointA | ProofValidationError::MalformedG1PointC => {
            ContractError::MalformedG1Point
        }
        ProofValidationError::MalformedG2Point => ContractError::MalformedG2Point,
        ProofValidationError::EmptyPublicInputs => ContractError::EmptyPublicInputs,
        ProofValidationError::ZeroedPublicInput => ContractError::ZeroedPublicInput,
    }
}

/// The main Zero-Knowledge Verifier smart contract for RetinaX.
#[contract]
pub struct ZkVerifierContract;

/// Returns `true` if every byte in `data` is zero.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$ (32 byte iterations).
/// - **Space Complexity**: $\mathcal{O}(1)$.
fn is_all_zeros(data: &BytesN<32>) -> bool {
    let arr = data.to_array();
    let mut all_zero = true;
    let mut i = 0;
    while i < 32 {
        if arr[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    all_zero
}

/// Performs high-level envelope validation on an [`AccessRequest`].
///
/// # Validation Checks
/// 1. `public_inputs` is non-empty.
/// 2. `public_inputs.len() <= MAX_PUBLIC_INPUTS` (16).
/// 3. Proof points $A, B, C$ are not point-at-infinity degenerate representations.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$ envelope checks.
/// - **Space Complexity**: $\mathcal{O}(1)$.
fn validate_request(request: &AccessRequest) -> Result<(), ContractError> {
    if request.public_inputs.is_empty() {
        return Err(ContractError::EmptyPublicInputs);
    }

    if request.public_inputs.len() > MAX_PUBLIC_INPUTS {
        return Err(ContractError::TooManyPublicInputs);
    }

    if (is_all_zeros(&request.proof.a.x) && is_all_zeros(&request.proof.a.y))
        || (is_all_zeros(&request.proof.b.x.0)
            && is_all_zeros(&request.proof.b.x.1)
            && is_all_zeros(&request.proof.b.y.0)
            && is_all_zeros(&request.proof.b.y.1))
        || (is_all_zeros(&request.proof.c.x) && is_all_zeros(&request.proof.c.y))
    {
        return Err(ContractError::DegenerateProof);
    }

    Ok(())
}

/// Validates that the requested authentication level is within the valid range $[1, 4]$.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$.
/// - **Space Complexity**: $\mathcal{O}(1)$.
fn validate_auth_level(level: u32) -> Result<(), ContractError> {
    if !(1..=4).contains(&level) {
        return Err(ContractError::InvalidAuthLevel);
    }
    Ok(())
}

/// Validates that Level 4 authentication requests include at least 2 public inputs.
///
/// Input 1 binds the primary operation; Input 2 binds the privacy-preserving attribute commitment.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$.
/// - **Space Complexity**: $\mathcal{O}(1)$.
fn validate_level4_attributes(request: &AccessRequest) -> Result<(), ContractError> {
    if request.public_inputs.len() < 2 {
        return Err(ContractError::ProofRequiredForAuthLevel);
    }
    Ok(())
}

#[contractimpl]
impl ZkVerifierContract {
    /// Initializes the contract with an initial administrator address.
    ///
    /// This is a one-time setup operation. If an admin is already initialized,
    /// this function is a no-op to prevent re-initialization takeovers.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `admin` - The address to designate as the initial contract administrator.
    ///
    /// # Security
    /// Requires cryptographic authorization from `admin` via `require_auth()`.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$ instance storage check and write.
    /// - **Space Complexity**: $\mathcal{O}(1)$ instance storage slot.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&ADMIN) {
            return;
        }

        admin.require_auth();
        env.storage().instance().set(&ADMIN, &admin);
    }

    /// Emits an access violation security event.
    fn emit_access_violation(env: &Env, caller: &Address, action: &str, required_permission: &str) {
        events::publish_access_violation(
            env,
            caller.clone(),
            String::from_str(env, action),
            String::from_str(env, required_permission),
        );
    }

    /// Emits an access violation event and returns [`ContractError::Unauthorized`].
    fn unauthorized<T>(
        env: &Env,
        caller: &Address,
        action: &str,
        required_permission: &str,
    ) -> Result<T, ContractError> {
        Self::emit_access_violation(env, caller, action, required_permission);
        Err(ContractError::Unauthorized)
    }

    /// Asserts that `caller` is authenticated and matches the registered contract administrator.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$ instance storage read.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    fn require_admin(env: &Env, caller: &Address, action: &str) -> Result<(), ContractError> {
        caller.require_auth();

        let admin: Address = match env.storage().instance().get(&ADMIN) {
            Some(admin) => admin,
            None => return Self::unauthorized(env, caller, action, "initialized_admin"),
        };

        if caller != &admin {
            return Self::unauthorized(env, caller, action, "current_admin");
        }

        Ok(())
    }

    /// Proposes a new administrator address in a two-step transfer process.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `current_admin` - The address of the current administrator.
    /// * `new_admin` - The address of the proposed nominee.
    ///
    /// # Errors
    /// * [`ContractError::Unauthorized`] if `current_admin` is not the active administrator.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &current_admin, "propose_admin")?;

        env.storage().instance().set(&PENDING_ADMIN, &new_admin);

        events::publish_admin_transfer_proposed(&env, current_admin, new_admin);

        Ok(())
    }

    /// Accepts the pending administrator role, completing the two-step transfer.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `new_admin` - The address of the nominated administrator.
    ///
    /// # Errors
    /// * [`ContractError::InvalidConfig`] if no admin transfer is currently pending.
    /// * [`ContractError::Unauthorized`] if caller is not the nominated address.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        new_admin.require_auth();

        let pending: Address = env
            .storage()
            .instance()
            .get(&PENDING_ADMIN)
            .ok_or(ContractError::InvalidConfig)?;

        if new_admin != pending {
            return Self::unauthorized(&env, &new_admin, "accept_admin", "pending_admin");
        }

        let old_admin: Address = match env.storage().instance().get(&ADMIN) {
            Some(admin) => admin,
            None => {
                return Self::unauthorized(&env, &new_admin, "accept_admin", "initialized_admin")
            }
        };

        env.storage().instance().set(&ADMIN, &new_admin);
        env.storage().instance().remove(&PENDING_ADMIN);

        events::publish_admin_transfer_accepted(&env, old_admin, new_admin);

        Ok(())
    }

    /// Cancels a pending administrator transfer. Only the current administrator can call this.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `current_admin` - The address of the active administrator.
    ///
    /// # Errors
    /// * [`ContractError::Unauthorized`] if caller is not the active administrator.
    /// * [`ContractError::InvalidConfig`] if no transfer is pending.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn cancel_admin_transfer(env: Env, current_admin: Address) -> Result<(), ContractError> {
        Self::require_admin(&env, &current_admin, "cancel_admin_transfer")?;

        let pending: Address = env
            .storage()
            .instance()
            .get(&PENDING_ADMIN)
            .ok_or(ContractError::InvalidConfig)?;

        env.storage().instance().remove(&PENDING_ADMIN);

        events::publish_admin_transfer_cancelled(&env, current_admin, pending);

        Ok(())
    }

    /// Returns the currently proposed pending administrator address, if one exists.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&PENDING_ADMIN)
    }

    /// Configures sliding-window rate limiting parameters for proof verification.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    /// * `max_requests_per_window` - Maximum allowed verification calls per user within `window_duration_seconds`.
    /// * `window_duration_seconds` - Duration of the rate limiting window in seconds.
    ///
    /// # Errors
    /// * [`ContractError::Unauthorized`] if `caller` is not the administrator.
    /// * [`ContractError::InvalidConfig`] if either argument is 0.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$ instance storage write.
    pub fn set_rate_limit_config(
        env: Env,
        caller: Address,
        max_requests_per_window: u64,
        window_duration_seconds: u64,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "set_rate_limit_config")?;

        if max_requests_per_window == 0 || window_duration_seconds == 0 {
            return Err(ContractError::InvalidConfig);
        }

        env.storage().instance().set(
            &RATE_CFG,
            &(max_requests_per_window, window_duration_seconds),
        );

        Ok(())
    }

    /// Sets the Groth16 [`VerificationKey`] parameters in contract instance storage.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    /// * `vk` - The verification key to register.
    ///
    /// # Errors
    /// * [`ContractError::Unauthorized`] if `caller` is not the administrator.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L = \text{vk.ic.len()}$.
    /// - **Space Complexity**: $\mathcal{O}(L)$ instance storage allocation.
    pub fn set_verification_key(
        env: Env,
        caller: Address,
        vk: VerificationKey,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "set_verification_key")?;
        env.storage().instance().set(&symbol_short!("VK"), &vk);
        Ok(())
    }

    /// Retrieves the currently configured Groth16 [`VerificationKey`], if set.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L$ is the number of public input commitments.
    /// - **Space Complexity**: $\mathcal{O}(L)$.
    pub fn get_verification_key(env: Env) -> Option<VerificationKey> {
        env.storage().instance().get(&symbol_short!("VK"))
    }

    /// Returns the current rate limiting configuration `(max_requests, window_duration_seconds)`.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn get_rate_limit_config(env: Env) -> Option<(u64, u64)> {
        env.storage().instance().get(&RATE_CFG)
    }

    /// Enables or disables whitelist enforcement for resource access.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    /// * `enabled` - Boolean flag to activate or deactivate whitelisting.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn set_whitelist_enabled(
        env: Env,
        caller: Address,
        enabled: bool,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "set_whitelist_enabled")?;
        whitelist::set_whitelist_enabled(&env, enabled);
        Ok(())
    }

    /// Adds a user address to the authorized whitelist.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    /// * `user` - Target address to whitelist.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$ persistent storage write.
    pub fn add_to_whitelist(env: Env, caller: Address, user: Address) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "add_to_whitelist")?;
        whitelist::add_to_whitelist(&env, &user);
        Ok(())
    }

    /// Removes a user address from the authorized whitelist.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    /// * `user` - Target address to remove from whitelist.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$ persistent storage removal.
    pub fn remove_from_whitelist(
        env: Env,
        caller: Address,
        user: Address,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "remove_from_whitelist")?;
        whitelist::remove_from_whitelist(&env, &user);
        Ok(())
    }

    /// Returns `true` if whitelist enforcement is currently active.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn is_whitelist_enabled(env: Env) -> bool {
        whitelist::is_whitelist_enabled(&env)
    }

    /// Returns `true` if `user` is currently present on the whitelist.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn is_whitelisted(env: Env, user: Address) -> bool {
        whitelist::is_whitelisted(&env, &user)
    }

    // ── Pause management ──────────────────────────────────────────────────

    /// Pauses all state-mutating verification operations (Emergency Circuit Breaker).
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn pause(env: Env, caller: Address) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "pause")?;
        common::pausable::pause(&env, &caller);
        Ok(())
    }

    /// Resumes contract operations following a pause.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `caller` - Administrator address.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn unpause(env: Env, caller: Address) -> Result<(), ContractError> {
        Self::require_admin(&env, &caller, "unpause")?;
        common::pausable::unpause(&env, &caller);
        Ok(())
    }

    /// Returns `true` if the contract is currently paused.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn is_paused(env: Env) -> bool {
        common::pausable::is_paused(&env)
    }

    /// Evaluates and increments the caller's request count within the active sliding window.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$ persistent storage access.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    fn check_and_update_rate_limit(env: &Env, user: &Address) -> Result<(), ContractError> {
        let cfg: Option<(u64, u64)> = env.storage().instance().get(&RATE_CFG);
        let (max_requests_per_window, window_duration_seconds) = match cfg {
            Some(c) => c,
            None => return Ok(()),
        };

        if max_requests_per_window == 0 || window_duration_seconds == 0 {
            return Ok(());
        }

        let now = env.ledger().timestamp();
        let key = (RATE_TRACK, user.clone());

        let mut state: (u64, u64) = env.storage().persistent().get(&key).unwrap_or((0, now));

        let window_end = state.1.saturating_add(window_duration_seconds);
        if now >= window_end {
            state.0 = 0;
            state.1 = now;
        }

        let next = state.0.saturating_add(1);
        if next > max_requests_per_window {
            return Err(ContractError::RateLimited);
        }

        state.0 = next;
        env.storage().persistent().set(&key, &state);

        Ok(())
    }

    /// Verifies a Zero-Knowledge access proof for a protected vision care resource.
    ///
    /// This is the primary entrypoint for patients and providers to prove access eligibility.
    ///
    /// # Execution Pipeline
    /// 1. **Circuit Breaker Check**: Asserts contract is not paused.
    /// 2. **Authentication**: Enforces `request.user.require_auth()`.
    /// 3. **Anti-Replay Nonce**: Asserts `request.nonce == stored_nonce(user)`.
    /// 4. **Structural Validation**: Validates `request` shape via `validate_request`.
    /// 5. **Access Policy & Rate Limiting**: Enforces whitelist and sliding window quota.
    /// 6. **Component Sanitization**: Calls [`Bn254Verifier::validate_proof_components`].
    /// 7. **Cryptographic Proof Evaluation**: Calls [`Bn254Verifier::verify_proof`].
    /// 8. **Audit Logging**: On success, records access in [`AuditTrail`] and increments nonce.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `request` - The complete access request envelope.
    ///
    /// # Returns
    /// * `Ok(true)` if the proof is valid and access is authorized.
    /// * `Ok(false)` if the proof is mathematically invalid.
    /// * `Err(ContractError)` if any pre-condition, policy, or validation fails.
    ///
    /// # Complexity Design
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L = \text{len}(public\_inputs)$
    ///   (includes Poseidon hashing of public inputs + Groth16 verification).
    /// - **Space Complexity**: $\mathcal{O}(L)$ working vector allocation.
    pub fn verify_access(env: Env, request: AccessRequest) -> Result<bool, ContractError> {
        common::pausable::require_not_paused(&env).map_err(|_| ContractError::Paused)?;
        request.user.require_auth();

        let nonce_key = (NONCE, request.user.clone());
        let current_nonce: u64 = env.storage().persistent().get(&nonce_key).unwrap_or(0);
        if request.nonce != current_nonce {
            return Err(ContractError::MalformedProofData);
        }

        validate_request(&request).map_err(|err| {
            events::publish_access_rejected(
                &env,
                request.user.clone(),
                request.resource_id.clone(),
                err,
            );
            err
        })?;

        if !whitelist::check_whitelist_access(&env, &request.user) {
            events::publish_access_rejected(
                &env,
                request.user.clone(),
                request.resource_id.clone(),
                ContractError::Unauthorized,
            );
            return Self::unauthorized(&env, &request.user, "verify_access", "whitelisted_user");
        }

        Self::check_and_update_rate_limit(&env, &request.user).map_err(|err| {
            events::publish_access_rejected(
                &env,
                request.user.clone(),
                request.resource_id.clone(),
                err,
            );
            err
        })?;

        Bn254Verifier::validate_proof_components(&request.proof, &request.public_inputs)
            .map_err(map_proof_validation_error)?;

        // TODO: post-quantum migration - The verification branch below is hardcoded for BN254 Groth16.
        // During migration, checking `request.proof_type` should branch to `PostQuantumVerifier::verify_proof`
        // or a native host-function call if STARK verification limits CPU budgets.
        let vk = Self::get_verification_key(env.clone()).ok_or(ContractError::InvalidConfig)?;
        let is_valid =
            Bn254Verifier::verify_proof(&env, &vk, &request.proof, &request.public_inputs);
        if is_valid {
            let proof_hash = PoseidonHasher::hash(&env, &request.public_inputs);
            AuditTrail::log_access(
                &env,
                request.user,
                request.resource_id,
                proof_hash,
                request.expires_at,
            );
            env.storage()
                .persistent()
                .set(&nonce_key, &current_nonce.saturating_add(1));
        } else {
            Self::emit_access_violation(
                &env,
                &request.user,
                "verify_access",
                "valid_groth16_proof",
            );
        }
        Ok(is_valid)
    }

    /// Retrieves the current anti-replay nonce for a given user address.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn get_nonce(env: Env, user: Address) -> u64 {
        env.storage().persistent().get(&(NONCE, user)).unwrap_or(0)
    }

    /// Verifies access with tiered authentication level requirements.
    ///
    /// # Level Specifications
    /// - **Levels 1, 2, 3**: Standard proof verification path.
    /// - **Level 4**: High-assurance tier requiring $\ge 2$ public inputs
    ///   (operation binding + attribute commitment).
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `request` - The access request envelope.
    /// * `required_auth_level` - Desired tier $(1 \le \text{level} \le 4)$.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L$ is public input count.
    /// - **Space Complexity**: $\mathcal{O}(L)$.
    pub fn verify_auth_level_access(
        env: Env,
        request: AccessRequest,
        required_auth_level: u32,
    ) -> Result<bool, ContractError> {
        validate_auth_level(required_auth_level)?;

        if required_auth_level >= 4 {
            validate_level4_attributes(&request)?;
        }

        Self::verify_access(env, request)
    }

    /// Verifies access using the PLONK proving system entrypoint.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$.
    /// - **Space Complexity**: $\mathcal{O}(L)$.
    pub fn verify_access_plonk(env: Env, request: AccessRequest) -> Result<bool, ContractError> {
        // Until a dedicated PLONK verifier is wired, keep entrypoint parity
        // with clients by using the Groth16 validation path.
        Self::verify_access(env, request)
    }

    /// Verifies cryptographic Merkle data inclusion of a leaf digest within a root commitment.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `root` - 32-byte expected Merkle root.
    /// * `leaf` - 32-byte target leaf digest.
    /// * `proof_path` - Vector of sibling hashes and positional orientation flags.
    ///
    /// # Returns
    /// `true` if the computed path matches `root`, otherwise `false`.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(D)$ where $D \le 32$ is the Merkle tree depth.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn verify_data_inclusion(
        env: Env,
        root: BytesN<32>,
        leaf: BytesN<32>,
        proof_path: Vec<(BytesN<32>, bool)>,
    ) -> bool {
        MerkleVerifier::verify_merkle_proof(&env, &root, &leaf, &proof_path)
    }

    /// Retrieves the most recent audit record for a given user and resource identifier.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn get_audit_record(
        env: Env,
        user: Address,
        resource_id: BytesN<32>,
    ) -> Option<AuditRecord> {
        AuditTrail::get_record(&env, user, resource_id)
    }

    /// Verifies the cryptographic hash-chain continuity of all audit records for a user/resource pair.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(K)$ where $K$ is the length of the audit chain.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    pub fn verify_audit_chain(env: Env, user: Address, resource_id: BytesN<32>) -> bool {
        AuditTrail::verify_chain(&env, user, resource_id)
    }
}
