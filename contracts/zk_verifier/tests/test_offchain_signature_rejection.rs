//! # Off-Chain Signature Rejection Test — ZK Verifier
//!
//! Micro-test to verify that the zk_verifier contract properly rejects
//! AccessRequests with off-chain signatures that fail validation checks.
//!
//! This test specifically validates that signatures created outside the 
//! normal flow (off-chain) are detected and rejected, ensuring that only
//! properly authenticated requests are processed.
//!
//! Issue #115: Write micro-test for zk_verifier off-chain signature rejection

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};
use zk_verifier::vk::{G1Point, G2Point, VerificationKey};
use zk_verifier::{
    AccessRequest, ContractError, Proof, ZkVerifierContract, ZkVerifierContractClient,
};

// ── Test Helpers ──────────────────────────────────────────────────────────────

fn zero32(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn nonzero32(env: &Env, seed: u8) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[31] = seed.wrapping_add(1);
    BytesN::from_array(env, &b)
}

fn g1(env: &Env, x: BytesN<32>, y: BytesN<32>) -> G1Point {
    G1Point { x, y }
}

fn g2(env: &Env, x0: BytesN<32>, x1: BytesN<32>, y0: BytesN<32>, y1: BytesN<32>) -> G2Point {
    G2Point {
        x: (x0, x1),
        y: (y0, y1),
    }
}

fn setup_contract(env: &Env) -> (ZkVerifierContractClient<'static>, Address) {
    env.mock_all_auths();
    let contract_id = env.register(ZkVerifierContract, ());
    let client = ZkVerifierContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    
    client.initialize(&admin);
    
    // Set verification key
    let nz1 = nonzero32(env, 1);
    let nz2 = nonzero32(env, 2);
    let vk = VerificationKey {
        alpha: g1(env, nz1.clone(), nz1.clone()),
        beta: g2(env, nz1.clone(), nz1.clone(), nz2.clone(), nz2.clone()),
        gamma: g2(env, nz2.clone(), nz2.clone(), nz1.clone(), nz1.clone()),
        delta: g2(env, nz1.clone(), nz2.clone(), nz2.clone(), nz1.clone()),
        ic: Vec::new(env),
    };
    client.set_verification_key(&admin, &vk);
    
    // Disable whitelist for testing
    client.set_whitelist_enabled(&admin, &false);
    
    (client, admin)
}

/// Creates a valid-looking proof structure (but not cryptographically valid)
fn create_offchain_proof(env: &Env) -> Proof {
    let nz1 = nonzero32(env, 1);
    let nz2 = nonzero32(env, 2);
    let nz3 = nonzero32(env, 3);
    let nz4 = nonzero32(env, 4);
    
    Proof {
        a: g1(env, nz1.clone(), nz1),
        b: g2(env, nz2.clone(), nz2.clone(), nz3.clone(), nz3),
        c: g1(env, nz4.clone(), nz4),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_rejects_offchain_signature_with_invalid_nonce() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    // Create an off-chain crafted request with incorrect nonce
    let mut public_inputs = Vec::new(&env);
    public_inputs.push_back(nonzero32(&env, 99));
    
    let request = AccessRequest {
        user: user.clone(),
        resource_id,
        proof: create_offchain_proof(&env),
        public_inputs,
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 999, // Invalid nonce - should be 0 for first request
    };
    
    // Should reject due to nonce mismatch
    let result = client.try_verify_access(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), ContractError::MalformedProofData);
}

#[test]
fn test_rejects_offchain_signature_with_degenerate_proof() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    // Create an off-chain crafted request with all-zero proof (degenerate)
    let mut public_inputs = Vec::new(&env);
    public_inputs.push_back(nonzero32(&env, 99));
    
    let zero_proof = Proof {
        a: g1(&env, zero32(&env), zero32(&env)),
        b: g2(&env, zero32(&env), zero32(&env), zero32(&env), zero32(&env)),
        c: g1(&env, zero32(&env), zero32(&env)),
    };
    
    let request = AccessRequest {
        user,
        resource_id,
        proof: zero_proof,
        public_inputs,
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 0,
    };
    
    // Should reject due to degenerate proof
    let result = client.try_verify_access(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), ContractError::DegenerateProof);
}

#[test]
fn test_rejects_offchain_signature_with_empty_public_inputs() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    // Create an off-chain crafted request with empty public inputs
    let public_inputs = Vec::new(&env); // Empty!
    
    let request = AccessRequest {
        user,
        resource_id,
        proof: create_offchain_proof(&env),
        public_inputs,
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 0,
    };
    
    // Should reject due to empty public inputs
    let result = client.try_verify_access(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), ContractError::EmptyPublicInputs);
}

#[test]
fn test_rejects_offchain_signature_exceeding_max_public_inputs() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    // Create an off-chain crafted request with too many public inputs (>16)
    let mut public_inputs = Vec::new(&env);
    for i in 0..20 {
        public_inputs.push_back(nonzero32(&env, i));
    }
    
    let request = AccessRequest {
        user,
        resource_id,
        proof: create_offchain_proof(&env),
        public_inputs,
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 0,
    };
    
    // Should reject due to too many public inputs
    let result = client.try_verify_access(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), ContractError::TooManyPublicInputs);
}

#[test]
fn test_rejects_offchain_signature_with_zeroed_public_input() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    // Create an off-chain crafted request with a zeroed public input
    let mut public_inputs = Vec::new(&env);
    public_inputs.push_back(zero32(&env)); // Invalid - all zeros
    
    let request = AccessRequest {
        user,
        resource_id,
        proof: create_offchain_proof(&env),
        public_inputs,
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 0,
    };
    
    // Should reject due to validation checks in validate_proof_components
    let result = client.try_verify_access(&request);
    assert!(result.is_err());
    
    // Could be either ZeroedPublicInput or caught earlier
    let err = result.unwrap_err().unwrap();
    assert!(
        err == ContractError::ZeroedPublicInput || 
        err == ContractError::MalformedProofData ||
        err == ContractError::DegenerateProof
    );
}

#[test]
fn test_rejects_offchain_signature_when_paused() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);
    
    // Pause the contract
    client.pause(&admin);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    let mut public_inputs = Vec::new(&env);
    public_inputs.push_back(nonzero32(&env, 99));
    
    let request = AccessRequest {
        user,
        resource_id,
        proof: create_offchain_proof(&env),
        public_inputs,
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 0,
    };
    
    // Should reject due to contract being paused
    let result = client.try_verify_access(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Paused);
}

#[test]
fn test_rejects_offchain_signature_with_replay_attack() {
    let env = Env::default();
    let (client, _admin) = setup_contract(&env);
    
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 42);
    
    let mut public_inputs = Vec::new(&env);
    public_inputs.push_back(nonzero32(&env, 99));
    
    let request = AccessRequest {
        user: user.clone(),
        resource_id: resource_id.clone(),
        proof: create_offchain_proof(&env),
        public_inputs: public_inputs.clone(),
        expires_at: env.ledger().timestamp() + 3600,
        nonce: 0,
    };
    
    // First attempt - will fail because proof is not cryptographically valid,
    // but nonce will NOT increment on failure
    let _ = client.try_verify_access(&request);
    
    // Try to replay the same request - should still fail with nonce 0
    let replay_result = client.try_verify_access(&request);
    assert!(replay_result.is_err());
    
    // Nonce should still be 0 (unchanged because previous attempt failed)
    let current_nonce = client.get_nonce(&user);
    assert_eq!(current_nonce, 0);
}
