//! # Negative Tests — ZK Verifier Contract
//!
//! Verifies that every guarded entry-point rejects invalid callers, invalid
//! state transitions, and invalid request envelopes with the documented
//! [`zk_verifier::ContractError`] variants.
//!
//! Covers issue #32: "Testing: Add negative unit tests (error cases) in zk_verifier".
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};
use zk_verifier::verifier::{G1Point, G2Point, Proof};
use zk_verifier::vk::VerificationKey;
use zk_verifier::{AccessRequest, ContractError, ZkVerifierContract, ZkVerifierContractClient};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup(env: &Env) -> (ZkVerifierContractClient<'static>, Address, Address) {
    env.mock_all_auths();
    let id = env.register(ZkVerifierContract, ());
    let client = ZkVerifierContractClient::new(env, &id);
    let admin = Address::generate(env);
    let user = Address::generate(env);
    client.initialize(&admin);
    (client, admin, user)
}

/// Structurally valid proof (passes `validate_request` and
/// `validate_proof_components`) — all coordinates non-zero, non-saturated.
fn valid_proof(env: &Env) -> (Proof, Vec<BytesN<32>>) {
    let mut ax = [0u8; 32];
    ax[0] = 1;
    let bx = [1u8; 32];
    let mut cx = [0u8; 32];
    cx[0] = 1;
    let mut pi = [0u8; 32];
    pi[0] = 1;

    let proof = Proof {
        a: G1Point {
            x: BytesN::from_array(env, &ax),
            y: BytesN::from_array(env, &ax),
        },
        b: G2Point {
            x: (BytesN::from_array(env, &bx), BytesN::from_array(env, &bx)),
            y: (BytesN::from_array(env, &bx), BytesN::from_array(env, &bx)),
        },
        c: G1Point {
            x: BytesN::from_array(env, &cx),
            y: BytesN::from_array(env, &ax),
        },
    };
    let mut inputs = Vec::new(env);
    inputs.push_back(BytesN::from_array(env, &pi));
    (proof, inputs)
}

/// A placeholder verification key. The mock Groth16 verifier ignores its
/// contents; it only needs to be present so `verify_access` reaches the
/// proof-evaluation stage instead of failing with `InvalidConfig`.
fn sample_vk(env: &Env) -> VerificationKey {
    let f = [1u8; 32];
    let g1 = G1Point {
        x: BytesN::from_array(env, &f),
        y: BytesN::from_array(env, &f),
    };
    let g2 = G2Point {
        x: (BytesN::from_array(env, &f), BytesN::from_array(env, &f)),
        y: (BytesN::from_array(env, &f), BytesN::from_array(env, &f)),
    };
    let mut ic = Vec::new(env);
    ic.push_back(g1.clone());
    VerificationKey {
        alpha_g1: g1,
        beta_g2: g2.clone(),
        gamma_g2: g2.clone(),
        delta_g2: g2,
        ic,
    }
}

fn make_request(
    env: &Env,
    user: Address,
    nonce: u64,
    proof: Proof,
    inputs: Vec<BytesN<32>>,
) -> AccessRequest {
    AccessRequest {
        user,
        resource_id: BytesN::from_array(env, &[7u8; 32]),
        proof,
        public_inputs: inputs,
        expires_at: env.ledger().timestamp().saturating_add(600),
        nonce,
    }
}

// ── Admin transfer: propose / accept / cancel ─────────────────────────────────

#[test]
fn propose_admin_requires_current_admin() {
    let env = Env::default();
    let (client, _, _) = setup(&env);
    let outsider = Address::generate(&env);
    let nominee = Address::generate(&env);

    let res = client.try_propose_admin(&outsider, &nominee);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);
    assert_eq!(client.get_pending_admin(), None);
}

#[test]
fn accept_admin_fails_when_no_transfer_pending() {
    let env = Env::default();
    let (client, _, _) = setup(&env);
    let nominee = Address::generate(&env);

    let res = client.try_accept_admin(&nominee);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::InvalidConfig);
}

#[test]
fn accept_admin_rejects_non_nominated_address() {
    let env = Env::default();
    let (client, admin, _) = setup(&env);
    let nominee = Address::generate(&env);
    let impostor = Address::generate(&env);

    client.propose_admin(&admin, &nominee);

    let res = client.try_accept_admin(&impostor);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);

    // Pending nomination survives a failed accept.
    assert_eq!(client.get_pending_admin(), Some(nominee));
}

#[test]
fn cancel_admin_transfer_requires_admin() {
    let env = Env::default();
    let (client, admin, _) = setup(&env);
    let nominee = Address::generate(&env);
    let outsider = Address::generate(&env);

    client.propose_admin(&admin, &nominee);

    let res = client.try_cancel_admin_transfer(&outsider);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);
    assert_eq!(client.get_pending_admin(), Some(nominee));

    // The real admin cancels successfully.
    client.cancel_admin_transfer(&admin);
    assert_eq!(client.get_pending_admin(), None);
}

#[test]
fn cancel_admin_transfer_fails_when_nothing_pending() {
    let env = Env::default();
    let (client, admin, _) = setup(&env);

    let res = client.try_cancel_admin_transfer(&admin);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::InvalidConfig);
}

#[test]
fn unauthorized_caller_cannot_pause_or_unpause() {
    let env = Env::default();
    let (client, _, _) = setup(&env);
    let outsider = Address::generate(&env);

    let res = client.try_pause(&outsider);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);

    let res = client.try_unpause(&outsider);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);

    assert!(!client.is_paused());
}

// ── verify_access error paths ─────────────────────────────────────────────────

#[test]
fn verify_access_is_rejected_while_paused() {
    let env = Env::default();
    let (client, admin, user) = setup(&env);

    client.pause(&admin);

    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_access(&req);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Paused);
}

#[test]
fn verify_access_rejects_stale_nonce() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 42, proof, inputs); // current nonce is 0

    let res = client.try_verify_access(&req);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::MalformedProofData);
}

#[test]
fn verify_access_rejects_empty_public_inputs() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let (proof, _) = valid_proof(&env);
    let empty: Vec<BytesN<32>> = Vec::new(&env);
    let req = make_request(&env, user, 0, proof, empty);

    let res = client.try_verify_access(&req);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::EmptyPublicInputs);
}

#[test]
fn verify_access_rejects_too_many_public_inputs() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let (proof, _inputs) = valid_proof(&env);
    let mut oversized = Vec::new(&env);
    for i in 0u8..17 {
        let mut buf = [0u8; 32];
        buf[0] = if i == 0 { 1 } else { i.saturating_add(1) };
        oversized.push_back(BytesN::from_array(&env, &buf));
    }
    let req = make_request(&env, user, 0, proof, oversized);

    let res = client.try_verify_access(&req);
    assert_eq!(
        res.unwrap_err().unwrap(),
        ContractError::TooManyPublicInputs
    );
}

#[test]
fn verify_access_rejects_degenerate_proof() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let z = [0u8; 32];
    let zero_proof = Proof {
        a: G1Point {
            x: BytesN::from_array(&env, &z),
            y: BytesN::from_array(&env, &z),
        },
        b: G2Point {
            x: (BytesN::from_array(&env, &z), BytesN::from_array(&env, &z)),
            y: (BytesN::from_array(&env, &z), BytesN::from_array(&env, &z)),
        },
        c: G1Point {
            x: BytesN::from_array(&env, &z),
            y: BytesN::from_array(&env, &z),
        },
    };
    let mut inputs = Vec::new(&env);
    let mut pi = [0u8; 32];
    pi[0] = 1;
    inputs.push_back(BytesN::from_array(&env, &pi));

    let req = make_request(&env, user, 0, zero_proof, inputs);
    let res = client.try_verify_access(&req);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::DegenerateProof);
}

#[test]
fn verify_access_rejects_non_whitelisted_user() {
    let env = Env::default();
    let (client, admin, user) = setup(&env);

    client.set_whitelist_enabled(&admin, &true);

    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_access(&req);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);
}

#[test]
fn verify_access_without_verification_key_configured_fails() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    // No VK set → InvalidConfig once structural validation passes.
    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_access(&req);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::InvalidConfig);
}

#[test]
fn verify_access_rate_limited_after_quota_exhausted() {
    let env = Env::default();
    let (client, admin, user) = setup(&env);

    // 1 request per 100-second window.
    client.set_rate_limit_config(&admin, &1, &100);
    client.set_verification_key(&admin, &sample_vk(&env));

    // First call succeeds (mock verifier accepts) and commits the rate-limit
    // counter along with the nonce increment.
    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user.clone(), 0, proof, inputs);
    assert!(
        client.try_verify_access(&req).unwrap().unwrap(),
        "first request must be admitted"
    );

    // Second call inside the window (with the advanced nonce) is rate limited.
    let (proof2, inputs2) = valid_proof(&env);
    let req2 = make_request(&env, user, 1, proof2, inputs2);
    let res = client.try_verify_access(&req2);
    assert_eq!(
        res.unwrap_err().unwrap(),
        ContractError::RateLimited,
        "second call inside the window must be rate limited"
    );
}

#[test]
fn failed_nonce_check_does_not_consume_rate_limit_quota() {
    let env = Env::default();
    let (client, admin, user) = setup(&env);

    client.set_rate_limit_config(&admin, &1, &100);

    // Stale nonce aborts before the rate limiter runs.
    let (proof, inputs) = valid_proof(&env);
    let stale = make_request(&env, user.clone(), 99, proof, inputs);
    let res = client.try_verify_access(&stale);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::MalformedProofData);

    // The valid-nonce request is still allowed (quota untouched): with no VK
    // configured it fails at the config stage, never with `RateLimited`.
    let (proof2, inputs2) = valid_proof(&env);
    let good = make_request(&env, user, 0, proof2, inputs2);
    let res = client.try_verify_access(&good);
    assert!(
        !matches!(res, Err(Ok(ContractError::RateLimited))),
        "stale-nonce attempts must not consume rate limit quota"
    );
}

// ── verify_auth_level_access error paths ──────────────────────────────────────

#[test]
fn auth_level_zero_is_rejected() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_auth_level_access(&req, &0);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::InvalidAuthLevel);
}

#[test]
fn auth_level_above_four_is_rejected() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_auth_level_access(&req, &5);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::InvalidAuthLevel);
}

#[test]
fn auth_level_four_requires_two_public_inputs() {
    let env = Env::default();
    let (client, _, user) = setup(&env);

    let (proof, inputs) = valid_proof(&env); // only 1 public input
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_auth_level_access(&req, &4);
    assert_eq!(
        res.unwrap_err().unwrap(),
        ContractError::ProofRequiredForAuthLevel
    );
}

#[test]
fn auth_level_validation_precedes_other_checks() {
    let env = Env::default();
    let (client, admin, user) = setup(&env);

    // Contract is paused, but the auth-level error takes priority.
    client.pause(&admin);

    let (proof, inputs) = valid_proof(&env);
    let req = make_request(&env, user, 0, proof, inputs);

    let res = client.try_verify_auth_level_access(&req, &9);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::InvalidAuthLevel);
}

// ── read/query endpoints on bad state ────────────────────────────────────────

#[test]
fn get_nonce_is_zero_for_unknown_user() {
    let env = Env::default();
    let (client, _, _) = setup(&env);

    let stranger = Address::generate(&env);
    assert_eq!(client.get_nonce(&stranger), 0);
}

#[test]
fn get_audit_record_returns_none_for_unknown_user() {
    let env = Env::default();
    let (client, _, _) = setup(&env);

    let stranger = Address::generate(&env);
    let rid = BytesN::from_array(&env, &[7u8; 32]);
    assert!(client.get_audit_record(&stranger, &rid).is_none());
}

#[test]
fn get_verification_key_is_none_when_unset() {
    let env = Env::default();
    let (client, _, _) = setup(&env);

    assert_eq!(client.get_verification_key(), None);
}
