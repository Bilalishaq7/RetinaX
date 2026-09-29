//! # Initialization Tests — ZK Verifier Contract
//!
//! Verifies the one-time bootstrap behavior of `ZkVerifierContract::initialize`
//! and the admin-gated configuration entry-points that depend on it.
//!
//! Covers issue #31: "Testing: Add unit tests for initialization in zk_verifier".
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};
use zk_verifier::vk::{G1Point, G2Point, VerificationKey};
use zk_verifier::{ZkVerifierContract, ZkVerifierContractClient};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Register the contract and return its client without initializing it.
fn fresh_client(env: &Env) -> ZkVerifierContractClient<'static> {
    env.mock_all_auths();
    let id = env.register(ZkVerifierContract, ());
    ZkVerifierContractClient::new(env, &id)
}

/// A deterministic zero verification key ( adequate for storage round-trip tests ).
fn zero_vk(env: &Env) -> VerificationKey {
    let z = BytesN::from_array(env, &[0u8; 32]);
    let g1z = G1Point {
        x: z.clone(),
        y: z.clone(),
    };
    let g2z = G2Point {
        x: (z.clone(), z.clone()),
        y: (z.clone(), z.clone()),
    };
    let mut ic = Vec::new(env);
    ic.push_back(g1z.clone());
    VerificationKey {
        alpha_g1: g1z,
        beta_g2: g2z.clone(),
        gamma_g2: g2z.clone(),
        delta_g2: g2z,
        ic,
    }
}

// ── initialize() ──────────────────────────────────────────────────────────────

#[test]
fn initialize_sets_admin_so_admin_ops_succeed() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    // The initialized admin can perform an admin-gated operation.
    let vk = zero_vk(&env);
    assert!(
        client.try_set_verification_key(&admin, &vk).is_ok(),
        "initialized admin must be able to set the verification key"
    );
    assert_eq!(client.get_verification_key(), Some(vk));
}

#[test]
fn initialize_is_idempotent_first_admin_wins() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);

    client.initialize(&admin1);
    // Second call is a silent no-op by design (re-initialization takeover guard).
    client.initialize(&admin2);

    // admin2 must NOT have gained admin rights...
    let vk = zero_vk(&env);
    let res = client.try_set_verification_key(&admin2, &vk);
    assert_eq!(
        res.unwrap_err().unwrap(),
        zk_verifier::ContractError::Unauthorized,
        "second initializer must not become admin"
    );

    // ...and admin1 retains full control.
    assert!(client.try_set_verification_key(&admin1, &vk).is_ok());
}

#[test]
fn admin_operations_fail_before_initialization() {
    let env = Env::default();
    let client = fresh_client(&env);

    let caller = Address::generate(&env);
    let vk = zero_vk(&env);

    let res = client.try_set_verification_key(&caller, &vk);
    assert_eq!(
        res.unwrap_err().unwrap(),
        zk_verifier::ContractError::Unauthorized,
        "admin-gated ops must fail while the contract is uninitialized"
    );
    assert_eq!(client.get_verification_key(), None);
}

#[test]
fn initialize_can_be_called_by_any_address_but_that_address_becomes_admin() {
    let env = Env::default();
    let client = fresh_client(&env);

    // initialize() requires auth from the candidate admin (mocked here), so
    // whoever calls it first becomes the admin — this pins down that contract.
    let founder = Address::generate(&env);
    let intruder = Address::generate(&env);

    client.initialize(&founder);
    client.initialize(&intruder); // no-op

    // founder still admin
    assert!(client
        .try_set_verification_key(&founder, &zero_vk(&env))
        .is_ok());
    // intruder still unauthorized
    let res = client.try_set_verification_key(&intruder, &zero_vk(&env));
    assert_eq!(
        res.unwrap_err().unwrap(),
        zk_verifier::ContractError::Unauthorized
    );
}

// ── Admin configuration surface reachable post-initialization ────────────────

#[test]
fn uninitialized_contract_reports_defaults() {
    let env = Env::default();
    let client = fresh_client(&env);

    assert_eq!(client.get_verification_key(), None);
    assert_eq!(client.get_rate_limit_config(), None);
    assert_eq!(client.get_pending_admin(), None);
    assert!(!client.is_paused());
    assert!(!client.is_whitelist_enabled());
}

#[test]
fn initialized_contract_defaults_are_clear() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    assert_eq!(client.get_verification_key(), None);
    assert_eq!(client.get_rate_limit_config(), None);
    assert_eq!(client.get_pending_admin(), None);
    assert!(!client.is_paused());
    assert!(!client.is_whitelist_enabled());
}

#[test]
fn rate_limit_config_roundtrip_after_initialization() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    client.set_rate_limit_config(&admin, &5, &60);
    assert_eq!(client.get_rate_limit_config(), Some((5, 60)));

    // Admin can update it later.
    client.set_rate_limit_config(&admin, &10, &120);
    assert_eq!(client.get_rate_limit_config(), Some((10, 120)));
}

#[test]
fn rate_limit_config_rejects_zero_parameters() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let zero_max = client.try_set_rate_limit_config(&admin, &0, &60);
    assert_eq!(
        zero_max.unwrap_err().unwrap(),
        zk_verifier::ContractError::InvalidConfig,
        "zero max_requests must be rejected"
    );

    let zero_window = client.try_set_rate_limit_config(&admin, &5, &0);
    assert_eq!(
        zero_window.unwrap_err().unwrap(),
        zk_verifier::ContractError::InvalidConfig,
        "zero window duration must be rejected"
    );

    // Nothing was stored.
    assert_eq!(client.get_rate_limit_config(), None);
}

#[test]
fn set_rate_limit_config_requires_admin() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    client.initialize(&admin);

    let res = client.try_set_rate_limit_config(&non_admin, &5, &60);
    assert_eq!(
        res.unwrap_err().unwrap(),
        zk_verifier::ContractError::Unauthorized
    );
    assert_eq!(client.get_rate_limit_config(), None);
}

#[test]
fn verification_key_roundtrip_after_initialization() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let vk = zero_vk(&env);
    client.set_verification_key(&admin, &vk);
    assert_eq!(client.get_verification_key(), Some(vk));
}

#[test]
fn set_verification_key_requires_admin() {
    let env = Env::default();
    let client = fresh_client(&env);

    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    client.initialize(&admin);

    let res = client.try_set_verification_key(&non_admin, &zero_vk(&env));
    assert_eq!(
        res.unwrap_err().unwrap(),
        zk_verifier::ContractError::Unauthorized
    );
    assert_eq!(client.get_verification_key(), None);
}
