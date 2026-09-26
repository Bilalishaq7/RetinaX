#![cfg(test)]
#![allow(clippy::unwrap_used)]

use audit::contract::{AuditContract, AuditContractClient, AuditContractError};
use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env};

// ── Mock Contract for Contract-Address Admin Testing ──────────────────────────

#[soroban_sdk::contract]
pub struct MockAdminContract;

#[soroban_sdk::contractimpl]
impl MockAdminContract {
    pub fn ping(_env: Env) -> bool {
        true
    }
}

// ── Test Setup Helpers ────────────────────────────────────────────────────────

fn deploy() -> (Env, AuditContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    (env, client, admin)
}

fn deploy_uninitialized() -> (Env, AuditContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);
    (env, client)
}

// ── Issue #13: Unit Tests for Initialization in Audit ─────────────────────────

#[test]
fn test_initialize_once_succeeds() {
    let (_, client, admin) = deploy();
    let result = client.try_initialize(&admin);
    assert!(result.is_ok(), "First initialization must succeed");
}

#[test]
fn test_initialize_twice_reverts() {
    let (_, client, admin) = deploy();
    client.initialize(&admin);
    let result = client.try_initialize(&admin);
    assert!(result.is_err(), "Second initialization must fail");
}

#[test]
fn test_initialize_twice_different_admin_reverts() {
    let (env, client, admin) = deploy();
    let admin2 = Address::generate(&env);
    client.initialize(&admin);
    let result = client.try_initialize(&admin2);
    assert!(
        result.is_err(),
        "Re-init with a different admin must still fail"
    );
}

#[test]
fn test_initialize_returns_typed_already_initialized_error() {
    let (_, client, admin) = deploy();
    client.initialize(&admin);

    let result = client.try_initialize(&admin);
    match result {
        Err(Ok(err)) => {
            assert_eq!(
                err,
                AuditContractError::AlreadyInitialized,
                "Must return typed AuditContractError::AlreadyInitialized (error code 1)"
            );
        }
        other => panic!("Expected AlreadyInitialized typed contract error, got {:?}", other),
    }
}

#[test]
fn test_repeated_reinitialization_always_fails() {
    let (env, client, admin) = deploy();
    client.initialize(&admin);

    // Multiple consecutive re-initialization attempts from various attacker addresses
    for _ in 0..5 {
        let attacker = Address::generate(&env);
        let result = client.try_initialize(&attacker);
        match result {
            Err(Ok(err)) => assert_eq!(err, AuditContractError::AlreadyInitialized),
            other => panic!("Every re-init attempt must fail with AlreadyInitialized, got {:?}", other),
        }
    }
}

#[test]
fn test_admin_storage_immutable_after_reinit_attempt() {
    let (env, client, original_admin) = deploy();
    client.initialize(&original_admin);

    let attacker = Address::generate(&env);
    let _ = client.try_initialize(&attacker);

    // Verify original admin remains the authorized admin by successfully creating a segment
    let segment = symbol_short!("SEC_SEG");
    client.create_segment(&segment);

    let count = client.get_entry_count(&segment);
    assert_eq!(count, 0, "Newly created segment by authorized admin must exist with 0 entries");
}

#[test]
fn test_uninitialized_contract_create_segment_fails() {
    let (_env, client) = deploy_uninitialized();
    let segment = symbol_short!("UNINIT");

    // Invoking administrative functions prior to initialization must fail
    let result = client.try_create_segment(&segment);
    assert!(
        result.is_err(),
        "create_segment on uninitialized contract must fail"
    );
}

#[test]
fn test_multi_instance_isolated_initialization() {
    let env = Env::default();
    env.mock_all_auths();

    // Register two independent contract instances
    let id_a = env.register(AuditContract, ());
    let client_a = AuditContractClient::new(&env, &id_a);

    let id_b = env.register(AuditContract, ());
    let client_b = AuditContractClient::new(&env, &id_b);

    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);

    // Initialize Instance A
    let res_a = client_a.try_initialize(&admin_a);
    assert!(res_a.is_ok(), "Instance A initialization must succeed");

    // Instance A re-initialization must fail
    let re_res_a = client_a.try_initialize(&admin_a);
    assert!(re_res_a.is_err(), "Instance A re-initialization must fail");

    // Instance B is still uninitialized; its first initialization must succeed
    let res_b = client_b.try_initialize(&admin_b);
    assert!(res_b.is_ok(), "Instance B initialization must succeed independently");

    // Both instances can now perform distinct operations
    let seg_a = symbol_short!("INST_A");
    let seg_b = symbol_short!("INST_B");

    client_a.create_segment(&seg_a);
    client_b.create_segment(&seg_b);

    assert_eq!(client_a.get_entry_count(&seg_a), 0);
    assert_eq!(client_b.get_entry_count(&seg_b), 0);

    // Segment A does not exist in Instance B
    assert!(client_b.try_get_entry_count(&seg_a).is_err());
    // Segment B does not exist in Instance A
    assert!(client_a.try_get_entry_count(&seg_b).is_err());
}

#[test]
fn test_initialize_with_contract_address_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_admin_id = env.register(MockAdminContract, ());
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);

    // Initializing with a smart contract address as admin
    let res = client.try_initialize(&contract_admin_id);
    assert!(res.is_ok(), "Initialization with a contract address admin must succeed");

    // Segment creation with contract admin
    let segment = symbol_short!("CON_ADM");
    client.create_segment(&segment);
    assert_eq!(client.get_entry_count(&segment), 0);
}

#[test]
fn test_post_activity_reinitialization_preserves_state() {
    let (env, client, admin) = deploy();
    client.initialize(&admin);

    let segment = symbol_short!("ACTIVITY");
    client.create_segment(&segment);

    let actor = Address::generate(&env);
    let action = symbol_short!("READ");
    let target = symbol_short!("PATIENT1");
    let result_sym = symbol_short!("OK");

    let seq1 = client.append_entry(&segment, &actor, &action, &target, &result_sym);
    let seq2 = client.append_entry(&segment, &actor, &action, &target, &result_sym);
    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
    assert_eq!(client.get_entry_count(&segment), 2);

    // Attempt re-initialization after data is committed
    let attacker = Address::generate(&env);
    let reinit_res = client.try_initialize(&attacker);
    match reinit_res {
        Err(Ok(err)) => assert_eq!(err, AuditContractError::AlreadyInitialized),
        other => panic!("Expected AlreadyInitialized, got {:?}", other),
    }

    // Ensure all pre-existing entries and counters are completely preserved
    assert_eq!(
        client.get_entry_count(&segment),
        2,
        "Entry count must not be modified or reset after failed re-initialization"
    );

    let entries = client.get_entries(&segment);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries.get(0).unwrap().sequence, 1);
    assert_eq!(entries.get(1).unwrap().sequence, 2);
}

