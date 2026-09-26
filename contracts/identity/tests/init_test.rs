#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(test)]

extern crate std;

use identity::{
    events::OwnerStatusChangedEvent,
    recovery::RecoveryError,
    IdentityContract, IdentityContractClient,
};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events, Ledger},
    xdr::{ContractEventBody, ScVal},
    Address, BytesN, Env, IntoVal, TryFromVal, Val, Vec,
};

// ── Test Helpers ─────────────────────────────────────────────────────────────

fn setup_uninit() -> (Env, Address, IdentityContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(IdentityContract, ());
    let client = IdentityContractClient::new(&env, &contract_id);

    (env, contract_id, client)
}

fn setup_initialized() -> (Env, Address, IdentityContractClient<'static>, Address) {
    let (env, contract_id, client) = setup_uninit();
    let owner = Address::generate(&env);
    client.initialize(&owner);
    (env, contract_id, client, owner)
}

// ── 1. Pre-Initialization State & Invariants ─────────────────────────────────

#[test]
fn test_pre_initialization_state() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(IdentityContract, ());
    let client = IdentityContractClient::new(&env, &contract_id);

    let owner = Address::generate(&env);

    // Before initialize: owner should not be active, guardians empty, threshold 0
    assert!(!client.is_owner_active(&owner));
    assert_eq!(client.get_guardians(&owner).len(), 0);
    assert_eq!(client.get_recovery_threshold(&owner), 0);

    // Calling guarded methods without initialization should return Unauthorized
    let attacker = Address::generate(&env);
    let new_guard = Address::generate(&env);
    assert_eq!(
        client.try_add_guardian(&attacker, &new_guard),
        Err(Ok(RecoveryError::Unauthorized))
    );
}

#[test]
fn test_uninitialized_default_queries() {
    let (env, _contract_id, client) = setup_uninit();
    let random_addr = Address::generate(&env);

    // All read queries on uninitialized state should return empty/default values
    assert!(!client.is_owner_active(&random_addr));
    assert_eq!(client.get_guardians(&random_addr).len(), 0);
    assert_eq!(client.get_recovery_threshold(&random_addr), 0);
    assert!(client.get_recovery_request(&random_addr).is_none());
    assert_eq!(client.get_bound_credentials(&random_addr).len(), 0);
    assert!(client.get_zk_verifier().is_none());

    let dummy_cred = BytesN::from_array(&env, &[0x42u8; 32]);
    assert!(!client.is_credential_bound(&random_addr, &dummy_cred));
}

// ── 2. Initialization Success & Event Emission ───────────────────────────────

#[test]
fn test_initialize_sets_state_and_prevents_double_init() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(IdentityContract, ());
    let client = IdentityContractClient::new(&env, &contract_id);

    let owner = Address::generate(&env);

    // Initialize should succeed and set owner active
    client.initialize(&owner);
    assert!(client.is_owner_active(&owner));
    assert_eq!(client.get_guardians(&owner).len(), 0);
    assert_eq!(client.get_recovery_threshold(&owner), 0);

    // Double initialization must fail with AlreadyInitialized
    assert_eq!(
        client.try_initialize(&Address::generate(&env)),
        Err(Ok(RecoveryError::AlreadyInitialized))
    );
}

#[test]
fn test_initialize_emits_event() {
    let (env, _contract_id, client) = setup_uninit();
    env.ledger().set_timestamp(1_700_000_000);

    let owner = Address::generate(&env);
    client.initialize(&owner);

    let events = env.events().all();
    let event = events.events().last().expect("OwnerStatusChangedEvent expected");
    let ContractEventBody::V0(body) = &event.body;

    let expected_topics: Vec<Val> =
        (symbol_short!("STREAM"), symbol_short!("ID_STAT")).into_val(&env);
    let mut expected_topics_scval = std::vec::Vec::new();
    for topic in expected_topics.iter() {
        expected_topics_scval.push(ScVal::try_from_val(&env, &topic).unwrap());
    }
    assert_eq!(body.topics.as_slice(), expected_topics_scval.as_slice());

    let expected_payload = OwnerStatusChangedEvent {
        owner: owner.clone(),
        active: true,
        timestamp: 1_700_000_000,
    };
    let expected_val: Val = expected_payload.into_val(&env);
    assert_eq!(body.data, ScVal::try_from_val(&env, &expected_val).unwrap());
}

#[test]
fn test_initialize_zero_state_invariants() {
    let (env, _contract_id, client, owner) = setup_initialized();

    // After initialization, owner is active but guardian/threshold/request are unconfigured
    assert!(client.is_owner_active(&owner));
    assert_eq!(client.get_guardians(&owner).len(), 0);
    assert_eq!(client.get_recovery_threshold(&owner), 0);
    assert!(client.get_recovery_request(&owner).is_none());
    assert_eq!(client.get_bound_credentials(&owner).len(), 0);
    assert!(client.get_zk_verifier().is_none());

    // Non-owner address remains completely inactive
    let non_owner = Address::generate(&env);
    assert!(!client.is_owner_active(&non_owner));
    assert_eq!(client.get_guardians(&non_owner).len(), 0);
    assert_eq!(client.get_recovery_threshold(&non_owner), 0);
}

// ── 3. Re-Initialization Guards & State Preservation ─────────────────────────

#[test]
fn test_double_reinitialization_exploits() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(IdentityContract, ());
    let client = IdentityContractClient::new(&env, &contract_id);
    let owner = Address::generate(&env);

    client.initialize(&owner);

    // Attempting to initialize the contract a second time
    let hacker = Address::generate(&env);
    let result = client.try_initialize(&hacker);

    assert_eq!(
        result,
        Err(Ok(RecoveryError::AlreadyInitialized)),
        "Double re-initialization exploits should revert"
    );
}

#[test]
fn test_failed_reinit_preserves_original_owner_state() {
    let (env, _contract_id, client, owner) = setup_initialized();

    // Add a guardian to original owner
    let g1 = Address::generate(&env);
    client.add_guardian(&owner, &g1);
    assert_eq!(client.get_guardians(&owner).len(), 1);

    // Attacker attempts re-initialization
    let attacker = Address::generate(&env);
    let reinit_result = client.try_initialize(&attacker);
    assert_eq!(reinit_result, Err(Ok(RecoveryError::AlreadyInitialized)));

    // Verify original owner state is completely preserved
    assert!(client.is_owner_active(&owner));
    assert_eq!(client.get_guardians(&owner).len(), 1);
    assert!(client.is_guardian(&owner, &g1));

    // Verify attacker gained zero privileges
    assert!(!client.is_owner_active(&attacker));
    let attacker_g = Address::generate(&env);
    assert_eq!(
        client.try_add_guardian(&attacker, &attacker_g),
        Err(Ok(RecoveryError::Unauthorized))
    );
}

// ── 4. Unauthorized Access on Uninitialized/Non-Owner Calls ──────────────────

#[test]
fn test_unauthorized_state_mutations_rejected_before_init() {
    let (env, _contract_id, client) = setup_uninit();

    let caller = Address::generate(&env);
    let target = Address::generate(&env);
    let cred_id = BytesN::from_array(&env, &[0xAAu8; 32]);

    // All owner-gated mutations must return Unauthorized
    assert_eq!(
        client.try_add_guardian(&caller, &target),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_remove_guardian(&caller, &target),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_set_recovery_threshold(&caller, &2),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_cancel_recovery(&caller),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_bind_credential(&caller, &cred_id),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_unbind_credential(&caller, &cred_id),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_set_zk_verifier(&caller, &target),
        Err(Ok(RecoveryError::Unauthorized))
    );
}

#[test]
fn test_uninitialized_recovery_operations_rejected() {
    let (env, _contract_id, client) = setup_uninit();

    let guardian = Address::generate(&env);
    let owner = Address::generate(&env);
    let new_addr = Address::generate(&env);

    // Attempting recovery actions on uninitialized accounts must fail with appropriate errors
    assert_eq!(
        client.try_initiate_recovery(&guardian, &owner, &new_addr),
        Err(Ok(RecoveryError::NotAGuardian))
    );
    assert_eq!(
        client.try_approve_recovery(&guardian, &owner),
        Err(Ok(RecoveryError::NotAGuardian))
    );
    assert_eq!(
        client.try_execute_recovery(&guardian, &owner),
        Err(Ok(RecoveryError::NoActiveRecovery))
    );
}

// ── 5. Multiple Contract Instances Isolation ─────────────────────────────────

#[test]
fn test_multiple_contract_instances_isolation() {
    let env = Env::default();
    env.mock_all_auths();

    let id_a = env.register(IdentityContract, ());
    let client_a = IdentityContractClient::new(&env, &id_a);

    let id_b = env.register(IdentityContract, ());
    let client_b = IdentityContractClient::new(&env, &id_b);

    let owner_a = Address::generate(&env);
    let owner_b = Address::generate(&env);

    // Initialize Contract A
    client_a.initialize(&owner_a);
    assert!(client_a.is_owner_active(&owner_a));

    // Contract B must remain uninitialized and isolated
    assert!(!client_b.is_owner_active(&owner_a));
    assert!(!client_b.is_owner_active(&owner_b));

    // Initialize Contract B with owner_b
    client_b.initialize(&owner_b);
    assert!(client_b.is_owner_active(&owner_b));
    assert!(!client_b.is_owner_active(&owner_a));
    assert!(!client_a.is_owner_active(&owner_b));

    // Re-initialization on either must be rejected
    assert_eq!(
        client_a.try_initialize(&owner_b),
        Err(Ok(RecoveryError::AlreadyInitialized))
    );
    assert_eq!(
        client_b.try_initialize(&owner_a),
        Err(Ok(RecoveryError::AlreadyInitialized))
    );
}

// ── 6. Two-Phase Commit Hooks with Initialization ────────────────────────────

#[test]
fn test_two_phase_commit_hooks_enforce_initialization() {
    let (env, _contract_id, client) = setup_uninit();
    let uninit_caller = Address::generate(&env);
    let guardian = Address::generate(&env);

    // 2PC prepare hooks fail before initialization
    assert_eq!(
        client.try_prepare_add_guardian(&uninit_caller, &guardian),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_prepare_remove_guardian(&uninit_caller, &guardian),
        Err(Ok(RecoveryError::Unauthorized))
    );
    assert_eq!(
        client.try_prepare_set_recovery_threshold(&uninit_caller, &2),
        Err(Ok(RecoveryError::Unauthorized))
    );
}

#[test]
fn test_two_phase_commit_works_after_initialization() {
    let (env, _contract_id, client, owner) = setup_initialized();
    let guardian = Address::generate(&env);

    // Prepare phase succeeds for initialized active owner
    assert!(client.try_prepare_add_guardian(&owner, &guardian).is_ok());

    // Commit phase successfully executes guardian addition
    assert!(client.try_commit_add_guardian(&owner, &guardian).is_ok());
    assert_eq!(client.get_guardians(&owner).len(), 1);
    assert!(client.is_guardian(&owner, &guardian));
}

// ── 7. Post-Initialization Operations Flow ───────────────────────────────────

#[test]
fn test_post_initialization_guardian_and_threshold_flow() {
    let (env, _contract_id, client, owner) = setup_initialized();

    let g1 = Address::generate(&env);
    let g2 = Address::generate(&env);
    let g3 = Address::generate(&env);

    client.add_guardian(&owner, &g1);
    client.add_guardian(&owner, &g2);
    client.add_guardian(&owner, &g3);

    assert_eq!(client.get_guardians(&owner).len(), 3);
    assert!(client.is_guardian(&owner, &g1));
    assert!(client.is_guardian(&owner, &g2));
    assert!(client.is_guardian(&owner, &g3));

    client.set_recovery_threshold(&owner, &2);
    assert_eq!(client.get_recovery_threshold(&owner), 2);
}

#[test]
fn test_post_initialization_set_zk_verifier_flow() {
    let (env, _contract_id, client, owner) = setup_initialized();
    let verifier_id = Address::generate(&env);

    // Owner can configure ZK verifier
    client.set_zk_verifier(&owner, &verifier_id);
    assert_eq!(client.get_zk_verifier(), Some(verifier_id));

    // Non-owner cannot overwrite ZK verifier
    let hacker = Address::generate(&env);
    let fake_verifier = Address::generate(&env);
    assert_eq!(
        client.try_set_zk_verifier(&hacker, &fake_verifier),
        Err(Ok(RecoveryError::Unauthorized))
    );
}

