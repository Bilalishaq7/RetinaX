#![cfg(test)]
#![allow(clippy::unwrap_used)]

use key_manager::{
    ContractError, KeyLevel, KeyManagerContract, KeyManagerContractClient, KeyPolicy, KeyType,
};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Symbol, Vec};

fn setup_env() -> (Env, KeyManagerContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(KeyManagerContract, ());
    let client = KeyManagerContractClient::new(&env, &contract_id);
    (env, client)
}

#[test]
fn test_successful_initialization() {
    let (env, client) = setup_env();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    // Should succeed silently
    client.initialize(&admin, &identity);

    // We can verify it worked by calling something admin-gated
    let new_identity = Address::generate(&env);
    assert!(client
        .try_set_identity_contract(&admin, &new_identity)
        .is_ok());
}

#[test]
fn test_double_initialization_is_ignored() {
    let (env, client) = setup_env();
    let admin_1 = Address::generate(&env);
    let identity_1 = Address::generate(&env);

    let admin_2 = Address::generate(&env);
    let identity_2 = Address::generate(&env);

    client.initialize(&admin_1, &identity_1);

    // Call a second time with different parameters - must return AlreadyInitialized error
    let res_init2 = client.try_initialize(&admin_2, &identity_2);
    assert_eq!(
        res_init2.unwrap_err().unwrap(),
        ContractError::AlreadyInitialized
    );

    // Verify admin 1 is still the admin
    let dummy = Address::generate(&env);
    let res = client.try_set_identity_contract(&admin_2, &dummy);

    // admin_2 should get Unauthorized, proving admin_1 is still the designated admin
    assert_eq!(res.unwrap_err().unwrap(), ContractError::Unauthorized);

    // admin_1 should succeed
    assert!(client.try_set_identity_contract(&admin_1, &dummy).is_ok());
}

#[test]
fn test_double_initialization_with_same_admin_rejected() {
    let (env, client) = setup_env();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    client.initialize(&admin, &identity);

    // Re-initialization attempt with the same admin must return AlreadyInitialized error
    let res = client.try_initialize(&admin, &identity);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::AlreadyInitialized);
}

#[test]
fn test_set_identity_contract_before_init_returns_not_initialized() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let identity = Address::generate(&env);

    let res = client.try_set_identity_contract(&caller, &identity);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::NotInitialized);
}

#[test]
fn test_create_master_key_before_init_returns_not_initialized() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let policy = KeyPolicy {
        max_uses: 10,
        not_before: 0,
        not_after: 0,
        allowed_ops: Vec::new(&env),
    };
    let key_bytes = BytesN::from_array(&env, &[1; 32]);

    let res =
        client.try_create_master_key(&caller, &KeyType::Encryption, &policy, &86400, &key_bytes);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::NotInitialized);
}

#[test]
fn test_derive_key_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let parent_id = BytesN::from_array(&env, &[1; 32]);
    let policy = KeyPolicy {
        max_uses: 10,
        not_before: 0,
        not_after: 0,
        allowed_ops: Vec::new(&env),
    };

    let res = client.try_derive_key(
        &caller,
        &parent_id,
        &KeyLevel::Contract,
        &1,
        &true,
        &KeyType::Signing,
        &policy,
        &86400,
    );
    // require_owner_or_admin checks ADMIN, but it happens after load_key_record
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_use_key_before_init_returns_not_initialized() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let key_id = BytesN::from_array(&env, &[1; 32]);
    let op = Symbol::new(&env, "sign");

    let res = client.try_use_key(&caller, &key_id, &op);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_rotate_key_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_rotate_key(&caller, &key_id);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_revoke_key_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_revoke_key(&caller, &key_id);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_initiate_recovery_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let guardian = Address::generate(&env);
    let key_id = BytesN::from_array(&env, &[1; 32]);
    let new_key = BytesN::from_array(&env, &[2; 32]);

    // load_key_record happens before load_guardians
    let res = client.try_initiate_recovery(&guardian, &key_id, &new_key);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_approve_recovery_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let guardian = Address::generate(&env);
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_approve_recovery(&guardian, &key_id);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_execute_recovery_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let caller = Address::generate(&env);
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_execute_recovery(&caller, &key_id);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_attest_key_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_attest_key(&key_id);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_derive_record_key_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_derive_record_key(&key_id, &1u64);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_derive_record_key_with_version_before_init_returns_not_found() {
    let (env, client) = setup_env();
    let key_id = BytesN::from_array(&env, &[1; 32]);

    let res = client.try_derive_record_key_with_version(&key_id, &1u64, &1u32);
    assert_eq!(res.unwrap_err().unwrap(), ContractError::KeyNotFound);
}

#[test]
fn test_read_only_endpoints_return_none_on_fresh_contract() {
    let (env, client) = setup_env();
    let key_id = BytesN::from_array(&env, &[1; 32]);

    assert!(client.get_key_record(&key_id).is_none());
    assert!(client.get_key_version(&key_id, &1).is_none());
    assert!(client.get_audit_entry(&1).is_none());
    assert!(client.get_audit_tail().is_none());
}

#[test]
fn test_initialization_enables_admin_operations_and_blocks_unauthorized() {
    let (env, client) = setup_env();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    client.initialize(&admin, &identity);

    let policy = KeyPolicy {
        max_uses: 5,
        not_before: 0,
        not_after: 0,
        allowed_ops: Vec::new(&env),
    };
    let key_bytes = BytesN::from_array(&env, &[42u8; 32]);

    // Unauthorized user cannot create master keys
    let fail_res = client.try_create_master_key(
        &unauthorized_user,
        &KeyType::Signing,
        &policy,
        &86400,
        &key_bytes,
    );
    assert_eq!(fail_res.unwrap_err().unwrap(), ContractError::Unauthorized);

    // Initialized admin successfully creates master key
    let ok_res =
        client.try_create_master_key(&admin, &KeyType::Signing, &policy, &86400, &key_bytes);
    assert!(ok_res.is_ok());
    let key_id = ok_res.unwrap().unwrap();
    assert!(client.get_key_record(&key_id).is_some());
}

#[test]
fn test_repeated_initialization_attempts_preserve_state() {
    let (env, client) = setup_env();
    let original_admin = Address::generate(&env);
    let original_identity = Address::generate(&env);

    client.initialize(&original_admin, &original_identity);

    // Repeated attempts to re-initialize fail with AlreadyInitialized
    for _ in 0..5 {
        let attacker = Address::generate(&env);
        let fake_identity = Address::generate(&env);
        let res = client.try_initialize(&attacker, &fake_identity);
        assert_eq!(res.unwrap_err().unwrap(), ContractError::AlreadyInitialized);
    }

    // Original admin remains fully empowered
    let new_identity = Address::generate(&env);
    assert!(client
        .try_set_identity_contract(&original_admin, &new_identity)
        .is_ok());
}
