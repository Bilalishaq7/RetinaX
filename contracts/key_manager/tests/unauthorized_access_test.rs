#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(test)]

extern crate std;

use key_manager::{
    ContractError, KeyLevel, KeyManagerContract, KeyManagerContractClient, KeyPolicy, KeyType,
};
use soroban_sdk::{
    symbol_short, testutils::Address as _, Address, BytesN, Env, Vec,
};

/// Helper: Setup initialized KeyManager contract instance
fn setup_key_manager() -> (Env, KeyManagerContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(KeyManagerContract, ());
    let client = KeyManagerContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let identity_contract = Address::generate(&env);
    client.initialize(&admin, &identity_contract);

    (env, client, admin, identity_contract)
}

#[test]
fn test_key_manager_unauthorized_access_attempts() {
    let (env, client, admin, _identity_contract) = setup_key_manager();
    let unauthorized_user = Address::generate(&env);
    let malicious_identity = Address::generate(&env);

    // 1. Unauthorized attempt to re-initialize contract
    let err_reinit = client.try_initialize(&unauthorized_user, &malicious_identity);
    assert_eq!(
        err_reinit,
        Err(Ok(ContractError::AlreadyInitialized)),
        "Re-initialization must fail with AlreadyInitialized"
    );

    // 2. Unauthorized attempt to update identity contract address
    let err_set_identity = client.try_set_identity_contract(&unauthorized_user, &malicious_identity);
    assert_eq!(
        err_set_identity,
        Err(Ok(ContractError::Unauthorized)),
        "Updating identity contract by non-admin must fail with Unauthorized"
    );

    // 3. Unauthorized attempt to create master key
    let policy = KeyPolicy {
        max_uses: 10,
        not_before: 0,
        not_after: 0,
        allowed_ops: Vec::new(&env),
    };
    let key_bytes = BytesN::from_array(&env, &[7u8; 32]);
    let err_create_master = client.try_create_master_key(
        &unauthorized_user,
        &KeyType::Signing,
        &policy,
        &0,
        &key_bytes,
    );
    assert_eq!(
        err_create_master,
        Err(Ok(ContractError::Unauthorized)),
        "Creating master key by non-admin must fail with Unauthorized"
    );

    // Create a legitimate master key with admin for testing key-level authorization
    let valid_key_id = client.create_master_key(&admin, &KeyType::Signing, &policy, &0, &key_bytes);

    // 4. Unauthorized attempt to derive key from valid master key
    let err_derive = client.try_derive_key(
        &unauthorized_user,
        &valid_key_id,
        &KeyLevel::Contract,
        &0,
        &false,
        &KeyType::Signing,
        &policy,
        &0,
    );
    assert_eq!(
        err_derive,
        Err(Ok(ContractError::Unauthorized)),
        "Deriving key by non-owner must fail with Unauthorized"
    );

    // 5. Unauthorized attempt to use key
    let err_use = client.try_use_key(&unauthorized_user, &valid_key_id, &symbol_short!("SIGN"));
    assert_eq!(
        err_use,
        Err(Ok(ContractError::Unauthorized)),
        "Using key by non-owner must fail with Unauthorized"
    );

    // 6. Unauthorized attempt to rotate key
    let err_rotate = client.try_rotate_key(&unauthorized_user, &valid_key_id);
    assert_eq!(
        err_rotate,
        Err(Ok(ContractError::Unauthorized)),
        "Rotating key by non-owner must fail with Unauthorized"
    );

    // 7. Unauthorized attempt to revoke key
    let err_revoke = client.try_revoke_key(&unauthorized_user, &valid_key_id);
    assert_eq!(
        err_revoke,
        Err(Ok(ContractError::Unauthorized)),
        "Revoking key by non-owner must fail with Unauthorized"
    );
}
