#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(test)]

extern crate std;

use identity::{
    recovery::RecoveryError,
    IdentityContract, IdentityContractClient,
};
use soroban_sdk::{
    testutils::Address as _,
    Address, Env,
};

/// Helper: Instantiate uninitialized Identity Contract
fn setup_uninit() -> (Env, Address, IdentityContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(IdentityContract, ());
    let client = IdentityContractClient::new(&env, &contract_id);

    (env, contract_id, client)
}

#[test]
fn test_identity_duplicate_registration_fails() {
    let (env, _contract_id, client) = setup_uninit();
    let initial_owner = Address::generate(&env);
    let duplicate_registrant = Address::generate(&env);

    // 1. Initial registration / initialization succeeds
    let init_res = client.try_initialize(&initial_owner);
    assert!(init_res.is_ok(), "Initial registration should succeed");
    assert!(client.is_owner_active(&initial_owner));

    // 2. Duplicate registration attempt with a different address fails
    let err_different_owner = client.try_initialize(&duplicate_registrant);
    assert_eq!(
        err_different_owner,
        Err(Ok(RecoveryError::AlreadyInitialized)),
        "Duplicate registration attempt with a different address must fail with AlreadyInitialized"
    );

    // 3. Duplicate registration attempt with the original owner address fails
    let err_same_owner = client.try_initialize(&initial_owner);
    assert_eq!(
        err_same_owner,
        Err(Ok(RecoveryError::AlreadyInitialized)),
        "Duplicate registration attempt with the same owner address must fail with AlreadyInitialized"
    );

    // 4. Verify contract ownership and state remain unchanged
    assert!(
        client.is_owner_active(&initial_owner),
        "Original owner must remain active after failed duplicate registrations"
    );
    assert!(
        !client.is_owner_active(&duplicate_registrant),
        "Duplicate registrant must not become active"
    );
}
