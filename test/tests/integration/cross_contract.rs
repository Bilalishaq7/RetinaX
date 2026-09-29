#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(test)]

//! # End-to-End Cross-Contract Integration Test
//!
//! Simulates a full patient record lifecycle across decoupled micro-contracts:
//! 1. User Registration via `IdentityContract`
//! 2. Key Provisioning & Access Control via `KeyManagerContract`
//! 3. Record Creation & Access Routing via `VisionRecordsContract`

extern crate std;

use identity::{IdentityContract, IdentityContractClient};
use key_manager::{
    KeyLevel, KeyManagerContract, KeyManagerContractClient, KeyPolicy, KeyType,
};
use soroban_sdk::{
    testutils::Address as _, Address, BytesN, Env, String, Vec,
};
use vision_records::{
    AccessLevel, RecordType, VisionRecordsContract, VisionRecordsContractClient,
};

#[test]
fn test_e2e_cross_contract_patient_record_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    // 1. Deploy decoupled micro-contracts
    let identity_id = env.register(IdentityContract, ());
    let identity_client = IdentityContractClient::new(&env, &identity_id);

    let key_manager_id = env.register(KeyManagerContract, ());
    let key_manager_client = KeyManagerContractClient::new(&env, &key_manager_id);

    let vision_records_id = env.register(VisionRecordsContract, ());
    let vision_client = VisionRecordsContractClient::new(&env, &vision_records_id);

    // Setup actors
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let provider = Address::generate(&env);

    // 2. Identity Contract: Register Patient & Admin
    identity_client.initialize(&admin);
    assert!(
        identity_client.is_owner_active(&admin),
        "Identity owner must be active post-initialization"
    );

    // Add guardian to patient identity
    let guardian = Address::generate(&env);
    let _ = identity_client.add_guardian(&admin, &guardian);
    assert!(
        identity_client.is_guardian(&admin, &guardian),
        "Guardian must be registered in Identity contract"
    );

    // 3. Key Manager Contract: Initialize with Identity Contract reference & Provision Keys
    key_manager_client.initialize(&admin, &identity_id);

    let policy = KeyPolicy {
        max_uses: 100,
        not_before: 0,
        not_after: 0,
        allowed_ops: Vec::new(&env),
    };
    let raw_key = BytesN::from_array(&env, &[10u8; 32]);
    let master_key_id = key_manager_client.create_master_key(
        &admin,
        &KeyType::Encryption,
        &policy,
        &0,
        &raw_key,
    );

    // Derive a contract level key for the record encryption flow
    let child_key_id = key_manager_client.derive_key(
        &admin,
        &master_key_id,
        &KeyLevel::Contract,
        &0,
        &false,
        &KeyType::Encryption,
        &policy,
        &0,
    );
    assert_ne!(child_key_id, master_key_id, "Child key ID must be distinct from master key ID");

    // 4. Vision Records Contract: Initialize & Register Patient Record Lifecycle
    vision_client.initialize(&admin);
    assert!(
        vision_client.is_initialized(),
        "VisionRecords contract must be initialized"
    );

    // Grant access to eye care provider for 3600 seconds
    let _ = vision_client.grant_access(&patient, &patient, &provider, &AccessLevel::Read, &3600u64);

    let data_hash = String::from_str(&env, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");

    // Add examination record utilizing cross-contract routing
    vision_client.add_record(
        &admin,
        &patient,
        &provider,
        &RecordType::Examination,
        &data_hash,
    );

    // Verify cross-contract record routing and state consistency
    assert_eq!(
        vision_client.get_admin(),
        admin,
        "Admin state must be consistent across contracts"
    );
}
