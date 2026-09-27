//! Contract-boundary happy-path unit tests for insurance endpoints.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use super::{
    InsuranceInfo, OptionalInsuranceInfo, Role, VisionRecordsContract, VisionRecordsContractClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String};

fn setup_test() -> (Env, VisionRecordsContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(VisionRecordsContract, ());
    let client = VisionRecordsContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    (env, client, admin)
}

fn create_patient(env: &Env, client: &VisionRecordsContractClient) -> Address {
    let patient = Address::generate(env);
    client.create_profile(
        &patient,
        &patient,
        &String::from_str(env, "hash_dob_1990_01_01"),
        &String::from_str(env, "hash_gender_female"),
        &String::from_str(env, "hash_blood_o_positive"),
    );
    patient
}

#[test]
fn test_update_insurance_happy_path() {
    let (env, client, _admin) = setup_test();
    let patient = create_patient(&env, &client);

    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "bluecross_blueshield_prov_hash"),
        policy_id_hash: String::from_str(&env, "policy_id_hash_987654321"),
        group_id_hash: String::from_str(&env, "group_id_hash_12345"),
        verified_at: env.ledger().timestamp(),
    };

    client.update_insurance(&patient, &patient, &Some(insurance.clone()));

    // Verify retrieval via get_insurance endpoint
    let retrieved = client.get_insurance(&patient, &patient);
    assert!(retrieved.is_some());
    let unwrapped = retrieved.unwrap();
    assert_eq!(unwrapped.provider_hash, insurance.provider_hash);
    assert_eq!(unwrapped.policy_id_hash, insurance.policy_id_hash);
    assert_eq!(unwrapped.group_id_hash, insurance.group_id_hash);
    assert_eq!(unwrapped.verified_at, insurance.verified_at);

    // Verify profile reflects insurance info
    let profile = client.get_profile(&patient);
    assert!(profile.insurance_info.is_some());
    assert_eq!(profile.insurance_info.unwrap(), insurance);
}

#[test]
fn test_update_insurance_empty_group_id() {
    let (env, client, _admin) = setup_test();
    let patient = create_patient(&env, &client);

    // Group ID can be empty string for individual plans
    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "aetna_vision_provider_hash"),
        policy_id_hash: String::from_str(&env, "policy_id_hash_indiv_999"),
        group_id_hash: String::from_str(&env, ""),
        verified_at: env.ledger().timestamp(),
    };

    client.update_insurance(&patient, &patient, &Some(insurance.clone()));

    let retrieved = client.get_insurance(&patient, &patient);
    assert!(retrieved.is_some());
    let unwrapped = retrieved.unwrap();
    assert_eq!(unwrapped.provider_hash, insurance.provider_hash);
    assert_eq!(unwrapped.policy_id_hash, insurance.policy_id_hash);
    assert_eq!(unwrapped.group_id_hash, String::from_str(&env, ""));
}

#[test]
fn test_update_insurance_clear_with_none() {
    let (env, client, _admin) = setup_test();
    let patient = create_patient(&env, &client);

    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "vsp_vision_provider_hash"),
        policy_id_hash: String::from_str(&env, "policy_id_vsp_12345"),
        group_id_hash: String::from_str(&env, "group_vsp_corp"),
        verified_at: env.ledger().timestamp(),
    };

    client.update_insurance(&patient, &patient, &Some(insurance));
    assert!(client.get_insurance(&patient, &patient).is_some());

    // Clear insurance with None
    client.update_insurance(&patient, &patient, &None);

    let retrieved = client.get_insurance(&patient, &patient);
    assert_eq!(retrieved, OptionalInsuranceInfo::None);

    let profile = client.get_profile(&patient);
    assert!(profile.insurance_info.is_none());
}

#[test]
fn test_update_insurance_multiple_revisions() {
    let (env, client, _admin) = setup_test();
    let patient = create_patient(&env, &client);

    let initial_insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "eyemed_provider_hash"),
        policy_id_hash: String::from_str(&env, "policy_eyemed_001"),
        group_id_hash: String::from_str(&env, "group_eyemed_corp"),
        verified_at: 1000,
    };
    client.update_insurance(&patient, &patient, &Some(initial_insurance));

    let updated_insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "cigna_health_provider_hash"),
        policy_id_hash: String::from_str(&env, "policy_cigna_renewed_002"),
        group_id_hash: String::from_str(&env, "group_cigna_new"),
        verified_at: 2000,
    };
    client.update_insurance(&patient, &patient, &Some(updated_insurance.clone()));

    let retrieved = client.get_insurance(&patient, &patient);
    assert!(retrieved.is_some());
    let unwrapped = retrieved.unwrap();
    assert_eq!(unwrapped.provider_hash, updated_insurance.provider_hash);
    assert_eq!(unwrapped.policy_id_hash, updated_insurance.policy_id_hash);
    assert_eq!(unwrapped.group_id_hash, updated_insurance.group_id_hash);
    assert_eq!(unwrapped.verified_at, 2000);
}

#[test]
fn test_get_insurance_by_authorized_provider() {
    let (env, client, admin) = setup_test();
    let patient = create_patient(&env, &client);
    let doctor = Address::generate(&env);

    client.register_user(
        &admin,
        &doctor,
        &Role::Ophthalmologist,
        &String::from_str(&env, "Dr. Alice"),
    );

    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "united_healthcare_hash"),
        policy_id_hash: String::from_str(&env, "uhc_policy_55555"),
        group_id_hash: String::from_str(&env, "uhc_group_777"),
        verified_at: env.ledger().timestamp(),
    };
    client.update_insurance(&patient, &patient, &Some(insurance.clone()));

    // Authorized medical provider can query insurance
    let retrieved = client.get_insurance(&doctor, &patient);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), insurance);
}

#[test]
fn test_initial_insurance_state_is_none() {
    let (env, client, _admin) = setup_test();
    let patient = create_patient(&env, &client);

    // Initial insurance on profile creation is None
    let retrieved = client.get_insurance(&patient, &patient);
    assert_eq!(retrieved, OptionalInsuranceInfo::None);
}
