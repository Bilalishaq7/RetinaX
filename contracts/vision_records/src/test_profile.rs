#![cfg(test)]

use super::*;
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

// -----------------------------------------------------------------------------
// Issue #51: Happy Path Unit Tests
// -----------------------------------------------------------------------------

#[test]
fn test_create_profile_success() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    // Patient creates their own profile
    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let profile = client.get_profile(&patient);
    assert_eq!(profile.patient, patient);
    assert_eq!(profile.date_of_birth_hash, dob_hash);
    assert_eq!(profile.gender_hash, gender_hash);
    assert_eq!(profile.blood_type_hash, blood_type_hash);
    assert!(profile.is_active);
    assert!(profile.emergency_contact.is_none());
    assert!(profile.insurance_info.is_none());
    assert_eq!(profile.medical_history_refs.len(), 0);
}

#[test]
fn test_create_profile_by_authorized_user() {
    let (env, client, admin) = setup_test();

    let patient = Address::generate(&env);
    let staff = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    // Register staff with ManageUsers permission
    client.register_user(
        &admin,
        &staff,
        &Role::Staff,
        &String::from_str(&env, "Staff"),
    );

    // Staff creates profile for patient
    client.create_profile(&staff, &patient, &dob_hash, &gender_hash, &blood_type_hash);

    let profile = client.get_profile(&patient);
    assert_eq!(profile.patient, patient);
}

#[test]
fn test_update_demographics() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let new_dob_hash = String::from_str(&env, "hash_dob_new");
    let new_gender_hash = String::from_str(&env, "hash_gender_new");
    let new_blood_type_hash = String::from_str(&env, "hash_blood_new");

    let old_timestamp = client.get_profile(&patient).updated_at;

    client.update_demographics(
        &patient,
        &patient,
        &new_dob_hash,
        &new_gender_hash,
        &new_blood_type_hash,
    );

    let updated_profile = client.get_profile(&patient);
    assert_eq!(updated_profile.date_of_birth_hash, new_dob_hash);
    assert_eq!(updated_profile.gender_hash, new_gender_hash);
    assert_eq!(updated_profile.blood_type_hash, new_blood_type_hash);
    assert!(updated_profile.updated_at >= old_timestamp);
}

#[test]
fn test_update_emergency_contact() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let contact = EmergencyContact {
        name: String::from_str(&env, "Jane Doe"),
        relationship: String::from_str(&env, "Spouse"),
        phone: String::from_str(&env, "+1234567890"),
        email: String::from_str(&env, "jane@example.com"),
    };

    client.update_emergency_contact(&patient, &patient, &Some(contact.clone()));

    let profile = client.get_profile(&patient);
    assert!(profile.emergency_contact.is_some());
    let stored_contact = profile.emergency_contact.unwrap();
    assert_eq!(stored_contact, contact);

    // Update with None to clear contact
    client.update_emergency_contact(&patient, &patient, &None);
    let profile = client.get_profile(&patient);
    assert!(profile.emergency_contact.is_none());
}

#[test]
fn test_update_insurance_info() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "provider_hash_123"),
        policy_id_hash: String::from_str(&env, "policy_hash_456"),
        group_id_hash: String::from_str(&env, "group_hash_789"),
        verified_at: env.ledger().timestamp(),
    };

    client.update_insurance(&patient, &patient, &Some(insurance.clone()));

    let profile = client.get_profile(&patient);
    assert!(profile.insurance_info.is_some());
    let stored_insurance = profile.insurance_info.unwrap();
    assert_eq!(stored_insurance, insurance);

    // Update with None to clear insurance
    client.update_insurance(&patient, &patient, &None);
    let profile = client.get_profile(&patient);
    assert!(profile.insurance_info.is_none());
}

#[test]
fn test_add_medical_history_reference() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let ref1 = String::from_str(&env, "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco");
    let ref2 = String::from_str(&env, "QmZtmD2qt8fJpq3CLDHytTXZncxcOECFarjwegK80MDvNN");

    client.add_medical_history_reference(&patient, &patient, &ref1);
    client.add_medical_history_reference(&patient, &patient, &ref2);

    let profile = client.get_profile(&patient);
    assert_eq!(profile.medical_history_refs.len(), 2);
    assert_eq!(profile.medical_history_refs.get(0).unwrap(), ref1);
    assert_eq!(profile.medical_history_refs.get(1).unwrap(), ref2);
}

#[test]
fn test_profile_exists() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let other_patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    assert!(!client.profile_exists(&patient));

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    assert!(client.profile_exists(&patient));
    assert!(!client.profile_exists(&other_patient));
}

// -----------------------------------------------------------------------------
// Issue #52: Failure / Revert Unit Tests
// -----------------------------------------------------------------------------

#[test]
fn test_create_profile_duplicate_rejection() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    // Duplicate creation must fail with UserAlreadyExists
    let result = client.try_create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_profile_unauthorized_user() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    let result = client.try_create_profile(
        &unauthorized,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );
    assert!(result.is_err());
}

#[test]
fn test_update_demographics_unauthorized() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let other_user = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let new_dob_hash = String::from_str(&env, "hash_dob_new");
    let result = client.try_update_demographics(
        &other_user,
        &patient,
        &new_dob_hash,
        &gender_hash,
        &blood_type_hash,
    );
    assert!(result.is_err());
}

#[test]
fn test_update_emergency_contact_unauthorized() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let other_user = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let contact = EmergencyContact {
        name: String::from_str(&env, "Jane Doe"),
        relationship: String::from_str(&env, "Spouse"),
        phone: String::from_str(&env, "+1234567890"),
        email: String::from_str(&env, "jane@example.com"),
    };

    let result = client.try_update_emergency_contact(&other_user, &patient, &Some(contact));
    assert!(result.is_err());
}

#[test]
fn test_update_insurance_unauthorized() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let other_user = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "provider_hash_123"),
        policy_id_hash: String::from_str(&env, "policy_hash_456"),
        group_id_hash: String::from_str(&env, "group_hash_789"),
        verified_at: env.ledger().timestamp(),
    };

    let result = client.try_update_insurance(&other_user, &patient, &Some(insurance));
    assert!(result.is_err());
}

#[test]
fn test_update_insurance_rejects_oversized_group_hash() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    client.create_profile(
        &patient,
        &patient,
        &String::from_str(&env, "hash_dob_123"),
        &String::from_str(&env, "hash_gender_456"),
        &String::from_str(&env, "hash_blood_789"),
    );

    let oversized_group_hash = String::from_str(
        &env,
        "group_hash_that_is_longer_than_the_allowed_128_character_limit_for_patient_profile_insurance_payloads_and_must_be_rejected_at_the_contract_boundary",
    );
    let insurance = InsuranceInfo {
        provider_hash: String::from_str(&env, "provider_hash_123"),
        policy_id_hash: String::from_str(&env, "policy_hash_456"),
        group_id_hash: oversized_group_hash,
        verified_at: env.ledger().timestamp(),
    };

    let result = client.try_update_insurance(&patient, &patient, &Some(insurance));
    assert!(result.is_err());

    let profile = client.get_profile(&patient);
    assert!(profile.insurance_info.is_none());
}

#[test]
fn test_add_medical_history_reference_unauthorized() {
    let (env, client, _admin) = setup_test();

    let patient = Address::generate(&env);
    let other_user = Address::generate(&env);
    let dob_hash = String::from_str(&env, "hash_dob_123");
    let gender_hash = String::from_str(&env, "hash_gender_456");
    let blood_type_hash = String::from_str(&env, "hash_blood_789");

    client.create_profile(
        &patient,
        &patient,
        &dob_hash,
        &gender_hash,
        &blood_type_hash,
    );

    let ref1 = String::from_str(&env, "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco");
    let result = client.try_add_medical_history_reference(&other_user, &patient, &ref1);
    assert!(result.is_err());
}

#[test]
fn test_get_profile_not_found() {
    let (env, client, _admin) = setup_test();

    let nonexistent_patient = Address::generate(&env);
    let result = client.try_get_profile(&nonexistent_patient);
    assert!(result.is_err());
}

#[test]
fn test_profile_storage_collision_prevention() {
    let (env, client, _admin) = setup_test();

    let patient1 = Address::generate(&env);
    let patient2 = Address::generate(&env);

    let dob1 = String::from_str(&env, "dob_1");
    let gender1 = String::from_str(&env, "gender_1");
    let blood1 = String::from_str(&env, "blood_1");

    let dob2 = String::from_str(&env, "dob_2");
    let gender2 = String::from_str(&env, "gender_2");
    let blood2 = String::from_str(&env, "blood_2");

    client.create_profile(&patient1, &patient1, &dob1, &gender1, &blood1);
    client.create_profile(&patient2, &patient2, &dob2, &gender2, &blood2);

    let prof1 = client.get_profile(&patient1);
    let prof2 = client.get_profile(&patient2);

    assert_eq!(prof1.patient, patient1);
    assert_eq!(prof1.date_of_birth_hash, dob1);

    assert_eq!(prof2.patient, patient2);
    assert_eq!(prof2.date_of_birth_hash, dob2);
}
