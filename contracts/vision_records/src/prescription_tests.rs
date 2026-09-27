//! Happy-path unit tests for the prescription endpoints (#41).
//!
//! The contract exposes a two-phase commit flow for prescriptions
//! (`prepare_add_prescription` → `commit_add_prescription`, with
//! `rollback_add_prescription` as the compensating action). These tests
//! exercise the success paths of that flow.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use soroban_sdk::testutils::Address as _;

fn setup() -> (Env, VisionRecordsContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(VisionRecordsContract, ());
    let client = VisionRecordsContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    (env, client, admin)
}

fn register_user(
    env: &Env,
    client: &VisionRecordsContractClient,
    admin: &Address,
    role: Role,
    name: &str,
) -> Address {
    let user = Address::generate(env);
    client.register_user(admin, &user, &role, &String::from_str(env, name));
    user
}

fn refraction_data(env: &Env, sphere: &str) -> PrescriptionData {
    PrescriptionData {
        sphere: String::from_str(env, sphere),
        cylinder: String::from_str(env, "-1.25"),
        axis: String::from_str(env, "180"),
        add: String::from_str(env, "0.00"),
        pd: String::from_str(env, "62"),
    }
}

#[test]
fn prepare_add_prescription_reserves_ids_and_persists_nothing() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id =
        client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.50"));
    assert_eq!(rx_id, 1);

    // The counter only advances on commit, so an uncommitted prepare does not
    // burn an ID: nothing is committed yet.
    assert_eq!(client.get_prescription_count(), 0);
}

#[test]
fn sequential_commits_get_sequential_ids() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx1 = client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.50"));
    client.commit_add_prescription(&rx1);

    let rx2 = client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.75"));
    client.commit_add_prescription(&rx2);

    assert_eq!(rx1, 1);
    assert_eq!(rx2, 2);
    assert_eq!(client.get_prescription_count(), 2);
}

#[test]
fn commit_add_prescription_persists_the_prescription() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id =
        client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.50"));
    client.commit_add_prescription(&rx_id);

    let stored = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_id).expect("prescription should exist")
    });

    assert_eq!(stored.id, rx_id);
    assert_eq!(stored.patient, patient);
    assert_eq!(stored.provider, provider);
    assert_eq!(stored.lens_type, LensType::Glasses);
    assert_eq!(stored.left_eye.sphere, String::from_str(&env, "-2.50"));
    assert_eq!(stored.right_eye.sphere, String::from_str(&env, "-2.50"));
    assert_eq!(stored.contact_data, OptionalContactLensData::None);
    assert!(!stored.verified);
    // Standard one-year validity applied.
    assert_eq!(
        stored.expires_at - stored.issued_at,
        prescription::STANDARD_EXPIRY_SECONDS
    );

    // The RX counter advanced exactly once.
    assert_eq!(client.get_prescription_count(), 1);
}

#[test]
fn committed_prescription_is_retrievable_and_tracked_in_history() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id =
        client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-3.00"));
    client.commit_add_prescription(&rx_id);

    let history = env.as_contract(&client.address, || {
        prescription::get_patient_history(&env, patient.clone())
    });
    assert_eq!(history.len(), 1);
    assert_eq!(history.get(0).unwrap(), rx_id);
}

#[test]
fn rollback_add_prescription_discards_the_prepared_state() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id =
        client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.50"));
    client.rollback_add_prescription(&rx_id);

    // No prescription was stored and the counter never advanced.
    assert_eq!(client.get_prescription_count(), 0);

    // The ID can be re-prepared and committed after a rollback.
    let rx_id2 =
        client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.50"));
    assert_eq!(rx_id2, rx_id);
    client.commit_add_prescription(&rx_id2);
    assert_eq!(client.get_prescription_count(), 1);
}

#[test]
fn rollback_after_commit_is_a_harmless_no_op() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id =
        client.prepare_add_prescription(&patient, &provider, &refraction_data(&env, "-2.50"));
    client.commit_add_prescription(&rx_id);

    // Rollback after commit is a harmless no-op (prep data already removed).
    client.rollback_add_prescription(&rx_id);

    // The committed prescription is still intact.
    let stored = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_id).expect("prescription should exist")
    });
    assert_eq!(stored.id, rx_id);
    assert_eq!(client.get_prescription_count(), 1);
}

#[test]
fn multiple_prescriptions_are_independently_stored() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient_a = Address::generate(&env);
    let patient_b = Address::generate(&env);

    let rx_a =
        client.prepare_add_prescription(&patient_a, &provider, &refraction_data(&env, "-1.00"));
    client.commit_add_prescription(&rx_a);

    let rx_b =
        client.prepare_add_prescription(&patient_b, &provider, &refraction_data(&env, "-2.00"));
    client.commit_add_prescription(&rx_b);

    assert_eq!(client.get_prescription_count(), 2);

    let stored_a = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_a).expect("prescription A should exist")
    });
    let stored_b = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_b).expect("prescription B should exist")
    });
    assert_eq!(stored_a.patient, patient_a);
    assert_eq!(stored_b.patient, patient_b);
    assert_ne!(stored_a.left_eye.sphere, stored_b.left_eye.sphere);

    // Each patient's history only contains their own prescription.
    let history_a = env.as_contract(&client.address, || {
        prescription::get_patient_history(&env, patient_a.clone())
    });
    let history_b = env.as_contract(&client.address, || {
        prescription::get_patient_history(&env, patient_b.clone())
    });
    assert_eq!(history_a.len(), 1);
    assert_eq!(history_a.get(0).unwrap(), rx_a);
    assert_eq!(history_b.len(), 1);
    assert_eq!(history_b.get(0).unwrap(), rx_b);
}
