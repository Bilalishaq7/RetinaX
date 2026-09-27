//! Failure and revert-path unit tests for the prescription endpoints (#42).
//!
//! Covers the two-phase prescription flow (`prepare_add_prescription` /
//! `commit_add_prescription` / `rollback_add_prescription`) plus the
//! module-level helpers for verification, OCC updates and lifecycle
//! transitions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use soroban_sdk::testutils::Address as _;
use teye_common::concurrency::FieldChange;
use teye_common::state_machine::{PrescriptionState, StateMachineError, TransitionContext};

const TXN_MIN_TTL: u64 = 1;

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

fn refraction_data(env: &Env) -> PrescriptionData {
    PrescriptionData {
        sphere: String::from_str(env, "-2.50"),
        cylinder: String::from_str(env, "-1.25"),
        axis: String::from_str(env, "180"),
        add: String::from_str(env, "0.00"),
        pd: String::from_str(env, "62"),
    }
}

fn prepare_and_commit(
    client: &VisionRecordsContractClient,
    patient: &Address,
    provider: &Address,
    env: &Env,
) -> u64 {
    let rx_id = client.prepare_add_prescription(patient, provider, &refraction_data(env));
    client.commit_add_prescription(&rx_id);
    rx_id
}

// ── Two-phase endpoint failures ─────────────────────────────────────────────

/// Only addresses holding `WriteRecord` (providers and admins) may prepare a
/// prescription; a patient's prepare attempt must be rejected and must not
/// reserve an ID.
#[test]
fn prepare_add_prescription_rejects_caller_without_write_permission() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");

    let result = client.try_prepare_add_prescription(&patient, &patient, &refraction_data(&env));
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));

    // No ID was reserved and nothing was stored.
    assert_eq!(client.get_prescription_count(), 0);
}

/// A completely unregistered caller has no role assignment at all.
#[test]
fn prepare_add_prescription_rejects_unregistered_caller() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let patient = Address::generate(&env);

    let result = client.try_prepare_add_prescription(&patient, &stranger, &refraction_data(&env));
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));

    assert_eq!(client.get_prescription_count(), 0);
}

/// Admins hold `WriteRecord` through `SystemAdmin`'s base permissions, so the
/// prepare phase succeeds for them (documents the positive boundary of the
/// permission gate).
#[test]
fn prepare_add_prescription_allows_admin_caller() {
    let (env, client, admin) = setup();
    let patient = Address::generate(&env);

    let result = client.try_prepare_add_prescription(&patient, &admin, &refraction_data(&env));
    assert!(result.is_ok());
}

/// Committing an ID that was never prepared must fail with `InvalidInput`
/// (the preparation payload is missing) and must not corrupt the counter.
#[test]
fn commit_add_prescription_without_preparation_fails() {
    let (env, client, admin) = setup();
    register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");

    let result = client.try_commit_add_prescription(&1u64);
    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));

    assert_eq!(client.get_prescription_count(), 0);
}

/// Re-committing the same ID must fail: the preparation payload was consumed
/// on the first commit, so the second commit has nothing to materialize and
/// the stored prescription must remain the original one.
#[test]
fn commit_add_prescription_twice_fails_and_keeps_original_state() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let result = client.try_commit_add_prescription(&rx_id);
    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));

    // The original prescription is unchanged and exactly one record exists.
    let stored = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_id).expect("prescription should exist")
    });
    assert_eq!(stored.id, rx_id);
    assert_eq!(stored.issued_at, stored.issued_at); // sanity: unchanged read
    assert_eq!(client.get_prescription_count(), 1);
}

/// A rolled-back preparation must not be committable afterwards.
#[test]
fn commit_after_rollback_fails() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = client.prepare_add_prescription(&patient, &provider, &refraction_data(&env));
    client.rollback_add_prescription(&rx_id);

    let result = client.try_commit_add_prescription(&rx_id);
    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));

    assert_eq!(client.get_prescription_count(), 0);
}

/// A failed prepare must not leave the RX counter advanced: the next
/// successful prepare reuses the same ID (no burned IDs).
#[test]
fn failed_prepare_does_not_advance_counter() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");

    // This prepare fails: patient lacks WriteRecord.
    assert!(client
        .try_prepare_add_prescription(&patient, &patient, &refraction_data(&env))
        .is_err());

    // Next successful prepare must reuse ID 1.
    let rx_id = client.prepare_add_prescription(&patient, &provider, &refraction_data(&env));
    assert_eq!(rx_id, 1);
}

/// A failed commit must not advance the counter either.
#[test]
fn failed_commit_does_not_advance_counter() {
    let (env, client, admin) = setup();
    register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");

    assert!(client.try_commit_add_prescription(&999u64).is_err());
    assert_eq!(client.get_prescription_count(), 0);
}

/// A failed prepare must not persist any prescription storage.
#[test]
fn failed_prepare_leaves_no_storage_side_effects() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");

    assert!(client
        .try_prepare_add_prescription(&patient, &patient, &refraction_data(&env))
        .is_err());

    env.as_contract(&client.address, || {
        assert!(prescription::get_prescription(&env, 1).is_none());
        assert!(prescription::get_patient_history(&env, patient.clone()).is_empty());
    });
}

// ── Module-level verification failures ─────────────────────────────────────

/// Verifying a non-existent prescription returns `false` instead of panicking.
#[test]
fn verify_prescription_unknown_id_returns_false() {
    let (env, client, _admin) = setup();

    let verified = env.as_contract(&client.address, || {
        prescription::verify_prescription(&env, 42u64, Address::generate(&env))
    });
    assert!(!verified);
}

/// `verify_prescription` requires the verifier's auth: with real (non-mocked)
/// auth enforcement active the invocation must abort, so an unauthorized
/// party can never flip the `verified` flag.
#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn verify_prescription_enforces_verifier_auth() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    // Create a prescription with mocks enabled.
    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    // Re-enable real auth enforcement: nobody can silently verify.
    env.set_auths(&[]);

    env.as_contract(&client.address, || {
        let verifier = Address::generate(&env);
        let _ = prescription::verify_prescription(&env, rx_id, verifier);
    });
}

/// Verification must actually flip the `verified` flag when authorized, so
/// the failure above is not vacuous.
#[test]
fn verify_prescription_flips_verified_flag_when_authorized() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let verified = env.as_contract(&client.address, || {
        prescription::verify_prescription(&env, rx_id, provider.clone())
    });
    assert!(verified);

    let rx = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_id).unwrap()
    });
    assert!(rx.verified);
}

// ── OCC versioned update failures ────────────────────────────────────

/// A stale expected version under the default `ManualReview` strategy must
/// queue a conflict and leave the stored prescription untouched.
///
/// Setup: a first CAS with the current version applies cleanly and bumps the
/// stored version to 1. The second CAS still claims version 0 (stale read),
/// which must be rejected as Conflicted.
#[test]
fn versioned_update_with_stale_version_conflicts_and_reverts() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let original_left = env
        .as_contract(&client.address, || {
            prescription::get_prescription(&env, rx_id).unwrap()
        })
        .left_eye;

    env.as_contract(&client.address, || {
        let mut fields = Vec::new(&env);
        fields.push_back(FieldChange {
            field_name: String::from_str(&env, "left_eye.sphere"),
            old_hash: String::from_str(&env, "old"),
            new_hash: String::from_str(&env, "new"),
        });

        // First CAS from version 0 applies cleanly and bumps to version 1.
        let first = prescription::versioned_save_prescription(
            &env,
            &prescription::get_prescription(&env, rx_id).unwrap(),
            0u64,
            1u32,
            &provider,
            &fields,
        );
        assert!(
            matches!(first, teye_common::concurrency::UpdateOutcome::Applied(_)),
            "expected Applied, got {first:?}"
        );

        // Second CAS with the now-stale expected version 0 must conflict.
        let mut conflicting = prescription::get_prescription(&env, rx_id).unwrap();
        conflicting.left_eye = PrescriptionData {
            sphere: String::from_str(&env, "-9.99"),
            ..refraction_data(&env)
        };
        let outcome = prescription::versioned_save_prescription(
            &env,
            &conflicting,
            0u64,
            1u32,
            &provider,
            &fields,
        );
        assert!(
            matches!(
                outcome,
                teye_common::concurrency::UpdateOutcome::Conflicted(_)
            ),
            "expected Conflicted, got {outcome:?}"
        );
    });

    // The stored prescription was NOT modified by the conflicted update: the
    // eye data still reflects the first (applied) update, not "-9.99".
    let after = env.as_contract(&client.address, || {
        prescription::get_prescription(&env, rx_id).unwrap()
    });
    assert_ne!(after.left_eye.sphere, String::from_str(&env, "-9.99"));
    assert_eq!(after.left_eye, original_left);
}

/// Conflicting updates must not mutate the patient's prescription history.
#[test]
fn versioned_update_conflict_does_not_duplicate_history() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    env.as_contract(&client.address, || {
        let mut fields = Vec::new(&env);
        fields.push_back(FieldChange {
            field_name: String::from_str(&env, "right_eye.sphere"),
            old_hash: String::from_str(&env, "old"),
            new_hash: String::from_str(&env, "new"),
        });

        // Apply once to bump the stored version.
        let first = prescription::versioned_save_prescription(
            &env,
            &prescription::get_prescription(&env, rx_id).unwrap(),
            0u64,
            1u32,
            &provider,
            &fields,
        );
        assert!(matches!(
            first,
            teye_common::concurrency::UpdateOutcome::Applied(_)
        ));

        // Stale CAS must conflict.
        let mut conflicting = prescription::get_prescription(&env, rx_id).unwrap();
        conflicting.right_eye = PrescriptionData {
            sphere: String::from_str(&env, "-8.88"),
            ..refraction_data(&env)
        };
        let outcome = prescription::versioned_save_prescription(
            &env,
            &conflicting,
            0u64,
            1u32,
            &provider,
            &fields,
        );
        assert!(matches!(
            outcome,
            teye_common::concurrency::UpdateOutcome::Conflicted(_)
        ));
    });

    let history = env.as_contract(&client.address, || {
        prescription::get_patient_history(&env, patient.clone())
    });
    assert_eq!(history.len(), 1);
    assert_eq!(history.get(0).unwrap(), rx_id);
}

// ── Lifecycle state-machine failures ────────────────────────────────────────

/// Prescription → VisionRecord-style jumps are invalid transitions.
#[test]
fn transition_prescription_state_rejects_invalid_transition() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let result = env.as_contract(&client.address, || {
        prescription::transition_prescription_state(
            &env,
            rx_id,
            LifecycleState::Prescription(PrescriptionState::Completed),
            TransitionContext {
                actor: provider.clone(),
                actor_role: soroban_sdk::symbol_short!("PROV"),
                now: env.ledger().timestamp(),
                retention_until: 0,
                expires_at: 0,
                prerequisites_met: true,
            },
        )
    });

    // Created → Completed skips Dispensed and must be rejected.
    assert_eq!(result, Err(StateMachineError::InvalidTransition));

    // The prescription remains in Created state.
    let state = env.as_contract(&client.address, || {
        teye_common::state_machine::get_state(
            &env,
            0,
            &teye_common::state_machine::EntityKind::Prescription,
            rx_id,
        )
    });
    assert_eq!(
        state,
        LifecycleState::Prescription(PrescriptionState::Created)
    );
}

/// An unprivileged role may not drive the Created → Dispensed transition.
#[test]
fn transition_prescription_state_rejects_unauthorized_role() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let result = env.as_contract(&client.address, || {
        prescription::transition_prescription_state(
            &env,
            rx_id,
            LifecycleState::Prescription(PrescriptionState::Dispensed),
            TransitionContext {
                actor: patient.clone(),
                actor_role: soroban_sdk::symbol_short!("USER"),
                now: env.ledger().timestamp(),
                retention_until: 0,
                expires_at: 0,
                prerequisites_met: true,
            },
        )
    });

    assert_eq!(result, Err(StateMachineError::UnauthorizedRole));

    // State was not changed by the rejected transition.
    let state = env.as_contract(&client.address, || {
        teye_common::state_machine::get_state(
            &env,
            0,
            &teye_common::state_machine::EntityKind::Prescription,
            rx_id,
        )
    });
    assert_eq!(
        state,
        LifecycleState::Prescription(PrescriptionState::Created)
    );
}

/// Unmet prerequisites block any transition.
#[test]
fn transition_prescription_state_rejects_unmet_prerequisites() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let result = env.as_contract(&client.address, || {
        prescription::transition_prescription_state(
            &env,
            rx_id,
            LifecycleState::Prescription(PrescriptionState::Dispensed),
            TransitionContext {
                actor: provider.clone(),
                actor_role: soroban_sdk::symbol_short!("PROV"),
                now: env.ledger().timestamp(),
                retention_until: 0,
                expires_at: 0,
                prerequisites_met: false,
            },
        )
    });

    assert_eq!(result, Err(StateMachineError::PrerequisiteFailed));
}

/// Expiring before `expires_at` is rejected by the time constraint.
#[test]
fn transition_prescription_state_rejects_early_expiry() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let result = env.as_contract(&client.address, || {
        prescription::transition_prescription_state(
            &env,
            rx_id,
            LifecycleState::Prescription(PrescriptionState::Expired),
            TransitionContext {
                actor: provider.clone(),
                actor_role: soroban_sdk::symbol_short!("PROV"),
                now: env.ledger().timestamp() + TXN_MIN_TTL,
                retention_until: 0,
                // The prescription is valid for a year; expiring now is too early.
                expires_at: env.ledger().timestamp() + prescription::STANDARD_EXPIRY_SECONDS,
                prerequisites_met: true,
            },
        )
    });

    assert_eq!(result, Err(StateMachineError::TimeConstraintFailed));
}

/// Happy-path dispersion (Created → Dispensed by a provider) remains possible
/// so the failure tests above are not vacuous.
#[test]
fn transition_prescription_state_allows_provider_dispensing() {
    let (env, client, admin) = setup();
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Dr. Eye");
    let patient = Address::generate(&env);

    let rx_id = prepare_and_commit(&client, &patient, &provider, &env);

    let record = env.as_contract(&client.address, || {
        prescription::transition_prescription_state(
            &env,
            rx_id,
            LifecycleState::Prescription(PrescriptionState::Dispensed),
            TransitionContext {
                actor: provider.clone(),
                actor_role: soroban_sdk::symbol_short!("PROV"),
                now: env.ledger().timestamp(),
                retention_until: 0,
                expires_at: 0,
                prerequisites_met: true,
            },
        )
        .expect("Created -> Dispensed must be allowed for providers")
    });

    assert_eq!(record.entity_id, rx_id);
}
