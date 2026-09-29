use crate::prescription::PrescriptionData;
use crate::validation;
use soroban_sdk::{Env, String};

#[test]
fn test_prescription_string_validation() {
    let env = Env::default();

    let valid_eye = PrescriptionData {
        sphere: String::from_str(&env, "-2.50"),
        cylinder: String::from_str(&env, "-1.25"),
        axis: String::from_str(&env, "180"),
        add: String::from_str(&env, "0.00"),
        pd: String::from_str(&env, "62"),
    };
    assert_eq!(validation::validate_prescription_data(&valid_eye), Ok(()));

    let invalid_eye = PrescriptionData {
        sphere: String::from_str(&env, "sphere_string_longer_than_sixteen_chars"),
        cylinder: String::from_str(&env, "-1.25"),
        axis: String::from_str(&env, "180"),
        add: String::from_str(&env, "0.00"),
        pd: String::from_str(&env, "62"),
    };
    assert!(validation::validate_prescription_data(&invalid_eye).is_err());
}

#[test]
fn test_prescription_events_emission() {
    use crate::prescription::{self, LensType, OptionalContactLensData, Prescription, PrescriptionData};
    use teye_common::state_machine::{self, LifecycleState, PrescriptionState, TransitionContext};
    use soroban_sdk::{symbol_short, Address, Env, String};
    use soroban_sdk::testutils::{Address as _, Events as _};

    let env = Env::default();
    env.mock_all_auths();

    let patient = Address::generate(&env);
    let provider = Address::generate(&env);

    let eye_data = PrescriptionData {
        sphere: String::from_str(&env, "-2.50"),
        cylinder: String::from_str(&env, "-1.25"),
        axis: String::from_str(&env, "180"),
        add: String::from_str(&env, "0.00"),
        pd: String::from_str(&env, "62"),
    };

    let rx = Prescription {
        id: 101,
        patient: patient.clone(),
        provider: provider.clone(),
        lens_type: LensType::Glasses,
        left_eye: eye_data.clone(),
        right_eye: eye_data,
        contact_data: OptionalContactLensData::None,
        issued_at: 1000,
        expires_at: 2000,
        verified: false,
        metadata_hash: String::from_str(&env, "hash123"),
    };

    // 1. Save prescription
    prescription::save_prescription(&env, &rx, Some(50));
    assert_eq!(env.events().all().len(), 2);

    // 2. Verify prescription
    let verifier = Address::generate(&env);
    let verified = prescription::verify_prescription(&env, 101, verifier.clone());
    assert!(verified);
    assert_eq!(env.events().all().len(), 3);

    // 3. Transition prescription state Created -> Dispensed
    let ctx = TransitionContext {
        actor: provider.clone(),
        actor_role: symbol_short!("PROV"),
        now: 1500,
        retention_until: 0,
        expires_at: 2000,
        prerequisites_met: true,
    };
    let transition_res = prescription::transition_prescription_state(
        &env,
        101,
        LifecycleState::Prescription(PrescriptionState::Dispensed),
        ctx,
    );
    assert!(transition_res.is_ok());
    assert_eq!(env.events().all().len(), 4);
}

