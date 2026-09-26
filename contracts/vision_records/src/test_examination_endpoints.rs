//! Contract-boundary tests for examination endpoint happy and failure paths.

#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use super::{
    examination::{OptPhysicalMeasurement, PhysicalMeasurement},
    ContractError, IntraocularPressure, OptFundusPhotography, OptRetinalImaging, OptVisualField,
    RecordType, Role, SlitLampFindings, VisionRecordsContract, VisionRecordsContractClient,
    VisualAcuity,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String};

const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

fn add_record(
    env: &Env,
    client: &VisionRecordsContractClient,
    provider: &Address,
    patient: &Address,
    record_type: RecordType,
) -> u64 {
    client.add_record(
        provider,
        patient,
        provider,
        &record_type,
        &String::from_str(env, VALID_HASH),
    )
}

fn visual_acuity(env: &Env) -> VisualAcuity {
    VisualAcuity {
        uncorrected: PhysicalMeasurement {
            left_eye: String::from_str(env, "20/25"),
            right_eye: String::from_str(env, "20/20"),
        },
        corrected: OptPhysicalMeasurement::Some(PhysicalMeasurement {
            left_eye: String::from_str(env, "20/20"),
            right_eye: String::from_str(env, "20/20"),
        }),
    }
}

fn iop(env: &Env) -> IntraocularPressure {
    IntraocularPressure {
        left_eye: 14,
        right_eye: 15,
        method: String::from_str(env, "Goldmann"),
        timestamp: env.ledger().timestamp(),
    }
}

fn slit_lamp(env: &Env) -> SlitLampFindings {
    SlitLampFindings {
        cornea: String::from_str(env, "Clear"),
        anterior_chamber: String::from_str(env, "Deep and quiet"),
        iris: String::from_str(env, "Normal"),
        lens: String::from_str(env, "Clear"),
    }
}

fn add_eye_exam(
    env: &Env,
    client: &VisionRecordsContractClient,
    provider: &Address,
    record_id: u64,
) {
    client.add_eye_examination(
        provider,
        &record_id,
        &visual_acuity(env),
        &iop(env),
        &slit_lamp(env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(env, "Routine exam"),
    );
}

#[test]
fn add_and_get_eye_examination_round_trip() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    add_eye_exam(&env, &client, &provider, record_id);

    let by_provider = client.get_eye_examination(&provider, &record_id);
    assert_eq!(by_provider.record_id, record_id);
    assert_eq!(by_provider.iop.left_eye, 14);
    assert_eq!(
        by_provider.visual_acuity.uncorrected.left_eye,
        String::from_str(&env, "20/25")
    );

    let by_patient = client.get_eye_examination(&patient, &record_id);
    assert_eq!(
        by_patient.clinical_notes,
        String::from_str(&env, "Routine exam")
    );
}

#[test]
fn add_eye_examination_rejects_unauthorized_writer_without_state_change() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let other_provider = register_user(&env, &client, &admin, Role::Optometrist, "Other");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let result = client.try_add_eye_examination(
        &other_provider,
        &record_id,
        &visual_acuity(&env),
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Should not persist"),
    );

    assert!(result.is_err());
    assert!(client
        .try_get_eye_examination(&provider, &record_id)
        .is_err());
}

#[test]
fn add_eye_examination_rejects_non_examination_records() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Prescription);

    let result = client.try_add_eye_examination(
        &provider,
        &record_id,
        &visual_acuity(&env),
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Should not persist"),
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidRecordType)));
    assert!(client
        .try_get_eye_examination(&provider, &record_id)
        .is_err());
}

#[test]
fn get_eye_examination_requires_access_and_existing_exam() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let other_provider = register_user(&env, &client, &admin, Role::Optometrist, "Other");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    assert_eq!(
        client.try_get_eye_examination(&provider, &record_id),
        Err(Ok(ContractError::RecordNotFound))
    );

    add_eye_exam(&env, &client, &provider, record_id);

    assert!(client
        .try_get_eye_examination(&other_provider, &record_id)
        .is_err());
}
