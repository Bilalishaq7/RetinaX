//! Contract-boundary tests for examination endpoint happy and failure paths.

#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use super::{
    examination::{OptPhysicalMeasurement, PhysicalMeasurement},
    ContractError, IntraocularPressure, OptFundusPhotography, OptRetinalImaging, OptVisualField,
    RecordType, Role, SlitLampFindings, VisionRecordsContract, VisionRecordsContractClient,
    VisualAcuity,
};
use soroban_sdk::{testutils::Address as _, testutils::Events as _, Address, Env, String, Vec};

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

#[test]
fn add_eye_examination_emits_detailed_events() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let events_before = env.events().all().events().len();
    add_eye_exam(&env, &client, &provider, record_id);
    let events_after = env.events().all().events().len();

    // Verify events were emitted (detailed examination added event, state transition, audit)
    assert!(events_after > events_before);
}

#[test]
fn update_examination_versioned_emits_event_and_updates_data() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    add_eye_exam(&env, &client, &provider, record_id);

    let mut updated_va = visual_acuity(&env);
    updated_va.uncorrected.left_eye = String::from_str(&env, "20/15");

    let changed_fields = Vec::new(&env);
    let events_before = env.events().all().events().len();

    let _outcome = client.update_examination_versioned(
        &provider,
        &record_id,
        &0,
        &1,
        &updated_va,
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Updated notes"),
        &changed_fields,
    );

    let events_after = env.events().all().events().len();
    assert!(events_after > events_before);

    let exam = client.get_eye_examination(&provider, &record_id);
    assert_eq!(
        exam.visual_acuity.uncorrected.left_eye,
        String::from_str(&env, "20/15")
    );
    assert_eq!(exam.clinical_notes, String::from_str(&env, "Updated notes"));
}

#[test]
fn add_eye_examination_rejects_oversized_visual_acuity() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let mut bad_va = visual_acuity(&env);
    bad_va.uncorrected.left_eye = String::from_str(
        &env,
        "measurement_string_that_exceeds_sixty_four_characters_limit_which_is_invalid",
    );

    let result = client.try_add_eye_examination(
        &provider,
        &record_id,
        &bad_va,
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Routine exam"),
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
}

#[test]
fn add_eye_examination_rejects_empty_visual_acuity() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let mut bad_va = visual_acuity(&env);
    bad_va.uncorrected.left_eye = String::from_str(&env, "");

    let result = client.try_add_eye_examination(
        &provider,
        &record_id,
        &bad_va,
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Routine exam"),
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
}

#[test]
fn add_eye_examination_rejects_oversized_iop_method() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let mut bad_iop = iop(&env);
    bad_iop.method = String::from_str(
        &env,
        "tonometry_method_description_that_exceeds_the_sixty_four_characters_limit_allowed",
    );

    let result = client.try_add_eye_examination(
        &provider,
        &record_id,
        &visual_acuity(&env),
        &bad_iop,
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Routine exam"),
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
}

#[test]
fn add_eye_examination_rejects_oversized_slit_lamp_findings() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let oversized_text = "cornea_findings_text_".repeat(15); // > 256 chars
    let mut bad_slit = slit_lamp(&env);
    bad_slit.cornea = String::from_str(&env, &oversized_text);

    let result = client.try_add_eye_examination(
        &provider,
        &record_id,
        &visual_acuity(&env),
        &iop(&env),
        &bad_slit,
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Routine exam"),
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
}

#[test]
fn add_eye_examination_rejects_oversized_clinical_notes() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    let oversized_notes = "clinical_notes_block_".repeat(110); // > 2048 chars
    let result = client.try_add_eye_examination(
        &provider,
        &record_id,
        &visual_acuity(&env),
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, &oversized_notes),
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
}

#[test]
fn update_examination_versioned_rejects_oversized_strings() {
    let (env, client, admin) = setup();
    let patient = register_user(&env, &client, &admin, Role::Patient, "Patient");
    let provider = register_user(&env, &client, &admin, Role::Optometrist, "Provider");
    let record_id = add_record(&env, &client, &provider, &patient, RecordType::Examination);

    add_eye_exam(&env, &client, &provider, record_id);

    let mut bad_va = visual_acuity(&env);
    bad_va.uncorrected.left_eye = String::from_str(
        &env,
        "measurement_string_that_exceeds_sixty_four_characters_limit_which_is_invalid",
    );

    let changed_fields = Vec::new(&env);
    let result = client.try_update_examination_versioned(
        &provider,
        &record_id,
        &0,
        &1,
        &bad_va,
        &iop(&env),
        &slit_lamp(&env),
        &OptVisualField::None,
        &OptRetinalImaging::None,
        &OptFundusPhotography::None,
        &String::from_str(&env, "Notes"),
        &changed_fields,
    );

    assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
}
