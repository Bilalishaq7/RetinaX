use crate::circuit_breaker::{self, PauseScope};
use crate::errors::ContractError;
use crate::events;
use crate::insurance::OptionalInsuranceInfo;
use crate::rbac::{self, Permission};
use crate::validation;
use soroban_sdk::{contracttype, symbol_short, Address, Env, String, Symbol, Vec};

pub const PATIENT_PROFILE_KEY_PREFIX: Symbol = symbol_short!("PAT_PROF");

/// Emergency contact information
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyContact {
    pub name: String,
    pub relationship: String,
    pub phone: String,
    pub email: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum OptionalEmergencyContact {
    None,
    Some(EmergencyContact),
}

impl OptionalEmergencyContact {
    pub fn is_none(&self) -> bool {
        matches!(self, OptionalEmergencyContact::None)
    }

    pub fn is_some(&self) -> bool {
        matches!(self, OptionalEmergencyContact::Some(_))
    }

    pub fn unwrap(self) -> EmergencyContact {
        match self {
            OptionalEmergencyContact::Some(c) => c,
            OptionalEmergencyContact::None => panic!("called unwrap on None EmergencyContact"),
        }
    }
}

/// Patient profile structure
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatientProfile {
    pub patient: Address,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_active: bool,

    // Demographics (hashed for privacy)
    pub date_of_birth_hash: String,
    pub gender_hash: String,
    pub blood_type_hash: String,

    // Emergency contact
    pub emergency_contact: OptionalEmergencyContact,

    // Insurance information
    pub insurance_info: OptionalInsuranceInfo,

    // Medical history references (IPFS hashes or record IDs)
    pub medical_history_refs: Vec<String>,
}

pub fn profile_storage_key(patient: &Address) -> (Symbol, Address) {
    (PATIENT_PROFILE_KEY_PREFIX, patient.clone())
}

/// Create a new patient profile
pub fn create_profile(
    env: &Env,
    caller: &Address,
    patient: &Address,
    date_of_birth_hash: String,
    gender_hash: String,
    blood_type_hash: String,
) -> Result<PatientProfile, ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    caller.require_auth();

    // Verification: caller must be the patient or have ManageUsers permission
    if caller != patient && !rbac::has_permission(env, caller, &Permission::ManageUsers) {
        return Err(ContractError::Unauthorized);
    }

    let key = profile_storage_key(patient);
    if env.storage().persistent().has(&key) {
        return Err(ContractError::UserAlreadyExists);
    }

    validation::validate_string_length(&date_of_birth_hash, 1, 128)?;
    validation::validate_string_length(&gender_hash, 1, 128)?;
    validation::validate_string_length(&blood_type_hash, 1, 128)?;

    let now = env.ledger().timestamp();
    let profile = PatientProfile {
        patient: patient.clone(),
        created_at: now,
        updated_at: now,
        is_active: true,
        date_of_birth_hash,
        gender_hash,
        blood_type_hash,
        emergency_contact: OptionalEmergencyContact::None,
        insurance_info: OptionalInsuranceInfo::None,
        medical_history_refs: Vec::new(env),
    };

    env.storage().persistent().set(&key, &profile);
    events::publish_profile_created(env, patient.clone());

    Ok(profile)
}

/// Update patient demographics (DOB, gender, blood type)
pub fn update_demographics(
    env: &Env,
    caller: &Address,
    patient: &Address,
    date_of_birth_hash: String,
    gender_hash: String,
    blood_type_hash: String,
) -> Result<PatientProfile, ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    caller.require_auth();

    // Only patient or authorized user with ManageUsers permission can update demographics
    if caller != patient && !rbac::has_permission(env, caller, &Permission::ManageUsers) {
        return Err(ContractError::Unauthorized);
    }

    let key = profile_storage_key(patient);
    let mut profile: PatientProfile = env
        .storage()
        .persistent()
        .get(&key)
        .ok_or(ContractError::UserNotFound)?;

    validation::validate_string_length(&date_of_birth_hash, 1, 128)?;
    validation::validate_string_length(&gender_hash, 1, 128)?;
    validation::validate_string_length(&blood_type_hash, 1, 128)?;

    profile.date_of_birth_hash = date_of_birth_hash;
    profile.gender_hash = gender_hash;
    profile.blood_type_hash = blood_type_hash;
    profile.updated_at = env.ledger().timestamp();

    env.storage().persistent().set(&key, &profile);
    events::publish_profile_updated(env, patient.clone());

    Ok(profile)
}

/// Update emergency contact information
pub fn update_emergency_contact(
    env: &Env,
    caller: &Address,
    patient: &Address,
    contact: Option<EmergencyContact>,
) -> Result<(), ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    caller.require_auth();

    // Only profile owner can update emergency contact
    if caller != patient {
        return Err(ContractError::Unauthorized);
    }

    let key = profile_storage_key(patient);
    let mut profile: PatientProfile = env
        .storage()
        .persistent()
        .get(&key)
        .ok_or(ContractError::UserNotFound)?;

    if let Some(ref c) = contact {
        validation::validate_string_length(&c.name, 1, 128)?;
        validation::validate_string_length(&c.relationship, 1, 64)?;
        validation::validate_string_length(&c.phone, 1, 32)?;
        validation::validate_string_length(&c.email, 1, 128)?;
    }

    profile.emergency_contact = match contact {
        Some(c) => OptionalEmergencyContact::Some(c),
        None => OptionalEmergencyContact::None,
    };
    profile.updated_at = env.ledger().timestamp();

    env.storage().persistent().set(&key, &profile);
    events::publish_profile_updated(env, patient.clone());

    Ok(())
}

/// Add medical history reference (IPFS hash or record ID)
pub fn add_medical_history_reference(
    env: &Env,
    caller: &Address,
    patient: &Address,
    reference: String,
) -> Result<(), ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    caller.require_auth();

    // Only profile owner can update medical history references
    if caller != patient {
        return Err(ContractError::Unauthorized);
    }

    validation::validate_string_length(&reference, 1, 256)?;

    let key = profile_storage_key(patient);
    let mut profile: PatientProfile = env
        .storage()
        .persistent()
        .get(&key)
        .ok_or(ContractError::UserNotFound)?;

    profile.medical_history_refs.push_back(reference);
    profile.updated_at = env.ledger().timestamp();

    env.storage().persistent().set(&key, &profile);
    events::publish_profile_updated(env, patient.clone());

    Ok(())
}

/// Get patient profile
pub fn get_profile(env: &Env, patient: &Address) -> Result<PatientProfile, ContractError> {
    let key = profile_storage_key(patient);
    env.storage()
        .persistent()
        .get(&key)
        .ok_or(ContractError::UserNotFound)
}

/// Check if patient profile exists
pub fn profile_exists(env: &Env, patient: &Address) -> bool {
    let key = profile_storage_key(patient);
    env.storage().persistent().has(&key)
}
