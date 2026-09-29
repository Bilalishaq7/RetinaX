use crate::circuit_breaker::{self, PauseScope};
use crate::errors::ContractError;
use crate::events;
use crate::patient_profile::{get_profile, profile_storage_key};
use crate::validation;
use soroban_sdk::{contracttype, Address, Env, String};

/// Insurance information (hashed values only for security).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsuranceInfo {
    pub provider_hash: String,
    pub policy_id_hash: String,
    pub group_id_hash: String,
    pub verified_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum OptionalInsuranceInfo {
    None,
    Some(InsuranceInfo),
}

impl OptionalInsuranceInfo {
    pub fn is_none(&self) -> bool {
        matches!(self, OptionalInsuranceInfo::None)
    }

    pub fn is_some(&self) -> bool {
        matches!(self, OptionalInsuranceInfo::Some(_))
    }

    pub fn unwrap(self) -> InsuranceInfo {
        match self {
            OptionalInsuranceInfo::Some(info) => info,
            OptionalInsuranceInfo::None => panic!("called unwrap on None InsuranceInfo"),
        }
    }
}

pub fn validate_insurance_info(info: &InsuranceInfo) -> Result<(), ContractError> {
    validation::validate_string_length(&info.provider_hash, 1, 128)?;
    validation::validate_string_length(&info.policy_id_hash, 1, 128)?;
    validation::validate_string_length(&info.group_id_hash, 0, 128)?;
    Ok(())
}

/// Update insurance information (hashed values only).
pub fn update_insurance(
    env: &Env,
    caller: &Address,
    patient: &Address,
    insurance_info: Option<InsuranceInfo>,
) -> Result<(), ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    caller.require_auth();

    if caller != patient {
        return Err(ContractError::Unauthorized);
    }

    let mut profile = get_profile(env, patient)?;

    if let Some(ref info) = insurance_info {
        validate_insurance_info(info)?;
    }

    profile.insurance_info = match insurance_info {
        Some(ref info) => OptionalInsuranceInfo::Some(info.clone()),
        None => OptionalInsuranceInfo::None,
    };
    profile.updated_at = env.ledger().timestamp();

    env.storage()
        .persistent()
        .set(&profile_storage_key(patient), &profile);

    events::publish_profile_updated(env, patient.clone());

    if let Some(info) = insurance_info {
        events::publish_insurance_updated(
            env,
            patient.clone(),
            caller.clone(),
            info.provider_hash,
            info.policy_id_hash,
            info.group_id_hash,
        );
    } else {
        events::publish_insurance_cleared(env, patient.clone(), caller.clone());
    }

    Ok(())
}

/// Retrieve insurance information for a patient.
pub fn get_insurance(
    env: &Env,
    caller: &Address,
    patient: &Address,
) -> Result<OptionalInsuranceInfo, ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    caller.require_auth();

    if caller != patient
        && !crate::rbac::has_permission(env, caller, &crate::rbac::Permission::ReadAnyRecord)
        && !crate::rbac::has_permission(env, caller, &crate::rbac::Permission::SystemAdmin)
    {
        return Err(ContractError::Unauthorized);
    }

    let profile = get_profile(env, patient)?;
    Ok(profile.insurance_info)
}
