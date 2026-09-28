use crate::circuit_breaker::{self, PauseScope};
use crate::errors::ContractError;
use crate::events;
use crate::validation;
use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

/// Consent types for data sharing and clinical operations
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsentType {
    /// Treatment consent
    Treatment,
    /// Sharing consent
    Sharing,
    /// Research consent
    Research,
    /// Emergency consent
    Emergency,
    /// Billing access consent
    Billing,
}

/// Consent grant structure for patient-to-provider consent tracking
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentGrant {
    pub patient: Address,
    pub grantee: Address,
    pub consent_type: ConsentType,
    pub granted_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// Helper function to construct consent storage key tuple
pub fn consent_key(patient: &Address, grantee: &Address) -> (Symbol, Address, Address) {
    (symbol_short!("CONSENT"), patient.clone(), grantee.clone())
}

/// Checks if there is an active (non-revoked, unexpired) consent grant for patient to grantee
pub fn has_active_consent(env: &Env, patient: &Address, grantee: &Address) -> bool {
    let key = consent_key(patient, grantee);
    if let Some(consent) = env.storage().persistent().get::<_, ConsentGrant>(&key) {
        !consent.revoked && consent.expires_at > env.ledger().timestamp()
    } else {
        false
    }
}

/// Retrieves the consent grant for a patient-grantee pair if present
pub fn get_consent(env: &Env, patient: &Address, grantee: &Address) -> Option<ConsentGrant> {
    let key = consent_key(patient, grantee);
    env.storage().persistent().get::<_, ConsentGrant>(&key)
}

/// Grant consent for a grantee to access patient records
pub fn grant_consent(
    env: &Env,
    patient: &Address,
    grantee: &Address,
    consent_type: ConsentType,
    duration_seconds: u64,
) -> Result<(), ContractError> {
    circuit_breaker::require_not_paused(
        env,
        &PauseScope::Function(symbol_short!("GNT_CNS")),
    )?;
    patient.require_auth();
    validation::validate_duration(duration_seconds)?;

    let now = env.ledger().timestamp();
    let expires_at = now.saturating_add(duration_seconds);

    let consent = ConsentGrant {
        patient: patient.clone(),
        grantee: grantee.clone(),
        consent_type: consent_type.clone(),
        granted_at: now,
        expires_at,
        revoked: false,
    };

    let key = consent_key(patient, grantee);
    env.storage().persistent().set(&key, &consent);

    events::publish_consent_granted(env, patient.clone(), grantee.clone(), consent_type, expires_at);

    Ok(())
}

/// Revoke previously granted consent
pub fn revoke_consent(
    env: &Env,
    patient: &Address,
    grantee: &Address,
) -> Result<(), ContractError> {
    circuit_breaker::require_not_paused(
        env,
        &PauseScope::Function(symbol_short!("RVK_CNS")),
    )?;
    patient.require_auth();

    let key = consent_key(patient, grantee);
    if let Some(mut consent) = env.storage().persistent().get::<_, ConsentGrant>(&key) {
        consent.revoked = true;
        env.storage().persistent().set(&key, &consent);
    }

    events::publish_consent_revoked(env, patient.clone(), grantee.clone());

    Ok(())
}
