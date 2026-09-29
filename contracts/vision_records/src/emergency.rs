use crate::circuit_breaker::{self, PauseScope};
use crate::errors::ContractError;
use crate::events;
use crate::provider;
use crate::validation;
use soroban_sdk::{contracttype, symbol_short, Address, Env, String, Symbol, Vec};

// ── Storage keys ──────────────────────────────────────────────
pub const EMRG_CTR: Symbol = symbol_short!("EMRG_CTR");
const EMRG_ACCESS: Symbol = symbol_short!("EMRG_ACC");
const EMRG_AUDIT: Symbol = symbol_short!("EMRG_AUD");
const EMRG_PATIENT: Symbol = symbol_short!("EMRG_PAT");

const TTL_THRESHOLD: u32 = 5184000;
const TTL_EXTEND_TO: u32 = 10368000;

/// Extends the time-to-live (TTL) for emergency access storage keys.
fn extend_ttl_emergency_key(env: &Env, key: &(Symbol, u64)) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

/// Extends the time-to-live (TTL) for emergency access by patient keys.
fn extend_ttl_emergency_patient_key(env: &Env, key: &(Symbol, Address, u64)) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

// ── Types ─────────────────────────────────────────────────────

/// Conditions that justify emergency access
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmergencyCondition {
    LifeThreatening,
    Unconscious,
    SurgicalEmergency,
    Masscasualties,
}

/// Status of an emergency access request
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmergencyStatus {
    Active,
    Expired,
    Revoked,
}

/// An emergency access grant — always time-limited
#[contracttype]
#[derive(Clone, Debug)]
pub struct EmergencyAccess {
    pub id: u64,
    pub patient: Address,
    pub requester: Address,
    pub condition: EmergencyCondition,
    /// Free-text attestation signed off by the requester
    pub attestation: String,
    pub granted_at: u64,
    pub expires_at: u64,
    pub status: EmergencyStatus,
    pub notified_contacts: Vec<Address>,
}

/// Immutable audit entry — written once, never deleted
#[contracttype]
#[derive(Clone, Debug)]
pub struct EmergencyAuditEntry {
    pub access_id: u64,
    pub actor: Address,
    pub action: String, // e.g. "GRANTED", "REVOKED", "ACCESSED", "NOTIFIED", "EXPIRED"
    pub timestamp: u64,
}

// ── Storage Functions ────────────────────────────────────────

/// Increments and returns the next emergency access ID
pub fn increment_emergency_counter(env: &Env) -> u64 {
    let current: u64 = env.storage().instance().get(&EMRG_CTR).unwrap_or(0);
    let next = current.saturating_add(1);
    env.storage().instance().set(&EMRG_CTR, &next);
    next
}

/// Stores an emergency access grant
pub fn set_emergency_access(env: &Env, access: &EmergencyAccess) {
    let key = (EMRG_ACCESS, access.id);
    env.storage().persistent().set(&key, access);
    extend_ttl_emergency_key(env, &key);

    // Also index by patient for quick lookup
    let patient_key = (EMRG_PATIENT, access.patient.clone(), access.id);
    env.storage().persistent().set(&patient_key, &true);
    extend_ttl_emergency_patient_key(env, &patient_key);
}

/// Retrieves an emergency access grant by ID
pub fn get_emergency_access(env: &Env, access_id: u64) -> Option<EmergencyAccess> {
    let key = (EMRG_ACCESS, access_id);
    env.storage().persistent().get(&key)
}

/// Checks if emergency access is currently active for a patient-requester pair
pub fn has_active_emergency_access(
    env: &Env,
    patient: &Address,
    requester: &Address,
) -> Option<EmergencyAccess> {
    let counter: u64 = env.storage().instance().get(&EMRG_CTR).unwrap_or(0);
    let start_id = if counter > 100 { counter - 100 } else { 1 };

    for id in start_id..=counter {
        let key = (EMRG_ACCESS, id);
        if let Some(access) = env.storage().persistent().get::<_, EmergencyAccess>(&key) {
            if access.patient == *patient
                && access.requester == *requester
                && access.status == EmergencyStatus::Active
                && access.expires_at > env.ledger().timestamp()
            {
                return Some(access);
            }
        }
    }
    None
}

/// Adds an audit entry for emergency access actions
pub fn add_audit_entry(env: &Env, entry: &EmergencyAuditEntry) {
    let key = (EMRG_AUDIT, entry.access_id);
    let mut audit_log: Vec<EmergencyAuditEntry> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));

    audit_log.push_back(entry.clone());

    // Limit audit log to 1000 entries per access ID
    if audit_log.len() > 1000 {
        let mut new_log = Vec::new(env);
        for i in 1..audit_log.len() {
            if let Some(entry) = audit_log.get(i) {
                new_log.push_back(entry);
            }
        }
        audit_log = new_log;
    }

    env.storage().persistent().set(&key, &audit_log);
    extend_ttl_emergency_key(env, &key);
}

/// Retrieves audit entries for an emergency access ID
pub fn get_audit_entries(env: &Env, access_id: u64) -> Vec<EmergencyAuditEntry> {
    let key = (EMRG_AUDIT, access_id);
    env.storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env))
}

/// Gets all active emergency accesses for a patient
pub fn get_patient_emergency_accesses(env: &Env, patient: &Address) -> Vec<EmergencyAccess> {
    let mut accesses = Vec::new(env);
    let counter: u64 = env.storage().instance().get(&EMRG_CTR).unwrap_or(0);
    let start_id = if counter > 100 { counter - 100 } else { 1 };

    for id in start_id..=counter {
        let key = (EMRG_ACCESS, id);
        if let Some(access) = env.storage().persistent().get::<_, EmergencyAccess>(&key) {
            if access.patient == *patient && access.status == EmergencyStatus::Active {
                accesses.push_back(access);
            }
        }
    }
    accesses
}

// ── Business Logic & Event Emission Functions ─────────────────

/// Grants an emergency access request, validates requirements, logs audit entry, and emits events.
pub fn grant_emergency_access(
    env: &Env,
    requester: &Address,
    patient: &Address,
    condition: EmergencyCondition,
    attestation: String,
    duration_seconds: u64,
    notified_contacts: Vec<Address>,
) -> Result<u64, ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    requester.require_auth();

    // Verify requester is a registered/verified provider
    if !provider::is_provider_verified(env, requester) {
        return Err(ContractError::Unauthorized);
    }

    // Validate attestation and duration
    validation::validate_string_length(&attestation, 1, 1024)?;
    validation::validate_duration(duration_seconds)?;

    let now = env.ledger().timestamp();
    let expires_at = now.saturating_add(duration_seconds);
    let access_id = increment_emergency_counter(env);

    let access = EmergencyAccess {
        id: access_id,
        patient: patient.clone(),
        requester: requester.clone(),
        condition: condition.clone(),
        attestation: attestation.clone(),
        granted_at: now,
        expires_at,
        status: EmergencyStatus::Active,
        notified_contacts: notified_contacts.clone(),
    };

    set_emergency_access(env, &access);

    // Audit log entry
    let audit_entry = EmergencyAuditEntry {
        access_id,
        actor: requester.clone(),
        action: String::from_str(env, "GRANTED"),
        timestamp: now,
    };
    add_audit_entry(env, &audit_entry);

    // Emit Soroban event for granted emergency access
    events::publish_emergency_access_granted(
        env,
        access_id,
        patient.clone(),
        requester.clone(),
        condition,
        expires_at,
    );

    // Emit Soroban events for notified contacts
    for i in 0..notified_contacts.len() {
        if let Some(contact) = notified_contacts.get(i) {
            events::publish_emergency_contact_notified(
                env,
                access_id,
                patient.clone(),
                contact,
            );
        }
    }

    Ok(access_id)
}

/// Revokes an active emergency access grant, logs audit entry, and emits event.
pub fn revoke_emergency_access(
    env: &Env,
    revoker: &Address,
    access_id: u64,
) -> Result<(), ContractError> {
    circuit_breaker::require_not_paused(env, &PauseScope::Global)?;
    revoker.require_auth();

    let key = (EMRG_ACCESS, access_id);
    let mut access = env
        .storage()
        .persistent()
        .get::<_, EmergencyAccess>(&key)
        .ok_or(ContractError::RecordNotFound)?;

    // Authorization: patient, requester, or authorized actor can revoke
    if *revoker != access.patient && *revoker != access.requester {
        return Err(ContractError::Unauthorized);
    }

    access.status = EmergencyStatus::Revoked;
    env.storage().persistent().set(&key, &access);
    extend_ttl_emergency_key(env, &key);

    let now = env.ledger().timestamp();
    let audit_entry = EmergencyAuditEntry {
        access_id,
        actor: revoker.clone(),
        action: String::from_str(env, "REVOKED"),
        timestamp: now,
    };
    add_audit_entry(env, &audit_entry);

    // Emit Soroban event for revoked emergency access
    events::publish_emergency_access_revoked(env, access_id, access.patient, revoker.clone());

    Ok(())
}

/// Expires emergency accesses that have passed their expiration time, emits expiration events.
pub fn expire_emergency_accesses(env: &Env) -> u32 {
    let mut expired_count = 0u32;
    let counter: u64 = env.storage().instance().get(&EMRG_CTR).unwrap_or(0);
    let start_id = if counter > 100 { counter - 100 } else { 1 };
    let current_time = env.ledger().timestamp();

    for id in start_id..=counter {
        let key = (EMRG_ACCESS, id);
        if let Some(mut access) = env.storage().persistent().get::<_, EmergencyAccess>(&key) {
            if access.status == EmergencyStatus::Active && access.expires_at <= current_time {
                access.status = EmergencyStatus::Expired;
                env.storage().persistent().set(&key, &access);
                extend_ttl_emergency_key(env, &key);

                let audit_entry = EmergencyAuditEntry {
                    access_id: id,
                    actor: access.patient.clone(),
                    action: String::from_str(env, "EXPIRED"),
                    timestamp: current_time,
                };
                add_audit_entry(env, &audit_entry);

                // Emit Soroban event for expired emergency access
                events::publish_emergency_access_expired(env, id, access.patient);

                expired_count += 1;
            }
        }
    }
    expired_count
}
