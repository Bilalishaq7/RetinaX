//! Structured event emitting for the identity contract.
//!
//! These functions emit events in a format compatible with the `events` contract
//! streaming system. Each publishes under a hierarchical topic so that external
//! subscribers can filter using wildcard patterns (e.g. `identity.*`).

#![allow(deprecated)] // events().publish migration tracked separately

use soroban_sdk::{contracttype, symbol_short, Address, Env};

// ── Event payloads ───────────────────────────────────────────────────────────

/// Event payload emitted when an identity owner status is changed (activated or deactivated).
/// Topic: `("STREAM", "ID_STAT")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerStatusChangedEvent {
    /// The owner address whose status changed.
    pub owner: Address,
    /// Whether the owner address is active (`true`) or deactivated (`false`).
    pub active: bool,
    /// Ledger timestamp when the status changed.
    pub timestamp: u64,
}

/// Event payload emitted when a guardian is added to or removed from an identity.
/// Topic: `("STREAM", "ID_GUARD")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianChangedEvent {
    /// The identity owner whose guardian set was modified.
    pub owner: Address,
    /// The address of the guardian added or removed.
    pub guardian: Address,
    /// `true` if the guardian was added; `false` if removed.
    pub added: bool,
    /// Ledger timestamp when the guardian change occurred.
    pub timestamp: u64,
}

/// Event payload emitted when a social recovery process is initiated by a guardian.
/// Topic: `("STREAM", "ID_RINIT")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInitiatedEvent {
    /// The owner address whose identity recovery is initiated.
    pub owner: Address,
    /// The proposed new address to receive identity ownership upon completion.
    pub new_address: Address,
    /// The guardian address that initiated the recovery proposal.
    pub initiated_by: Address,
    /// Ledger timestamp when the recovery was initiated.
    pub timestamp: u64,
}

/// Event payload emitted when a recovery process is successfully executed.
/// Topic: `("STREAM", "ID_REXEC")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryExecutedEvent {
    /// The old owner address that has been deactivated.
    pub old_address: Address,
    /// The new owner address that has assumed active ownership.
    pub new_address: Address,
    /// Ledger timestamp when the recovery was executed.
    pub timestamp: u64,
}

/// Event payload emitted when an in-flight recovery process is cancelled by the owner.
/// Topic: `("STREAM", "ID_RCNCL")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCancelledEvent {
    /// The owner address who cancelled the active recovery.
    pub owner: Address,
    /// Ledger timestamp when the recovery was cancelled.
    pub timestamp: u64,
}

/// Event payload emitted when a ZK credential proof is verified via cross-contract call.
/// Topic: `("STREAM", "ID_ZKCRD")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkCredentialVerifiedEvent {
    /// The user address whose credential was verified.
    pub user: Address,
    /// `true` if ZK proof verification succeeded; `false` otherwise.
    pub verified: bool,
    /// Ledger timestamp when the verification took place.
    pub timestamp: u64,
}

// ── Publishers ───────────────────────────────────────────────────────────────

/// Emit a streaming event when identity ownership status changes.
pub fn emit_owner_status_changed(env: &Env, owner: Address, active: bool) {
    env.events().publish(
        (symbol_short!("STREAM"), symbol_short!("ID_STAT")),
        OwnerStatusChangedEvent {
            owner,
            active,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Emit a streaming event when a guardian is added or removed.
pub fn emit_guardian_changed(env: &Env, owner: Address, guardian: Address, added: bool) {
    env.events().publish(
        (symbol_short!("STREAM"), symbol_short!("ID_GUARD")),
        GuardianChangedEvent {
            owner,
            guardian,
            added,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Emit a streaming event when recovery is initiated.
pub fn emit_recovery_initiated(
    env: &Env,
    owner: Address,
    new_address: Address,
    initiated_by: Address,
) {
    env.events().publish(
        (symbol_short!("STREAM"), symbol_short!("ID_RINIT")),
        RecoveryInitiatedEvent {
            owner,
            new_address,
            initiated_by,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Emit a streaming event when recovery is executed.
pub fn emit_recovery_executed(env: &Env, old_address: Address, new_address: Address) {
    env.events().publish(
        (symbol_short!("STREAM"), symbol_short!("ID_REXEC")),
        RecoveryExecutedEvent {
            old_address,
            new_address,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Emit a streaming event when recovery is cancelled.
pub fn emit_recovery_cancelled(env: &Env, owner: Address) {
    env.events().publish(
        (symbol_short!("STREAM"), symbol_short!("ID_RCNCL")),
        RecoveryCancelledEvent {
            owner,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Emit a streaming event when a ZK credential is verified.
pub fn emit_zk_credential_verified(env: &Env, user: Address, verified: bool) {
    env.events().publish(
        (symbol_short!("STREAM"), symbol_short!("ID_ZKCRD")),
        ZkCredentialVerifiedEvent {
            user,
            verified,
            timestamp: env.ledger().timestamp(),
        },
    );
}
