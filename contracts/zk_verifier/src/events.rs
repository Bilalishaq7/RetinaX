#![allow(deprecated)] // events().publish migration tracked separately
//! # Contract Event Definitions and Publishers
//!
//! This module defines the event schemas emitted by the `ZkVerifierContract`.
//! These events allow off-chain indexers, auditing dashboards, and vision care providers
//! to monitor real-time access requests, admin lifecycle events, and security violations.
//!
//! ## Event Topics & Structure
//! - **Admin Lifecycle**: `ADM_PROP`, `ADM_ACPT`, `ADM_CNCL`
//! - **Access Control**: `REJECT`, `ACC_VIOL`

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, String};

/// Emitted when the contract administrator initiates a two-step admin transfer.
///
/// # Topic
/// `(Symbol::short!("ADM_PROP"), current_admin)`
///
/// # Complexity
/// - **Space Complexity**: $\mathcal{O}(1)$ (approx 72 bytes).
/// - **Time Complexity**: $\mathcal{O}(1)$ event publication.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferProposedEvent {
    /// The address of the current contract admin initiating the transfer.
    pub current_admin: Address,
    /// The address of the proposed nominee for the admin role.
    pub proposed_admin: Address,
    /// The ledger timestamp when the proposal was registered.
    pub timestamp: u64,
}

/// Emitted when the proposed administrator claims and accepts the admin role.
///
/// # Topic
/// `(Symbol::short!("ADM_ACPT"), new_admin)`
///
/// # Complexity
/// - **Space Complexity**: $\mathcal{O}(1)$ (approx 72 bytes).
/// - **Time Complexity**: $\mathcal{O}(1)$ event publication.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferAcceptedEvent {
    /// The address of the previous administrator.
    pub old_admin: Address,
    /// The address of the newly confirmed administrator.
    pub new_admin: Address,
    /// The ledger timestamp when the transfer was finalized.
    pub timestamp: u64,
}

/// Emitted when a pending admin transfer is revoked or cancelled by the current administrator.
///
/// # Topic
/// `(Symbol::short!("ADM_CNCL"), admin)`
///
/// # Complexity
/// - **Space Complexity**: $\mathcal{O}(1)$ (approx 72 bytes).
/// - **Time Complexity**: $\mathcal{O}(1)$ event publication.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferCancelledEvent {
    /// The address of the administrator who cancelled the transfer.
    pub admin: Address,
    /// The address of the nominee whose proposal was cancelled.
    pub cancelled_proposed: Address,
    /// The ledger timestamp when cancellation occurred.
    pub timestamp: u64,
}

/// Emitted whenever a resource verification request is rejected by validation or rate limiting.
///
/// # Topic
/// `(Symbol::short!("REJECT"), user, resource_id)`
///
/// # Complexity
/// - **Space Complexity**: $\mathcal{O}(1)$ (approx 76 bytes).
/// - **Time Complexity**: $\mathcal{O}(1)$ event publication.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRejectedEvent {
    /// The address of the user who requested access.
    pub user: Address,
    /// The 32-byte resource identifier that access was attempted on.
    pub resource_id: BytesN<32>,
    /// The numerical error code matching [`crate::ContractError`].
    pub error: u32,
    /// The ledger timestamp when the request was rejected.
    pub timestamp: u64,
}

/// Emitted when an unauthorized actor attempts a privileged action or fails proof verification.
///
/// # Topic
/// `(Symbol::short!("ACC_VIOL"), caller, action)`
///
/// # Complexity
/// - **Space Complexity**: $\mathcal{O}(S)$ where $S$ is the combined byte length of action and permission strings.
/// - **Time Complexity**: $\mathcal{O}(S)$ string serialization.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessViolationEvent {
    /// The address of the caller that triggered the violation.
    pub caller: Address,
    /// Name of the contract action or method that was invoked.
    pub action: String,
    /// Description of the required permission or check that failed.
    pub required_permission: String,
    /// The ledger timestamp of the violation.
    pub timestamp: u64,
}

/// Publishes an [`AdminTransferProposedEvent`] to the Soroban event stream.
///
/// # Arguments
/// * `env` - The Soroban environment.
/// * `current_admin` - Address of current administrator.
/// * `proposed_admin` - Address of nominated administrator.
pub fn publish_admin_transfer_proposed(env: &Env, current_admin: Address, proposed_admin: Address) {
    env.events().publish(
        (symbol_short!("ADM_PROP"), current_admin.clone()),
        AdminTransferProposedEvent {
            current_admin,
            proposed_admin,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Publishes an [`AdminTransferAcceptedEvent`] to the Soroban event stream.
///
/// # Arguments
/// * `env` - The Soroban environment.
/// * `old_admin` - Address of previous administrator.
/// * `new_admin` - Address of new administrator.
pub fn publish_admin_transfer_accepted(env: &Env, old_admin: Address, new_admin: Address) {
    env.events().publish(
        (symbol_short!("ADM_ACPT"), new_admin.clone()),
        AdminTransferAcceptedEvent {
            old_admin,
            new_admin,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Publishes an [`AdminTransferCancelledEvent`] to the Soroban event stream.
///
/// # Arguments
/// * `env` - The Soroban environment.
/// * `admin` - Address of administrator.
/// * `cancelled_proposed` - Address of cancelled nominee.
pub fn publish_admin_transfer_cancelled(env: &Env, admin: Address, cancelled_proposed: Address) {
    env.events().publish(
        (symbol_short!("ADM_CNCL"), admin.clone()),
        AdminTransferCancelledEvent {
            admin,
            cancelled_proposed,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Publishes an [`AccessRejectedEvent`] to the Soroban event stream.
///
/// # Arguments
/// * `env` - The Soroban environment.
/// * `user` - User address that was rejected.
/// * `resource_id` - Target resource identifier.
/// * `error` - Contract error variant that caused rejection.
pub fn publish_access_rejected(
    env: &Env,
    user: Address,
    resource_id: BytesN<32>,
    error: crate::ContractError,
) {
    env.events().publish(
        (symbol_short!("REJECT"), user.clone(), resource_id.clone()),
        AccessRejectedEvent {
            user,
            resource_id,
            error: error as u32,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Publishes an [`AccessViolationEvent`] to the Soroban event stream.
///
/// # Arguments
/// * `env` - The Soroban environment.
/// * `caller` - Unauthorized caller address.
/// * `action` - Action attempted.
/// * `required_permission` - Required permission name.
pub fn publish_access_violation(
    env: &Env,
    caller: Address,
    action: String,
    required_permission: String,
) {
    env.events().publish(
        (symbol_short!("ACC_VIOL"), caller.clone(), action.clone()),
        AccessViolationEvent {
            caller,
            action,
            required_permission,
            timestamp: env.ledger().timestamp(),
        },
    );
}
