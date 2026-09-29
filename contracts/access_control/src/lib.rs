#![no_std]

pub mod admin;
pub mod permissions;
pub mod types;
pub mod whitelist;

#[cfg(test)]
mod test;

pub use admin::*;
pub use permissions::*;
pub use types::*;
pub use whitelist::*;

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

/// AccessControl micro-contract for decentralized role-based and attribute-based permissions.
#[contract]
pub struct AccessControlContract;

#[contractimpl]
impl AccessControlContract {
    /// Initializes the AccessControl micro-contract with an initial administrator.
    pub fn initialize(env: Env, admin: Address) -> Result<(), AccessControlError> {
        admin::initialize(&env, &admin)
    }

    /// Returns the currently active administrator address.
    pub fn get_admin(env: Env) -> Option<Address> {
        admin::get_admin(&env)
    }

    /// Proposes an administrative transfer in a two-step handshake.
    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), AccessControlError> {
        admin::propose_admin(&env, &current_admin, &new_admin)
    }

    /// Accepts a proposed administrative role.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), AccessControlError> {
        admin::accept_admin(&env, &new_admin)
    }

    // ── Whitelist Management ────────────────────────────────────────────────

    /// Activates or deactivates whitelist enforcement.
    pub fn set_whitelist_enabled(
        env: Env,
        caller: Address,
        enabled: bool,
    ) -> Result<(), AccessControlError> {
        whitelist::set_whitelist_enabled(&env, &caller, enabled)
    }

    /// Returns whether whitelist enforcement is active.
    pub fn is_whitelist_enabled(env: Env) -> bool {
        whitelist::is_whitelist_enabled(&env)
    }

    /// Whitelists a user address.
    pub fn add_to_whitelist(
        env: Env,
        caller: Address,
        user: Address,
    ) -> Result<(), AccessControlError> {
        whitelist::add_to_whitelist(&env, &caller, &user)
    }

    /// Removes a user address from the whitelist.
    pub fn remove_from_whitelist(
        env: Env,
        caller: Address,
        user: Address,
    ) -> Result<(), AccessControlError> {
        whitelist::remove_from_whitelist(&env, &caller, &user)
    }

    /// Checks if a user is whitelisted (returns true if whitelist is disabled).
    pub fn check_whitelist(env: Env, user: Address) -> bool {
        whitelist::check_whitelist(&env, &user)
    }

    /// Returns raw whitelist status for an address.
    pub fn is_whitelisted(env: Env, user: Address) -> bool {
        whitelist::is_whitelisted(&env, &user)
    }

    // ── RBAC & Role Management ──────────────────────────────────────────────

    /// Assigns a role to a user.
    pub fn assign_role(
        env: Env,
        caller: Address,
        user: Address,
        role: Role,
        expires_at: u64,
    ) -> Result<(), AccessControlError> {
        permissions::assign_role(&env, &caller, &user, role, expires_at)
    }

    /// Revokes an assigned role.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        user: Address,
    ) -> Result<(), AccessControlError> {
        permissions::revoke_role(&env, &caller, &user)
    }

    /// Returns a user's active role.
    pub fn get_role(env: Env, user: Address) -> Role {
        permissions::get_role(&env, &user)
    }

    /// Checks if a user holds a permission.
    pub fn has_permission(env: Env, user: Address, permission: Permission) -> bool {
        permissions::has_permission(&env, &user, &permission)
    }

    /// Checks if a delegatee holds a delegated permission.
    pub fn has_delegated_permission(
        env: Env,
        delegator: Address,
        delegatee: Address,
        permission: Permission,
    ) -> bool {
        permissions::has_delegated_permission(&env, &delegator, &delegatee, &permission)
    }

    /// Grants a custom permission to a user.
    pub fn grant_custom_permission(
        env: Env,
        caller: Address,
        user: Address,
        permission: Permission,
    ) -> Result<(), AccessControlError> {
        permissions::grant_custom_permission(&env, &caller, &user, permission)
    }

    /// Explicitly revokes a custom permission from a user.
    pub fn revoke_custom_permission(
        env: Env,
        caller: Address,
        user: Address,
        permission: Permission,
    ) -> Result<(), AccessControlError> {
        permissions::revoke_custom_permission(&env, &caller, &user, permission)
    }

    /// Delegates a complete role to a delegatee.
    pub fn delegate_role(
        env: Env,
        delegator: Address,
        delegatee: Address,
        role: Role,
        expires_at: u64,
    ) -> Result<(), AccessControlError> {
        permissions::delegate_role(&env, &delegator, &delegatee, role, expires_at)
    }

    /// Revokes a role delegation.
    pub fn revoke_delegation(
        env: Env,
        delegator: Address,
        delegatee: Address,
    ) -> Result<(), AccessControlError> {
        permissions::revoke_delegation(&env, &delegator, &delegatee)
    }

    /// Delegates specific permissions to a delegatee.
    pub fn delegate_permissions(
        env: Env,
        delegator: Address,
        delegatee: Address,
        permissions: Vec<Permission>,
        expires_at: u64,
    ) -> Result<(), AccessControlError> {
        permissions::delegate_permissions(&env, &delegator, &delegatee, permissions, expires_at)
    }

    /// Revokes a scoped delegation.
    pub fn revoke_scoped_delegation(
        env: Env,
        delegator: Address,
        delegatee: Address,
    ) -> Result<(), AccessControlError> {
        permissions::revoke_scoped_delegation(&env, &delegator, &delegatee)
    }

    // ── ACL Group Management ────────────────────────────────────────────────

    /// Creates an ACL group with specified permissions.
    pub fn create_group(
        env: Env,
        caller: Address,
        group_name: Symbol,
        permissions: Vec<Permission>,
    ) -> Result<(), AccessControlError> {
        permissions::create_group(&env, &caller, group_name, permissions)
    }

    /// Adds a user to an ACL group.
    pub fn add_to_group(
        env: Env,
        caller: Address,
        user: Address,
        group_name: Symbol,
    ) -> Result<(), AccessControlError> {
        permissions::add_to_group(&env, &caller, &user, group_name)
    }

    /// Removes a user from an ACL group.
    pub fn remove_from_group(
        env: Env,
        caller: Address,
        user: Address,
        group_name: Symbol,
    ) -> Result<(), AccessControlError> {
        permissions::remove_from_group(&env, &caller, &user, group_name)
    }

    /// Returns all groups a user belongs to.
    pub fn get_user_groups(env: Env, user: Address) -> Vec<Symbol> {
        permissions::get_user_groups(&env, &user)
    }

    // ── Attribute-Based Access Control (ABAC) ───────────────────────────────

    /// Creates an ABAC policy.
    pub fn create_access_policy(
        env: Env,
        caller: Address,
        policy_id: Symbol,
        name: Symbol,
        conditions: PolicyConditions,
    ) -> Result<(), AccessControlError> {
        permissions::create_access_policy(&env, &caller, policy_id, name, conditions)
    }

    /// Sets user professional credential.
    pub fn set_user_credential(
        env: Env,
        caller: Address,
        user: Address,
        credential: CredentialType,
    ) -> Result<(), AccessControlError> {
        permissions::set_user_credential(&env, &caller, &user, credential)
    }

    /// Sets record sensitivity classification.
    pub fn set_record_sensitivity(
        env: Env,
        caller: Address,
        record_id: u64,
        sensitivity: SensitivityLevel,
    ) -> Result<(), AccessControlError> {
        permissions::set_record_sensitivity(&env, &caller, record_id, sensitivity)
    }

    /// Evaluates an ABAC policy against contextual variables.
    pub fn evaluate_access_policy(
        env: Env,
        policy_id: Symbol,
        user: Address,
        record_id: u64,
        current_time: u64,
    ) -> bool {
        permissions::evaluate_access_policy(&env, policy_id, &user, record_id, current_time)
    }
}
