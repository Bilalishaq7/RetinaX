use soroban_sdk::{contracterror, contracttype, Address, Symbol, Vec};

/// Maximum bounded length for RBAC string identifiers in persistent storage.
pub const MAX_STRING_LEN: u32 = 64;

/// Granular error codes emitted by the AccessControl micro-contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AccessControlError {
    /// Caller is not authorized to execute the operation.
    Unauthorized = 1,
    /// Provided string parameter or identifier is empty or exceeds length limits.
    InvalidInput = 2,
    /// The specified role assignment or entity was not found.
    NotFound = 3,
    /// Requested delegation has expired or is invalid.
    DelegationExpired = 4,
    /// Access control micro-contract is currently paused by emergency admin.
    Paused = 5,
    /// The target user already belongs to the group or role.
    AlreadyExists = 6,
    /// Contract is already initialized.
    AlreadyInitialized = 7,
}

/// Core permissions in the RetinaX access control system.
///
/// Permissions are granted through roles, custom grants, delegations, or ACL group membership.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
#[repr(u32)]
pub enum Permission {
    /// Read any patient record across the system.
    ReadAnyRecord = 1,
    /// Create, update, or modify vision care and clinical examination records.
    WriteRecord = 2,
    /// Grant, revoke, or modify clinical access to records.
    ManageAccess = 3,
    /// Create, update, or remove user roles, delegations, and assignments.
    ManageUsers = 4,
    /// System-level administrative access (circuit breaker, contract upgrades, parameters).
    SystemAdmin = 5,
}

/// User roles in the RetinaX system forming a strict hierarchical trust model.
///
/// Hierarchy: Patient (1) → Staff (2) → Optometrist (3) → Ophthalmologist (4) → Admin (5)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
#[repr(u32)]
pub enum Role {
    /// No role assigned.
    None = 0,
    /// Patient: owns their own medical records, manages access through consent.
    Patient = 1,
    /// Clinical staff: can read records, assist with data entry.
    Staff = 2,
    /// Optometrist: specialist eye care, can prescribe and manage exams.
    Optometrist = 3,
    /// Ophthalmologist: senior surgical/diagnostic specialist with full clinical rights.
    Ophthalmologist = 4,
    /// System administrator: full administrative rights.
    Admin = 5,
}

/// Returns the default base permissions associated with a given role.
///
/// # Complexity
/// - **Time Complexity**: $\mathcal{O}(1)$ fixed-size vector instantiation.
/// - **Space Complexity**: $\mathcal{O}(1)$ (at most 5 elements).
pub fn get_base_permissions(role: &Role, env: &soroban_sdk::Env) -> Vec<Permission> {
    let mut perms = Vec::new(env);
    match role {
        Role::Admin => {
            perms.push_back(Permission::SystemAdmin);
            perms.push_back(Permission::ManageUsers);
            perms.push_back(Permission::WriteRecord);
            perms.push_back(Permission::ManageAccess);
            perms.push_back(Permission::ReadAnyRecord);
        }
        Role::Ophthalmologist => {
            perms.push_back(Permission::ManageUsers);
            perms.push_back(Permission::WriteRecord);
            perms.push_back(Permission::ManageAccess);
            perms.push_back(Permission::ReadAnyRecord);
        }
        Role::Optometrist => {
            perms.push_back(Permission::ManageUsers);
            perms.push_back(Permission::WriteRecord);
            perms.push_back(Permission::ManageAccess);
            perms.push_back(Permission::ReadAnyRecord);
        }
        Role::Staff => {
            perms.push_back(Permission::ManageUsers);
        }
        Role::Patient | Role::None => {}
    }
    perms
}

/// Time-based access restrictions for contextual policy evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub enum TimeRestriction {
    /// No time restriction.
    None,
    /// Only allow access during standard business hours (09:00 - 17:00 UTC).
    BusinessHours,
    /// Only allow access within specific hour range (start_hour, end_hour).
    HourRange(u32, u32),
    /// Only allow access on specific days of week (bitmask: 0b0000001 = Sunday).
    DaysOfWeek(u32),
}

/// Credential types for verified professional credentials.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub enum CredentialType {
    None,
    MedicalLicense,
    ResearchCredentials,
    EmergencyCredentials,
    AdminCredentials,
}

/// Record sensitivity classification for data governance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub enum SensitivityLevel {
    Public,
    Standard,
    Confidential,
    Restricted,
}

/// Attribute-Based Access Control (ABAC) policy conditions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConditions {
    pub required_role: Role,
    pub time_restriction: TimeRestriction,
    pub required_credential: CredentialType,
    pub min_sensitivity_level: SensitivityLevel,
    pub consent_required: bool,
}

/// Composite access policy record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessPolicy {
    pub id: Symbol,
    pub name: Symbol,
    pub conditions: PolicyConditions,
    pub enabled: bool,
}

/// Role assignment record stored persistently per user.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleAssignment {
    pub role: Role,
    pub custom_grants: Vec<Permission>,
    pub custom_revokes: Vec<Permission>,
    pub expires_at: u64, // 0 = permanent / never expires
}

/// Role delegation record from delegator to delegatee.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegation {
    pub delegator: Address,
    pub delegatee: Address,
    pub role: Role,
    pub expires_at: u64,
}

/// Scoped delegation record granting specific permissions from delegator to delegatee.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedDelegation {
    pub delegator: Address,
    pub delegatee: Address,
    pub permissions: Vec<Permission>,
    pub expires_at: u64,
}

/// Access Control List (ACL) group definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AclGroup {
    pub name: Symbol,
    pub permissions: Vec<Permission>,
}
