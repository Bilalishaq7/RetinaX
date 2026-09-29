#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use super::{
    ConsentType, ContractError, CredentialType, Permission, RecordType, Role,
    SensitivityLevel, TimeRestriction, VisionRecordsContract, VisionRecordsContractClient,
};
use crate::events::{
    AclGroupCreatedEvent, AclGroupMembershipEvent, PermissionGrantedEvent, PermissionRevokedEvent,
    RoleDelegatedEvent,
};
use crate::rbac::MAX_RBAC_STRING_LEN;
use soroban_sdk::{
    symbol_short, testutils::Address as _, testutils::Events as _, testutils::Ledger as _, vec,
    Address, Env, IntoVal, String, Vec,
};

fn setup_test() -> (Env, VisionRecordsContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(VisionRecordsContract, ());
    let client = VisionRecordsContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    (env, client, admin)
}

#[test]
fn test_role_hierarchy_and_inheritance() {
    let (env, client, admin) = setup_test();

    let optometrist = Address::generate(&env);
    client.register_user(
        &admin,
        &optometrist,
        &Role::Optometrist,
        &String::from_str(&env, "Opto"),
    );

    let staff = Address::generate(&env);
    client.register_user(
        &admin,
        &staff,
        &Role::Staff,
        &String::from_str(&env, "Staff"),
    );

    let patient = Address::generate(&env);
    client.register_user(
        &admin,
        &patient,
        &Role::Patient,
        &String::from_str(&env, "Pat"),
    );

    // Admin should have all permissions implicitly
    assert!(client.check_permission(&admin, &Permission::SystemAdmin));
    assert!(client.check_permission(&admin, &Permission::ManageUsers));
    assert!(client.check_permission(&admin, &Permission::WriteRecord));

    // Optometrist should have read/write/access/users but NOT SystemAdmin
    assert!(!client.check_permission(&optometrist, &Permission::SystemAdmin));
    assert!(client.check_permission(&optometrist, &Permission::WriteRecord));
    assert!(client.check_permission(&optometrist, &Permission::ManageUsers));

    // Staff should have ManageUsers but NOT WriteRecord
    assert!(client.check_permission(&staff, &Permission::ManageUsers));
    assert!(!client.check_permission(&staff, &Permission::WriteRecord));

    // Patient has no implicit system permissions
    assert!(!client.check_permission(&patient, &Permission::ManageUsers));
    assert!(!client.check_permission(&patient, &Permission::WriteRecord));
}

#[test]
fn test_custom_permission_grants() {
    let (env, client, admin) = setup_test();

    let staff = Address::generate(&env);
    client.register_user(
        &admin,
        &staff,
        &Role::Staff,
        &String::from_str(&env, "Staff"),
    );

    // Staff originally cannot write records
    assert!(!client.check_permission(&staff, &Permission::WriteRecord));

    // Admin grants WriteRecord to staff
    client.grant_custom_permission(&admin, &staff, &Permission::WriteRecord);

    // Staff can now write records
    assert!(client.check_permission(&staff, &Permission::WriteRecord));

    // Admin revokes WriteRecord
    client.revoke_custom_permission(&admin, &staff, &Permission::WriteRecord);

    // Staff again cannot write records
    assert!(!client.check_permission(&staff, &Permission::WriteRecord));
}

#[test]
fn test_custom_permission_revocations() {
    let (env, client, admin) = setup_test();

    let optometrist = Address::generate(&env);
    client.register_user(
        &admin,
        &optometrist,
        &Role::Optometrist,
        &String::from_str(&env, "Opto"),
    );

    // Optometrist initially has ManageUsers
    assert!(client.check_permission(&optometrist, &Permission::ManageUsers));

    // Admin explicitly revokes ManageUsers from this specific Optometrist
    client.revoke_custom_permission(&admin, &optometrist, &Permission::ManageUsers);

    // They no longer have it, even though their base role does
    assert!(!client.check_permission(&optometrist, &Permission::ManageUsers));

    // But they still have WriteRecord
    assert!(client.check_permission(&optometrist, &Permission::WriteRecord));

    // Admin grants it back
    client.grant_custom_permission(&admin, &optometrist, &Permission::ManageUsers);
    assert!(client.check_permission(&optometrist, &Permission::ManageUsers));
}

#[test]
fn test_role_delegation() {
    let (env, client, admin) = setup_test();

    let pt1 = Address::generate(&env);
    let pt2 = Address::generate(&env);

    client.register_user(&admin, &pt1, &Role::Patient, &String::from_str(&env, "Pt1"));
    client.register_user(&admin, &pt2, &Role::Patient, &String::from_str(&env, "Pt2"));

    // pt1 delegates the Optometrist role (which has ManageAccess) to pt2 with an expiration.
    let future_time = env.ledger().timestamp() + 86400; // 1 day
    client.delegate_role(&pt1, &pt2, &Role::Optometrist, &future_time);

    // To test the delegation practically, pt2 tries to grant access to a doctor for pt1's records.
    let doctor = Address::generate(&env);
    client.register_user(
        &admin,
        &doctor,
        &Role::Optometrist,
        &String::from_str(&env, "Doc"),
    );

    // pt1 grants consent so check_access passes the consent gate
    client.grant_consent(&pt1, &doctor, &ConsentType::Treatment, &3600);

    // pt2 should be able to grant access acting for pt1
    // (caller: pt2, patient: pt1, grantee: doctor)
    client.grant_access(&pt2, &pt1, &doctor, &super::AccessLevel::Read, &3600);

    assert_eq!(client.check_access(&pt1, &doctor), super::AccessLevel::Read);
}

#[test]
fn test_role_delegation_expiration() {
    let (env, client, admin) = setup_test();

    let delegator = Address::generate(&env);
    let delegatee = Address::generate(&env);

    client.register_user(
        &admin,
        &delegator,
        &Role::Patient,
        &String::from_str(&env, "Delegator"),
    );
    client.register_user(
        &admin,
        &delegatee,
        &Role::Patient,
        &String::from_str(&env, "Delegatee"),
    );

    // Delegate role expiring immediately (timestamp 0 or already passed)
    // env.ledger().timestamp() is typically 0 at setup, we can advance it.
    env.ledger().set_timestamp(100);

    let expire_at = 50; // In the past
    client.delegate_role(&delegator, &delegatee, &Role::Patient, &expire_at);

    let doctor = Address::generate(&env);
    client.register_user(
        &admin,
        &doctor,
        &Role::Optometrist,
        &String::from_str(&env, "Doc"),
    );

    // Delegatee attempts to act for Delegator and should FAIL
    let result = client.try_grant_access(
        &delegatee,
        &delegator,
        &doctor,
        &super::AccessLevel::Read,
        &3600,
    );
    assert!(result.is_err());
}

#[test]
fn test_acl_group_lifecycle_and_permissions() {
    let (env, client, admin) = setup_test();

    let user = Address::generate(&env);
    client.register_user(
        &admin,
        &user,
        &Role::Patient,
        &String::from_str(&env, "User"),
    );

    let group_name = String::from_str(&env, "Retina Specialists");
    let mut perms = Vec::new(&env);
    perms.push_back(Permission::WriteRecord);
    perms.push_back(Permission::ReadAnyRecord);

    // Create group
    client.create_acl_group(&admin, &group_name, &perms);

    // Initial check: user has no WriteRecord
    assert!(!client.check_permission(&user, &Permission::WriteRecord));

    // Add user to group
    client.add_user_to_group(&admin, &user, &group_name);

    // Now user should have permissions from the group
    assert!(client.check_permission(&user, &Permission::WriteRecord));
    assert!(client.check_permission(&user, &Permission::ReadAnyRecord));

    // Remove user from group
    client.remove_user_from_group(&admin, &user, &group_name);

    // Permissions should be gone
    assert!(!client.check_permission(&user, &Permission::WriteRecord));
}

#[test]
fn test_acl_group_multiple_groups() {
    let (env, client, admin) = setup_test();

    let user = Address::generate(&env);
    client.register_user(
        &admin,
        &user,
        &Role::Patient,
        &String::from_str(&env, "User"),
    );

    let group1_name = String::from_str(&env, "Group 1");
    let mut perms1 = Vec::new(&env);
    perms1.push_back(Permission::WriteRecord);
    client.create_acl_group(&admin, &group1_name, &perms1);

    let group2_name = String::from_str(&env, "Group 2");
    let mut perms2 = Vec::new(&env);
    perms2.push_back(Permission::ManageUsers);
    client.create_acl_group(&admin, &group2_name, &perms2);

    client.add_user_to_group(&admin, &user, &group1_name);
    client.add_user_to_group(&admin, &user, &group2_name);

    // Should have both
    assert!(client.check_permission(&user, &Permission::WriteRecord));
    assert!(client.check_permission(&user, &Permission::ManageUsers));

    // Check listing
    let groups = client.get_user_groups(&user);
    assert_eq!(groups.len(), 2);
    assert!(groups.contains(group1_name));
    assert!(groups.contains(group2_name));
}

#[test]
fn test_acl_group_unauthorized_management() {
    let (env, client, admin) = setup_test();

    let non_admin = Address::generate(&env);
    client.register_user(
        &admin,
        &non_admin,
        &Role::Patient,
        &String::from_str(&env, "NoAdmin"),
    );

    let group_name = String::from_str(&env, "Restricted");
    let perms = Vec::new(&env);

    // Non-admin tries to create group - should fail
    // Note: mock_all_auths is on, but has_permission check in lib.rs will trigger
    let result = client.try_create_acl_group(&non_admin, &group_name, &perms);
    assert!(result.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// #479 — Explicit vs inherited permissions
// ─────────────────────────────────────────────────────────────────────────────

/// An explicit custom grant on user A must not affect user B who shares the
/// same base role — permissions are scoped to individual identities.
#[test]
fn test_explicit_grant_scoped_to_individual_user() {
    let (env, client, admin) = setup_test();

    let staff_a = Address::generate(&env);
    let staff_b = Address::generate(&env);

    client.register_user(
        &admin,
        &staff_a,
        &Role::Staff,
        &String::from_str(&env, "StaffA"),
    );
    client.register_user(
        &admin,
        &staff_b,
        &Role::Staff,
        &String::from_str(&env, "StaffB"),
    );

    // Both Staff users cannot write records via their base role.
    assert!(!client.check_permission(&staff_a, &Permission::WriteRecord));
    assert!(!client.check_permission(&staff_b, &Permission::WriteRecord));

    // Grant WriteRecord only to staff_a.
    client.grant_custom_permission(&admin, &staff_a, &Permission::WriteRecord);

    assert!(client.check_permission(&staff_a, &Permission::WriteRecord));
    // staff_b must remain unaffected.
    assert!(!client.check_permission(&staff_b, &Permission::WriteRecord));
}

/// An explicit revocation on user A must not affect user B who shares the
/// same base role — revocations are scoped to individual identities.
#[test]
fn test_explicit_revoke_scoped_to_individual_user() {
    let (env, client, admin) = setup_test();

    let opto_a = Address::generate(&env);
    let opto_b = Address::generate(&env);

    client.register_user(
        &admin,
        &opto_a,
        &Role::Optometrist,
        &String::from_str(&env, "OptoA"),
    );
    client.register_user(
        &admin,
        &opto_b,
        &Role::Optometrist,
        &String::from_str(&env, "OptoB"),
    );

    // Both Optometrists inherit WriteRecord.
    assert!(client.check_permission(&opto_a, &Permission::WriteRecord));
    assert!(client.check_permission(&opto_b, &Permission::WriteRecord));

    // Revoke WriteRecord from opto_a only.
    client.revoke_custom_permission(&admin, &opto_a, &Permission::WriteRecord);

    assert!(!client.check_permission(&opto_a, &Permission::WriteRecord));
    // opto_b must keep the inherited permission.
    assert!(client.check_permission(&opto_b, &Permission::WriteRecord));
}

/// Verifies that `check_record_access` returns `AccessLevel::None` when no
/// record-level grant exists for a grantee — default deny for sub-record access.
#[test]
fn test_record_level_access_defaults_to_none() {
    let (env, client, admin) = setup_test();

    let doctor = Address::generate(&env);
    client.register_user(
        &admin,
        &doctor,
        &Role::Optometrist,
        &String::from_str(&env, "Doc"),
    );

    // No record-level grant has been made — must return None access.
    let access = client.check_record_access(&99u64, &doctor);
    assert_eq!(access, super::AccessLevel::None);
}

/// Trying to grant record-level access on a non-existent record must fail.
#[test]
fn test_grant_record_access_nonexistent_record_fails() {
    let (env, client, admin) = setup_test();

    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);

    client.register_user(
        &admin,
        &patient,
        &Role::Patient,
        &String::from_str(&env, "Patient"),
    );
    client.register_user(
        &admin,
        &doctor,
        &Role::Optometrist,
        &String::from_str(&env, "Doctor"),
    );

    let result = client.try_grant_record_access(
        &patient,
        &doctor,
        &9999u64,
        &super::AccessLevel::Read,
        &3600,
    );
    assert!(result.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// #479 — Scoped delegation
// ─────────────────────────────────────────────────────────────────────────────

/// After a delegation expires the delegatee loses the delegated role, while
/// the original delegator continues to hold their own permissions.
#[test]
fn test_scoped_delegation_expiry_does_not_affect_delegator() {
    let (env, client, admin) = setup_test();

    let delegator = Address::generate(&env);
    let delegatee = Address::generate(&env);

    client.register_user(
        &admin,
        &delegator,
        &Role::Optometrist,
        &String::from_str(&env, "Delegator"),
    );
    client.register_user(
        &admin,
        &delegatee,
        &Role::Patient,
        &String::from_str(&env, "Delegatee"),
    );

    // Delegator holds WriteRecord via their base role.
    assert!(client.check_permission(&delegator, &Permission::WriteRecord));

    // Delegate the Optometrist role to delegatee for 1 second.
    env.ledger().set_timestamp(500);
    let expire_at = 501u64; // expires almost immediately
    client.delegate_role(&delegator, &delegatee, &Role::Optometrist, &expire_at);

    // Advance past expiry.
    env.ledger().set_timestamp(600);

    let doctor = Address::generate(&env);
    client.register_user(
        &admin,
        &doctor,
        &Role::Optometrist,
        &String::from_str(&env, "Doc"),
    );

    // Delegatee attempts to act for delegator — should fail (delegation expired)
    let result = client.try_grant_access(
        &delegatee,
        &delegator,
        &doctor,
        &super::AccessLevel::Read,
        &3600,
    );
    assert!(result.is_err(), "Expired delegation must be rejected");

    // Delegator retains their own permissions unaffected.
    assert!(client.check_permission(&delegator, &Permission::WriteRecord));
}

// ─────────────────────────────────────────────────────────────────────────────
// #479 — Institution sharing via ACL groups
// ─────────────────────────────────────────────────────────────────────────────

/// Adding multiple practitioners to a shared group grants all of them the
/// same permissions simultaneously (institution sharing pattern).
#[test]
fn test_institution_group_grants_access_to_all_members() {
    let (env, client, admin) = setup_test();

    let practitioner_a = Address::generate(&env);
    let practitioner_b = Address::generate(&env);
    let practitioner_c = Address::generate(&env);

    for (addr, name) in [
        (&practitioner_a, "PA"),
        (&practitioner_b, "PB"),
        (&practitioner_c, "PC"),
    ] {
        client.register_user(&admin, addr, &Role::Staff, &String::from_str(&env, name));
    }

    // Staff base role does not include ReadAnyRecord.
    assert!(!client.check_permission(&practitioner_a, &Permission::ReadAnyRecord));

    let institution_group = String::from_str(&env, "Teye Eye Clinic");
    let mut perms = Vec::new(&env);
    perms.push_back(Permission::ReadAnyRecord);
    client.create_acl_group(&admin, &institution_group, &perms);

    // Add all three to the institution group.
    for addr in [&practitioner_a, &practitioner_b, &practitioner_c] {
        client.add_user_to_group(&admin, addr, &institution_group);
    }

    // All three should now have the institution-level permission.
    assert!(client.check_permission(&practitioner_a, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&practitioner_b, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&practitioner_c, &Permission::ReadAnyRecord));

    // Removing one practitioner revokes only their access.
    client.remove_user_from_group(&admin, &practitioner_b, &institution_group);

    assert!(client.check_permission(&practitioner_a, &Permission::ReadAnyRecord));
    assert!(!client.check_permission(&practitioner_b, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&practitioner_c, &Permission::ReadAnyRecord));
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #36 — Happy-path unit tests for RBAC endpoints
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_happy_path_grant_custom_permission_endpoint() {
    let (env, client, admin) = setup_test();

    let staff = Address::generate(&env);
    client.register_user(
        &admin,
        &staff,
        &Role::Staff,
        &String::from_str(&env, "StaffMember"),
    );

    // Baseline: Staff role does NOT have WriteRecord or ManageAccess
    assert!(!client.check_permission(&staff, &Permission::WriteRecord));
    assert!(!client.check_permission(&staff, &Permission::ManageAccess));

    // Admin grants WriteRecord to staff
    let res1 = client.try_grant_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert!(res1.is_ok());

    // Admin grants ManageAccess to staff
    let res2 = client.try_grant_custom_permission(&admin, &staff, &Permission::ManageAccess);
    assert!(res2.is_ok());

    // Staff now holds both granted permissions
    assert!(client.check_permission(&staff, &Permission::WriteRecord));
    assert!(client.check_permission(&staff, &Permission::ManageAccess));
}

#[test]
fn test_happy_path_revoke_custom_permission_endpoint() {
    let (env, client, admin) = setup_test();

    let optometrist = Address::generate(&env);
    client.register_user(
        &admin,
        &optometrist,
        &Role::Optometrist,
        &String::from_str(&env, "DoctorOpto"),
    );

    // Baseline: Optometrist role has ManageUsers and WriteRecord
    assert!(client.check_permission(&optometrist, &Permission::ManageUsers));
    assert!(client.check_permission(&optometrist, &Permission::WriteRecord));

    // Revoke ManageUsers permission from optometrist
    let res_revoke =
        client.try_revoke_custom_permission(&admin, &optometrist, &Permission::ManageUsers);
    assert!(res_revoke.is_ok());

    // ManageUsers is revoked, but WriteRecord remains intact
    assert!(!client.check_permission(&optometrist, &Permission::ManageUsers));
    assert!(client.check_permission(&optometrist, &Permission::WriteRecord));

    // Re-grant ManageUsers permission to optometrist
    let res_grant =
        client.try_grant_custom_permission(&admin, &optometrist, &Permission::ManageUsers);
    assert!(res_grant.is_ok());
    assert!(client.check_permission(&optometrist, &Permission::ManageUsers));
}

#[test]
fn test_happy_path_delegate_role_endpoint() {
    let (env, client, admin) = setup_test();

    let delegator = Address::generate(&env);
    let delegatee = Address::generate(&env);

    client.register_user(
        &admin,
        &delegator,
        &Role::Optometrist,
        &String::from_str(&env, "DelegatorDoc"),
    );
    client.register_user(
        &admin,
        &delegatee,
        &Role::Staff,
        &String::from_str(&env, "DelegateeStaff"),
    );

    // Delegatee as staff cannot write records initially
    assert!(!client.check_permission(&delegatee, &Permission::WriteRecord));

    // Happy-path with a future expiration timestamp
    let future_time = env.ledger().timestamp() + 7200;
    let res = client.try_delegate_role(&delegator, &delegatee, &Role::Optometrist, &future_time);
    assert!(res.is_ok());

    // Happy-path with non-expiring delegation (expires_at = 0)
    let res_indefinite = client.try_delegate_role(&delegator, &delegatee, &Role::Optometrist, &0);
    assert!(res_indefinite.is_ok());
}

#[test]
fn test_happy_path_acl_group_lifecycle_endpoints() {
    let (env, client, admin) = setup_test();

    let user_a = Address::generate(&env);
    let user_b = Address::generate(&env);

    client.register_user(
        &admin,
        &user_a,
        &Role::Patient,
        &String::from_str(&env, "UserA"),
    );
    client.register_user(
        &admin,
        &user_b,
        &Role::Staff,
        &String::from_str(&env, "UserB"),
    );

    // 1. Create ACL group with permissions
    let group_name = String::from_str(&env, "ClinicalAuditors");
    let mut perms = Vec::new(&env);
    perms.push_back(Permission::ReadAnyRecord);
    perms.push_back(Permission::WriteRecord);

    let res_create = client.try_create_acl_group(&admin, &group_name, &perms);
    assert!(res_create.is_ok());

    // 2. Add user to group
    let res_add_a = client.try_add_user_to_group(&admin, &user_a, &group_name);
    assert!(res_add_a.is_ok());
    let res_add_b = client.try_add_user_to_group(&admin, &user_b, &group_name);
    assert!(res_add_b.is_ok());

    // 3. Query get_user_groups endpoint
    let groups_a = client.get_user_groups(&user_a);
    assert_eq!(groups_a.len(), 1);
    assert_eq!(groups_a.get(0).unwrap(), group_name);

    // Both users now inherit permissions from the group
    assert!(client.check_permission(&user_a, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&user_a, &Permission::WriteRecord));
    assert!(client.check_permission(&user_b, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&user_b, &Permission::WriteRecord));

    // 4. Create and add to a second group
    let group_2 = String::from_str(&env, "SupportTeam");
    let mut perms_2 = Vec::new(&env);
    perms_2.push_back(Permission::ManageAccess);
    assert!(client
        .try_create_acl_group(&admin, &group_2, &perms_2)
        .is_ok());
    assert!(client
        .try_add_user_to_group(&admin, &user_a, &group_2)
        .is_ok());

    let groups_a_updated = client.get_user_groups(&user_a);
    assert_eq!(groups_a_updated.len(), 2);
    assert!(client.check_permission(&user_a, &Permission::ManageAccess));

    // 5. Remove user from first group
    let res_remove = client.try_remove_user_from_group(&admin, &user_a, &group_name);
    assert!(res_remove.is_ok());

    // User A loses permissions from group 1, but retains group 2
    assert!(!client.check_permission(&user_a, &Permission::ReadAnyRecord));
    assert!(!client.check_permission(&user_a, &Permission::WriteRecord));
    assert!(client.check_permission(&user_a, &Permission::ManageAccess));
    assert_eq!(client.get_user_groups(&user_a).len(), 1);

    // User B was unaffected by User A's removal
    assert!(client.check_permission(&user_b, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&user_b, &Permission::WriteRecord));
}

#[test]
fn test_happy_path_create_access_policy_endpoint() {
    let (env, client, admin) = setup_test();

    let policy_id = String::from_str(&env, "POL-RESEARCH-001");
    let policy_name = String::from_str(&env, "Research Protocol Access");

    let res = client.try_create_access_policy(
        &admin,
        &policy_id,
        &policy_name,
        &Role::Ophthalmologist,
        &TimeRestriction::None,
        &CredentialType::ResearchCredentials,
        &SensitivityLevel::Confidential,
        &true,
    );
    assert!(res.is_ok());

    // Second policy with different constraints
    let policy_id_2 = String::from_str(&env, "POL-EMERGENCY-002");
    let policy_name_2 = String::from_str(&env, "Emergency Treatment Access");
    let res_2 = client.try_create_access_policy(
        &admin,
        &policy_id_2,
        &policy_name_2,
        &Role::Optometrist,
        &TimeRestriction::BusinessHours,
        &CredentialType::EmergencyCredentials,
        &SensitivityLevel::Standard,
        &false,
    );
    assert!(res_2.is_ok());
}

#[test]
fn test_happy_path_set_user_credential_endpoint() {
    let (env, client, admin) = setup_test();

    let doctor = Address::generate(&env);
    client.register_user(
        &admin,
        &doctor,
        &Role::Ophthalmologist,
        &String::from_str(&env, "DrSmith"),
    );

    // Set MedicalLicense credential
    let res = client.try_set_user_credential(&admin, &doctor, &CredentialType::MedicalLicense);
    assert!(res.is_ok());

    // Update credential to ResearchCredentials
    let res_update =
        client.try_set_user_credential(&admin, &doctor, &CredentialType::ResearchCredentials);
    assert!(res_update.is_ok());

    // Set EmergencyCredentials
    let res_emergency =
        client.try_set_user_credential(&admin, &doctor, &CredentialType::EmergencyCredentials);
    assert!(res_emergency.is_ok());
}

#[test]
fn test_happy_path_set_record_sensitivity_endpoint() {
    let (env, client, admin) = setup_test();

    let patient = Address::generate(&env);
    let provider = Address::generate(&env);

    client.register_user(
        &admin,
        &patient,
        &Role::Patient,
        &String::from_str(&env, "PatientJane"),
    );
    client.register_user(
        &admin,
        &provider,
        &Role::Optometrist,
        &String::from_str(&env, "ProviderDan"),
    );

    let data_hash = String::from_str(&env, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
    let record_id = client.add_record(
        &provider,
        &patient,
        &provider,
        &RecordType::Examination,
        &data_hash,
    );

    // Provider sets record sensitivity to Confidential
    let res_provider =
        client.try_set_record_sensitivity(&provider, &record_id, &SensitivityLevel::Confidential);
    assert!(res_provider.is_ok());

    // Admin updates record sensitivity to Restricted
    let res_admin =
        client.try_set_record_sensitivity(&admin, &record_id, &SensitivityLevel::Restricted);
    assert!(res_admin.is_ok());
}

#[test]
fn test_happy_path_check_permission_all_roles() {
    let (env, client, admin) = setup_test();

    let ophthalmologist = Address::generate(&env);
    let optometrist = Address::generate(&env);
    let staff = Address::generate(&env);
    let patient = Address::generate(&env);

    client.register_user(
        &admin,
        &ophthalmologist,
        &Role::Ophthalmologist,
        &String::from_str(&env, "Ophth"),
    );
    client.register_user(
        &admin,
        &optometrist,
        &Role::Optometrist,
        &String::from_str(&env, "Opto"),
    );
    client.register_user(
        &admin,
        &staff,
        &Role::Staff,
        &String::from_str(&env, "Staff"),
    );
    client.register_user(
        &admin,
        &patient,
        &Role::Patient,
        &String::from_str(&env, "Patient"),
    );

    // Admin has full permissions
    assert!(client.check_permission(&admin, &Permission::SystemAdmin));
    assert!(client.check_permission(&admin, &Permission::ManageUsers));
    assert!(client.check_permission(&admin, &Permission::WriteRecord));
    assert!(client.check_permission(&admin, &Permission::ManageAccess));
    assert!(client.check_permission(&admin, &Permission::ReadAnyRecord));

    // Ophthalmologist has clinical and user management permissions, but not SystemAdmin
    assert!(!client.check_permission(&ophthalmologist, &Permission::SystemAdmin));
    assert!(client.check_permission(&ophthalmologist, &Permission::ManageUsers));
    assert!(client.check_permission(&ophthalmologist, &Permission::WriteRecord));
    assert!(client.check_permission(&ophthalmologist, &Permission::ManageAccess));
    assert!(client.check_permission(&ophthalmologist, &Permission::ReadAnyRecord));

    // Optometrist has clinical and user management permissions, but not SystemAdmin
    assert!(!client.check_permission(&optometrist, &Permission::SystemAdmin));
    assert!(client.check_permission(&optometrist, &Permission::ManageUsers));
    assert!(client.check_permission(&optometrist, &Permission::WriteRecord));
    assert!(client.check_permission(&optometrist, &Permission::ManageAccess));
    assert!(client.check_permission(&optometrist, &Permission::ReadAnyRecord));

    // Staff has only ManageUsers
    assert!(!client.check_permission(&staff, &Permission::SystemAdmin));
    assert!(client.check_permission(&staff, &Permission::ManageUsers));
    assert!(!client.check_permission(&staff, &Permission::WriteRecord));
    assert!(!client.check_permission(&staff, &Permission::ManageAccess));
    assert!(!client.check_permission(&staff, &Permission::ReadAnyRecord));

    // Patient has no global permissions
    assert!(!client.check_permission(&patient, &Permission::SystemAdmin));
    assert!(!client.check_permission(&patient, &Permission::ManageUsers));
    assert!(!client.check_permission(&patient, &Permission::WriteRecord));
    assert!(!client.check_permission(&patient, &Permission::ManageAccess));
    assert!(!client.check_permission(&patient, &Permission::ReadAnyRecord));
}

// ======================== RBAC events (#38) ========================

fn register(
    env: &Env,
    client: &VisionRecordsContractClient,
    admin: &Address,
    role: Role,
) -> Address {
    let user = Address::generate(env);
    client.register_user(admin, &user, &role, &String::from_str(env, "User"));
    user
}

#[test]
fn test_permission_changes_emit_events_only_on_change() {
    let (env, client, admin) = setup_test();
    let staff = register(&env, &client, &admin, Role::Staff);

    client.grant_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("PERM_GRT"), staff.clone()).into_val(&env),
                PermissionGrantedEvent {
                    user: staff.clone(),
                    permission: Permission::WriteRecord,
                    granted_by: admin.clone(),
                    timestamp: env.ledger().timestamp(),
                }
                .into_val(&env),
            ),
        ]
    );
    // Granting a permission already held changes nothing.
    client.grant_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert!(env.events().all().events().is_empty());

    client.revoke_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("PERM_REV"), staff.clone()).into_val(&env),
                PermissionRevokedEvent {
                    user: staff.clone(),
                    permission: Permission::WriteRecord,
                    revoked_by: admin.clone(),
                    timestamp: env.ledger().timestamp(),
                }
                .into_val(&env),
            ),
        ]
    );
    client.revoke_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert!(env.events().all().events().is_empty());
}

#[test]
fn test_role_delegation_emits_event() {
    let (env, client, admin) = setup_test();
    let delegator = register(&env, &client, &admin, Role::Optometrist);
    let delegatee = Address::generate(&env);
    let expires_at = env.ledger().timestamp() + 86_400;

    client.delegate_role(&delegator, &delegatee, &Role::Optometrist, &expires_at);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (
                    symbol_short!("ROLE_DEL"),
                    delegator.clone(),
                    delegatee.clone()
                )
                    .into_val(&env),
                RoleDelegatedEvent {
                    delegator,
                    delegatee,
                    role: Role::Optometrist,
                    expires_at,
                    timestamp: env.ledger().timestamp(),
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_acl_group_changes_emit_events_only_on_change() {
    let (env, client, admin) = setup_test();
    let user = Address::generate(&env);
    let group = String::from_str(&env, "researchers");
    let permissions = vec![&env, Permission::ReadAnyRecord];

    client.create_acl_group(&admin, &group, &permissions);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("GRP_CRT"), group.clone()).into_val(&env),
                AclGroupCreatedEvent {
                    group_name: group.clone(),
                    permissions,
                    created_by: admin.clone(),
                    timestamp: env.ledger().timestamp(),
                }
                .into_val(&env),
            ),
        ]
    );

    let membership = AclGroupMembershipEvent {
        user: user.clone(),
        group_name: group.clone(),
        changed_by: admin.clone(),
        timestamp: env.ledger().timestamp(),
    };
    client.add_user_to_group(&admin, &user, &group);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("GRP_ADD"), user.clone(), group.clone()).into_val(&env),
                membership.clone().into_val(&env),
            ),
        ]
    );
    client.add_user_to_group(&admin, &user, &group);
    assert!(env.events().all().events().is_empty());

    client.remove_user_from_group(&admin, &user, &group);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("GRP_REM"), user.clone(), group.clone()).into_val(&env),
                membership.into_val(&env),
            ),
        ]
    );
    client.remove_user_from_group(&admin, &user, &group);
    assert!(env.events().all().events().is_empty());
    assert!(client.get_user_groups(&user).is_empty());
}

// ======================== RBAC string validation (#39) ========================

#[test]
fn test_rbac_strings_are_length_bounded() {
    let (env, client, admin) = setup_test();
    let user = Address::generate(&env);
    let empty = String::from_str(&env, "");
    let too_long = String::from_bytes(&env, &[b'g'; MAX_RBAC_STRING_LEN as usize + 1]);
    let longest = String::from_bytes(&env, &[b'g'; MAX_RBAC_STRING_LEN as usize]);
    let invalid = Err(Ok(ContractError::InvalidInput));

    for name in [&empty, &too_long] {
        assert_eq!(
            client.try_create_acl_group(&admin, name, &Vec::new(&env)),
            invalid
        );
        assert_eq!(client.try_add_user_to_group(&admin, &user, name), invalid);
        assert_eq!(
            client.try_remove_user_from_group(&admin, &user, name),
            invalid
        );
    }
    client.create_acl_group(&admin, &longest, &Vec::new(&env));
    client.add_user_to_group(&admin, &user, &longest);

    let create_policy = |policy_id: &String, name: &String| {
        client.try_create_access_policy(
            &admin,
            policy_id,
            name,
            &Role::Optometrist,
            &TimeRestriction::None,
            &CredentialType::None,
            &SensitivityLevel::Standard,
            &false,
        )
    };
    for bad in [&empty, &too_long] {
        assert_eq!(create_policy(bad, &longest), invalid);
        assert_eq!(create_policy(&longest, bad), invalid);
    }
    assert_eq!(create_policy(&longest, &longest), Ok(Ok(())));
}

#[test]
fn test_access_control_micro_contract_integration() {
    let (env, client, admin) = setup_test();

    // 1. Deploy the AccessControl micro-contract
    let access_control_id = env.register(access_control::AccessControlContract, ());
    let ac_client = access_control::AccessControlContractClient::new(&env, &access_control_id);
    ac_client.initialize(&admin);

    // 2. Configure access_control in vision_records
    assert!(client.get_access_control().is_none());
    client.set_access_control(&admin, &access_control_id);
    assert_eq!(client.get_access_control(), Some(access_control_id));

    // 3. User initially has no permissions in access_control
    let doctor = Address::generate(&env);
    assert!(!client.check_permission(&doctor, &Permission::WriteRecord));

    // 4. Assign role in access_control micro-contract
    ac_client.assign_role(&admin, &doctor, &access_control::Role::Ophthalmologist, &0);

    // 5. VisionRecords queries access_control micro-contract cross-contract and confirms permission!
    assert!(client.check_permission(&doctor, &Permission::WriteRecord));
    assert!(client.check_permission(&doctor, &Permission::ReadAnyRecord));
    assert!(client.check_permission(&doctor, &Permission::ManageAccess));
    assert!(client.check_permission(&doctor, &Permission::ManageUsers));
    assert!(!client.check_permission(&doctor, &Permission::SystemAdmin));
}
