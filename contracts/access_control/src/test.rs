#![cfg(test)]

use crate::{
    AccessControlContract, AccessControlContractClient, CredentialType, Permission,
    PolicyConditions, Role, SensitivityLevel, TimeRestriction,
};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    Address, Env, Vec,
};

#[test]
fn test_initialize_and_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    assert_eq!(client.get_admin(), Some(admin.clone()));

    // Propose admin
    let new_admin = Address::generate(&env);
    client.propose_admin(&admin, &new_admin);

    // Accept admin
    client.accept_admin(&new_admin);
    assert_eq!(client.get_admin(), Some(new_admin));
}

#[test]
fn test_roles_and_permissions() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let doctor = Address::generate(&env);
    let patient = Address::generate(&env);

    // Admin has ManageUsers, so assign Optometrist to doctor
    client.assign_role(&admin, &doctor, &Role::Optometrist, &0);
    assert_eq!(client.get_role(&doctor), Role::Optometrist);

    // Optometrist can WriteRecord and ReadAnyRecord
    assert!(client.has_permission(&doctor, &Permission::WriteRecord));
    assert!(client.has_permission(&doctor, &Permission::ReadAnyRecord));
    assert!(!client.has_permission(&doctor, &Permission::SystemAdmin));

    // Patient has no global permissions
    client.assign_role(&admin, &patient, &Role::Patient, &0);
    assert!(!client.has_permission(&patient, &Permission::WriteRecord));
}

#[test]
fn test_custom_permissions() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let staff = Address::generate(&env);
    client.assign_role(&admin, &staff, &Role::Staff, &0);

    // Staff cannot write record by default
    assert!(!client.has_permission(&staff, &Permission::WriteRecord));

    // Grant custom permission
    client.grant_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert!(client.has_permission(&staff, &Permission::WriteRecord));

    // Revoke custom permission
    client.revoke_custom_permission(&admin, &staff, &Permission::WriteRecord);
    assert!(!client.has_permission(&staff, &Permission::WriteRecord));
}

#[test]
fn test_delegation() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let ophth = Address::generate(&env);
    let assistant = Address::generate(&env);

    client.assign_role(&admin, &ophth, &Role::Ophthalmologist, &0);

    // Scoped delegation of WriteRecord to assistant
    let mut perms = Vec::new(&env);
    perms.push_back(Permission::WriteRecord);
    client.delegate_permissions(&ophth, &assistant, &perms, &0);

    assert!(client.has_delegated_permission(&ophth, &assistant, &Permission::WriteRecord));
    assert!(!client.has_delegated_permission(&ophth, &assistant, &Permission::SystemAdmin));

    // Revoke scoped delegation
    client.revoke_scoped_delegation(&ophth, &assistant);
    assert!(!client.has_delegated_permission(&ophth, &assistant, &Permission::WriteRecord));
}

#[test]
fn test_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let user = Address::generate(&env);

    // When disabled, all pass
    assert!(!client.is_whitelist_enabled());
    assert!(client.check_whitelist(&user));

    // Enable whitelist
    client.set_whitelist_enabled(&admin, &true);
    assert!(client.is_whitelist_enabled());
    assert!(!client.check_whitelist(&user));

    // Add to whitelist
    client.add_to_whitelist(&admin, &user);
    assert!(client.check_whitelist(&user));
    assert!(client.is_whitelisted(&user));

    // Remove from whitelist
    client.remove_from_whitelist(&admin, &user);
    assert!(!client.check_whitelist(&user));
}

#[test]
fn test_acl_groups() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let user = Address::generate(&env);
    let group_name = symbol_short!("CLINIC_A");

    let mut perms = Vec::new(&env);
    perms.push_back(Permission::ReadAnyRecord);

    client.create_group(&admin, &group_name, &perms);
    client.add_to_group(&admin, &user, &group_name);

    assert!(client.has_permission(&user, &Permission::ReadAnyRecord));

    let groups = client.get_user_groups(&user);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups.get(0), Some(group_name.clone()));

    client.remove_from_group(&admin, &user, &group_name);
    assert!(!client.has_permission(&user, &Permission::ReadAnyRecord));
}

#[test]
fn test_abac_policy() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1700000000);
    let contract_id = env.register(AccessControlContract, ());
    let client = AccessControlContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let doctor = Address::generate(&env);
    client.assign_role(&admin, &doctor, &Role::Optometrist, &0);
    client.set_user_credential(&admin, &doctor, &CredentialType::MedicalLicense);

    let policy_id = symbol_short!("EXAM_POL");
    let conditions = PolicyConditions {
        required_role: Role::Optometrist,
        time_restriction: TimeRestriction::None,
        required_credential: CredentialType::MedicalLicense,
        min_sensitivity_level: SensitivityLevel::Standard,
        consent_required: false,
    };

    client.create_access_policy(&admin, &policy_id, &symbol_short!("EXAM"), &conditions);
    client.set_record_sensitivity(&doctor, &101, &SensitivityLevel::Standard);

    assert!(client.evaluate_access_policy(&policy_id, &doctor, &101, &1700000000));
}
