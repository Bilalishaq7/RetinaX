use soroban_sdk::{testutils::Address as _, Env};
use teye_delegation::{DelegationContract, DelegationContractClient};

#[test]
fn test_revocation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(DelegationContract, ());
    let _client = DelegationContractClient::new(&env, &contract_id);

    let _owner = soroban_sdk::Address::generate(&env);
    let _delegate_a = soroban_sdk::Address::generate(&env);
    let _delegate_b = soroban_sdk::Address::generate(&env);
    let _delegate_c = soroban_sdk::Address::generate(&env);
}
