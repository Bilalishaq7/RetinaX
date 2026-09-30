use soroban_sdk::{testutils::{Address as _, Ledger as _}, Env};
use teye_delegation::{DelegationContract, DelegationContractClient};

#[test]
fn test_expiration() {
    let env = Env::default();
    env.mock_all_auths();

    env.ledger().with_mut(|li| {
        li.timestamp = 1000;
    });

    let contract_id = env.register(DelegationContract, ());
    let _client = DelegationContractClient::new(&env, &contract_id);

    let _owner = soroban_sdk::Address::generate(&env);
    let _delegate = soroban_sdk::Address::generate(&env);
}
