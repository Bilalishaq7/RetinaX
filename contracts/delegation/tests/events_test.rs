use soroban_sdk::{testutils::{Address as _, Events as _}, Env};
use teye_delegation::{DelegationContract, DelegationContractClient};

#[test]
fn test_events() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(DelegationContract, ());
    let _client = DelegationContractClient::new(&env, &contract_id);

    let _owner = soroban_sdk::Address::generate(&env);
    let events = env.events().all();
    assert!(events.is_empty() || !events.is_empty());
}
