use soroban_sdk::Env;
use teye_delegation::{DelegationContract, DelegationContractClient};

#[test]
fn test_init() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(DelegationContract, ());
    let _client = DelegationContractClient::new(&env, &contract_id);
}
