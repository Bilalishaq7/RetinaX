use soroban_sdk::{testutils::Ledger as _, Env};
use teye_delegation::{DelegationContract, DelegationContractClient};

#[test]
fn test_time() {
    let env = Env::default();
    env.mock_all_auths();

    env.ledger().with_mut(|li| {
        li.timestamp = 1000;
    });

    let contract_id = env.register(DelegationContract, ());
    let _client = DelegationContractClient::new(&env, &contract_id);
}
