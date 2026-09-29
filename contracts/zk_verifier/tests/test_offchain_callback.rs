#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env,
};
use zk_verifier::offchain::{build_offchain_verification_message, OffChainVerificationPayload};
use zk_verifier::{ContractError, ZkVerifierContract, ZkVerifierContractClient};


fn nonzero32(env: &Env, val: u8) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[0] = val;
    b[31] = val.wrapping_add(1);
    BytesN::from_array(env, &b)
}

fn setup_contract(env: &Env) -> (ZkVerifierContractClient<'static>, Address) {
    env.mock_all_auths();
    let contract_id = env.register(ZkVerifierContract, ());
    let client = ZkVerifierContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.initialize(&admin);
    (client, admin)
}

#[test]
fn test_offchain_verifier_registration() {
    let env = Env::default();
    let (client, admin) = setup_contract(&env);

    let verifier_pk = nonzero32(&env, 7);

    // Initial state: not trusted
    assert!(!client.is_trusted_verifier(&verifier_pk));

    // Admin registers trusted verifier
    client.set_trusted_verifier(&admin, &verifier_pk, &true);
    assert!(client.is_trusted_verifier(&verifier_pk));

    // Admin unregisters verifier
    client.set_trusted_verifier(&admin, &verifier_pk, &false);
    assert!(!client.is_trusted_verifier(&verifier_pk));
}

#[test]
fn test_offchain_proof_verification_success() {
    let env = Env::default();
    env.ledger().set_timestamp(1700000000);
    let (client, admin) = setup_contract(&env);

    // 1. Generate off-chain verifier Ed25519 keypair
    let mut secret_bytes = [0u8; 32];
    secret_bytes[0] = 42;
    secret_bytes[31] = 99;
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let verifier_pubkey = BytesN::from_array(&env, verifying_key.as_bytes());
    client.set_trusted_verifier(&admin, &verifier_pubkey, &true);

    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 10);
    let public_inputs_hash = nonzero32(&env, 11);
    let proof_hash = nonzero32(&env, 12);
    let expires_at = 1700003600; // valid for 1 hour
    let nonce = 0;

    // 2. Build canonical attestation message
    let msg_bytes = build_offchain_verification_message(
        &env,
        &user,
        &resource_id,
        &public_inputs_hash,
        &proof_hash,
        expires_at,
        nonce,
    );

    // 3. Sign canonical message with verifier's secret key
    let mut raw_msg = [0u8; 256];
    let msg_len = msg_bytes.len() as usize;
    msg_bytes.copy_into_slice(&mut raw_msg[..msg_len]);

    let sig = signing_key.sign(&raw_msg[..msg_len]);
    let signature = BytesN::from_array(&env, &sig.to_bytes());

    let payload = OffChainVerificationPayload {
        user: user.clone(),
        resource_id,
        public_inputs_hash,
        proof_hash,
        verifier_pubkey,
        expires_at,
        nonce,
        signature,
    };

    // 4. Verify on-chain via callback
    let result = client.verify_offchain_proof(&payload);
    assert!(result);

    // 5. Nonce must be incremented
    assert_eq!(client.get_nonce(&user), 1);
}

#[test]
fn test_offchain_proof_rejects_untrusted_verifier() {
    let env = Env::default();
    env.ledger().set_timestamp(1700000000);
    let (client, _admin) = setup_contract(&env);

    let mut secret_bytes = [0u8; 32];
    secret_bytes[0] = 77;
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifier_pubkey = BytesN::from_array(&env, signing_key.verifying_key().as_bytes());

    // NOT registered as trusted!
    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 1);
    let public_inputs_hash = nonzero32(&env, 2);
    let proof_hash = nonzero32(&env, 3);
    let expires_at = 1700003600;
    let nonce = 0;

    let payload = OffChainVerificationPayload {
        user: user.clone(),
        resource_id,
        public_inputs_hash,
        proof_hash,
        verifier_pubkey,
        expires_at,
        nonce,
        signature: BytesN::from_array(&env, &[0u8; 64]),
    };

    let result = client.try_verify_offchain_proof(&payload);
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));
}

#[test]
fn test_offchain_proof_rejects_expired() {
    let env = Env::default();
    env.ledger().set_timestamp(1700005000); // After expiry
    let (client, admin) = setup_contract(&env);

    let verifier_pubkey = nonzero32(&env, 9);
    client.set_trusted_verifier(&admin, &verifier_pubkey, &true);

    let user = Address::generate(&env);
    let payload = OffChainVerificationPayload {
        user: user.clone(),
        resource_id: nonzero32(&env, 1),
        public_inputs_hash: nonzero32(&env, 2),
        proof_hash: nonzero32(&env, 3),
        verifier_pubkey,
        expires_at: 1700001000, // Expired
        nonce: 0,
        signature: BytesN::from_array(&env, &[0u8; 64]),
    };

    let result = client.try_verify_offchain_proof(&payload);
    assert_eq!(result, Err(Ok(ContractError::MalformedProofData)));
}

#[test]
fn test_offchain_proof_rejects_replay_nonce() {
    let env = Env::default();
    env.ledger().set_timestamp(1700000000);
    let (client, admin) = setup_contract(&env);

    let mut secret_bytes = [0u8; 32];
    secret_bytes[0] = 55;
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifier_pubkey = BytesN::from_array(&env, signing_key.verifying_key().as_bytes());
    client.set_trusted_verifier(&admin, &verifier_pubkey, &true);

    let user = Address::generate(&env);
    let resource_id = nonzero32(&env, 1);
    let public_inputs_hash = nonzero32(&env, 2);
    let proof_hash = nonzero32(&env, 3);
    let expires_at = 1700003600;

    // First verification with nonce = 0
    let msg1 = build_offchain_verification_message(
        &env,
        &user,
        &resource_id,
        &public_inputs_hash,
        &proof_hash,
        expires_at,
        0,
    );
    let mut raw_msg1 = [0u8; 256];
    let len1 = msg1.len() as usize;
    msg1.copy_into_slice(&mut raw_msg1[..len1]);
    let sig1 = signing_key.sign(&raw_msg1[..len1]);

    let payload1 = OffChainVerificationPayload {
        user: user.clone(),
        resource_id: resource_id.clone(),
        public_inputs_hash: public_inputs_hash.clone(),
        proof_hash: proof_hash.clone(),
        verifier_pubkey: verifier_pubkey.clone(),
        expires_at,
        nonce: 0,
        signature: BytesN::from_array(&env, &sig1.to_bytes()),
    };

    assert!(client.verify_offchain_proof(&payload1));
    assert_eq!(client.get_nonce(&user), 1);

    // Replay attack: resubmitting payload1 with nonce 0 must fail
    let replay_result = client.try_verify_offchain_proof(&payload1);
    assert_eq!(replay_result, Err(Ok(ContractError::MalformedProofData)));
}
