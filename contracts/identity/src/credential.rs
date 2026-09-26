#![allow(deprecated)]
use soroban_sdk::{symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};
/// Serialized representation of a BN254 G1 affine point (64 bytes: 32 bytes X, 32 bytes Y).
pub type VkG1Point = Bytes;

/// Serialized representation of a BN254 G2 affine point (128 bytes: 64 bytes X [c0, c1], 64 bytes Y [c0, c1]).
pub type VkG2Point = Bytes;

const ZK_VERIFIER: Symbol = symbol_short!("ZK_VER");

/// Errors that can occur during ZK credential verification operations.
#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CredentialError {
    /// Caller is not authorized to perform the requested credential operation.
    Unauthorized = 100,
    /// The ZK verifier contract address has not been configured in contract storage.
    VerifierNotSet = 101,
    /// ZK proof verification failed, malformed proof buffers, or invalid public inputs.
    ZkVerificationFailed = 102,
    /// Nonce provided is invalid or has already been consumed (replay protection).
    InvalidNonce = 103,
    /// Credential expiration timestamp (`expires_at`) is in the past relative to current ledger time.
    CredentialExpired = 104,
}

pub fn set_zk_verifier(env: &Env, verifier_id: &Address) {
    env.storage().instance().set(&ZK_VERIFIER, verifier_id);
}

pub fn get_zk_verifier(env: &Env) -> Option<Address> {
    env.storage().instance().get(&ZK_VERIFIER)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_zk_credential(
    env: &Env,
    user: &Address,
    resource_id: BytesN<32>,
    proof_a: Bytes,
    proof_b: Bytes,
    proof_c: Bytes,
    public_inputs: Vec<BytesN<32>>,
    expires_at: u64,
    nonce: u64,
) -> Result<bool, CredentialError> {
    if env.ledger().timestamp() > expires_at {
        return Err(CredentialError::CredentialExpired);
    }

    let verifier_id = get_zk_verifier(env).ok_or(CredentialError::VerifierNotSet)?;
    let client = zk_verifier::ZkVerifierContractClient::new(env, &verifier_id);

    // Reconstruct the proof points from raw bytes.
    // The proof bytes are expected to be in G1 (64 bytes: 32x, 32y) and G2 (128 bytes: 32x0, 32x1, 32y0, 32y1) format.
    let mut a_buf = [0u8; 64];
    if proof_a.len() < 64 {
        return Err(CredentialError::ZkVerificationFailed);
    }
    proof_a.copy_into_slice(&mut a_buf);

    let mut b_buf = [0u8; 128];
    if proof_b.len() < 128 {
        return Err(CredentialError::ZkVerificationFailed);
    }
    proof_b.copy_into_slice(&mut b_buf);

    let mut c_buf = [0u8; 64];
    if proof_c.len() < 64 {
        return Err(CredentialError::ZkVerificationFailed);
    }
    proof_c.copy_into_slice(&mut c_buf);

    let proof = zk_verifier::Proof {
        a: zk_verifier::vk::G1Point {
            x: BytesN::from_array(env, &a_buf[0..32].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            y: BytesN::from_array(env, &a_buf[32..64].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
        },
        b: zk_verifier::vk::G2Point {
            x: (
                BytesN::from_array(env, &b_buf[0..32].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
                BytesN::from_array(env, &b_buf[32..64].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            ),
            y: (
                BytesN::from_array(env, &b_buf[64..96].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
                BytesN::from_array(env, &b_buf[96..128].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            ),
        },
        c: zk_verifier::vk::G1Point {
            x: BytesN::from_array(env, &c_buf[0..32].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            y: BytesN::from_array(env, &c_buf[32..64].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
        },
    };

    let request = zk_verifier::AccessRequest {
        user: user.clone(),
        resource_id,
        proof,
        public_inputs,
        expires_at,
        nonce,
    };

    let valid = client.verify_access(&request);
    if valid {
        Ok(true)
    } else {
        Err(CredentialError::ZkVerificationFailed)
    }
}
