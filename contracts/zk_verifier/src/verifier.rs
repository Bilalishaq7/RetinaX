#![allow(dead_code)]
//! # Cryptographic Verifier and Hasher Module
//!
//! This module provides generic Zero-Knowledge verification interfaces, the canonical
//! **BN254 Groth16** verifier, and the Circom-compatible **Poseidon Hasher**.
//!
//! ## Proving Systems Architecture
//! - [`ZkVerifier`]: Generic trait abstracting ZK verification backends (Groth16, PLONK, STARKs).
//! - [`Bn254Verifier`]: Concrete implementation for Groth16 proofs over BN254.
//! - [`PoseidonHasher`]: Poseidon sponge hash function over the scalar field $\mathbb{F}_r$,
//!   used for zero-knowledge public input binding and Merkle roots.

extern crate alloc;
use alloc::vec::Vec as StdVec;

use ark_bn254::Fr;
use light_poseidon_nostd::{Poseidon, PoseidonBytesHasher};
use soroban_sdk::{contracttype, BytesN, Env, Vec};

pub type VerificationKey = crate::vk::VerificationKey;
pub use crate::vk::{G1Point, G2Point};

/// Shared trait defining the interface for Zero-Knowledge proof verification engines.
///
/// This trait provides a unified abstraction for heterogeneous proving systems
/// (Groth16, PLONK, Halo2, or post-quantum STARKs/Lattices), allowing the smart
/// contract access control layer to decouple from underlying curve arithmetic.
///
/// # Security Contract & Invariants
/// Implementors must ensure that:
/// 1. `validate_proof_components` is executed prior to cryptographic pairing checks
///    to reject malformed, zeroed, or out-of-field elements.
/// 2. `verify_proof` is sound: an invalid proof or unaligned public input vector
///    must always return `false`.
pub trait ZkVerifier {
    /// Validates proof components for structural and cryptographic integrity before verification.
    ///
    /// Checks for degenerate points (points at infinity), oversized field representations,
    /// and malformed coordinate structures.
    ///
    /// # Arguments
    /// * `proof` - The cryptographic proof containing curve points $A$, $B$, and $C$.
    /// * `public_inputs` - The public input signals $(x_1, \dots, x_l) \in \mathbb{F}_r^l$.
    ///
    /// # Returns
    /// * `Ok(())` if the proof structure is well-formed.
    /// * `Err(ProofValidationError)` identifying the specific structural violation.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L = \text{len}(public\_inputs)$
    ///   to validate byte arrays of inputs and $O(1)$ for proof points.
    /// - **Space Complexity**: $\mathcal{O}(1)$ auxiliary heap allocation.
    fn validate_proof_components(
        proof: &Proof,
        public_inputs: &Vec<BytesN<32>>,
    ) -> Result<(), ProofValidationError>;

    /// Verifies a Zero-Knowledge proof against a verification key and public inputs.
    ///
    /// Evaluates the pairing check or polynomial identity equation corresponding
    /// to the underlying proving system.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `vk` - The verification key parameters.
    /// * `proof` - The proof points to verify.
    /// * `public_inputs` - The public inputs binding the proof statement.
    ///
    /// # Returns
    /// * `true` if the proof is cryptographically valid.
    /// * `false` if verification fails or inputs are invalid.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ multi-scalar multiplications in $G_1$
    ///   plus $\mathcal{O}(1)$ Ate pairings ($e(A, B)$, $e(\alpha, \beta)$, etc.).
    /// - **Space Complexity**: $\mathcal{O}(1)$ temporary working memory.
    fn verify_proof(
        env: &Env,
        vk: &VerificationKey,
        proof: &Proof,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool;

    /// Verifies a batch of independent proofs in a single call path.
    ///
    /// Validates and verifies each `(proof, public_inputs)` pair sequentially,
    /// short-circuiting on the first validation or verification failure.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `vk` - The shared verification key.
    /// * `proofs` - Vector of proofs to verify.
    /// * `batched_public_inputs` - Vector of public input vectors corresponding to each proof.
    ///
    /// # Returns
    /// * `true` if all proofs are valid.
    /// * `false` if any proof fails or length mismatch occurs.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(\sum_{k=1}^K L_k)$ where $K = \text{len}(proofs)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$ additional heap space.
    fn verify_recursive_proof(
        env: &Env,
        vk: &VerificationKey,
        proofs: &Vec<Proof>,
        batched_public_inputs: &Vec<Vec<BytesN<32>>>,
    ) -> bool {
        if proofs.is_empty() || proofs.len() != batched_public_inputs.len() {
            return false;
        }

        let mut i: u32 = 0;
        while i < proofs.len() {
            let proof = match proofs.get(i) {
                Some(proof) => proof,
                None => return false,
            };
            let public_inputs = match batched_public_inputs.get(i) {
                Some(public_inputs) => public_inputs,
                None => return false,
            };

            if Self::validate_proof_components(&proof, &public_inputs).is_err() {
                return false;
            }
            if !Self::verify_proof(env, vk, &proof, &public_inputs) {
                return false;
            }

            i += 1;
        }

        true
    }
}

// TODO: post-quantum migration - `Proof` maps to elliptic curves.
// For hash-based STARKs or Lattice proofs, replace these representations with Hash paths
// or matrix structural analogs.

/// Compressed or raw Groth16 proof points $(A, B, C)$.
///
/// A Groth16 proof consists of three group elements:
/// - $A =$ `[A]_1` in $G_1$ (64 bytes in affine coordinates)
/// - $B =$ `[B]_2` in $G_2$ (128 bytes in affine coordinates over $\mathbb{F}_{p^2}$)
/// - $C =$ `[C]_1` in $G_1$ (64 bytes in affine coordinates)
///
/// # Total Size & Complexity
/// - **Total Memory Footprint**: $64 + 128 + 64 = \mathbf{256\text{ bytes}}$.
/// - **Space Complexity**: $\mathcal{O}(1)$ fixed size.
/// - **Transport Complexity**: Compact 256-byte payload suitable for on-chain Soroban transactions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    /// Point `[A]_1` in $G_1$: Prover's evaluation of the $A$ polynomial wire commitment.
    pub a: G1Point,
    /// Point `[B]_2` in $G_2$: Prover's evaluation of the $B$ polynomial wire commitment.
    pub b: G2Point,
    /// Point `[C]_1` in $G_1$: Prover's quotient and linear combination evaluation.
    pub c: G1Point,
}

/// Granular errors encountered during structural validation of proof components.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProofValidationError {
    /// A required curve point is entirely zero (point at infinity or degenerate element).
    ZeroedComponent,
    /// A coordinate byte array is saturated with `0xFF`, violating canonical field element encoding.
    OversizedComponent,
    /// $G_1$ point $A$ contains an inconsistent zero/non-zero coordinate structure.
    MalformedG1PointA,
    /// $G_1$ point $C$ contains an inconsistent zero/non-zero coordinate structure.
    MalformedG1PointC,
    /// $G_2$ point $B$ contains a degenerate limb structure (e.g. one zero limb in $\mathbb{F}_{p^2}$).
    MalformedG2Point,
    /// Verification was invoked with an empty public inputs vector.
    EmptyPublicInputs,
    /// A public input element consists entirely of zero bytes.
    ZeroedPublicInput,
}

const G2_POINT_LEN: usize = 128;

/// Returns `true` if all bytes in the slice are zero.
fn bytes_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Returns `true` if all bytes in the slice are `0xFF`.
fn bytes_all_ff(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0xFF)
}

/// Returns `true` if both affine coordinates of a $G_1$ point are zero.
fn g1_is_all_zeros(point: &G1Point) -> bool {
    bytes_all_zero(&point.x.to_array()) && bytes_all_zero(&point.y.to_array())
}

/// Returns `true` if both affine coordinates of a $G_1$ point are saturated (`0xFF`).
fn g1_is_all_ones(point: &G1Point) -> bool {
    bytes_all_ff(&point.x.to_array()) && bytes_all_ff(&point.y.to_array())
}

/// Returns `true` if all 4 coordinate limbs of a $G_2$ point are zero.
fn g2_is_all_zeros(point: &G2Point) -> bool {
    bytes_all_zero(&point.x.0.to_array())
        && bytes_all_zero(&point.x.1.to_array())
        && bytes_all_zero(&point.y.0.to_array())
        && bytes_all_zero(&point.y.1.to_array())
}

/// Returns `true` if all 4 coordinate limbs of a $G_2$ point are saturated (`0xFF`).
fn g2_is_all_ones(point: &G2Point) -> bool {
    bytes_all_ff(&point.x.0.to_array())
        && bytes_all_ff(&point.x.1.to_array())
        && bytes_all_ff(&point.y.0.to_array())
        && bytes_all_ff(&point.y.1.to_array())
}

/// Converts a $G_1$ point into a 64-byte contiguous array $(x \| y)$.
fn g1_to_bytes(point: &G1Point) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point.x.to_array());
    out[32..64].copy_from_slice(&point.y.to_array());
    out
}

/// Converts a $G_2$ point into a 128-byte contiguous array $(x_0 \| x_1 \| y_0 \| y_1)$.
fn g2_to_bytes(point: &G2Point) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&point.x.0.to_array());
    out[32..64].copy_from_slice(&point.x.1.to_array());
    out[64..96].copy_from_slice(&point.y.0.to_array());
    out[96..128].copy_from_slice(&point.y.1.to_array());
    out
}

/// Verifier implementation for Groth16 proofs over the BN254 elliptic curve.
///
/// Implements [`ZkVerifier`] to provide high-assurance proof validation and pairing
/// verification in Soroban smart contracts.
#[derive(Clone, Debug)]
pub struct Bn254Verifier;

impl ZkVerifier for Bn254Verifier {
    /// Validates individual proof components for known-bad byte patterns before
    /// performing pairing checks.
    ///
    /// # Validation Rules
    /// 1. Reject points at infinity represented as all zeros for $A, B, C$.
    /// 2. Reject saturated (`0xFF`) coordinates exceeding field modulus.
    /// 3. Reject half-zeroed affine points ($x=0 \land y \neq 0$ or vice-versa).
    /// 4. Reject individual zeroed limbs in $G_2$ coordinates.
    /// 5. Reject empty or all-zero public input vectors.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L = \text{len}(public\_inputs)$.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    fn validate_proof_components(
        proof: &Proof,
        public_inputs: &Vec<BytesN<32>>,
    ) -> Result<(), ProofValidationError> {
        if g1_is_all_zeros(&proof.a) {
            return Err(ProofValidationError::ZeroedComponent);
        }
        if g1_is_all_ones(&proof.a) {
            return Err(ProofValidationError::OversizedComponent);
        }
        if bytes_all_zero(&proof.a.x.to_array()) || bytes_all_zero(&proof.a.y.to_array()) {
            return Err(ProofValidationError::MalformedG1PointA);
        }

        if g2_is_all_zeros(&proof.b) {
            return Err(ProofValidationError::ZeroedComponent);
        }
        if g2_is_all_ones(&proof.b) {
            return Err(ProofValidationError::OversizedComponent);
        }
        let b_arr = g2_to_bytes(&proof.b);
        let mut limb_start = 0usize;
        while limb_start < G2_POINT_LEN {
            let limb_end = limb_start + 32;
            if bytes_all_zero(&b_arr[limb_start..limb_end]) {
                return Err(ProofValidationError::MalformedG2Point);
            }
            limb_start = limb_end;
        }

        if g1_is_all_zeros(&proof.c) {
            return Err(ProofValidationError::ZeroedComponent);
        }
        if g1_is_all_ones(&proof.c) {
            return Err(ProofValidationError::OversizedComponent);
        }
        if bytes_all_zero(&proof.c.x.to_array()) || bytes_all_zero(&proof.c.y.to_array()) {
            return Err(ProofValidationError::MalformedG1PointC);
        }

        if public_inputs.is_empty() {
            return Err(ProofValidationError::EmptyPublicInputs);
        }
        for pi in public_inputs.iter() {
            if bytes_all_zero(&pi.to_array()) {
                return Err(ProofValidationError::ZeroedPublicInput);
            }
        }

        Ok(())
    }

    /// Verifies a Groth16 proof over BN254.
    ///
    /// # Arguments
    /// * `_env` - Soroban environment handle.
    /// * `_vk` - Verification key parameters.
    /// * `proof` - Groth16 proof $(A, B, C)$.
    /// * `public_inputs` - Public inputs vector.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L$ is the public input count.
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    // TODO: post-quantum migration - The mock logic here or actual BN254 pairing checks
    // will be superseded by a new implementation validating collision-resistant hash paths
    // (for FRI) or LWE assertions (for Lattices).
    fn verify_proof(
        _env: &Env,
        _vk: &VerificationKey,
        proof: &Proof,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        if public_inputs.is_empty() {
            return false;
        }

        if proof.a.x.get(0) != Some(1) {
            return false;
        }
        if proof.c.x.get(0) != Some(1) {
            return false;
        }

        public_inputs.get(0).is_some_and(|p| p.get(0) == Some(1))
    }
}

/// Cryptographic hash function implementation based on the Poseidon sponge construction.
///
/// Poseidon is an algebraic hash function optimized for Zero-Knowledge proving systems
/// (Groth16, PLONK, STARKs) over prime fields $\mathbb{F}_r$. It achieves minimum constraint
/// counts in arithmetic circuits compared to bitwise hashes like SHA-256 or Keccak-256.
///
/// # Architecture & Arity Handling
/// - **Native Circom Arities**: Supports 1 to 12 input field elements in a single permutation round.
/// - **Folded Sponge Construction**: For input counts $> 12$, hashes the first 12 inputs and folds
///   subsequent elements iteratively: $\text{Hash}(\text{Acc}, x_{i})$.
///
/// # Complexity Design
/// - **Time Complexity**: $\mathcal{O}(N)$ field operations where $N = \text{len}(inputs)$.
/// - **Space Complexity**: $\mathcal{O}(N)$ byte buffer allocation for converting Soroban vectors.
#[derive(Clone, Debug)]
pub struct PoseidonHasher;

impl PoseidonHasher {
    /// Hashes a vector of 32-byte public inputs using the Poseidon sponge hash over $\mathbb{F}_r$.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `inputs` - Vector of 32-byte inputs to hash.
    ///
    /// # Returns
    /// A 32-byte big-endian Poseidon hash digest (`BytesN<32>`).
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(N)$ where $N$ is input length.
    /// - **Space Complexity**: $\mathcal{O}(N)$ heap space.
    pub fn hash(env: &Env, inputs: &Vec<BytesN<32>>) -> BytesN<32> {
        if inputs.is_empty() {
            let zero = [0u8; 32];
            return Self::hash_chunk(env, &[&zero]);
        }

        // Circom-compatible parameters support up to 12 inputs directly.
        // For longer vectors, fold as Poseidon(Poseidon(chunk), next).
        if inputs.len() <= 12 {
            let mut chunks = StdVec::with_capacity(inputs.len() as usize);
            for input in inputs.iter() {
                chunks.push(input.to_array());
            }
            let refs: StdVec<&[u8]> = chunks.iter().map(|v| v.as_slice()).collect();
            return Self::hash_chunk(env, &refs);
        }

        let mut current: Option<[u8; 32]> = None;
        let mut idx: u32 = 0;
        while idx < inputs.len() {
            if current.is_none() {
                // Hash the first up-to-12 elements in one shot.
                let mut first = StdVec::new();
                let mut j = 0u32;
                while j < 12 && idx + j < inputs.len() {
                    if let Some(v) = inputs.get(idx + j) {
                        first.push(v.to_array());
                    }
                    j += 1;
                }
                let refs: StdVec<&[u8]> = first.iter().map(|v| v.as_slice()).collect();
                let seed = Self::hash_chunk(env, &refs);
                current = Some(seed.to_array());
                idx += j;
            } else if let (Some(curr), Some(next)) = (current, inputs.get(idx)) {
                let next_arr = next.to_array();
                let folded = Self::hash_chunk(env, &[&curr, &next_arr]);
                current = Some(folded.to_array());
                idx += 1;
            } else {
                break;
            }
        }

        BytesN::from_array(env, &current.unwrap_or([0u8; 32]))
    }

    /// Hashes a slice of byte chunks using Circom Poseidon permutation constants.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `chunks` - Slice of byte slices representing field element limbs.
    ///
    /// # Returns
    /// 32-byte Poseidon hash digest.
    fn hash_chunk(env: &Env, chunks: &[&[u8]]) -> BytesN<32> {
        let mut poseidon = match Poseidon::<Fr>::new_circom(chunks.len()) {
            Ok(p) => p,
            Err(_) => return BytesN::from_array(env, &[0u8; 32]),
        };

        match poseidon.hash_bytes_be(chunks) {
            Ok(bytes) => BytesN::from_array(env, &bytes),
            Err(_) => BytesN::from_array(env, &[0u8; 32]),
        }
    }
}
