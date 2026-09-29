//! # Helper Utilities and Merkle Verifier Module
//!
//! This module contains helper constructs for building [`crate::AccessRequest`] instances
//! and verifying Merkle inclusion proofs using the algebraic [`crate::PoseidonHasher`].
//!
//! ## Key Capabilities
//! - [`ZkAccessHelper`]: Simplifies constructing well-formed access requests from raw byte arrays.
//! - [`MerkleVerifier`]: On-chain cryptographic verification of data membership in large medical datasets.

use crate::{
    verifier::{G1Point, G2Point, PoseidonHasher, Proof},
    AccessRequest,
};
use soroban_sdk::{BytesN, Env, Vec};

/// Utility for constructing standard [`AccessRequest`] structures from raw byte slices.
pub struct ZkAccessHelper;

impl ZkAccessHelper {
    /// Converts a raw byte slice into a fixed-size `BytesN<32>`.
    ///
    /// If `bytes.len() == 32`, copies the slice directly; otherwise pads with zeroes.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(1)$ (32-byte copy).
    /// - **Space Complexity**: $\mathcal{O}(1)$.
    fn to_bytesn32(env: &Env, bytes: &[u8]) -> BytesN<32> {
        let mut buf = [0u8; 32];
        if bytes.len() == 32 {
            buf.copy_from_slice(bytes);
        }
        BytesN::from_array(env, &buf)
    }

    /// Formats raw cryptographic proof points and public inputs into a standard [`AccessRequest`].
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `user` - The address of the requesting user.
    /// * `resource_id` - 32-byte resource identifier.
    /// * `proof_a` - 64-byte affine $G_1$ point $A$ $(x \| y)$.
    /// * `proof_b` - 128-byte affine $G_2$ point $B$ $(x_0 \| x_1 \| y_0 \| y_1)$.
    /// * `proof_c` - 64-byte affine $G_1$ point $C$ $(x \| y)$.
    /// * `public_inputs` - Array of 32-byte public input signals.
    /// * `expires_at` - Unix timestamp when authorization expires.
    ///
    /// # Returns
    /// An instantiated [`AccessRequest`] with default nonce `0`.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(L)$ where $L = \text{public\_inputs.len()}$.
    /// - **Space Complexity**: $\mathcal{O}(L)$ vector allocation.
    #[allow(clippy::too_many_arguments)]
    pub fn create_request(
        env: &Env,
        user: soroban_sdk::Address,
        resource_id: [u8; 32],
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_inputs: &[&[u8; 32]],
        expires_at: u64,
    ) -> AccessRequest {
        let mut pi_vec = Vec::new(env);
        for &pi in public_inputs {
            pi_vec.push_back(BytesN::from_array(env, pi));
        }

        AccessRequest {
            user,
            resource_id: BytesN::from_array(env, &resource_id),
            proof: Proof {
                a: G1Point {
                    x: Self::to_bytesn32(env, &proof_a[0..32]),
                    y: Self::to_bytesn32(env, &proof_a[32..64]),
                },
                b: G2Point {
                    x: (
                        Self::to_bytesn32(env, &proof_b[0..32]),
                        Self::to_bytesn32(env, &proof_b[32..64]),
                    ),
                    y: (
                        Self::to_bytesn32(env, &proof_b[64..96]),
                        Self::to_bytesn32(env, &proof_b[96..128]),
                    ),
                },
                c: G1Point {
                    x: Self::to_bytesn32(env, &proof_c[0..32]),
                    y: Self::to_bytesn32(env, &proof_c[32..64]),
                },
            },
            public_inputs: pi_vec,
            expires_at,
            nonce: 0, // Default nonce; caller should set appropriately for replay protection
        }
    }
}

/// Cryptographic Merkle tree proof verification engine using [`PoseidonHasher`].
///
/// Enables privacy-preserving data inclusion checks where a patient or provider
/// proves that a specific medical diagnosis or credential leaf is part of an on-chain
/// Merkle root commitment without revealing the complete dataset.
pub struct MerkleVerifier;

impl MerkleVerifier {
    /// Verifies a Merkle authentication path proving a leaf belongs to a tree with root `root`.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `root` - The expected 32-byte Merkle root hash.
    /// * `leaf` - The 32-byte leaf digest to verify.
    /// * `proof_path` - Vector of `(sibling_hash, is_left)` tuples:
    ///   - `sibling_hash`: The hash of the sibling node at this depth.
    ///   - `is_left`: `true` if sibling is on the left; `false` if sibling is on the right.
    ///
    /// # Returns
    /// * `true` if the computed root matches `*root`.
    /// * `false` if the path is invalid or exceeds maximum tree depth (32).
    ///
    /// # Proof Traversal Diagram
    /// ```text
    ///          root
    ///         /    \
    ///        h1     h2
    ///       /  \   /  \
    ///      L0  L1 L2  L3
    ///
    ///  To prove L0 exists:
    ///  proof_path = [(hash(L1), false), (hash(h2), false)]
    ///  Step 1: hash(L0, L1) = h1
    ///  Step 2: hash(h1, h2) = root
    /// ```
    ///
    /// # Complexity Design
    /// - **Time Complexity**: $\mathcal{O}(D)$ where $D \le 32$ is the length of `proof_path`
    ///   (each step performs a 2-input Poseidon permutation).
    /// - **Space Complexity**: $\mathcal{O}(1)$ working vector of 2 elements per step.
    pub fn verify_merkle_proof(
        env: &Env,
        root: &BytesN<32>,
        leaf: &BytesN<32>,
        proof_path: &Vec<(BytesN<32>, bool)>,
    ) -> bool {
        // Maximum tree depth to prevent excessive gas consumption (2^32 capacity)
        const MAX_DEPTH: u32 = 32;

        if proof_path.len() > MAX_DEPTH {
            return false;
        }

        // Start with the leaf hash
        let mut current_hash = leaf.clone();

        // Traverse the proof path from leaf to root
        for i in 0..proof_path.len() {
            let (sibling_hash, is_left) = proof_path.get_unchecked(i);

            // Create a vector with both hashes in the correct order
            let mut hashes = Vec::new(env);

            if is_left {
                // Sibling is on the left, current is on the right
                hashes.push_back(sibling_hash);
                hashes.push_back(current_hash.clone());
            } else {
                // Current is on the left, sibling is on the right
                hashes.push_back(current_hash.clone());
                hashes.push_back(sibling_hash);
            }

            // Hash the pair to get the parent node
            current_hash = PoseidonHasher::hash(env, &hashes);
        }

        // The final computed hash should match the root
        current_hash == *root
    }

    /// Computes the Merkle root from an array of leaves by recursively hashing pairwise.
    ///
    /// If an odd number of nodes is present at any level, duplicates the last node.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `leaves` - Vector of 32-byte leaf hashes.
    ///
    /// # Returns
    /// The computed 32-byte Merkle root hash.
    ///
    /// # Complexity
    /// - **Time Complexity**: $\mathcal{O}(N)$ where $N = \text{len}(leaves)$ (computes $N - 1$ total hashes).
    /// - **Space Complexity**: $\mathcal{O}(N)$ temporary vector space across reduction tree levels.
    pub fn compute_merkle_root(env: &Env, leaves: &Vec<BytesN<32>>) -> BytesN<32> {
        if leaves.is_empty() {
            return BytesN::from_array(env, &[0u8; 32]);
        }

        if leaves.len() == 1 {
            return leaves.get_unchecked(0);
        }

        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new(env);
            let mut i = 0;

            while i < current_level.len() {
                let left = current_level.get_unchecked(i);

                // If odd number of nodes, duplicate the last one
                let right = if i + 1 < current_level.len() {
                    current_level.get_unchecked(i + 1)
                } else {
                    left.clone()
                };

                let mut pair = Vec::new(env);
                pair.push_back(left);
                pair.push_back(right);

                let parent = PoseidonHasher::hash(env, &pair);
                next_level.push_back(parent);

                i += 2;
            }

            current_level = next_level;
        }

        current_level.get_unchecked(0)
    }
}
