//! # Verification Key and Elliptic Curve Points Module
//!
//! This module defines the canonical data types for elliptic curve points and
//! verification keys used in Zero-Knowledge proof verification over the **BN254**
//! (also known as *Alt-BN128* or *bn128*) pairing-friendly elliptic curve.
//!
//! ## Mathematical Foundations
//!
//! The BN254 curve is defined by the equation:
//! $$E(\mathbb{F}_p): y^2 = x^3 + 3$$
//! over the prime field $\mathbb{F}_p$ where:
//! $$p = 21888242871839275222246405745257275088696311157297823662689037894645226208583$$
//!
//! The curve possesses an optimal Ate pairing $e: G_1 \times G_2 \to G_T$ where:
//! - $G_1$ is a subgroup of $E(\mathbb{F}_p)$ of prime order $r$.
//! - $G_2$ is a subgroup of the twist curve $E'(\mathbb{F}_{p^2}): y^2 = x^3 + 3/(9+u)$
//!   over the quadratic extension field $\mathbb{F}_{p^2} \cong \mathbb{F}_p\[u\]/(u^2 + 1)$.
//! - $G_T$ is the subgroup of $r$-th roots of unity in $\mathbb{F}_{p^{12}}^*$.
//! - $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617$.

use soroban_sdk::{contracttype, BytesN};

/// Represents an affine point $(x, y)$ on the $G_1$ subgroup of the BN254 curve.
///
/// $G_1$ points reside in the base prime field $\mathbb{F}_p$. In affine coordinates,
/// each point consists of two 254-bit field elements represented as 32-byte big-endian
/// byte arrays (`BytesN<32>`).
///
/// # Memory Layout & Space Complexity
/// - **Affine Coordinates**: `x` (32 bytes) + `y` (32 bytes) = **64 bytes**.
/// - **Point at Infinity**: Represented by convention as $(0, 0)$.
/// - **Space Complexity**: $\mathcal{O}(1)$ fixed size (64 bytes).
/// - **Time Complexity**: Serialization/deserialization $\mathcal{O}(1)$ Soroban Val conversion.
///
/// # Role in ZK Protocols
/// - In **Groth16**: Used for proof elements `[A]_1`, `[C]_1` in $G_1$, verification key element `[alpha]_1`,
///   and public input accumulation vectors `[IC_i]_1` in $G_1$.
/// - In **PLONK**: Used for wire polynomial commitments `[a]_1`, `[b]_1`, `[c]_1` and quotient commitments.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G1Point {
    /// The $x$-coordinate in the prime field $\mathbb{F}_p$ (32 bytes, big-endian).
    pub x: BytesN<32>,
    /// The $y$-coordinate in the prime field $\mathbb{F}_p$ (32 bytes, big-endian).
    pub y: BytesN<32>,
}

/// Represents an affine point on the $G_2$ subgroup of the BN254 twist curve.
///
/// $G_2$ points reside over the quadratic extension field $\mathbb{F}_{p^2} \cong \mathbb{F}_p\[u\]/(u^2 + 1)$.
/// Each coordinate $(x, y)$ is an element of $\mathbb{F}_{p^2}$, structured as $c_0 + c_1 u$
/// where $c_0, c_1 \in \mathbb{F}_p$.
///
/// # Memory Layout & Space Complexity
/// - **$x$-coordinate**: $(c_0, c_1)$ pair of `BytesN<32>` (64 bytes).
/// - **$y$-coordinate**: $(c_0, c_1)$ pair of `BytesN<32>` (64 bytes).
/// - **Total Size**: **128 bytes** (4 field elements $\times$ 32 bytes).
/// - **Space Complexity**: $\mathcal{O}(1)$ fixed size (128 bytes).
/// - **Time Complexity**: Serialization/deserialization $\mathcal{O}(1)$.
///
/// # Role in ZK Protocols
/// - In **Groth16**: Used for proof element `[B]_2` in $G_2$ and verification key elements
///   `[beta]_2`, `[gamma]_2`, `[delta]_2` in $G_2$ in the pairing check.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2Point {
    /// The $x$-coordinate in $\mathbb{F}_{p^2}$, represented as $(c_0, c_1)$ where $x = c_0 + c_1 u$.
    pub x: (BytesN<32>, BytesN<32>),
    /// The $y$-coordinate in $\mathbb{F}_{p^2}$, represented as $(c_0, c_1)$ where $y = c_0 + c_1 u$.
    pub y: (BytesN<32>, BytesN<32>),
}

/// Verification Key for Groth16 Zero-Knowledge SNARK verification over BN254.
///
/// The verification key encapsulates the pre-processed Common Reference String (CRS)
/// parameters required to verify a Groth16 proof without revealing the witness.
///
/// # Groth16 Verification Equation
/// A proof `pi = (A, B, C)` is valid for public inputs `(x_1, ..., x_l)`
/// if and only if the following pairing equation holds:
/// ```text
/// e(A, B) = e(alpha, beta) * e(IC_0 + sum(x_i * IC_i), gamma) * e(C, delta)
/// ```
///
/// # Complexity Design
/// - **Space Complexity**: $\mathcal{O}(L)$ where $L = \text{len}(ic)$ is the number of input commitments.
///   - Base parameters: $\alpha$ (64B) $+ \beta$ (128B) $+ \gamma$ (128B) $+ \delta$ (128B) = 448 bytes.
///   - Input commitments: $(l + 1) \times 64$ bytes.
///   - Total storage footprint: $448 + 64(l + 1)$ bytes.
/// - **Time Complexity**:
///   - Deserialization from Soroban host storage: $\mathcal{O}(L)$.
///   - Verification evaluation: $\mathcal{O}(L)$ scalar multiplications in $G_1$ followed by $\mathcal{O}(1)$ pairing evaluations.
///
/// # Invariants
/// - `ic.len()` must be equal to the expected public input count plus 1 (for the constant $x_0 = 1$ term).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationKey {
    /// `[alpha]_1` in $G_1$: First pairing parameter from the trusted setup.
    pub alpha_g1: G1Point,
    /// `[beta]_2` in $G_2$: Second pairing parameter from the trusted setup.
    pub beta_g2: G2Point,
    /// `[gamma]_2` in $G_2$: Public input blinding factor parameter.
    pub gamma_g2: G2Point,
    /// `[delta]_2` in $G_2$: Private witness blinding factor parameter.
    pub delta_g2: G2Point,
    /// Input Commitments `[IC_0, IC_1, ..., IC_l]` in $G_1^{l+1}$: Generator linear combination bases
    /// for accumulating public inputs $x_1, ..., x_l$ during verification.
    pub ic: soroban_sdk::Vec<G1Point>,
}
