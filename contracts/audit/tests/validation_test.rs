//! Zero-value, boundary parameter, and negative (error case) tests for the `audit` crate.
//!
//! Verifies that functions accept or correctly reject zero, empty, and extreme
//! boundary inputs, and validates that all error pathways return appropriate
//! error variants without panicking or corrupting state.

#![allow(clippy::unwrap_used)]

extern crate alloc;
extern crate std;

use audit::{
    consistency::ConsistencyProver,
    contract::{AuditContract, AuditContractClient},
    merkle_log::MerkleLog,
    search::{SearchEngine, SearchKey},
    types::{AuditError, LogSegmentId, RetentionPolicy},
};
use soroban_sdk::{
    symbol_short, testutils::Address as _, Address, Env, Symbol,
};

// ── Mock Contracts for Cross-Contract Negative Tests ─────────────────────────

#[soroban_sdk::contract]
pub struct MockIdentityValidation;

#[soroban_sdk::contractimpl]
impl MockIdentityValidation {
    pub fn verify_actor_ok(_env: Env, _actor: Address) -> bool {
        true
    }
    pub fn verify_actor_fail(_env: Env, _actor: Address) -> bool {
        false
    }
}

#[soroban_sdk::contract]
pub struct MockVaultValidation;

#[soroban_sdk::contractimpl]
impl MockVaultValidation {
    pub fn check_balance_positive(_env: Env, _account: Address) -> i128 {
        1000
    }
    pub fn check_balance_negative(_env: Env, _account: Address) -> i128 {
        -50
    }
}

#[soroban_sdk::contract]
pub struct MockComplianceValidation;

#[soroban_sdk::contractimpl]
impl MockComplianceValidation {
    pub fn check_compliance_ok(_env: Env, _action: Symbol) -> bool {
        true
    }
    pub fn check_compliance_fail(_env: Env, _action: Symbol) -> bool {
        false
    }
}

// ── Test Setup Helpers ────────────────────────────────────────────────────────

fn setup_contract() -> (Env, AuditContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

// ── LogSegmentId boundary tests ───────────────────────────────────────────────

#[test]
fn test_segment_id_empty_string_is_rejected() {
    // An empty label has no identity and must be rejected.
    assert!(LogSegmentId::new("").is_err());
}

#[test]
fn test_segment_id_max_length_is_valid() {
    // A 64-byte label is exactly at the limit — must be accepted.
    let label = "a".repeat(64);
    assert!(LogSegmentId::new(&label).is_ok());
}

#[test]
fn test_segment_id_over_max_length_rejected() {
    // A 65-byte label exceeds the limit — must return InvalidSegmentId.
    let label = "a".repeat(65);
    assert_eq!(
        LogSegmentId::new(&label),
        Err(AuditError::InvalidSegmentId),
        "65-byte label must be rejected"
    );
}

// ── MerkleLog append with zero / boundary values ──────────────────────────────

#[test]
fn test_append_with_zero_timestamp() {
    let seg = LogSegmentId::new("zero-ts").unwrap();
    let mut log = MerkleLog::new(seg);
    // timestamp = 0 is a valid edge case; must be accepted without panic.
    let seq = log.append(0, "actor", "action", "target", "ok").unwrap();
    assert_eq!(seq, 1, "first entry must have sequence 1");
}

#[test]
fn test_append_with_u64_max_timestamp() {
    let seg = LogSegmentId::new("max-ts").unwrap();
    let mut log = MerkleLog::new(seg);
    let seq = log
        .append(u64::MAX, "actor", "action", "target", "ok")
        .unwrap();
    assert_eq!(seq, 1);
    // Inclusion proof must still be constructable.
    assert!(log.inclusion_proof(seq).is_ok());
}

#[test]
fn test_append_with_empty_actor_and_action() {
    let seg = LogSegmentId::new("empty-fields").unwrap();
    let mut log = MerkleLog::new(seg);
    // All string fields empty — must be accepted without panic.
    let seq = log.append(1000, "", "", "", "").unwrap();
    assert_eq!(seq, 1);
    assert!(log.get_entry(seq).is_ok());
}

#[test]
fn test_append_increments_sequence_correctly() {
    let seg = LogSegmentId::new("seq-check").unwrap();
    let mut log = MerkleLog::new(seg);
    let s1 = log.append(0, "", "", "", "").unwrap();
    let s2 = log.append(0, "", "", "", "").unwrap();
    let s3 = log.append(0, "", "", "", "").unwrap();
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(s3, 3);
}

// ── get_entry on missing sequence ─────────────────────────────────────────────

#[test]
fn test_get_entry_nonexistent_returns_error() {
    let seg = LogSegmentId::new("missing").unwrap();
    let log = MerkleLog::new(seg);
    // No entries appended — sequence 1 does not exist.
    let result = log.get_entry(1);
    assert!(
        matches!(result, Err(AuditError::EntryNotFound { sequence: 1 })),
        "get_entry on missing sequence must return EntryNotFound"
    );
}

#[test]
fn test_get_entry_sequence_zero_returns_error() {
    let seg = LogSegmentId::new("seq-zero").unwrap();
    let mut log = MerkleLog::new(seg);
    log.append(1000, "actor", "action", "target", "ok").unwrap();
    // Sequence 0 is never a valid entry (sequences start at 1).
    let result = log.get_entry(0);
    assert!(result.is_err());
}

// ── inclusion_proof on non-existent entry ─────────────────────────────────────

#[test]
fn test_inclusion_proof_on_empty_log_returns_error() {
    let seg = LogSegmentId::new("empty-proof").unwrap();
    let log = MerkleLog::new(seg);
    assert!(
        log.inclusion_proof(1).is_err(),
        "proof on empty log must return an error"
    );
}

// ── SearchEngine with empty / zero-length inputs ──────────────────────────────

#[test]
fn test_search_query_on_empty_engine_returns_empty() {
    let key = SearchKey::from_bytes(&[0u8; 32]).unwrap();
    let engine = SearchEngine::new(key);
    assert!(
        engine.query("anything").is_empty(),
        "query on un-indexed engine must return empty results"
    );
}

#[test]
fn test_search_query_empty_string_returns_empty() {
    let key = SearchKey::from_bytes(&[0u8; 32]).unwrap();
    let mut engine = SearchEngine::new(key);
    engine.index_entry(1, "actor", "read", "target", "ok", &[]);
    // Empty-string query should match nothing.
    assert!(engine.query("").is_empty());
}

#[test]
fn test_search_key_all_zeros_is_valid() {
    // A 32-byte all-zero key should be constructed without error.
    assert!(SearchKey::from_bytes(&[0u8; 32]).is_ok());
}

#[test]
fn test_search_key_wrong_length_rejected() {
    // A key that is not 32 bytes must be rejected.
    assert!(SearchKey::from_bytes(&[0u8; 16]).is_err());
    assert!(SearchKey::from_bytes(&[]).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Issue #14: Negative Unit Tests (Error Cases) in Audit
// ═══════════════════════════════════════════════════════════════════════════════

// ── Contract-Level Negative Tests (AuditContractError) ────────────────────────

#[test]
fn test_contract_append_entry_missing_segment_returns_error() {
    let (env, client, _) = setup_contract();
    let actor = Address::generate(&env);
    let missing_segment = symbol_short!("MISS_SEG");

    let result = client.try_append_entry(
        &missing_segment,
        &actor,
        &symbol_short!("READ"),
        &symbol_short!("PATIENT1"),
        &symbol_short!("OK"),
    );
    assert!(
        result.is_err(),
        "Appending to a non-existent segment must fail"
    );
}

#[test]
fn test_contract_get_entries_missing_segment_returns_error() {
    let (_, client, _) = setup_contract();
    let missing_segment = symbol_short!("NO_SEG");

    let result = client.try_get_entries(&missing_segment);
    assert!(
        result.is_err(),
        "get_entries for non-existent segment must fail"
    );
}

#[test]
fn test_contract_get_entry_count_missing_segment_returns_error() {
    let (_, client, _) = setup_contract();
    let missing_segment = symbol_short!("NO_SEG");

    let result = client.try_get_entry_count(&missing_segment);
    assert!(
        result.is_err(),
        "get_entry_count for non-existent segment must fail"
    );
}

#[test]
fn test_contract_create_duplicate_segment_returns_error() {
    let (_, client, _) = setup_contract();
    let segment = symbol_short!("DUPL");

    // First creation succeeds
    client.create_segment(&segment);

    // Second creation of the exact same segment must fail with error
    let result = client.try_create_segment(&segment);
    assert!(
        result.is_err(),
        "Creating a duplicate segment must fail"
    );
}

#[test]
fn test_contract_append_with_checks_identity_failure_returns_error() {
    let (env, client, _) = setup_contract();
    let identity_id = env.register(MockIdentityValidation, ());
    let vault_id = env.register(MockVaultValidation, ());
    let compliance_id = env.register(MockComplianceValidation, ());

    let segment = symbol_short!("CHK_SEG");
    client.create_segment(&segment);

    let actor = Address::generate(&env);
    let result = client.try_append_entry_with_checks(
        &segment,
        &actor,
        &symbol_short!("READ"),
        &symbol_short!("PATIENT1"),
        &symbol_short!("OK"),
        &identity_id,
        &symbol_short!("verify_f"), // failing identity method
        &vault_id,
        &symbol_short!("check_b"),
        &compliance_id,
        &symbol_short!("check_c"),
        &symbol_short!("check_c"),
    );

    assert!(
        result.is_err(),
        "append_entry_with_checks must fail when identity verification fails"
    );
}

#[test]
fn test_contract_append_with_checks_insufficient_vault_balance_returns_error() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let identity_id = env.register(MockIdentityValidation, ());
    let vault_id = env.register(MockVaultValidation, ());
    let compliance_id = env.register(MockComplianceValidation, ());

    let segment = symbol_short!("CHK_SEG");
    client.create_segment(&segment);

    let actor = Address::generate(&env);
    let result = client.try_append_entry_with_checks(
        &segment,
        &actor,
        &symbol_short!("READ"),
        &symbol_short!("PATIENT1"),
        &symbol_short!("OK"),
        &identity_id,
        &Symbol::new(&env, "verify_actor_ok"),
        &vault_id,
        &Symbol::new(&env, "check_balance_negative"), // returns -50 balance
        &compliance_id,
        &symbol_short!("READ"),
        &Symbol::new(&env, "check_compliance_ok"),
    );

    assert!(
        result.is_err(),
        "append_entry_with_checks must fail when vault balance is negative"
    );
}

#[test]
fn test_contract_append_with_checks_compliance_failure_returns_error() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let identity_id = env.register(MockIdentityValidation, ());
    let vault_id = env.register(MockVaultValidation, ());
    let compliance_id = env.register(MockComplianceValidation, ());

    let segment = symbol_short!("CHK_SEG");
    client.create_segment(&segment);

    let actor = Address::generate(&env);
    let result = client.try_append_entry_with_checks(
        &segment,
        &actor,
        &symbol_short!("READ"),
        &symbol_short!("PATIENT1"),
        &symbol_short!("OK"),
        &identity_id,
        &Symbol::new(&env, "verify_actor_ok"),
        &vault_id,
        &Symbol::new(&env, "check_balance_positive"),
        &compliance_id,
        &symbol_short!("READ"),
        &Symbol::new(&env, "check_compliance_fail"), // returns false
    );

    assert!(
        result.is_err(),
        "append_entry_with_checks must fail when compliance check fails"
    );
}

#[test]
fn test_contract_append_with_checks_missing_segment_returns_error() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditContract, ());
    let client = AuditContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let identity_id = env.register(MockIdentityValidation, ());
    let vault_id = env.register(MockVaultValidation, ());
    let compliance_id = env.register(MockComplianceValidation, ());

    // Target segment UNCREATED_SEG is deliberately not created
    let actor = Address::generate(&env);
    let result = client.try_append_entry_with_checks(
        &symbol_short!("UNCREATED"),
        &actor,
        &symbol_short!("READ"),
        &symbol_short!("PATIENT1"),
        &symbol_short!("OK"),
        &identity_id,
        &Symbol::new(&env, "verify_actor_ok"),
        &vault_id,
        &Symbol::new(&env, "check_balance_positive"),
        &compliance_id,
        &symbol_short!("READ"),
        &Symbol::new(&env, "check_compliance_ok"),
    );

    assert!(
        result.is_err(),
        "append_entry_with_checks must fail with SegmentNotFound when segment does not exist"
    );
}

// ── Domain-Level Negative Tests (AuditError) ──────────────────────────────────

#[test]
fn test_merkle_log_out_of_order_timestamp_rejected() {
    let seg = LogSegmentId::new("chrono-err").unwrap();
    let mut log = MerkleLog::new(seg);

    // First entry at timestamp 5000
    let seq1 = log.append(5000, "alice", "read", "rec:1", "ok").unwrap();
    assert_eq!(seq1, 1);

    // Second entry with timestamp 4999 (earlier than previous timestamp) must be rejected
    let res = log.append(4999, "alice", "read", "rec:2", "ok");
    match res {
        Err(AuditError::OutOfOrderTimestamp {
            sequence,
            supplied,
            minimum,
        }) => {
            assert_eq!(sequence, 2);
            assert_eq!(supplied, 4999);
            assert_eq!(minimum, 5000);
        }
        other => panic!("Expected OutOfOrderTimestamp error, got {:?}", other),
    }
}

#[test]
fn test_merkle_log_corrupted_inclusion_proof_verification_fails() {
    let seg = LogSegmentId::new("proof-err").unwrap();
    let mut log = MerkleLog::new(seg);

    let seq1 = log.append(1000, "alice", "create", "patient:1", "ok").unwrap();
    let _seq2 = log.append(1001, "bob", "read", "patient:1", "ok").unwrap();
    let _seq3 = log.append(1002, "carol", "modify", "patient:1", "ok").unwrap();

    let root = log.current_root();
    let mut proof = log.inclusion_proof(seq1).unwrap();

    // Verification of valid proof succeeds
    assert!(proof.verify(&root).is_ok());

    // Corrupt proof leaf hash
    proof.leaf_hash[0] ^= 0xFF;
    assert_eq!(
        proof.verify(&root),
        Err(AuditError::InvalidInclusionProof),
        "Corrupted leaf hash in inclusion proof must fail verification"
    );
}

#[test]
fn test_merkle_log_inclusion_proof_against_wrong_root_fails() {
    let seg = LogSegmentId::new("root-err").unwrap();
    let mut log = MerkleLog::new(seg);

    let seq = log.append(1000, "alice", "read", "patient:1", "ok").unwrap();
    let proof = log.inclusion_proof(seq).unwrap();

    let wrong_root = [0x55u8; 32];
    assert_eq!(
        proof.verify(&wrong_root),
        Err(AuditError::InvalidInclusionProof),
        "Inclusion proof verification against mismatched root must return InvalidInclusionProof"
    );
}

#[test]
fn test_consistency_proof_corrupted_proof_hash_fails() {
    let seg = LogSegmentId::new("consist-err").unwrap();
    let mut log = MerkleLog::new(seg);

    for i in 1..=4 {
        log.append(1000 + i, "actor", "action", "target", "ok").unwrap();
    }

    let root_v1 = log.current_root();
    let size_v1 = log.len();

    // Advance log
    for i in 5..=8 {
        log.append(1000 + i, "actor", "action", "target", "ok").unwrap();
    }

    let prover = ConsistencyProver::new(
        (1..=8).map(|s| log.get_entry(s).unwrap().entry_hash).collect(),
    );

    let mut proof = prover.generate(root_v1, size_v1).unwrap();
    assert!(proof.verify().is_ok());

    // Corrupt one of the proof hashes
    if let Some(first_hash) = proof.proof_hashes.first_mut() {
        first_hash[0] ^= 0xFF;
        assert!(
            proof.verify().is_err(),
            "Consistency proof with corrupted hash must fail verification"
        );
    }
}

#[test]
fn test_consistency_proof_invalid_size_ordering_rejected() {
    let leaves = alloc::vec![[0x01u8; 32], [0x02u8; 32]];
    let prover = ConsistencyProver::new(leaves);

    // Requesting consistency proof where size_v1 > size_v2 must fail
    let res = prover.generate([0xAAu8; 32], 5);
    assert_eq!(
        res.err(),
        Some(AuditError::InvalidConsistencyProof),
        "Prover must reject size_v1 > current size"
    );
}

#[test]
fn test_retention_policy_premature_compaction_violation() {
    let seg = LogSegmentId::new("retention-err").unwrap();
    let mut log = MerkleLog::new(seg.clone());

    log.set_retention(RetentionPolicy {
        segment: seg,
        min_retention_secs: 86400, // 24 hours
        requires_witness_for_deletion: false,
    });

    let seq = log.append(1000, "alice", "action", "target", "ok").unwrap();

    // Attempt compaction at timestamp 5000 (retained until 1000 + 86400 = 87400)
    let res = log.compact(seq, seq, 5000, 0);
    match res {
        Err(AuditError::RetentionPolicyViolation {
            sequence,
            retained_until,
        }) => {
            assert_eq!(sequence, 1);
            assert_eq!(retained_until, 87400);
        }
        other => panic!("Expected RetentionPolicyViolation error, got {:?}", other),
    }
}

#[test]
fn test_retention_policy_insufficient_witnesses_rejected() {
    let seg = LogSegmentId::new("witness-err").unwrap();
    let mut log = MerkleLog::new(seg.clone());

    log.set_retention(RetentionPolicy {
        segment: seg,
        min_retention_secs: 100,
        requires_witness_for_deletion: true,
    });

    let seq = log.append(1000, "alice", "action", "target", "ok").unwrap();

    // Compaction at valid timestamp (10000 > 1100), but requiring 2 witnesses with 0 present
    let res = log.compact(seq, seq, 10000, 2);
    match res {
        Err(AuditError::InsufficientWitnesses { required, present }) => {
            assert_eq!(required, 2);
            assert_eq!(present, 0);
        }
        other => panic!("Expected InsufficientWitnesses error, got {:?}", other),
    }
}

#[test]
fn test_audit_error_display_formatting_all_variants() {
    extern crate std;
    use std::format;

    let errs = [
        AuditError::HashChainBroken { at_sequence: 42 },
        AuditError::InvalidInclusionProof,
        AuditError::InvalidConsistencyProof,
        AuditError::InvalidSearchToken,
        AuditError::EntryNotFound { sequence: 99 },
        AuditError::InvalidSegmentId,
        AuditError::InsufficientWitnesses { required: 3, present: 1 },
        AuditError::RetentionPolicyViolation { sequence: 5, retained_until: 10000 },
        AuditError::RootMismatch,
        AuditError::InternalError("internal failure"),
        AuditError::SegmentNotFound,
        AuditError::SearchKeyNotSet,
        AuditError::OutOfOrderTimestamp { sequence: 3, supplied: 100, minimum: 200 },
    ];

    for err in errs {
        let msg = format!("{}", err);
        assert!(!msg.is_empty(), "AuditError display output must not be empty");
    }
}

