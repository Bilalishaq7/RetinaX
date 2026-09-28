# Glossary

This glossary defines key technical terms, acronyms, and concepts used throughout the RetinaX platform. It serves as a reference for developers, auditors, healthcare providers, and other stakeholders working with or integrating RetinaX.

---

## Table of Contents

- [Blockchain & Distributed Systems](#blockchain--distributed-systems)
- [Cryptography & Privacy](#cryptography--privacy)
- [Healthcare & Compliance](#healthcare--compliance)
- [Smart Contracts & Development](#smart-contracts--development)
- [Access Control & Security](#access-control--security)
- [RetinaX-Specific Terms](#retinax-specific-terms)

---

## Blockchain & Distributed Systems

### BN254 (Alt-BN128)
A pairing-friendly elliptic curve optimized for zero-knowledge proof systems. RetinaX uses BN254 for efficient on-chain cryptographic operations, particularly in the ZK verifier contract. It enables fast pairing computations required for Groth16 proof verification.

### Cross-Chain Bridge
A protocol that enables asset or data transfer between different blockchain networks. In RetinaX, the cross-chain bridge allows interoperability with other healthcare systems and blockchains, facilitating data portability and multi-chain identity anchoring.

### DID (Decentralized Identifier)
A globally unique identifier that enables verifiable, self-sovereign digital identity without relying on centralized authorities. In RetinaX, DIDs are used to identify patients, providers, and institutions on the blockchain, enabling privacy-preserving authentication and authorization.

### Gas
The computational unit that measures the cost of executing operations on a blockchain. In Stellar/Soroban, gas represents the resources consumed by smart contract execution. RetinaX implements gas-efficient contract designs to minimize transaction costs.

### Ledger
The immutable, append-only record of all transactions and state changes on a blockchain. Stellar's ledger provides the foundation for RetinaX's tamper-proof audit trails and record integrity guarantees.

### Merkle Tree
A cryptographic tree structure where each leaf node contains a data hash and each non-leaf node contains a hash of its children. RetinaX uses Merkle trees in audit logs to enable efficient verification of data integrity and to prove inclusion of specific records without revealing the entire dataset.

### Smart Contract
Self-executing code deployed on a blockchain that automatically enforces predefined rules and agreements. RetinaX consists of multiple smart contracts written in Rust that manage identity, vision records, governance, and compliance on the Stellar blockchain.

### Soroban
Stellar's smart contract platform that enables developers to write, test, and deploy Rust-based contracts. Soroban provides the execution environment for all RetinaX contracts, offering WebAssembly-based performance and native Stellar integration.

### Stellar
A decentralized, open-source blockchain network optimized for fast, low-cost financial transactions and asset issuance. RetinaX is built on Stellar to leverage its speed, efficiency, and robust infrastructure for healthcare data management.

### Timestamp
A verifiable record of when a transaction or event occurred. In RetinaX, blockchain timestamps provide immutable proof of when medical records were created, accessed, or modified, essential for regulatory compliance and audit trails.

### Wasm (WebAssembly)
A binary instruction format that enables high-performance execution in web browsers and other environments. Soroban contracts compile to Wasm, providing portable, efficient smart contract execution on the Stellar network.

---

## Cryptography & Privacy

### Differential Privacy
A mathematical framework for sharing information about a dataset while protecting individual privacy by adding controlled statistical noise. RetinaX's analytics contract implements differential privacy to enable population-level vision health insights without exposing individual patient data.

### Elliptic Curve Cryptography (ECC)
A public-key cryptography approach based on the algebraic structure of elliptic curves. RetinaX uses ECC for key generation, digital signatures, and zero-knowledge proofs, providing strong security with smaller key sizes compared to traditional methods.

### Groth16
A zero-knowledge proof system known for its constant-size proofs (three elliptic curve points) and fast verification time. RetinaX uses Groth16 for efficient on-chain proof verification, enabling privacy-preserving access control with minimal gas costs.

### HD Key Derivation (Hierarchical Deterministic)
A method for generating a tree of cryptographic key pairs from a single master seed, following BIP-32/BIP-44 standards. RetinaX's key manager uses HD key derivation to generate deterministic, recoverable keys for patients and providers while maintaining cryptographic isolation between different purposes.

### Homomorphic Encryption
Encryption that allows computations to be performed on encrypted data without decrypting it first. RetinaX's analytics contract supports homomorphic operations to enable secure data processing while maintaining end-to-end encryption of sensitive vision care records.

### Key Rotation
The cryptographic best practice of periodically replacing encryption keys while maintaining access to previously encrypted data. RetinaX implements automated key rotation in the key manager contract to minimize the impact of potential key compromise and maintain forward secrecy.

### Poseidon Hash
A cryptographic hash function specifically designed for zero-knowledge proof circuits. RetinaX uses Poseidon for efficient hashing within ZK circuits, providing better performance than traditional hash functions like SHA-256 in constraint-based proof systems.

### Public Key Infrastructure (PKI)
A framework for managing digital certificates and public-private key pairs. RetinaX uses PKI principles for identity verification, ensuring that only authorized parties can sign transactions and access encrypted medical records.

### Zero-Knowledge Proof (zk-proof)
A cryptographic method that allows one party (the prover) to prove to another party (the verifier) that a statement is true without revealing any information beyond the validity of the statement itself. RetinaX uses zk-proofs to enable privacy-preserving access control, allowing users to prove eligibility without revealing sensitive credentials.

---

## Healthcare & Compliance

### Audit Log
A chronological record of system activities and access events that cannot be modified or deleted. RetinaX maintains comprehensive audit logs on-chain to track all access to and modifications of vision care records, supporting compliance and security investigations.

### BAA (Business Associate Agreement)
A HIPAA-mandated contract between a covered entity and a business associate that handles protected health information (PHI). RetinaX's compliance contract implements BAA requirements through on-chain agreement tracking and enforcement.

### Clinical Record
Structured medical documentation of patient care, including diagnoses, treatments, prescriptions, and examination results. In RetinaX, clinical records are specifically focused on vision care data including eye exams, prescriptions, and optometry/ophthalmology findings.

### Consent Management
The process of obtaining, tracking, and enforcing patient authorization for data access and usage. RetinaX implements granular consent management, allowing patients to control who can access their vision records and for what purposes, with all consent decisions recorded immutably on-chain.

### EMR (Electronic Medical Record)
A digital version of a patient's paper chart, typically used within a single healthcare organization. RetinaX's EMR bridge enables integration with existing electronic medical record systems, facilitating data exchange while maintaining blockchain security and privacy.

### FHIR (Fast Healthcare Interoperability Resources)
An HL7 standard for exchanging healthcare information electronically. RetinaX includes FHIR contract support for standardized data exchange with external healthcare systems, enabling interoperability while maintaining privacy and compliance.

### GDPR (General Data Protection Regulation)
European Union regulation on data protection and privacy that grants individuals control over their personal data. RetinaX's compliance contract implements GDPR requirements including the right to access, rectification, erasure, and data portability for healthcare data.

### HIPAA (Health Insurance Portability and Accountability Act)
U.S. federal law establishing national standards for protecting sensitive patient health information. RetinaX implements HIPAA technical safeguards including encryption, access controls, audit logs, and breach detection to ensure compliance with Protected Health Information (PHI) regulations.

### PHI (Protected Health Information)
Individually identifiable health information that is protected under HIPAA regulations. RetinaX encrypts all PHI and stores only encrypted hashes and access control metadata on-chain, with the encrypted data stored off-chain.

### Right to Erasure (Right to be Forgotten)
A GDPR requirement allowing individuals to request deletion of their personal data. RetinaX implements cryptographic erasure through key destruction, rendering encrypted data permanently inaccessible while maintaining blockchain immutability.

---

## Smart Contracts & Development

### Circuit
In zero-knowledge proof systems, a circuit is a mathematical representation of a computation expressed as a set of constraints. RetinaX developers define circuits to represent access control policies and credential verification logic that can be proven without revealing sensitive data.

### Contract Deployment
The process of publishing smart contract code to the blockchain, making it available for execution. RetinaX contracts are deployed through a multi-stage process (local, testnet, futurenet, mainnet) with comprehensive testing and security validation at each stage.

### Gas Optimization
Techniques for minimizing the computational resources required to execute smart contract operations. RetinaX implements gas-efficient patterns including storage optimization, batching, and efficient data structures to reduce transaction costs.

### Instance Storage
Soroban's storage tier for contract-level configuration and singleton data. RetinaX uses instance storage for admin addresses, global parameters, and contract initialization state.

### Persistent Storage
Soroban's storage tier for data that must be preserved across contract executions. RetinaX stores critical data like patient records, consent grants, and audit logs in persistent storage with appropriate TTL extensions.

### Proof System
A cryptographic framework for generating and verifying zero-knowledge proofs. RetinaX uses the Groth16 proof system for its optimal trade-off between proof size and verification speed, crucial for on-chain verification efficiency.

### Rust
A systems programming language focused on safety, concurrency, and performance. All RetinaX smart contracts are written in Rust, leveraging its memory safety guarantees and strong type system to prevent common vulnerabilities.

### Temporary Storage
Soroban's storage tier for ephemeral data that expires after a short period. RetinaX uses temporary storage for transaction state, session data, and other short-lived information that doesn't require long-term persistence.

### TTL (Time To Live)
The duration for which data remains accessible in Soroban storage before requiring rent payment or extension. RetinaX implements strategic TTL extension for critical records to ensure availability while managing storage costs.

### Verifying Key
In zero-knowledge proof systems, the public parameters used to verify proofs. RetinaX stores verifying keys on-chain in the ZK verifier contract, enabling anyone to verify proofs without trusted setup participation.

---

## Access Control & Security

### Access Control List (ACL)
A list specifying which users or systems are granted access to specific resources and what operations they can perform. RetinaX implements ACLs for fine-grained control over vision care record access.

### Authentication
The process of verifying the identity of a user or system. RetinaX uses public key authentication, ensuring that only the holder of the corresponding private key can authorize actions on behalf of an identity.

### Authorization
The process of determining whether an authenticated entity has permission to perform a specific action. RetinaX's RBAC system handles authorization, granting permissions based on roles like patient, optometrist, ophthalmologist, or administrator.

### Emergency Access
A special access mechanism that allows authorized healthcare providers to access patient records in urgent medical situations, even without prior consent. RetinaX implements emergency access with comprehensive audit logging and time-limited grants that can be reviewed and disputed by patients.

### Multi-Signature (Multisig)
A security mechanism requiring multiple parties to approve a transaction before it can be executed. RetinaX uses multisig for high-privilege operations like contract upgrades, treasury management, and emergency protocol activation.

### Principle of Least Privilege
A security principle stating that users should have only the minimum access rights necessary to perform their functions. RetinaX's RBAC implementation follows this principle, granting only essential permissions for each role.

### Rate Limiting
A security mechanism that restricts the number of requests or operations a user can perform within a specified time period. RetinaX implements rate limiting to prevent denial-of-service attacks and brute-force attempts against ZK proof verification.

### RBAC (Role-Based Access Control)
An access control approach that assigns permissions to users based on their role within an organization. RetinaX implements RBAC with roles including Patient, Optometrist, Ophthalmologist, Researcher, Administrator, and Emergency Responder, each with specific permissions tailored to their responsibilities.

### Reentrancy Guard
A security pattern preventing recursive calls to a contract function before the first invocation completes. RetinaX implements reentrancy guards in critical functions to prevent exploitation through malicious callbacks.

### Session Management
The process of tracking and managing user authentication state over multiple interactions. RetinaX supports session tokens for improved user experience while maintaining security through time-limited credentials and replay protection.

### Whitelist
A list of explicitly approved addresses or entities that are permitted to perform certain operations. RetinaX uses whitelisting for provider registration, bridge relayers, and access to certain ZK-protected resources.

---

## RetinaX-Specific Terms

### Audit Contract
A RetinaX smart contract that maintains an immutable, chronologically-ordered log of all system events using Merkle tree structures. It ensures tamper-proof record-keeping and enables efficient verification of historical events.

### Compliance Contract
A RetinaX smart contract implementing HIPAA and GDPR requirements, including consent tracking, data retention policies, breach detection, and right-to-erasure mechanisms. It serves as the regulatory enforcement layer of the platform.

### Governor Contract
A RetinaX smart contract implementing decentralized governance through proposal creation, voting, and execution. It enables stakeholders to participate in platform decisions including parameter changes, upgrades, and treasury management.

### Identity Contract
A RetinaX smart contract managing decentralized identifiers (DIDs), social recovery mechanisms, and credential verification. It serves as the foundation for all authentication and identity-related operations in the platform.

### Key Manager Contract
A RetinaX smart contract implementing HD key derivation, key rotation, and cryptographic key lifecycle management. It generates deterministic keys from master seeds and enables secure key updates without data loss.

### Micro-Contract Architecture
RetinaX's design pattern where functionality is distributed across specialized, independent smart contracts that interact through well-defined interfaces. This approach improves modularity, testability, and upgradeability compared to monolithic contract designs.

### Orchestrator Contract
A RetinaX smart contract coordinating complex multi-contract workflows and transaction sequences. It simplifies client interactions by providing high-level operations that internally manage calls across multiple specialized contracts.

### Retina Scan Data
Optometry and ophthalmology diagnostic data including retinal images, optical coherence tomography (OCT) scans, visual field tests, and other vision-specific clinical measurements. RetinaX specializes in managing this type of sensitive healthcare data.

### Staking Contract
A RetinaX smart contract managing token deposits, delegation, and rewards distribution. Stakers participate in governance by locking tokens to gain voting power and earn rewards for securing the platform.

### Timelock Contract
A RetinaX smart contract enforcing delay periods between proposal approval and execution in governance workflows. It provides a security buffer allowing stakeholders to review and potentially veto malicious or erroneous proposals before they take effect.

### Treasury Contract
A RetinaX smart contract managing platform funds, including revenue from transaction fees, grant distributions, and ecosystem development funding. It operates under governance control with multisig security requirements.

### Vision Records Contract
The core RetinaX smart contract managing optometry and ophthalmology patient records, including exam results, prescriptions, diagnoses, and treatment plans. It implements consent-based access control and integrates with other platform contracts for comprehensive healthcare data management.

### ZK Verifier Contract
A RetinaX smart contract implementing on-chain zero-knowledge proof verification using the BN254 curve and Groth16 proof system. It enables privacy-preserving access control by allowing users to prove eligibility without revealing credentials.

### ZK Voting Contract
A RetinaX smart contract enabling privacy-preserving governance participation through zero-knowledge proofs. It allows stakeholders to vote on proposals without publicly revealing their voting choices or stake amounts until results are tallied.

---

## Additional Resources

- **Architecture Documentation**: [docs/architecture.md](architecture.md)
- **API Reference**: [docs/api.md](api.md)
- **Security Model**: [docs/security.md](security.md)
- **ZK Integration Guide**: [docs/zk-integration-guide.md](zk-integration-guide.md)
- **RBAC Quick Reference**: [docs/rbac-quick-reference.md](rbac-quick-reference.md)
- **Compliance Documentation**: [docs/compliance/](compliance/)

---

## Contributing to this Glossary

If you identify missing terms or unclear definitions, please submit a pull request or open an issue. When adding new terms:

1. Place terms in the appropriate category
2. Maintain alphabetical order within each category
3. Provide clear, concise definitions (2-4 sentences)
4. Focus on how the term applies to RetinaX specifically
5. Include cross-references to related terms where helpful

---

*Last Updated: 2025*
