# RECEIPT — Cross-Chain Agent Credit Backed by Private, Attested Work

RECEIPT is a cross-chain reputation and credit primitive for autonomous agents. Every completed job produces a portable work credential that is co-signed by the buyer and provider, attested by an Intel TDX enclave, and turned into cross-chain collateral using NEAR Chain Signatures and MPC Foreign-Chain Verification.

**Live Testnet Loop:** A private work receipt is registered on NEAR → authorized for a credit loan via Chain Signatures → drawn on Base Sepolia → verified back on NEAR by the MPC network.

### Architecture & Honesty Statement
*   **The Problem:** ERC-8004's Reputation Registry stores subjective feedback. It is chain-specific and easily manipulated. RECEIPT provides cryptographic proof of completed work.
*   **Confidential Intents Bridge:** NEAR's Confidential Intents private shard is mainnet-only and does not execute arbitrary contracts. To demonstrate the loop on testnet, we use a clearly labeled `TestnetConfidentialSettlementBridge` to generate the salted commitment for the TDX acceptance test. 
*   **TEE Capabilities:** Intel TDX proves code, input, and output integrity inside an approved enclave (verified against 129 approved OutLayer measurements). It does not judge subjective fairness; the buyer and provider co-sign the acceptance criteria.
*   **Live Testnet Evidence:** The TDX attestation, Chain Signatures loan authorization, and MPC verification are all live and verifiable on testnet.

### Live Testnet Deployments
*   **NEAR Registry:** `receipt-registry.testnet`
*   **Base Sepolia Vault:** `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8`
*   **Base Sepolia MockUSDC:** `0x99ac11cf7b392d27074253937163ad1a82786e8a`
*   **Derived MPC EVM Signer:** `0x6cb5858d8310045e4f2caea4e1231e4980af4e4b`

### End-to-End Execution Evidence (Live)
1.  **Sync OutLayer TDX Measurements:** `3Wm2R2Jb93ZiXQubfwACCjmFAqJiUWgZ5Wy88sBvSgxj` (129 measurements)
2.  **Register Receipt (NEAR):** `A5QEf2jnvB2nNCRVra249btAjt1h52TSV61AZ4bmQKBu`
3.  **Authorize Loan (NEAR Chain Signatures):** `FNsbX3M42GhWhQewi8kKFcNWi2xgASW9kPcYBTq6LeBL`
4.  **Draw Credit (Base Sepolia):** `0xf3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283`
5.  **Verify Consequence (NEAR Read RPC):** `3kgoyP8dr6nANZgzYmsrjp9PB3xPr29uD1oPTR25vJ6Y`

**MPC Domain 3 Signature (Proof of Verification):**
*   `r`: `0106b0af1622112404cb36ee9a20eaff48d863b62323d67750b0dbcf2a867001`
*   `s`: `238f95e757bd6455d5306605b537680227ca099d06b50e745b6f4e2cf802f28a`
*   `v`: `27`
