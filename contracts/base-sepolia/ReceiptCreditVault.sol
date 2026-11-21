// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title ReceiptCreditVault
/// @notice Base Sepolia credit vault that verifies EIP-712 loan authorizations signed by the
///         NEAR `ReceiptRegistry` contract via NEAR Chain Signatures (`v1.signer-prod.testnet`,
///         `domain_id: 0`, path `"receipt-credit-vault-v1"`), prevents receipt replay, emits
///         `LoanDrawn` at `log_index: 0` for NEAR MPC Foreign-Tx verification (`domain_id: 3`),
///         and disburses `MockCreditUSDC` to the borrower.
contract ReceiptCreditVault {
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant LOAN_AUTH_TYPEHASH =
        keccak256(
            "LoanAuthorization(bytes32 receiptId,address borrower,uint256 principal,bytes32 evidenceCommitment,uint256 deadline)"
        );
    uint256 internal constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice Derived secp256k1 EVM address of `(receipt_registry.testnet, "receipt-credit-vault-v1")`
    ///         under `v1.signer-prod.testnet` `domain_id: 0`.
    address public immutable nearAuthorizedSigner;

    /// @notice Credit token disbursed on valid loan draws (`MockCreditUSDC`).
    IERC20Minimal public immutable creditToken;

    /// @notice Canonical 32-byte identifier of this lending pool / facility.
    bytes32 public immutable lenderId;

    /// @notice Cached EIP-712 domain separator for `(block.chainid, address(this))`.
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Replay guard tracking whether a `receiptId` has already drawn credit.
    mapping(bytes32 => bool) public consumedReceipts;

    /// @notice Emitted at `log_index: 0` before the ERC-20 `Transfer` log so that NEAR MPC
    ///         `verify_foreign_transaction` (`EvmExtractor::Log { log_index: 0 }`) deterministically
    ///         extracts this event.
    event LoanDrawn(
        bytes32 indexed receiptId,
        address indexed borrower,
        uint256 principal,
        bytes32 indexed lenderId,
        bytes32 evidenceCommitment
    );

    error ZeroConfiguration();
    error AuthorizationExpired(uint256 deadline, uint256 currentTimestamp);
    error InvalidLoanParameters();
    error ReceiptAlreadyConsumed(bytes32 receiptId);
    error InvalidSignatureScalars();
    error InvalidNearSignature(address recovered, address expected);
    error CreditTransferFailed();

    constructor(address _nearAuthorizedSigner, address _creditToken, bytes32 _lenderId) {
        if (
            _nearAuthorizedSigner == address(0) ||
            _creditToken == address(0) ||
            _lenderId == bytes32(0)
        ) {
            revert ZeroConfiguration();
        }
        nearAuthorizedSigner = _nearAuthorizedSigner;
        creditToken = IERC20Minimal(_creditToken);
        lenderId = _lenderId;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("ReceiptCreditVault")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Compute the EIP-712 struct hash for a loan authorization.
    function computeStructHash(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        bytes32 evidenceCommitment,
        uint256 deadline
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    LOAN_AUTH_TYPEHASH,
                    receiptId,
                    borrower,
                    principal,
                    evidenceCommitment,
                    deadline
                )
            );
    }

    /// @notice Compute the EIP-712 signing digest (`\x19\x01 || DOMAIN_SEPARATOR || structHash`).
    function computeLoanDigest(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        bytes32 evidenceCommitment,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = computeStructHash(
            receiptId,
            borrower,
            principal,
            evidenceCommitment,
            deadline
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Verify a NEAR Chain Signatures EIP-712 loan authorization, mark `receiptId` consumed,
    ///         emit `LoanDrawn` at `log_index: 0`, and disburse `principal` to `borrower`.
    function drawCredit(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        bytes32 evidenceCommitment,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (block.timestamp > deadline) {
            revert AuthorizationExpired(deadline, block.timestamp);
        }
        if (
            borrower == address(0) ||
            principal == 0 ||
            receiptId == bytes32(0) ||
            evidenceCommitment == bytes32(0)
        ) {
            revert InvalidLoanParameters();
        }
        if (consumedReceipts[receiptId]) {
            revert ReceiptAlreadyConsumed(receiptId);
        }
        if ((v != 27 && v != 28) || uint256(s) == 0 || uint256(s) > SECP256K1N_HALF) {
            revert InvalidSignatureScalars();
        }

        bytes32 digest = computeLoanDigest(
            receiptId,
            borrower,
            principal,
            evidenceCommitment,
            deadline
        );
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != nearAuthorizedSigner) {
            revert InvalidNearSignature(recovered, nearAuthorizedSigner);
        }

        // Effects before interactions (CEI)
        consumedReceipts[receiptId] = true;

        // Emit LoanDrawn BEFORE creditToken.transfer so LoanDrawn is log_index 0 in the tx receipt
        emit LoanDrawn(receiptId, borrower, principal, lenderId, evidenceCommitment);

        // Interaction
        bool ok = creditToken.transfer(borrower, principal);
        if (!ok) {
            revert CreditTransferFailed();
        }
    }
}

