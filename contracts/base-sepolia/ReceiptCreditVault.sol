// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title AgentPayoutProxy
/// @notice Vault-controlled revenue receiving address deployed per borrower agent.
///         Payers (e.g., x402 facilitators) settle USDC here. Only the owning
///         `ReceiptCreditVault` may pull accumulated funds to enforce repayment at the
///         source before forwarding any residual revenue to the agent.
contract AgentPayoutProxy {
    address public immutable vault;
    address public immutable agent;
    IERC20Minimal public immutable creditToken;

    error OnlyVault();
    error TokenTransferFailed();

    constructor(address _vault, address _agent, address _creditToken) {
        vault = _vault;
        agent = _agent;
        creditToken = IERC20Minimal(_creditToken);
    }

    function pullToVault() external returns (uint256 amount) {
        if (msg.sender != vault) revert OnlyVault();
        amount = creditToken.balanceOf(address(this));
        if (amount > 0) {
            bool ok = creditToken.transfer(vault, amount);
            if (!ok) revert TokenTransferFailed();
        }
    }
}

/// @title ReceiptCreditVault
/// @notice Base Sepolia credit vault supporting:
///         1. NEAR Chain Signatures EIP-712 LoanAuthorization (`domain_id: 0`, v2).
///         2. Vault-controlled `AgentPayoutProxy` addresses per borrower agent so incoming
///            x402 USDC settlements are skimmed for repayment before the agent touches residual.
///         3. Three-tranche first-loss pool accounting (`providerHoldbackBond`,
///            `juniorFirstLossReserve`, `seniorLiquidityReserve`).
///         4. Permissionless `markDefaulted` waterfall + `LoanDrawn`/`LoanRepaid`/`LoanDefaulted`
///            always emitted at `log_index: 0` for NEAR MPC Foreign-Tx verification (`domain_id: 3`).
///         5. Owner pause switch and configurable `hardPerAgentCap`.
contract ReceiptCreditVault {
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant LOAN_AUTH_TYPEHASH =
        keccak256(
            "LoanAuthorization(bytes32 receiptId,address borrower,uint256 principal,uint256 feeAmount,uint64 maturityAt,bytes32 evidenceCommitment,uint256 deadline)"
        );
    uint256 internal constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 internal constant BPS_DENOMINATOR = 10_000;

    enum LoanState {
        None,
        Active,
        Repaid,
        Defaulted
    }

    struct LoanPosition {
        bytes32 receiptId;
        address borrower;
        uint128 principal;
        uint128 feeAmount;
        uint128 repaidAmount;
        uint128 holdbackBonded;
        uint64 drawnAt;
        uint64 maturityAt;
        bytes32 evidenceCommitment;
        LoanState state;
    }

    address public immutable owner;
    address public immutable nearAuthorizedSigner;
    IERC20Minimal public immutable creditToken;
    bytes32 public immutable lenderId;
    bytes32 public immutable DOMAIN_SEPARATOR;

    uint64 public immutable gracePeriodSecs;
    uint16 public immutable providerHoldbackBps;
    uint16 public immutable minFirstLossCoverageBps;
    uint16 public immutable juniorYieldShareBps;

    bool public paused;
    uint256 public hardPerAgentCap;

    uint256 public juniorFirstLossReserve;
    uint256 public seniorLiquidityReserve;
    uint256 public totalActivePrincipal;

    mapping(bytes32 => bool) public consumedReceipts;
    mapping(bytes32 => LoanPosition) public loans;
    mapping(address => address) public agentPayoutProxy;
    mapping(address => bytes32) public activeLoanByBorrower;
    mapping(address => uint256) public activePrincipalByBorrower;
    mapping(address => uint256) public providerHoldbackBond;
    mapping(address => bool) public defaultedBorrower;
    mapping(address => uint256) public juniorDeposits;
    mapping(address => uint256) public seniorDeposits;

    // ERC-8004-compatible repayment summary counters
    mapping(address => uint32) public repaidLoanCount;
    mapping(address => uint32) public defaultedLoanCount;
    mapping(address => uint256) public cumulativeRepaidVolume;

    /// @notice ALWAYS emitted at `log_index: 0` during `drawCredit` for NEAR MPC Read RPC.
    event LoanDrawn(
        bytes32 indexed receiptId,
        address indexed borrower,
        uint256 principal,
        bytes32 indexed lenderId,
        bytes32 evidenceCommitment
    );

    /// @notice ALWAYS emitted at `log_index: 0` during `repayLoan` and active `sweepAgentPayout`.
    event LoanRepaid(
        bytes32 indexed receiptId,
        address indexed borrower,
        uint256 amountPaid,
        uint256 remainingBalance,
        bytes32 indexed lenderId,
        bytes32 evidenceCommitment
    );

    /// @notice ALWAYS emitted at `log_index: 0` during `markDefaulted` for NEAR MPC Read RPC.
    event LoanDefaulted(
        bytes32 indexed receiptId,
        address indexed borrower,
        uint256 unpaidPrincipal,
        uint256 firstLossAbsorbed,
        bytes32 indexed lenderId,
        bytes32 evidenceCommitment
    );

    event PayoutProxyDeployed(address indexed agent, address indexed proxy);
    event RevenueSwept(
        bytes32 indexed receiptId,
        address indexed agent,
        uint256 grossIncoming,
        uint256 skimmedForLoan,
        uint256 forwardedToAgent
    );
    event FirstLossDeposited(address indexed lp, uint256 amount, uint256 newJuniorReserve);
    event SeniorLiquidityDeposited(address indexed lp, uint256 amount, uint256 newSeniorReserve);
    event VaultPauseSet(bool paused);
    event HardPerAgentCapUpdated(uint256 newCap);
    event Erc8004FeedbackPrepared(
        address indexed agent,
        bytes32 indexed receiptId,
        int128 value,
        uint8 valueDecimals,
        string tag1,
        string tag2
    );

    error ZeroConfiguration();
    error InvalidPolicyParams();
    error OnlyOwner();
    error VaultPaused();
    error AuthorizationExpired(uint256 deadline, uint256 currentTimestamp);
    error InvalidLoanParameters();
    error PayoutProxyRequired(address borrower);
    error BorrowerAlreadyActive(address borrower, bytes32 activeReceiptId);
    error BorrowerDefaulted(address borrower);
    error ExceedsHardPerAgentCap(uint256 requested, uint256 cap);
    error InsufficientFirstLossCoverage(uint256 juniorReserve, uint256 requiredReserve);
    error InsufficientVaultLiquidity(uint256 available, uint256 required);
    error ReceiptAlreadyConsumed(bytes32 receiptId);
    error InvalidSignatureScalars();
    error InvalidNearSignature(address recovered, address expected);
    error LoanNotActive(bytes32 receiptId);
    error LoanNotExpired(bytes32 receiptId, uint256 defaultableAt, uint256 currentTimestamp);
    error NothingToSweep(address agent);
    error ProxySweepMismatch(uint256 pulled, uint256 expected);
    error CreditTransferFailed();

    constructor(
        address _nearAuthorizedSigner,
        address _creditToken,
        bytes32 _lenderId,
        uint256 _hardPerAgentCap,
        uint64 _gracePeriodSecs,
        uint16 _providerHoldbackBps,
        uint16 _minFirstLossCoverageBps,
        uint16 _juniorYieldShareBps
    ) {
        if (
            _nearAuthorizedSigner == address(0) ||
            _creditToken == address(0) ||
            _lenderId == bytes32(0)
        ) {
            revert ZeroConfiguration();
        }
        if (
            _hardPerAgentCap == 0 ||
            _providerHoldbackBps >= BPS_DENOMINATOR ||
            _juniorYieldShareBps > BPS_DENOMINATOR
        ) {
            revert InvalidPolicyParams();
        }
        owner = msg.sender;
        nearAuthorizedSigner = _nearAuthorizedSigner;
        creditToken = IERC20Minimal(_creditToken);
        lenderId = _lenderId;
        hardPerAgentCap = _hardPerAgentCap;
        gracePeriodSecs = _gracePeriodSecs;
        providerHoldbackBps = _providerHoldbackBps;
        minFirstLossCoverageBps = _minFirstLossCoverageBps;
        juniorYieldShareBps = _juniorYieldShareBps;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("ReceiptCreditVault")),
                keccak256(bytes("2")),
                block.chainid,
                address(this)
            )
        );
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert VaultPaused();
        _;
    }

    function pause() external onlyOwner {
        paused = true;
        emit VaultPauseSet(true);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit VaultPauseSet(false);
    }

    function setHardPerAgentCap(uint256 newCap) external onlyOwner {
        if (newCap == 0) revert InvalidPolicyParams();
        hardPerAgentCap = newCap;
        emit HardPerAgentCapUpdated(newCap);
    }

    /// @notice Deploy an immutable `AgentPayoutProxy` for `agent` if one does not yet exist.
    function deployAgentPayoutProxy(address agent) external returns (address proxy) {
        if (agent == address(0)) revert ZeroConfiguration();
        proxy = agentPayoutProxy[agent];
        if (proxy != address(0)) return proxy;
        AgentPayoutProxy deployed = new AgentPayoutProxy(address(this), agent, address(creditToken));
        proxy = address(deployed);
        agentPayoutProxy[agent] = proxy;
        emit PayoutProxyDeployed(agent, proxy);
    }

    function depositFirstLoss(uint256 amount) external whenNotPaused {
        if (amount == 0) revert InvalidLoanParameters();
        juniorFirstLossReserve += amount;
        juniorDeposits[msg.sender] += amount;
        emit FirstLossDeposited(msg.sender, amount, juniorFirstLossReserve);
        if (!creditToken.transferFrom(msg.sender, address(this), amount)) {
            revert CreditTransferFailed();
        }
    }

    function depositSeniorLiquidity(uint256 amount) external whenNotPaused {
        if (amount == 0) revert InvalidLoanParameters();
        seniorLiquidityReserve += amount;
        seniorDeposits[msg.sender] += amount;
        emit SeniorLiquidityDeposited(msg.sender, amount, seniorLiquidityReserve);
        if (!creditToken.transferFrom(msg.sender, address(this), amount)) {
            revert CreditTransferFailed();
        }
    }

    function computeStructHash(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        uint256 feeAmount,
        uint64 maturityAt,
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
                    feeAmount,
                    maturityAt,
                    evidenceCommitment,
                    deadline
                )
            );
    }

    function computeLoanDigest(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        uint256 feeAmount,
        uint64 maturityAt,
        bytes32 evidenceCommitment,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = computeStructHash(
            receiptId,
            borrower,
            principal,
            feeAmount,
            maturityAt,
            evidenceCommitment,
            deadline
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _verifyDrawSignature(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view {
        if ((v != 27 && v != 28) || uint256(s) == 0 || uint256(s) > SECP256K1N_HALF) {
            revert InvalidSignatureScalars();
        }
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != nearAuthorizedSigner) {
            revert InvalidNearSignature(recovered, nearAuthorizedSigner);
        }
    }

    function _validateDrawParams(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        uint256 feeAmount,
        uint64 maturityAt,
        bytes32 evidenceCommitment,
        uint256 deadline
    ) internal view {
        if (block.timestamp > deadline) {
            revert AuthorizationExpired(deadline, block.timestamp);
        }
        if (
            borrower == address(0) ||
            principal == 0 ||
            receiptId == bytes32(0) ||
            evidenceCommitment == bytes32(0) ||
            maturityAt <= block.timestamp ||
            principal > type(uint128).max ||
            feeAmount > type(uint128).max
        ) {
            revert InvalidLoanParameters();
        }
        if (agentPayoutProxy[borrower] == address(0)) {
            revert PayoutProxyRequired(borrower);
        }
        if (defaultedBorrower[borrower]) {
            revert BorrowerDefaulted(borrower);
        }
        if (activeLoanByBorrower[borrower] != bytes32(0)) {
            revert BorrowerAlreadyActive(borrower, activeLoanByBorrower[borrower]);
        }
        uint256 projectedPrincipal = activePrincipalByBorrower[borrower] + principal;
        if (projectedPrincipal > hardPerAgentCap) {
            revert ExceedsHardPerAgentCap(projectedPrincipal, hardPerAgentCap);
        }
        if (consumedReceipts[receiptId]) {
            revert ReceiptAlreadyConsumed(receiptId);
        }
        uint256 requiredJunior = ((totalActivePrincipal + principal) * minFirstLossCoverageBps) /
            BPS_DENOMINATOR;
        if (juniorFirstLossReserve < requiredJunior) {
            revert InsufficientFirstLossCoverage(juniorFirstLossReserve, requiredJunior);
        }
    }

    function drawCredit(
        bytes32 receiptId,
        address borrower,
        uint256 principal,
        uint256 feeAmount,
        uint64 maturityAt,
        bytes32 evidenceCommitment,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        _validateDrawParams(
            receiptId,
            borrower,
            principal,
            feeAmount,
            maturityAt,
            evidenceCommitment,
            deadline
        );
        {
            bytes32 digest = computeLoanDigest(
                receiptId,
                borrower,
                principal,
                feeAmount,
                maturityAt,
                evidenceCommitment,
                deadline
            );
            _verifyDrawSignature(digest, v, r, s);
        }

        uint256 holdback = (principal * providerHoldbackBps) / BPS_DENOMINATOR;
        uint256 netDisbursement = principal - holdback;
        {
            uint256 vaultBal = creditToken.balanceOf(address(this));
            if (vaultBal < netDisbursement) {
                revert InsufficientVaultLiquidity(vaultBal, netDisbursement);
            }
        }

        // Effects before interactions (CEI)
        consumedReceipts[receiptId] = true;
        activeLoanByBorrower[borrower] = receiptId;
        activePrincipalByBorrower[borrower] += principal;
        totalActivePrincipal += principal;
        providerHoldbackBond[borrower] += holdback;

        loans[receiptId] = LoanPosition({
            receiptId: receiptId,
            borrower: borrower,
            principal: uint128(principal),
            feeAmount: uint128(feeAmount),
            repaidAmount: 0,
            holdbackBonded: uint128(holdback),
            drawnAt: uint64(block.timestamp),
            maturityAt: maturityAt,
            evidenceCommitment: evidenceCommitment,
            state: LoanState.Active
        });

        // Emit LoanDrawn BEFORE transfer so LoanDrawn is log_index: 0
        emit LoanDrawn(receiptId, borrower, principal, lenderId, evidenceCommitment);

        if (!creditToken.transfer(borrower, netDisbursement)) {
            revert CreditTransferFailed();
        }
    }

    function _applyRepayment(
        bytes32 receiptId,
        uint256 incomingAmount
    ) internal returns (uint256 applied, uint256 holdbackReleased, uint256 newRemaining, bool fullyRepaid) {
        LoanPosition storage loan = loans[receiptId];
        if (loan.state != LoanState.Active) revert LoanNotActive(receiptId);

        uint256 totalDue = uint256(loan.principal) + uint256(loan.feeAmount);
        uint256 remainingBefore = totalDue - uint256(loan.repaidAmount);
        applied = incomingAmount <= remainingBefore ? incomingAmount : remainingBefore;

        uint256 unpaidPrincipalBefore = loan.principal > loan.repaidAmount
            ? uint256(loan.principal) - uint256(loan.repaidAmount)
            : 0;
        uint256 principalPortion = applied <= unpaidPrincipalBefore ? applied : unpaidPrincipalBefore;
        uint256 feePortion = applied - principalPortion;

        loan.repaidAmount += uint128(applied);
        newRemaining = totalDue - uint256(loan.repaidAmount);

        if (principalPortion > 0) {
            totalActivePrincipal -= principalPortion;
            activePrincipalByBorrower[loan.borrower] -= principalPortion;
        }
        if (feePortion > 0) {
            uint256 juniorYield = (feePortion * juniorYieldShareBps) / BPS_DENOMINATOR;
            juniorFirstLossReserve += juniorYield;
            seniorLiquidityReserve += (feePortion - juniorYield);
        }

        if (newRemaining == 0) {
            fullyRepaid = true;
            loan.state = LoanState.Repaid;
            activeLoanByBorrower[loan.borrower] = bytes32(0);
            holdbackReleased = uint256(loan.holdbackBonded);
            loan.holdbackBonded = 0;
            providerHoldbackBond[loan.borrower] -= holdbackReleased;
            repaidLoanCount[loan.borrower] += 1;
            cumulativeRepaidVolume[loan.borrower] += uint256(loan.principal);
        }
    }

    /// @notice Sweep incoming USDC from `agent`'s vault-controlled `AgentPayoutProxy`,
    ///         repaying active debt at the source before forwarding residual + released bond.
    ///         Emits `LoanRepaid` strictly at `log_index: 0` when an active loan is repaid.
    function sweepAgentPayout(
        address agent
    ) external returns (uint256 skimmed, uint256 netToAgent) {
        address proxy = agentPayoutProxy[agent];
        if (proxy == address(0)) revert PayoutProxyRequired(agent);

        uint256 incoming = creditToken.balanceOf(proxy);
        if (incoming == 0) revert NothingToSweep(agent);

        bytes32 activeId = activeLoanByBorrower[agent];
        if (activeId != bytes32(0) && loans[activeId].state == LoanState.Active) {
            (
                uint256 applied,
                uint256 holdbackReleased,
                uint256 remainingBalance,
                bool fullyRepaid
            ) = _applyRepayment(activeId, incoming);
            skimmed = applied;
            netToAgent = (incoming - applied) + holdbackReleased;

            // Emit LoanRepaid at log_index: 0 BEFORE external token transfers
            emit LoanRepaid(
                activeId,
                agent,
                applied,
                remainingBalance,
                lenderId,
                loans[activeId].evidenceCommitment
            );
            emit RevenueSwept(activeId, agent, incoming, applied, netToAgent);
            if (fullyRepaid) {
                emit Erc8004FeedbackPrepared(agent, activeId, 100, 0, "receipt-repaid", "on-time");
            }
        } else {
            netToAgent = incoming;
            emit RevenueSwept(bytes32(0), agent, incoming, 0, incoming);
        }

        uint256 pulled = AgentPayoutProxy(proxy).pullToVault();
        if (pulled != incoming) revert ProxySweepMismatch(pulled, incoming);

        if (netToAgent > 0) {
            if (!creditToken.transfer(agent, netToAgent)) {
                revert CreditTransferFailed();
            }
        }
    }

    /// @notice Direct repayment entrypoint (also emits `LoanRepaid` at `log_index: 0`).
    function repayLoan(bytes32 receiptId, uint256 amount) external {
        if (amount == 0) revert InvalidLoanParameters();
        address borrower = loans[receiptId].borrower;
        bytes32 evidenceCommitment = loans[receiptId].evidenceCommitment;
        (
            uint256 applied,
            uint256 holdbackReleased,
            uint256 remainingBalance,
            bool fullyRepaid
        ) = _applyRepayment(receiptId, amount);

        emit LoanRepaid(receiptId, borrower, applied, remainingBalance, lenderId, evidenceCommitment);
        if (fullyRepaid) {
            emit Erc8004FeedbackPrepared(borrower, receiptId, 100, 0, "receipt-repaid", "direct");
        }

        if (!creditToken.transferFrom(msg.sender, address(this), applied)) {
            revert CreditTransferFailed();
        }
        if (holdbackReleased > 0) {
            if (!creditToken.transfer(borrower, holdbackReleased)) {
                revert CreditTransferFailed();
            }
        }
    }

    /// @notice Permissionlessly mark an expired active loan defaulted and run the 3-tier waterfall:
    ///         1. `providerHoldbackBond[borrower]`
    ///         2. `juniorFirstLossReserve`
    ///         3. `seniorLiquidityReserve`
    ///         Emits `LoanDefaulted` at `log_index: 0` for NEAR MPC Read RPC verification.
    function markDefaulted(bytes32 receiptId) external {
        LoanPosition storage loan = loans[receiptId];
        if (loan.state != LoanState.Active) revert LoanNotActive(receiptId);

        uint256 defaultableAt = uint256(loan.maturityAt) + uint256(gracePeriodSecs);
        if (block.timestamp <= defaultableAt) {
            revert LoanNotExpired(receiptId, defaultableAt, block.timestamp);
        }

        uint256 unpaidPrincipal = loan.principal > loan.repaidAmount
            ? uint256(loan.principal) - uint256(loan.repaidAmount)
            : 0;
        address borrower = loan.borrower;
        bytes32 evidenceCommitment = loan.evidenceCommitment;

        uint256 remainingLoss = unpaidPrincipal;
        uint256 bondAvailable = providerHoldbackBond[borrower];
        uint256 bondSlashed = remainingLoss <= bondAvailable ? remainingLoss : bondAvailable;
        providerHoldbackBond[borrower] -= bondSlashed;
        remainingLoss -= bondSlashed;

        uint256 juniorSlashed = remainingLoss <= juniorFirstLossReserve
            ? remainingLoss
            : juniorFirstLossReserve;
        juniorFirstLossReserve -= juniorSlashed;
        remainingLoss -= juniorSlashed;

        if (remainingLoss > 0) {
            seniorLiquidityReserve = seniorLiquidityReserve > remainingLoss
                ? seniorLiquidityReserve - remainingLoss
                : 0;
        }

        loan.state = LoanState.Defaulted;
        loan.holdbackBonded = 0;
        totalActivePrincipal -= unpaidPrincipal;
        activePrincipalByBorrower[borrower] = 0;
        activeLoanByBorrower[borrower] = bytes32(0);
        defaultedBorrower[borrower] = true;
        defaultedLoanCount[borrower] += 1;

        uint256 firstLossAbsorbed = bondSlashed + juniorSlashed;
        emit LoanDefaulted(
            receiptId,
            borrower,
            unpaidPrincipal,
            firstLossAbsorbed,
            lenderId,
            evidenceCommitment
        );
        emit Erc8004FeedbackPrepared(borrower, receiptId, -100, 0, "receipt-default", "slashed");
    }

    /// @notice ERC-8004-compatible summary view of an agent's Base vault credit history.
    function getErc8004ReputationSummary(
        address agent
    ) external view returns (uint64 count, int128 value, uint8 valueDecimals) {
        uint32 repaid = repaidLoanCount[agent];
        uint32 defaulted = defaultedLoanCount[agent];
        count = uint64(repaid) + uint64(defaulted);
        value = int128(int256(uint256(repaid) * 100) - int256(uint256(defaulted) * 100));
        valueDecimals = 0;
    }
}
