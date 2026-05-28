// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VetoGuard — Singleton Safe Guard module for Veto's on-chain hard-stop.
///
/// @notice TESTNET ONLY — do not deploy to mainnet without an external review.
///
///         One Guard contract deployed once at a known address per chain.
///         Any Safe that calls `setGuard(<VetoGuard address>)` gates every
///         subsequent transaction through this contract: the Veto co-signer's
///         secp256k1 signature must appear in the trailing bytes of the
///         Safe's `signatures` blob, or the transaction reverts.
///
/// @dev    Per-Safe state lives in `configs[safe]`. Each Safe gets:
///           - An effective Veto signer (its own override, or the
///             contract-wide default if none set).
///           - A pending signer rotation (14-day timelock).
///           - An escape-hatch unlock time (14-day timelock).
///         All admin functions read msg.sender as the calling Safe — the
///         Safe owner approves them via execTransaction with their normal
///         signing flow, so "msg.sender == Safe" implies "owner authorized".
///
/// @dev    EIP-712 domain separator uses block.chainid + msg.sender, so each
///         Safe gets its own per-tx hash; signatures don't cross between
///         Safes even with the same nonce/to/value.
///
/// @dev    Onboarding cost: each user deploys a Safe + makes one `setGuard()`
///         call. They do NOT deploy a Guard contract — the singleton is
///         shared. Cheaper, simpler, easier to explain.
contract VetoGuard {
    // ─────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────

    error VetoSignatureMissing();
    error VetoSignatureInvalid();
    error RotationAlreadyPending();
    error RotationNotPending();
    error RotationTimelockActive();
    error EscapeAlreadyPending();
    error EscapeNotPending();
    error ZeroAddress();

    // ─────────────────────────────────────────────────────────────────
    // Events  (`safe` is indexed so we can per-tenant filter logs)
    // ─────────────────────────────────────────────────────────────────

    event VetoSignerRotationRequested(address indexed safe, address indexed newSigner, uint256 unlockAt);
    event VetoSignerRotationCancelled(address indexed safe);
    event VetoSignerRotated(address indexed safe, address indexed oldSigner, address indexed newSigner);
    event EscapeRequested(address indexed safe, uint256 unlockAt);
    event EscapeCancelled(address indexed safe);

    // ─────────────────────────────────────────────────────────────────
    // Per-Safe configuration. Read via `configs(safe)` getter.
    // ─────────────────────────────────────────────────────────────────

    struct SafeConfig {
        address vetoSigner;         // 0 = use defaultVetoSigner
        address pendingSigner;      // 0 = no pending rotation
        uint256 pendingSignerUnlockAt;
        uint256 escapeUnlockAt;     // 0 = no escape pending
    }

    /// @notice Contract-wide default Veto signer. Used by any Safe that
    ///         hasn't set its own override via `requestSignerRotation`.
    address public immutable defaultVetoSigner;

    /// @notice Per-Safe overrides + state. Keyed by the calling Safe's address.
    mapping(address safe => SafeConfig) public configs;

    /// @notice Hard-coded timelock — same value for rotation + escape.
    uint256 public constant TIMELOCK = 14 days;

    // ─────────────────────────────────────────────────────────────────
    // EIP-712 type hashes — must agree byte-for-byte with the off-chain
    // signer (gateway.services.safe_signer in the Veto backend).
    // ─────────────────────────────────────────────────────────────────

    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");

    bytes32 private constant SAFE_TX_TYPEHASH =
        keccak256(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,"
            "uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
        );

    // ─────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────

    constructor(address _defaultVetoSigner) {
        if (_defaultVetoSigner == address(0)) revert ZeroAddress();
        defaultVetoSigner = _defaultVetoSigner;
    }

    // ─────────────────────────────────────────────────────────────────
    // Lookup — what signer is effective for `safe`?
    // ─────────────────────────────────────────────────────────────────

    function effectiveSigner(address safe) public view returns (address) {
        address override_ = configs[safe].vetoSigner;
        return override_ != address(0) ? override_ : defaultVetoSigner;
    }

    function isEscaped(address safe) public view returns (bool) {
        uint256 unlock = configs[safe].escapeUnlockAt;
        return unlock != 0 && block.timestamp >= unlock;
    }

    // ─────────────────────────────────────────────────────────────────
    // Safe Guard hook — called by Safe before each execTransaction.
    // ─────────────────────────────────────────────────────────────────

    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address /* msgSender */
    ) external view {
        address safe = msg.sender;
        SafeConfig storage cfg = configs[safe];

        // Escape elapsed → no enforcement. Owner can now call setGuard(0).
        if (cfg.escapeUnlockAt != 0 && block.timestamp >= cfg.escapeUnlockAt) return;

        uint256 nonce = ISafeNonce(safe).nonce();
        bytes32 txHash = _safeTxHash(
            safe, to, value, data, operation, safeTxGas, baseGas,
            gasPrice, gasToken, refundReceiver, nonce
        );

        // Veto signature lives in the trailing bytes after the Safe's
        // threshold's worth of owner sigs. For one-of-one Safes that's
        // bytes [65:130].
        if (signatures.length < 130) revert VetoSignatureMissing();
        (uint8 v, bytes32 r, bytes32 s) = _splitSig(signatures, 65);

        address expected = cfg.vetoSigner != address(0) ? cfg.vetoSigner : defaultVetoSigner;
        address recovered = ecrecover(txHash, v, r, s);
        if (recovered == address(0) || recovered != expected) {
            revert VetoSignatureInvalid();
        }
    }

    function checkAfterExecution(bytes32 /* txHash */, bool /* success */) external pure {}

    // ─────────────────────────────────────────────────────────────────
    // Per-Safe admin — only callable through the Safe's own execTransaction
    // (the Safe is msg.sender, having already verified the owner's sig).
    // ─────────────────────────────────────────────────────────────────

    function requestSignerRotation(address newSigner) external {
        if (newSigner == address(0)) revert ZeroAddress();
        SafeConfig storage cfg = configs[msg.sender];
        if (cfg.pendingSigner != address(0)) revert RotationAlreadyPending();
        cfg.pendingSigner = newSigner;
        cfg.pendingSignerUnlockAt = block.timestamp + TIMELOCK;
        emit VetoSignerRotationRequested(msg.sender, newSigner, cfg.pendingSignerUnlockAt);
    }

    function cancelSignerRotation() external {
        SafeConfig storage cfg = configs[msg.sender];
        if (cfg.pendingSigner == address(0)) revert RotationNotPending();
        cfg.pendingSigner = address(0);
        cfg.pendingSignerUnlockAt = 0;
        emit VetoSignerRotationCancelled(msg.sender);
    }

    /// @notice Apply a pending rotation after its timelock elapses. Anyone
    ///         can trigger it on behalf of the Safe — the owner already
    ///         requested it and the timer permitted.
    function executeSignerRotation(address safe) external {
        SafeConfig storage cfg = configs[safe];
        if (cfg.pendingSigner == address(0)) revert RotationNotPending();
        if (block.timestamp < cfg.pendingSignerUnlockAt) revert RotationTimelockActive();
        address old = cfg.vetoSigner != address(0) ? cfg.vetoSigner : defaultVetoSigner;
        cfg.vetoSigner = cfg.pendingSigner;
        cfg.pendingSigner = address(0);
        cfg.pendingSignerUnlockAt = 0;
        emit VetoSignerRotated(safe, old, cfg.vetoSigner);
    }

    function requestEscape() external {
        SafeConfig storage cfg = configs[msg.sender];
        if (cfg.escapeUnlockAt != 0) revert EscapeAlreadyPending();
        cfg.escapeUnlockAt = block.timestamp + TIMELOCK;
        emit EscapeRequested(msg.sender, cfg.escapeUnlockAt);
    }

    function cancelEscape() external {
        SafeConfig storage cfg = configs[msg.sender];
        if (cfg.escapeUnlockAt == 0) revert EscapeNotPending();
        cfg.escapeUnlockAt = 0;
        emit EscapeCancelled(msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────
    // Internal
    // ─────────────────────────────────────────────────────────────────

    function _safeTxHash(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safe)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _splitSig(
        bytes calldata sigBytes,
        uint256 offset
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        r = bytes32(sigBytes[offset:offset + 32]);
        s = bytes32(sigBytes[offset + 32:offset + 64]);
        v = uint8(sigBytes[offset + 64]);
    }
}

/// @dev Minimal interface to read the Safe's nonce.
interface ISafeNonce {
    function nonce() external view returns (uint256);
}
