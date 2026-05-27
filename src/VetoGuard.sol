// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VetoGuard — Safe Guard module that requires a fresh Veto co-signature on every transaction.
///
/// @notice TESTNET ONLY — do not deploy to mainnet without an external review.
///         This contract gates a Safe smart account so that no transaction
///         executes unless a designated Veto co-signer has signed it
///         off-chain first. The Veto signature is appended to the Safe's
///         `signatures` bytes after the owner signature(s). Safe's own logic
///         ignores trailing bytes after the threshold's worth of sigs; this
///         Guard parses them.
///
/// @dev    Design constraints (deliberate, v1):
///         - Single Veto signer per Guard (rotatable by the Safe owner via
///           a 14-day timelock).
///         - Replay protection comes from Safe's own nonce — the nonce is
///           part of the EIP-712 hash Veto signs. Safe increments the nonce
///           after each execTransaction; signing a stale nonce won't match.
///         - Escape hatch: the Safe owner can request the Guard's removal
///           via `requestEscape()`. After 14 days, `checkTransaction` no
///           longer enforces the Veto signature — letting the owner call
///           `Safe.setGuard(0)` to unbind from Veto entirely. This is the
///           "Veto went down, let me out" safety valve.
///         - The Guard never holds funds, never executes external calls,
///           never reads from contracts it doesn't already require. Single
///           responsibility: revert if Veto didn't sign.
///
/// @dev    What this Guard does NOT do (deferred to future versions):
///         - Per-mandate scope (amount caps, recipient restrictions, etc.).
///           Those live in Veto's off-chain policy engine; on-chain enforces
///           "did Veto sign THIS transaction?", not "is this within policy?"
///         - Multi-signer Veto quorum.
///         - Per-action allowlist on-chain. The whole point of off-chain
///           policy is that it's expressive without committing it to bytecode.
contract VetoGuard {
    // ─────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────

    error NotSafeOwner();
    error VetoSignatureMissing();
    error VetoSignatureInvalid();
    error RotationAlreadyPending();
    error RotationNotPending();
    error RotationTimelockActive();
    error EscapeAlreadyPending();
    error EscapeNotPending();
    error EscapeTimelockActive();
    error ZeroAddress();
    error NotImplemented();

    // ─────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────

    event VetoSignerRotationRequested(address indexed newSigner, uint256 unlockAt);
    event VetoSignerRotated(address indexed oldSigner, address indexed newSigner);
    event EscapeRequested(uint256 unlockAt);
    event EscapeCancelled();
    event EscapeExecuted();

    // ─────────────────────────────────────────────────────────────────
    // Configuration
    // ─────────────────────────────────────────────────────────────────

    /// @notice The Safe this Guard is installed on. Set immutably at deploy.
    address public immutable safe;

    /// @notice The address whose secp256k1 signature must appear on every
    ///         Safe transaction for the Guard to allow it.
    address public vetoSigner;

    /// @notice Timelock duration. 14 days is hard-coded for v1 — non-config
    ///         keeps the contract small and the social contract clear.
    uint256 public constant TIMELOCK = 14 days;

    /// @notice Pending Veto-signer rotation. zero address = none pending.
    address public pendingSigner;
    uint256 public pendingSignerUnlockAt;

    /// @notice Escape-hatch state. When set, the Guard becomes a no-op after
    ///         the unlock time, letting the owner detach the Guard.
    uint256 public escapeUnlockAt;

    // ─────────────────────────────────────────────────────────────────
    // EIP-712 — replicates Safe's domain so we can recompute the same
    // SafeTx hash Safe itself uses. This lets the Veto co-signer sign
    // exactly the same hash the Safe verifies for its own owner sigs.
    // ─────────────────────────────────────────────────────────────────

    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");

    bytes32 private constant SAFE_TX_TYPEHASH =
        keccak256(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
        );

    // ─────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────

    constructor(address _safe, address _vetoSigner) {
        if (_safe == address(0) || _vetoSigner == address(0)) revert ZeroAddress();
        safe = _safe;
        vetoSigner = _vetoSigner;
    }

    // ─────────────────────────────────────────────────────────────────
    // Modifier — only the Safe itself can call admin functions. The Safe
    // is one-of-one (for v1); calls from the Safe come via execTransaction
    // which has already been signed by the owner. So "msg.sender == safe"
    // is equivalent to "owner has authorized this call".
    // ─────────────────────────────────────────────────────────────────

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafeOwner();
        _;
    }

    // ─────────────────────────────────────────────────────────────────
    // Safe Guard hook — the heart of this contract.
    // ─────────────────────────────────────────────────────────────────

    /// @dev Called by Safe before each execTransaction. We reject if the
    ///      Veto signature is missing or invalid, UNLESS the escape hatch
    ///      has elapsed (in which case we're a no-op so the owner can
    ///      detach the Guard).
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
        // Escape elapsed → no enforcement. Owner can now call setGuard(0).
        if (escapeUnlockAt != 0 && block.timestamp >= escapeUnlockAt) return;

        // Read Safe's current nonce for this tx. Safe increments nonce
        // AFTER execTransaction succeeds, so reading nonce() here gives
        // the nonce that's encoded in the hash being verified.
        uint256 nonce = ISafeNonce(safe).nonce();

        bytes32 txHash = _safeTxHash(
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            nonce
        );

        // Read the Veto signature from the trailing bytes. Safe consumed
        // the first `threshold * 65` bytes for owner signatures; for our
        // one-of-one Safes that's exactly 65. We require at least 130
        // bytes total (owner sig + Veto sig).
        if (signatures.length < 130) revert VetoSignatureMissing();
        (uint8 v, bytes32 r, bytes32 s) = _splitSig(signatures, 65);

        address recovered = ecrecover(txHash, v, r, s);
        if (recovered == address(0) || recovered != vetoSigner) {
            revert VetoSignatureInvalid();
        }
    }

    /// @dev Safe also calls this after execution. We don't use it but the
    ///      Guard interface requires it.
    function checkAfterExecution(bytes32 /* txHash */, bool /* success */) external pure {}

    // ─────────────────────────────────────────────────────────────────
    // Veto-signer rotation (owner-initiated, 14-day timelock)
    // ─────────────────────────────────────────────────────────────────

    /// @notice Start the process of rotating to a new Veto co-signer.
    ///         Owner submits this through their Safe; takes effect in 14 days
    ///         to give a paranoid user time to escape if the rotation is
    ///         coerced.
    function requestSignerRotation(address newSigner) external onlySafe {
        if (newSigner == address(0)) revert ZeroAddress();
        if (pendingSigner != address(0)) revert RotationAlreadyPending();
        pendingSigner = newSigner;
        pendingSignerUnlockAt = block.timestamp + TIMELOCK;
        emit VetoSignerRotationRequested(newSigner, pendingSignerUnlockAt);
    }

    /// @notice Cancel a pending rotation. Owner-only.
    function cancelSignerRotation() external onlySafe {
        if (pendingSigner == address(0)) revert RotationNotPending();
        delete pendingSigner;
        delete pendingSignerUnlockAt;
    }

    /// @notice Apply a pending rotation after its timelock elapses. Anyone
    ///         can call this — it just executes a state change the owner
    ///         already requested and the timer permitted.
    function executeSignerRotation() external {
        if (pendingSigner == address(0)) revert RotationNotPending();
        if (block.timestamp < pendingSignerUnlockAt) revert RotationTimelockActive();
        address old = vetoSigner;
        vetoSigner = pendingSigner;
        delete pendingSigner;
        delete pendingSignerUnlockAt;
        emit VetoSignerRotated(old, vetoSigner);
    }

    // ─────────────────────────────────────────────────────────────────
    // Escape hatch — "Veto is down / I want out"
    // ─────────────────────────────────────────────────────────────────

    /// @notice Start the escape process. After TIMELOCK elapses,
    ///         `checkTransaction` becomes a no-op and the owner can call
    ///         `Safe.setGuard(address(0))` to detach the Guard entirely.
    function requestEscape() external onlySafe {
        if (escapeUnlockAt != 0) revert EscapeAlreadyPending();
        escapeUnlockAt = block.timestamp + TIMELOCK;
        emit EscapeRequested(escapeUnlockAt);
    }

    /// @notice Cancel a pending escape. If the owner changed their mind.
    function cancelEscape() external onlySafe {
        if (escapeUnlockAt == 0) revert EscapeNotPending();
        delete escapeUnlockAt;
        emit EscapeCancelled();
    }

    /// @notice Status helper: is the escape elapsed (Guard now no-op)?
    function isEscaped() external view returns (bool) {
        return escapeUnlockAt != 0 && block.timestamp >= escapeUnlockAt;
    }

    // ─────────────────────────────────────────────────────────────────
    // Internal — EIP-712 hash construction
    // ─────────────────────────────────────────────────────────────────

    function _safeTxHash(
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

    /// @dev Read a 65-byte (r,s,v) signature starting at `offset` in `sigBytes`.
    function _splitSig(
        bytes calldata sigBytes,
        uint256 offset
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        // bounds-check is implicit — calldata access reverts on overrun
        r = bytes32(sigBytes[offset:offset + 32]);
        s = bytes32(sigBytes[offset + 32:offset + 64]);
        v = uint8(sigBytes[offset + 64]);
    }
}

/// @dev Minimal interface to read Safe's nonce. We don't import the full
///      Safe contract — just the one function we need.
interface ISafeNonce {
    function nonce() external view returns (uint256);
}
