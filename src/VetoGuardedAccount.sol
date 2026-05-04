// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VetoGuardedAccount — funds-holder that only spends on a fresh Veto mandate.
/// @notice This is the v0.6 STUB. Unaudited. Testnet-only. Production v2 ships with
///         an audited ERC-4337 module and Safe Guard variants.
///
/// @dev    The chain-side enforcement primitive for Veto. The off-chain Mandate JWT
///         (the veto/mandate-verifier package) gives wallets and services a trust
///         signal; this contract makes that signal mandatory at the chain level.
///         Even a compromised agent can't move funds without a fresh, in-scope,
///         Veto-signed mandate.
///
///         On-chain verification uses secp256k1 + EIP-712 (cheap via `ecrecover`).
///         Off-chain verification uses Ed25519 JWTs. Same scope fields, two
///         signatures, paired by `jti`. The Veto backend signs both.
contract VetoGuardedAccount {
    /// @notice Single-spend permission slip. Pins exactly what may move and where.
    struct Mandate {
        bytes32 jti;        // single-use nonce; same as `jti` in the JWT mandate
        uint256 exp;        // unix seconds; settle must be before this
        address recipient;  // exact destination
        uint256 maxAmount;  // upper bound; actual settle amount may be ≤ this
        address token;      // address(0) = native ETH; otherwise ERC20 contract
    }

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    address public owner;
    address public vetoSigner;
    mapping(bytes32 => bool) public spent;

    // EIP-712 cached domain separator pieces
    bytes32 private immutable _DOMAIN_NAME = keccak256(bytes("Veto"));
    bytes32 private immutable _DOMAIN_VERSION = keccak256(bytes("1"));
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant _MANDATE_TYPEHASH = keccak256(
        "Mandate(bytes32 jti,uint256 exp,address recipient,uint256 maxAmount,address token)"
    );

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error NotOwner();
    error MandateExpired();
    error MandateAlreadySpent();
    error RecipientMismatch();
    error AmountOverCap();
    error TokenMismatch();
    error BadSignature();
    error TransferFailed();

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event MandateExecuted(
        bytes32 indexed jti,
        address indexed recipient,
        uint256 amount,
        address token
    );
    event VetoSignerRotated(address indexed oldSigner, address indexed newSigner);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    // ---------------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------------

    constructor(address _owner, address _vetoSigner) {
        require(_owner != address(0) && _vetoSigner != address(0), "zero address");
        owner = _owner;
        vetoSigner = _vetoSigner;
    }

    receive() external payable {}

    // ---------------------------------------------------------------------
    // Core: execute a single mandate
    // ---------------------------------------------------------------------

    /// @notice Execute the spend authorized by `m`, signed by Veto.
    /// @param m         The mandate (recipient + cap + jti + expiry pinned).
    /// @param signature 65-byte secp256k1 signature by `vetoSigner` over the
    ///                  EIP-712 hash of `m`.
    /// @param amount    Actual amount to send. Must be ≤ `m.maxAmount`.
    function executeWithMandate(
        Mandate calldata m,
        bytes calldata signature,
        uint256 amount
    ) external {
        // 1. Signature: scope must come from the Veto operator.
        bytes32 digest = _hashMandate(m);
        if (_recover(digest, signature) != vetoSigner) revert BadSignature();

        // 2. Replay: each jti can only burn once.
        if (spent[m.jti]) revert MandateAlreadySpent();

        // 3. Time: hard expiry.
        if (block.timestamp >= m.exp) revert MandateExpired();

        // 4. Scope: caller-provided amount must fit under the mandate's cap.
        if (amount > m.maxAmount) revert AmountOverCap();

        // Mark spent BEFORE the external call (CEI pattern — no reentrancy window).
        spent[m.jti] = true;
        emit MandateExecuted(m.jti, m.recipient, amount, m.token);

        if (m.token == address(0)) {
            (bool ok, ) = m.recipient.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            // ERC20 transfer(address,uint256). 0xa9059cbb is the selector.
            (bool ok, bytes memory result) = m.token.call(
                abi.encodeWithSelector(0xa9059cbb, m.recipient, amount)
            );
            if (!ok || (result.length != 0 && !abi.decode(result, (bool)))) {
                revert TransferFailed();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------------

    function rotateVetoSigner(address newSigner) external {
        if (msg.sender != owner) revert NotOwner();
        require(newSigner != address(0), "zero address");
        emit VetoSignerRotated(vetoSigner, newSigner);
        vetoSigner = newSigner;
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        require(newOwner != address(0), "zero address");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    // ---------------------------------------------------------------------
    // EIP-712 helpers (public so backend can predict the digest)
    // ---------------------------------------------------------------------

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _DOMAIN_NAME,
                _DOMAIN_VERSION,
                block.chainid,
                address(this)
            )
        );
    }

    function hashMandate(Mandate calldata m) external view returns (bytes32) {
        return _hashMandate(m);
    }

    function _hashMandate(Mandate calldata m) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _MANDATE_TYPEHASH,
                m.jti,
                m.exp,
                m.recipient,
                m.maxAmount,
                m.token
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        // EIP-2 — reject high-s to prevent malleability.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSignature();
        }
        address rec = ecrecover(digest, v, r, s);
        if (rec == address(0)) revert BadSignature();
        return rec;
    }
}
