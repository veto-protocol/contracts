// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VetoGuard, ISafeNonce} from "../src/VetoGuard.sol";

/// @dev Stand-in for a Safe that exposes only the `nonce()` function the
///      Guard needs to read. Lets us call the Guard "as a Safe" via vm.prank.
contract MockSafeWithNonce is ISafeNonce {
    uint256 public override nonce;

    function setNonce(uint256 n) external {
        nonce = n;
    }

    function bumpNonce() external {
        nonce += 1;
    }
}

contract VetoGuardTest is Test {
    VetoGuard internal guard;
    MockSafeWithNonce internal safe;
    address internal safeAddr;

    uint256 internal vetoKey;
    address internal vetoSigner;
    uint256 internal newVetoKey;
    address internal newVetoSigner;
    uint256 internal otherKey;
    address internal otherSigner;

    function setUp() public {
        vetoKey = uint256(keccak256("veto-test-key"));
        vetoSigner = vm.addr(vetoKey);
        newVetoKey = uint256(keccak256("new-veto-test-key"));
        newVetoSigner = vm.addr(newVetoKey);
        otherKey = uint256(keccak256("attacker-key"));
        otherSigner = vm.addr(otherKey);

        safe = new MockSafeWithNonce();
        safeAddr = address(safe);
        guard = new VetoGuard(safeAddr, vetoSigner);
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers — build signatures + tx hashes the way Safe does
    // ─────────────────────────────────────────────────────────────────

    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 internal constant SAFE_TX_TYPEHASH =
        keccak256(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
        );

    struct Tx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address payable refundReceiver;
        uint256 nonce;
    }

    function _txHash(Tx memory t) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safeAddr)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                t.to,
                t.value,
                keccak256(t.data),
                t.operation,
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                t.refundReceiver,
                t.nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _sign(uint256 key, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, h);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build the full Safe `signatures` blob: [owner_sig | veto_sig].
    ///      For one-of-one Safes, owner_sig is 65 bytes; we just stuff a
    ///      dummy owner sig (Safe verifies it itself; the Guard ignores it).
    function _sigsBlob(bytes memory ownerSig, bytes memory vetoSig)
        internal
        pure
        returns (bytes memory)
    {
        require(ownerSig.length == 65, "ownerSig must be 65");
        require(vetoSig.length == 65, "vetoSig must be 65");
        return abi.encodePacked(ownerSig, vetoSig);
    }

    function _defaultTx() internal pure returns (Tx memory) {
        return Tx({
            to: address(0xBEEF),
            value: 1 ether,
            data: hex"",
            operation: 0,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: 0
        });
    }

    function _ownerSigDummy() internal pure returns (bytes memory) {
        // 65 zero bytes — doesn't need to be a real signature for the
        // Guard's tests because we're testing the Guard logic in isolation.
        // In production, Safe verifies this against the owner's key before
        // even calling the Guard.
        return new bytes(65);
    }

    function _call(Tx memory t, bytes memory sigs) internal {
        guard.checkTransaction(
            t.to,
            t.value,
            t.data,
            t.operation,
            t.safeTxGas,
            t.baseGas,
            t.gasPrice,
            t.gasToken,
            t.refundReceiver,
            sigs,
            address(this)
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Happy path
    // ─────────────────────────────────────────────────────────────────

    function test_happy_path_allows_with_valid_veto_signature() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(vetoKey, h));
        _call(t, sigs); // must not revert
    }

    // ─────────────────────────────────────────────────────────────────
    // Missing / malformed signature
    // ─────────────────────────────────────────────────────────────────

    function test_reverts_when_only_owner_sig_present() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        // Only 65 bytes — no Veto sig appended.
        bytes memory sigs = _ownerSigDummy();
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(t, sigs);
    }

    function test_reverts_when_signatures_empty() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(t, "");
    }

    function test_reverts_when_signatures_truncated() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        // 129 bytes — one byte short of having a Veto sig.
        bytes memory sigs = new bytes(129);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Wrong signer
    // ─────────────────────────────────────────────────────────────────

    function test_reverts_when_veto_sig_from_random_key() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(otherKey, h));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    function test_reverts_when_veto_sig_for_different_tx() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        // Sign a DIFFERENT tx hash than the one being checked.
        Tx memory otherTx = _defaultTx();
        otherTx.value = 999 ether;
        bytes32 otherHash = _txHash(otherTx);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(vetoKey, otherHash));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    function test_reverts_when_veto_sig_garbage() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        // 65 bytes of zeros — ecrecover returns address(0) → invalid.
        bytes memory junkSig = new bytes(65);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), junkSig);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Replay protection — relies on Safe's nonce being in the hash
    // ─────────────────────────────────────────────────────────────────

    function test_replay_with_stale_nonce_fails() public {
        // Sign a tx for nonce=0.
        Tx memory t = _defaultTx();
        t.nonce = 0;
        bytes32 h = _txHash(t);
        bytes memory vetoSig = _sign(vetoKey, h);

        // Safe has now advanced to nonce=1. The Guard reads current nonce
        // and recomputes the hash with nonce=1, so the stored sig won't
        // match.
        safe.setNonce(1);

        bytes memory sigs = _sigsBlob(_ownerSigDummy(), vetoSig);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    function test_two_distinct_nonces_both_pass_with_distinct_sigs() public {
        // nonce 0 → fresh sig → allow
        Tx memory t0 = _defaultTx();
        t0.nonce = 0;
        safe.setNonce(0);
        _call(t0, _sigsBlob(_ownerSigDummy(), _sign(vetoKey, _txHash(t0))));

        // bump nonce, re-sign for nonce 1, allow
        safe.setNonce(1);
        Tx memory t1 = _defaultTx();
        t1.nonce = 1;
        _call(t1, _sigsBlob(_ownerSigDummy(), _sign(vetoKey, _txHash(t1))));
    }

    // ─────────────────────────────────────────────────────────────────
    // Cross-chain replay protection — chainId is in the domain separator
    // ─────────────────────────────────────────────────────────────────

    function test_signature_from_other_chain_fails() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);

        // Sign a hash computed with a DIFFERENT chainId.
        bytes32 foreignDomain = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, uint256(999), safeAddr)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                t.to,
                t.value,
                keccak256(t.data),
                t.operation,
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                t.refundReceiver,
                t.nonce
            )
        );
        bytes32 foreignHash = keccak256(
            abi.encodePacked("\x19\x01", foreignDomain, structHash)
        );
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(vetoKey, foreignHash));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Cross-Safe replay protection — Safe address is in the domain
    // ─────────────────────────────────────────────────────────────────

    function test_signature_for_other_safe_fails() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);

        // Sign a hash computed for a DIFFERENT Safe address.
        address otherSafe = address(0xDEAD);
        bytes32 foreignDomain = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, otherSafe)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                t.to,
                t.value,
                keccak256(t.data),
                t.operation,
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                t.refundReceiver,
                t.nonce
            )
        );
        bytes32 foreignHash = keccak256(
            abi.encodePacked("\x19\x01", foreignDomain, structHash)
        );
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(vetoKey, foreignHash));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Signer rotation (timelock)
    // ─────────────────────────────────────────────────────────────────

    function test_rotation_requires_safe_caller() public {
        vm.expectRevert(VetoGuard.NotSafeOwner.selector);
        guard.requestSignerRotation(newVetoSigner);
    }

    function test_rotation_revert_on_zero_address() public {
        vm.prank(safeAddr);
        vm.expectRevert(VetoGuard.ZeroAddress.selector);
        guard.requestSignerRotation(address(0));
    }

    function test_rotation_revert_when_already_pending() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(newVetoSigner);
        vm.prank(safeAddr);
        vm.expectRevert(VetoGuard.RotationAlreadyPending.selector);
        guard.requestSignerRotation(otherSigner);
    }

    function test_rotation_revert_before_timelock() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(newVetoSigner);
        // 13 days later — still locked
        vm.warp(block.timestamp + 13 days);
        vm.expectRevert(VetoGuard.RotationTimelockActive.selector);
        guard.executeSignerRotation();
    }

    function test_rotation_succeeds_after_timelock() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(newVetoSigner);
        vm.warp(block.timestamp + 14 days);
        guard.executeSignerRotation();
        assertEq(guard.vetoSigner(), newVetoSigner);
        assertEq(guard.pendingSigner(), address(0));
    }

    function test_rotation_cancel() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(newVetoSigner);
        vm.prank(safeAddr);
        guard.cancelSignerRotation();
        assertEq(guard.pendingSigner(), address(0));
        // Now executing should fail.
        vm.expectRevert(VetoGuard.RotationNotPending.selector);
        guard.executeSignerRotation();
    }

    function test_after_rotation_old_signer_rejected() public {
        // Rotate signer.
        vm.prank(safeAddr);
        guard.requestSignerRotation(newVetoSigner);
        vm.warp(block.timestamp + 14 days);
        guard.executeSignerRotation();

        // Old signer's sig no longer works.
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(vetoKey, h));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);

        // New signer's sig works.
        sigs = _sigsBlob(_ownerSigDummy(), _sign(newVetoKey, h));
        _call(t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Escape hatch
    // ─────────────────────────────────────────────────────────────────

    function test_escape_requires_safe_caller() public {
        vm.expectRevert(VetoGuard.NotSafeOwner.selector);
        guard.requestEscape();
    }

    function test_escape_before_timelock_still_enforces() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.warp(block.timestamp + 13 days);
        // Still enforced — escape hasn't elapsed.
        assertFalse(guard.isEscaped());
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(t, _ownerSigDummy());
    }

    function test_escape_after_timelock_is_no_op() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.warp(block.timestamp + 14 days);
        assertTrue(guard.isEscaped());

        // Now checkTransaction passes with NO Veto sig — owner can detach.
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        _call(t, _ownerSigDummy()); // must not revert
    }

    function test_escape_cancel() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.prank(safeAddr);
        guard.cancelEscape();
        assertEq(guard.escapeUnlockAt(), 0);

        // Even after 14 days, no escape because it was cancelled.
        vm.warp(block.timestamp + 14 days);
        assertFalse(guard.isEscaped());
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(t, _ownerSigDummy());
    }

    function test_escape_already_pending() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.prank(safeAddr);
        vm.expectRevert(VetoGuard.EscapeAlreadyPending.selector);
        guard.requestEscape();
    }

    function test_escape_cancel_when_not_pending() public {
        vm.prank(safeAddr);
        vm.expectRevert(VetoGuard.EscapeNotPending.selector);
        guard.cancelEscape();
    }

    // ─────────────────────────────────────────────────────────────────
    // Adversarial — things I'd try if I were attacking this contract
    // ─────────────────────────────────────────────────────────────────

    /// @dev If an attacker reuses a Veto sig from a prior tx (same nonce
    ///      same hash), the Guard would accept it — but Safe itself won't
    ///      let the same nonce execute twice. So even if the Guard passes,
    ///      Safe reverts. This test documents that Safe is the canonical
    ///      replay defense; the Guard just enforces "Veto signed THIS
    ///      version of THIS nonce."
    function test_same_nonce_replay_at_guard_layer_passes_but_safe_blocks() public {
        Tx memory t = _defaultTx();
        safe.setNonce(0);
        bytes32 h = _txHash(t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(vetoKey, h));

        // First call: Guard accepts.
        _call(t, sigs);

        // Second call with the SAME nonce: Guard also accepts (it's stateless).
        // In production, Safe would have already incremented the nonce and
        // would reject the second execTransaction. We document this is the
        // intentional separation of concerns.
        _call(t, sigs);
    }

    /// @dev Signature with v=0 or v=1 (legacy/non-canonical) should not
    ///      recover to the Veto signer unless they actually signed it.
    ///      OpenZeppelin's ECDSA has a malleability check; we rely on
    ///      ecrecover returning a different address (or zero) for malleated
    ///      sigs, which fails the equality check.
    function test_malformed_v_byte_does_not_match_signer() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(t);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vetoKey, h);
        // Corrupt v.
        v = v == 27 ? 28 : 27;
        bytes memory badSig = abi.encodePacked(r, s, v);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), badSig);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    /// @dev Front-running the executeSignerRotation: anyone can call it
    ///      after the timelock. That's fine because it's idempotent and
    ///      the new signer is what the owner already requested. Confirm.
    function test_rotation_execute_callable_by_anyone() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(newVetoSigner);
        vm.warp(block.timestamp + 14 days);

        // Non-owner calls — should still succeed.
        vm.prank(otherSigner);
        guard.executeSignerRotation();
        assertEq(guard.vetoSigner(), newVetoSigner);
    }

    /// @dev Escape hatch state can be toggled but cannot be silently
    ///      revoked once unlocked — only by an explicit cancelEscape AFTER
    ///      the timelock elapses, the Guard returns true from isEscaped().
    ///      Once isEscaped(), the only way to re-engage Veto's protection
    ///      is to detach this Guard entirely and install a fresh one. Test
    ///      that explicit cancel after elapse still has effect (resets
    ///      the state so future requests start cleanly).
    function test_escape_can_be_cancelled_after_elapse() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.warp(block.timestamp + 14 days);
        assertTrue(guard.isEscaped());

        // Cancel even though elapsed — escape state cleared.
        vm.prank(safeAddr);
        guard.cancelEscape();
        assertFalse(guard.isEscaped());

        // Enforcement back on.
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(t, _ownerSigDummy());
    }

    /// @dev Owner cannot bypass enforcement by calling checkTransaction
    ///      directly. It's a view function callable by anyone, but the
    ///      "anyone" is decorative — only Safe's own execTransaction path
    ///      will route through it. Verifying anyway: a direct call from
    ///      a random EOA with a fake Veto sig still must satisfy the
    ///      cryptographic check.
    function test_direct_call_from_eoa_still_requires_real_signature() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        // Attacker forges a "sig" but doesn't have the Veto key.
        bytes memory forgedSig = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            uint8(27)
        );
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), forgedSig);
        vm.prank(otherSigner); // attacker calls
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Fuzz tests — random hashes shouldn't accidentally validate
    // ─────────────────────────────────────────────────────────────────

    function testFuzz_random_signatures_dont_validate(
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public {
        // Skip degenerate v values; ecrecover returns 0 for those anyway.
        if (v != 27 && v != 28) v = 27;

        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes memory fuzzedSig = abi.encodePacked(r, s, v);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), fuzzedSig);

        // Recover what this fuzz sig points at.
        bytes32 h = _txHash(t);
        address recovered = ecrecover(h, v, r, s);

        // If by infinitesimal chance the random sig recovers to our
        // vetoSigner, the call WOULD succeed. Otherwise it must revert.
        if (recovered == vetoSigner && recovered != address(0)) {
            _call(t, sigs);
        } else {
            vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
            _call(t, sigs);
        }
    }
}
