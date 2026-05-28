// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VetoGuard, ISafeNonce} from "../src/VetoGuard.sol";

/// @dev Stand-in Safe that exposes `nonce()`. The Guard reads it via
///      ISafeNonce(msg.sender).nonce() during checkTransaction. We call
///      the Guard via vm.prank from this contract's address so msg.sender
///      = this contract = the "Safe" in the Guard's view.
contract MockSafeWithNonce is ISafeNonce {
    uint256 public override nonce;

    function setNonce(uint256 n) external {
        nonce = n;
    }
}

contract VetoGuardTest is Test {
    VetoGuard internal guard;
    MockSafeWithNonce internal safe;
    MockSafeWithNonce internal safe2;        // a second Safe for cross-Safe isolation tests
    address internal safeAddr;
    address internal safe2Addr;

    uint256 internal defaultKey;
    address internal defaultSigner;
    uint256 internal overrideKey;
    address internal overrideSigner;
    uint256 internal otherKey;
    address internal otherSigner;

    function setUp() public {
        defaultKey = uint256(keccak256("veto-default-key"));
        defaultSigner = vm.addr(defaultKey);
        overrideKey = uint256(keccak256("veto-override-key"));
        overrideSigner = vm.addr(overrideKey);
        otherKey = uint256(keccak256("attacker-key"));
        otherSigner = vm.addr(otherKey);

        safe = new MockSafeWithNonce();
        safeAddr = address(safe);
        safe2 = new MockSafeWithNonce();
        safe2Addr = address(safe2);
        guard = new VetoGuard(defaultSigner);
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
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

    function _txHash(address whichSafe, Tx memory t) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, whichSafe)
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
        return new bytes(65);
    }

    /// @dev Call checkTransaction as if from `whichSafe`. Uses vm.prank so
    ///      msg.sender = whichSafe inside the Guard.
    function _call(address whichSafe, Tx memory t, bytes memory sigs) internal {
        vm.prank(whichSafe);
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
    // Default signer + happy path
    // ─────────────────────────────────────────────────────────────────

    function test_default_signer_set_at_construction() public {
        assertEq(guard.defaultVetoSigner(), defaultSigner);
        // Unregistered Safe inherits the default.
        assertEq(guard.effectiveSigner(safeAddr), defaultSigner);
    }

    function test_constructor_rejects_zero_address() public {
        vm.expectRevert(VetoGuard.ZeroAddress.selector);
        new VetoGuard(address(0));
    }

    function test_happy_path_allows_with_default_signer() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(safeAddr, t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, h));
        _call(safeAddr, t, sigs); // must not revert
    }

    // ─────────────────────────────────────────────────────────────────
    // Missing / malformed signature
    // ─────────────────────────────────────────────────────────────────

    function test_reverts_when_only_owner_sig_present() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(safeAddr, t, _ownerSigDummy());
    }

    function test_reverts_when_signatures_empty() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(safeAddr, t, "");
    }

    function test_reverts_when_signatures_truncated() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(safeAddr, t, new bytes(129));
    }

    // ─────────────────────────────────────────────────────────────────
    // Wrong signer
    // ─────────────────────────────────────────────────────────────────

    function test_reverts_when_veto_sig_from_random_key() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(safeAddr, t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(otherKey, h));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);
    }

    function test_reverts_when_veto_sig_for_different_tx() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        Tx memory otherTx = _defaultTx();
        otherTx.value = 999 ether;
        bytes32 otherHash = _txHash(safeAddr, otherTx);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, otherHash));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);
    }

    function test_reverts_when_veto_sig_garbage() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), new bytes(65));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Replay protection (Safe nonce + per-Safe domain)
    // ─────────────────────────────────────────────────────────────────

    function test_replay_with_stale_nonce_fails() public {
        Tx memory t = _defaultTx();
        t.nonce = 0;
        bytes32 h = _txHash(safeAddr, t);
        bytes memory vetoSig = _sign(defaultKey, h);
        safe.setNonce(1);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), vetoSig);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);
    }

    function test_two_distinct_nonces_both_pass_with_distinct_sigs() public {
        Tx memory t0 = _defaultTx();
        t0.nonce = 0;
        safe.setNonce(0);
        _call(safeAddr, t0, _sigsBlob(_ownerSigDummy(), _sign(defaultKey, _txHash(safeAddr, t0))));

        safe.setNonce(1);
        Tx memory t1 = _defaultTx();
        t1.nonce = 1;
        _call(safeAddr, t1, _sigsBlob(_ownerSigDummy(), _sign(defaultKey, _txHash(safeAddr, t1))));
    }

    function test_signature_for_other_safe_fails() public {
        // Sign for safe2 but invoke from safe.
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 hSafe2 = _txHash(safe2Addr, t);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, hSafe2));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);
    }

    function test_signature_from_other_chain_fails() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);

        bytes32 foreignDomain = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, uint256(999), safeAddr)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                t.to, t.value, keccak256(t.data),
                t.operation, t.safeTxGas, t.baseGas, t.gasPrice,
                t.gasToken, t.refundReceiver, t.nonce
            )
        );
        bytes32 foreignHash = keccak256(
            abi.encodePacked("\x19\x01", foreignDomain, structHash)
        );
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, foreignHash));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Per-Safe isolation — two Safes, independent configs
    // ─────────────────────────────────────────────────────────────────

    function test_two_safes_use_default_independently() public {
        Tx memory t = _defaultTx();
        safe.setNonce(0);
        safe2.setNonce(0);

        _call(safeAddr, t, _sigsBlob(_ownerSigDummy(), _sign(defaultKey, _txHash(safeAddr, t))));
        _call(safe2Addr, t, _sigsBlob(_ownerSigDummy(), _sign(defaultKey, _txHash(safe2Addr, t))));
    }

    function test_safe_a_rotation_does_not_affect_safe_b() public {
        // Safe A rotates to overrideSigner.
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.warp(block.timestamp + 14 days);
        guard.executeSignerRotation(safeAddr);

        // Safe A now requires overrideSigner.
        Tx memory t = _defaultTx();
        safe.setNonce(0);
        bytes memory aSigs = _sigsBlob(_ownerSigDummy(), _sign(overrideKey, _txHash(safeAddr, t)));
        _call(safeAddr, t, aSigs);

        // Safe B still uses the default.
        safe2.setNonce(0);
        bytes memory bSigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, _txHash(safe2Addr, t)));
        _call(safe2Addr, t, bSigs);
    }

    // ─────────────────────────────────────────────────────────────────
    // Signer rotation (per-Safe timelock)
    // ─────────────────────────────────────────────────────────────────

    function test_rotation_revert_on_zero_address() public {
        vm.prank(safeAddr);
        vm.expectRevert(VetoGuard.ZeroAddress.selector);
        guard.requestSignerRotation(address(0));
    }

    function test_rotation_revert_when_already_pending() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.prank(safeAddr);
        vm.expectRevert(VetoGuard.RotationAlreadyPending.selector);
        guard.requestSignerRotation(otherSigner);
    }

    function test_rotation_revert_before_timelock() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.warp(block.timestamp + 13 days);
        vm.expectRevert(VetoGuard.RotationTimelockActive.selector);
        guard.executeSignerRotation(safeAddr);
    }

    function test_rotation_succeeds_after_timelock() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.warp(block.timestamp + 14 days);
        guard.executeSignerRotation(safeAddr);
        (address signer, address pending, , ) = guard.configs(safeAddr);
        assertEq(signer, overrideSigner);
        assertEq(pending, address(0));
        assertEq(guard.effectiveSigner(safeAddr), overrideSigner);
    }

    function test_rotation_cancel() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.prank(safeAddr);
        guard.cancelSignerRotation();
        (, address pending, , ) = guard.configs(safeAddr);
        assertEq(pending, address(0));
        vm.expectRevert(VetoGuard.RotationNotPending.selector);
        guard.executeSignerRotation(safeAddr);
    }

    function test_after_rotation_default_signer_rejected() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.warp(block.timestamp + 14 days);
        guard.executeSignerRotation(safeAddr);

        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(safeAddr, t);

        // Default signer (the deploy-time one) no longer works for this Safe.
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, h));
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, sigs);

        // Override signer does.
        sigs = _sigsBlob(_ownerSigDummy(), _sign(overrideKey, h));
        _call(safeAddr, t, sigs);
    }

    function test_rotation_execute_callable_by_anyone() public {
        vm.prank(safeAddr);
        guard.requestSignerRotation(overrideSigner);
        vm.warp(block.timestamp + 14 days);
        vm.prank(otherSigner);
        guard.executeSignerRotation(safeAddr);
        assertEq(guard.effectiveSigner(safeAddr), overrideSigner);
    }

    // ─────────────────────────────────────────────────────────────────
    // Escape hatch (per-Safe)
    // ─────────────────────────────────────────────────────────────────

    function test_escape_before_timelock_still_enforces() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.warp(block.timestamp + 13 days);
        assertFalse(guard.isEscaped(safeAddr));

        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(safeAddr, t, _ownerSigDummy());
    }

    function test_escape_after_timelock_is_no_op() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.warp(block.timestamp + 14 days);
        assertTrue(guard.isEscaped(safeAddr));

        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        _call(safeAddr, t, _ownerSigDummy()); // must not revert
    }

    function test_escape_cancel() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.prank(safeAddr);
        guard.cancelEscape();
        (, , , uint256 escapeUnlock) = guard.configs(safeAddr);
        assertEq(escapeUnlock, 0);

        vm.warp(block.timestamp + 14 days);
        assertFalse(guard.isEscaped(safeAddr));
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(safeAddr, t, _ownerSigDummy());
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

    function test_safe_a_escape_does_not_affect_safe_b() public {
        vm.prank(safeAddr);
        guard.requestEscape();
        vm.warp(block.timestamp + 14 days);
        assertTrue(guard.isEscaped(safeAddr));
        assertFalse(guard.isEscaped(safe2Addr));

        // Safe B still enforced.
        Tx memory t = _defaultTx();
        safe2.setNonce(0);
        vm.expectRevert(VetoGuard.VetoSignatureMissing.selector);
        _call(safe2Addr, t, _ownerSigDummy());
    }

    // ─────────────────────────────────────────────────────────────────
    // Adversarial
    // ─────────────────────────────────────────────────────────────────

    function test_malformed_v_byte_does_not_match_signer() public {
        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes32 h = _txHash(safeAddr, t);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(defaultKey, h);
        v = v == 27 ? 28 : 27;
        bytes memory badSig = abi.encodePacked(r, s, v);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _call(safeAddr, t, _sigsBlob(_ownerSigDummy(), badSig));
    }

    function test_direct_call_from_eoa_treats_eoa_as_unknown_safe() public {
        // If an EOA calls checkTransaction directly with a sig that
        // would validate against itself-as-safe... well, the EOA can't
        // be a Safe (no nonce() function), so the call should revert.
        Tx memory t = _defaultTx();
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), _sign(defaultKey, _txHash(otherSigner, t)));
        vm.prank(otherSigner);
        // ISafeNonce(otherSigner).nonce() reverts because the EOA has no code.
        vm.expectRevert();
        guard.checkTransaction(
            t.to, t.value, t.data, t.operation, t.safeTxGas, t.baseGas,
            t.gasPrice, t.gasToken, t.refundReceiver, sigs, address(this)
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Fuzz
    // ─────────────────────────────────────────────────────────────────

    function testFuzz_random_signatures_dont_validate(bytes32 r, bytes32 s, uint8 v) public {
        if (v != 27 && v != 28) v = 27;

        Tx memory t = _defaultTx();
        safe.setNonce(t.nonce);
        bytes memory fuzzedSig = abi.encodePacked(r, s, v);
        bytes memory sigs = _sigsBlob(_ownerSigDummy(), fuzzedSig);

        bytes32 h = _txHash(safeAddr, t);
        address recovered = ecrecover(h, v, r, s);

        if (recovered == defaultSigner && recovered != address(0)) {
            _call(safeAddr, t, sigs);
        } else {
            vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
            _call(safeAddr, t, sigs);
        }
    }
}
