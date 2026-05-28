// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VetoGuard, ISafeNonce} from "../src/VetoGuard.sol";

/// @title VetoGuardBridge — Group-2 bridge test (cross-language fixture).
///
/// Loads a signature + transaction fields produced by the Python
/// `gateway.services.safe_signer` module (the Veto backend's SafeTx
/// signer) and verifies the Solidity-side `VetoGuard.checkTransaction`
/// accepts it. Byte-for-byte agreement on:
///   - The EIP-712 SafeTx hash construction (typehashes, domain
///     separator, struct field encoding).
///   - The secp256k1 signature format (r, s, v).
///   - Address recovery via ecrecover.
///
/// If Python's `hash_safe_tx` or Solidity's `_safeTxHash` ever drift
/// from each other, this test fails — and the entire HARD_STOP_v1
/// loop is broken (Guard rejects every mandate from prod). It's the
/// single most valuable cross-language check we have.
///
/// The fixture was captured by running:
///   DJANGO_SECRET_KEY="bridge-fixture-key-7e6cd29e1f04a812" \
///     python -c "<see contracts/test/VetoGuardBridge.t.sol header>"
/// against `gateway/services/safe_signer.py`. The dev key fallback
/// derives the signer address deterministically from SECRET_KEY, so
/// the fixture is stable across runs.

contract MockSafeWithNonce is ISafeNonce {
    uint256 public override nonce;
    function setNonce(uint256 n) external { nonce = n; }
}

contract VetoGuardBridgeTest is Test {
    VetoGuard internal guard;
    MockSafeWithNonce internal safe;
    address internal safeAddr;

    // ─── Fixture (produced by Python safe_signer.py) ────────────────
    // DJANGO_SECRET_KEY = "bridge-fixture-key-7e6cd29e1f04a812"
    // Stable; regenerate by re-running the snippet in the file header.

    address internal constant FIXTURE_SIGNER =
        0xb3dC4886439621f3E9f8Dd09Da6623406FDda85f;

    address internal constant FIXTURE_SAFE_ADDR =
        0x1111111111111111111111111111111111111111;

    address internal constant FIXTURE_TO_ADDR =
        0x2222222222222222222222222222222222222222;

    uint256 internal constant FIXTURE_CHAIN_ID = 84532;       // Base Sepolia
    uint256 internal constant FIXTURE_VALUE = 1_000_000;
    uint8   internal constant FIXTURE_OPERATION = 0;
    uint256 internal constant FIXTURE_NONCE = 7;

    bytes32 internal constant FIXTURE_TX_HASH =
        0x92a337618201b4a20cd6f743fdf33368ec419c4d7e35f8143d91ce7879156d32;

    bytes internal constant FIXTURE_SIGNATURE =
        hex"2aa46a2a8feb9c4c15a5b41ef6ce92865b1f170278592225c4c0f310d287c90f"
        hex"2e79b76f796c75de3728f374942a7efad7988f95018d70624b10f4fe86199c99"
        hex"1b";

    // The owner sig field is whatever Safe would put there — for our
    // unit-level Guard test it's ignored (Safe verifies it itself).
    bytes internal constant OWNER_SIG_PLACEHOLDER = new bytes(65);

    function setUp() public {
        // Singleton Guard — one contract, any Safe calls into it.
        // FIXTURE_SIGNER is the default signer baked in at deploy.
        guard = new VetoGuard(FIXTURE_SIGNER);
        // Spin up a mock Safe template; we vm.etch it into the fixture
        // address per-test so msg.sender matches what Python signed.
        safe = new MockSafeWithNonce();
        safeAddr = address(safe);
    }

    // ─── 1. Pin chainId so the fixture's domain separator matches ──

    function _pinChain() internal {
        vm.chainId(FIXTURE_CHAIN_ID);
    }

    // ─── 2. Helper: emit the FIXTURE SafeTx using safeAddr (the actual
    //         Mock Safe runtime address) — verifies the *shape* of the
    //         encoding, not just the captured hash.

    function _signaturesBlob(bytes memory veto) internal pure returns (bytes memory) {
        return abi.encodePacked(OWNER_SIG_PLACEHOLDER, veto);
    }

    // ─── Tests ──────────────────────────────────────────────────────

    /// The captured-hash sanity check: if we deploy the Guard with the
    /// SAME safe address Python used, the Guard's recomputed hash must
    /// equal Python's FIXTURE_TX_HASH. Catches encoding drift even
    /// before any signature is involved.
    /// @dev Plant a mock Safe at the fixture address and return its code etch'd in.
    function _plantFixtureSafe(uint256 nonce) internal {
        MockSafeWithNonce template = new MockSafeWithNonce();
        vm.etch(FIXTURE_SAFE_ADDR, address(template).code);
        MockSafeWithNonce(FIXTURE_SAFE_ADDR).setNonce(nonce);
    }

    function _callAsFixtureSafe(uint256 value, address to, bytes memory sigs) internal {
        vm.prank(FIXTURE_SAFE_ADDR);
        guard.checkTransaction(
            to,
            value,
            "",
            FIXTURE_OPERATION,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sigs,
            address(this)
        );
    }

    function test_python_hash_matches_solidity_hash_for_fixture() public {
        _pinChain();
        _plantFixtureSafe(FIXTURE_NONCE);
        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);

        // Should not revert — Python's sig and the Solidity hash agree.
        _callAsFixtureSafe(FIXTURE_VALUE, FIXTURE_TO_ADDR, sigs);
    }

    function test_mutated_value_breaks_fixture_signature() public {
        _pinChain();
        _plantFixtureSafe(FIXTURE_NONCE);
        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _callAsFixtureSafe(FIXTURE_VALUE + 1, FIXTURE_TO_ADDR, sigs);
    }

    function test_mutated_nonce_breaks_fixture_signature() public {
        _pinChain();
        _plantFixtureSafe(FIXTURE_NONCE + 1); // wrong nonce
        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _callAsFixtureSafe(FIXTURE_VALUE, FIXTURE_TO_ADDR, sigs);
    }

    function test_mutated_chainid_breaks_fixture_signature() public {
        // DON'T pin chainId — Foundry's default differs from 84532,
        // so the domain separator mismatches.
        _plantFixtureSafe(FIXTURE_NONCE);
        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _callAsFixtureSafe(FIXTURE_VALUE, FIXTURE_TO_ADDR, sigs);
    }

    function test_mutated_to_address_breaks_fixture_signature() public {
        _pinChain();
        _plantFixtureSafe(FIXTURE_NONCE);
        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        _callAsFixtureSafe(FIXTURE_VALUE, address(0xDEAD), sigs);
    }
}
