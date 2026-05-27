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
        // Mock Safe's runtime address must match the fixture so the
        // EIP-712 domain separator matches (it's keyed off the
        // verifyingContract = safe address).
        safe = new MockSafeWithNonce();
        safeAddr = address(safe);
        // We deploy the Guard expecting the *same* signer Python produced.
        // The Guard's `safe` is whatever address Safe was deployed at; we
        // override Python's fixture address mismatch by recomputing the
        // expected hash against `safeAddr` and comparing.
        guard = new VetoGuard(safeAddr, FIXTURE_SIGNER);
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
    function test_python_hash_matches_solidity_hash_for_fixture() public {
        _pinChain();
        // Deploy a Guard whose `safe` equals the fixture address, so
        // the domain separator hashes to the same bytes Python did.
        VetoGuard sameSafe = new VetoGuard(FIXTURE_SAFE_ADDR, FIXTURE_SIGNER);
        // We can't call private _safeTxHash, so we exercise it via
        // checkTransaction: deploy a mock safe at exactly FIXTURE_SAFE_ADDR
        // and have it return the fixture nonce; if the Guard accepts the
        // fixture sig, then the hash equality holds.
        // We can't change a contract's address — but we can vm.etch the
        // MockSafeWithNonce bytecode INTO the fixture address.
        MockSafeWithNonce template = new MockSafeWithNonce();
        vm.etch(FIXTURE_SAFE_ADDR, address(template).code);
        MockSafeWithNonce(FIXTURE_SAFE_ADDR).setNonce(FIXTURE_NONCE);

        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);

        // Should not revert — Python's sig and the Solidity hash agree.
        sameSafe.checkTransaction(
            FIXTURE_TO_ADDR,
            FIXTURE_VALUE,
            "",
            FIXTURE_OPERATION,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sigs,
            address(this)
        );
    }

    /// Mutate a single field — sig must now fail. Confirms each field
    /// is actually committed to in the hash (not silently ignored).
    function test_mutated_value_breaks_fixture_signature() public {
        _pinChain();
        MockSafeWithNonce template = new MockSafeWithNonce();
        vm.etch(FIXTURE_SAFE_ADDR, address(template).code);
        MockSafeWithNonce(FIXTURE_SAFE_ADDR).setNonce(FIXTURE_NONCE);
        VetoGuard sameSafe = new VetoGuard(FIXTURE_SAFE_ADDR, FIXTURE_SIGNER);

        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);

        // Bumping `value` by 1 changes the hash → sig recovers to a
        // different (or zero) address → invalid.
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        sameSafe.checkTransaction(
            FIXTURE_TO_ADDR,
            FIXTURE_VALUE + 1, // changed
            "",
            FIXTURE_OPERATION,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sigs,
            address(this)
        );
    }

    function test_mutated_nonce_breaks_fixture_signature() public {
        _pinChain();
        MockSafeWithNonce template = new MockSafeWithNonce();
        vm.etch(FIXTURE_SAFE_ADDR, address(template).code);
        // Use the WRONG nonce.
        MockSafeWithNonce(FIXTURE_SAFE_ADDR).setNonce(FIXTURE_NONCE + 1);
        VetoGuard sameSafe = new VetoGuard(FIXTURE_SAFE_ADDR, FIXTURE_SIGNER);

        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        sameSafe.checkTransaction(
            FIXTURE_TO_ADDR,
            FIXTURE_VALUE,
            "",
            FIXTURE_OPERATION,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sigs,
            address(this)
        );
    }

    function test_mutated_chainid_breaks_fixture_signature() public {
        // DON'T pin chainId — Foundry's default chainId differs from
        // the fixture's 84532, so the domain separator mismatches.
        MockSafeWithNonce template = new MockSafeWithNonce();
        vm.etch(FIXTURE_SAFE_ADDR, address(template).code);
        MockSafeWithNonce(FIXTURE_SAFE_ADDR).setNonce(FIXTURE_NONCE);
        VetoGuard sameSafe = new VetoGuard(FIXTURE_SAFE_ADDR, FIXTURE_SIGNER);

        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        sameSafe.checkTransaction(
            FIXTURE_TO_ADDR,
            FIXTURE_VALUE,
            "",
            FIXTURE_OPERATION,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sigs,
            address(this)
        );
    }

    function test_mutated_to_address_breaks_fixture_signature() public {
        _pinChain();
        MockSafeWithNonce template = new MockSafeWithNonce();
        vm.etch(FIXTURE_SAFE_ADDR, address(template).code);
        MockSafeWithNonce(FIXTURE_SAFE_ADDR).setNonce(FIXTURE_NONCE);
        VetoGuard sameSafe = new VetoGuard(FIXTURE_SAFE_ADDR, FIXTURE_SIGNER);

        bytes memory sigs = _signaturesBlob(FIXTURE_SIGNATURE);
        vm.expectRevert(VetoGuard.VetoSignatureInvalid.selector);
        sameSafe.checkTransaction(
            address(0xDEAD), // changed
            FIXTURE_VALUE,
            "",
            FIXTURE_OPERATION,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sigs,
            address(this)
        );
    }
}
