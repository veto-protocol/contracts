// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VetoGuardedAccount} from "../src/VetoGuardedAccount.sol";

/// Minimal ERC20 stub for the token-path test.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// ERC20 that returns false on transfer — verifies the contract reverts on it.
contract FailingERC20 {
    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

contract VetoGuardedAccountTest is Test {
    VetoGuardedAccount internal account;
    address internal owner = address(0xA11CE);
    address internal recipient = address(0xBEEF);
    uint256 internal vetoKey;
    address internal vetoSigner;

    function setUp() public {
        vetoKey = uint256(keccak256("veto-test-key"));
        vetoSigner = vm.addr(vetoKey);
        account = new VetoGuardedAccount(owner, vetoSigner);
        // Fund the account with native ETH for the spend tests.
        vm.deal(address(account), 10 ether);
    }

    // ----- Helpers -----

    function _mandate(
        bytes32 jti,
        uint256 exp,
        address rec,
        uint256 cap,
        address token
    ) internal pure returns (VetoGuardedAccount.Mandate memory m) {
        m = VetoGuardedAccount.Mandate({
            jti: jti,
            exp: exp,
            recipient: rec,
            maxAmount: cap,
            token: token
        });
    }

    function _sign(VetoGuardedAccount.Mandate memory m, uint256 key) internal view returns (bytes memory) {
        bytes32 digest = account.hashMandate(m);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    // ----- Construction -----

    function test_initial_state() public view {
        assertEq(account.owner(), owner);
        assertEq(account.vetoSigner(), vetoSigner);
    }

    function test_revert_on_zero_addresses() public {
        vm.expectRevert(bytes("zero address"));
        new VetoGuardedAccount(address(0), vetoSigner);
        vm.expectRevert(bytes("zero address"));
        new VetoGuardedAccount(owner, address(0));
    }

    // ----- Native ETH happy path -----

    function test_native_eth_happy_path() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-1"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);

        uint256 before = recipient.balance;
        account.executeWithMandate(m, sig, 0.5 ether);
        assertEq(recipient.balance - before, 0.5 ether);
        assertTrue(account.spent(m.jti));
    }

    function test_native_at_exact_cap() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-cap"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);
        account.executeWithMandate(m, sig, 1 ether);
        assertEq(recipient.balance, 1 ether);
    }

    // ----- Replay -----

    function test_revert_on_replay() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-replay"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);
        account.executeWithMandate(m, sig, 0.1 ether);

        vm.expectRevert(VetoGuardedAccount.MandateAlreadySpent.selector);
        account.executeWithMandate(m, sig, 0.1 ether);
    }

    // ----- Expiry -----

    function test_revert_on_expired_mandate() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-exp"),
            block.timestamp + 100,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);
        vm.warp(block.timestamp + 200);
        vm.expectRevert(VetoGuardedAccount.MandateExpired.selector);
        account.executeWithMandate(m, sig, 0.1 ether);
    }

    // ----- Scope -----

    function test_revert_on_amount_over_cap() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-cap-over"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);
        vm.expectRevert(VetoGuardedAccount.AmountOverCap.selector);
        account.executeWithMandate(m, sig, 2 ether);
    }

    // ----- Bad signature -----

    function test_revert_on_signature_by_wrong_key() public {
        uint256 attackerKey = uint256(keccak256("attacker-key"));
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-evil"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory badSig = _sign(m, attackerKey);
        vm.expectRevert(VetoGuardedAccount.BadSignature.selector);
        account.executeWithMandate(m, badSig, 0.1 ether);
    }

    function test_revert_on_tampered_recipient() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-tamper"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);
        m.recipient = address(0xBAD);
        // Same signature, mutated mandate → digest changes → recovers a different
        // address, which won't match vetoSigner → BadSignature.
        vm.expectRevert(VetoGuardedAccount.BadSignature.selector);
        account.executeWithMandate(m, sig, 0.1 ether);
    }

    function test_revert_on_malformed_signature_length() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-shortsig"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory shortSig = hex"deadbeef";
        vm.expectRevert(VetoGuardedAccount.BadSignature.selector);
        account.executeWithMandate(m, shortSig, 0.1 ether);
    }

    // ----- Domain separator anti-replay across chains/contracts -----

    function test_signature_does_not_replay_to_other_contract() public {
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-cross"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);

        // Same backend signs for one VetoGuardedAccount; another VetoGuardedAccount
        // (different `verifyingContract`) should reject the same sig.
        VetoGuardedAccount other = new VetoGuardedAccount(owner, vetoSigner);
        vm.deal(address(other), 5 ether);
        vm.expectRevert(VetoGuardedAccount.BadSignature.selector);
        other.executeWithMandate(m, sig, 0.1 ether);
    }

    // ----- ERC20 path -----

    function test_erc20_happy_path() public {
        MockERC20 token = new MockERC20();
        token.mint(address(account), 100e6);

        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-erc20"),
            block.timestamp + 600,
            recipient,
            50e6,
            address(token)
        );
        bytes memory sig = _sign(m, vetoKey);
        account.executeWithMandate(m, sig, 25e6);
        assertEq(token.balanceOf(recipient), 25e6);
        assertEq(token.balanceOf(address(account)), 75e6);
    }

    function test_erc20_revert_on_failing_transfer() public {
        FailingERC20 token = new FailingERC20();
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-erc20-fail"),
            block.timestamp + 600,
            recipient,
            50e6,
            address(token)
        );
        bytes memory sig = _sign(m, vetoKey);
        vm.expectRevert(VetoGuardedAccount.TransferFailed.selector);
        account.executeWithMandate(m, sig, 25e6);
    }

    // ----- Admin -----

    function test_owner_can_rotate_signer() public {
        address newSigner = address(0xC0FFEE);
        vm.prank(owner);
        account.rotateVetoSigner(newSigner);
        assertEq(account.vetoSigner(), newSigner);

        // Old signer's mandate should now be rejected.
        VetoGuardedAccount.Mandate memory m = _mandate(
            keccak256("jti-after-rotate"),
            block.timestamp + 600,
            recipient,
            1 ether,
            address(0)
        );
        bytes memory sig = _sign(m, vetoKey);
        vm.expectRevert(VetoGuardedAccount.BadSignature.selector);
        account.executeWithMandate(m, sig, 0.1 ether);
    }

    function test_non_owner_cannot_rotate_signer() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(VetoGuardedAccount.NotOwner.selector);
        account.rotateVetoSigner(address(0xC0FFEE));
    }

    function test_owner_can_transfer_ownership() public {
        address newOwner = address(0xC0DE);
        vm.prank(owner);
        account.transferOwnership(newOwner);
        assertEq(account.owner(), newOwner);
    }
}
