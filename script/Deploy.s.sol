// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {VetoGuardedAccount} from "../src/VetoGuardedAccount.sol";

/// Deploy a fresh VetoGuardedAccount on the configured network.
///
/// Required env vars:
///   PRIVATE_KEY      — deployer key (will become `owner` unless OWNER_ADDRESS is set)
///   VETO_SIGNER      — secp256k1 address Veto uses to sign on-chain mandates
///   OWNER_ADDRESS    — (optional) override owner; defaults to deployer
///
/// Run on Base Sepolia:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url $BASE_SEPOLIA_RPC_URL \
///     --broadcast \
///     --verify
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address vetoSigner = vm.envAddress("VETO_SIGNER");
        address ownerAddr = vm.envOr("OWNER_ADDRESS", vm.addr(pk));

        vm.startBroadcast(pk);
        VetoGuardedAccount account = new VetoGuardedAccount(ownerAddr, vetoSigner);
        vm.stopBroadcast();

        console2.log("VetoGuardedAccount deployed at:", address(account));
        console2.log("  owner:      ", ownerAddr);
        console2.log("  vetoSigner: ", vetoSigner);
    }
}
