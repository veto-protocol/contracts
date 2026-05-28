// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {VetoGuard} from "../src/VetoGuard.sol";

/// @title DeployVetoGuard — deploys the singleton VetoGuard.
///
/// Usage (Base Sepolia):
///
///     export VETO_DEPLOYER_PRIVATE_KEY=0x<your-key-here>     # funded with a tiny bit of Sepolia ETH
///     export VETO_DEFAULT_SIGNER=0x<the address gateway/services/safe_signer.py recovers to>
///     export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org   # or your provider
///
///     forge script script/DeployVetoGuard.s.sol \
///         --rpc-url base_sepolia \
///         --broadcast \
///         --verify
///
/// The default signer comes from `gateway.services.safe_signer.get_signer_address()`
/// — that's the address the on-chain Guard will recover from on-chain
/// signatures. If you ever rotate the backend's signing key, deploy a
/// fresh Guard (or use the per-Safe rotation timelock).
contract DeployVetoGuard is Script {
    function run() external returns (VetoGuard) {
        uint256 deployerKey = vm.envUint("VETO_DEPLOYER_PRIVATE_KEY");
        address defaultSigner = vm.envAddress("VETO_DEFAULT_SIGNER");

        console2.log("Deployer:", vm.addr(deployerKey));
        console2.log("Default Veto signer:", defaultSigner);
        console2.log("Chain id:", block.chainid);

        vm.startBroadcast(deployerKey);
        VetoGuard guard = new VetoGuard(defaultSigner);
        vm.stopBroadcast();

        console2.log("");
        console2.log("===========================================");
        console2.log("VetoGuard deployed at:", address(guard));
        console2.log("===========================================");
        console2.log("");
        console2.log("Next steps:");
        console2.log("  1. Update veto-ai-frontend env: VITE_VETO_GUARD_ADDRESS=", address(guard));
        console2.log("  2. Update Django settings: VETO_GUARD_ADDRESS_BASE_SEPOLIA");
        console2.log("  3. Update contracts/README.md with the deployment address");
        return guard;
    }
}
