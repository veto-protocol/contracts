<div align="center">

<br>

<img src="https://veto-ai.com/veto-logo.png" alt="Veto" width="180">

<br><br>

<h3>The chain refuses, not just our SDK.</h3>

<p>
  Smart wallet contracts that hold an agent's funds and only release them<br>
  on a fresh, in-scope, Veto-signed mandate. Live on Base Sepolia.
</p>

<p>
  <a href="https://sepolia.basescan.org/address/0xCBbbC4b924AF40D29f135c3a88b6F650d55d92c5"><img src="https://img.shields.io/badge/Base_Sepolia-live-0052FF?style=flat-square&logo=coinbase&logoColor=white" alt="live on Base Sepolia"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="license"></a>
  <a href="https://soliditylang.org"><img src="https://img.shields.io/badge/Solidity-0.8.24-363636?style=flat-square&logo=solidity&logoColor=white" alt="Solidity"></a>
  <a href="https://book.getfoundry.sh/"><img src="https://img.shields.io/badge/Foundry-tested-FCC419?style=flat-square" alt="Foundry"></a>
  <a href="#status"><img src="https://img.shields.io/badge/audit-pending-F59E0B?style=flat-square" alt="audit pending"></a>
  <a href="#what-this-is"><img src="https://img.shields.io/badge/v0.6-stub-22d3ee?style=flat-square" alt="v0.6 stub"></a>
</p>

<p>
  <a href="#what-this-is">What it is</a> ·
  <a href="#live-now">Live deploy</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#run-the-tests">Tests</a> ·
  <a href="#deploy-to-base-sepolia">Deploy</a> ·
  <a href="#threat-model">Threat&nbsp;model</a>
</p>

</div>

> **⚠ Unaudited. Testnet only for production funds.**
> v2 ships with externally audited contracts on mainnet. This stub exists to prove the chain-side enforcement primitive end-to-end.

---

## What this is

A minimal smart wallet — `VetoGuardedAccount` — that holds funds and **only** releases them when presented with a fresh, in-scope mandate signed by Veto.

```
agent  ──asks Veto──►  authorize endpoint
                              │ approves + issues
                              ▼
                       Mandate (Ed25519 JWT, off-chain)
                       Mandate (secp256k1 EIP-712, on-chain)   ← this contract verifies
                              │
agent  ──tx + on-chain mandate──►  VetoGuardedAccount.executeWithMandate
                                                │ signature OK?
                                                │ jti unspent?
                                                │ exp not passed?
                                                │ recipient matches?
                                                │ amount ≤ cap?
                                                │ token matches?
                                                ▼
                                          settles the spend
```

If the agent tries to spend without a mandate, or with an expired/replayed/wrong-scope mandate, the contract reverts. The chain refuses; cooperation isn't the safety property.

---

## Live now

The stub is deployed on Base Sepolia and proven end-to-end:

| | |
|---|---|
| **Contract address** | [`0xCBbbC4b924AF40D29f135c3a88b6F650d55d92c5`](https://sepolia.basescan.org/address/0xCBbbC4b924AF40D29f135c3a88b6F650d55d92c5) |
| **First mandate execution** | [`0x2f9ec…d2af`](https://sepolia.basescan.org/tx/0x2f9ec691a6f5958bea296c5f630b26d1be1d93667dc3c974671cce0773cad2af) — 0.000001 ETH transferred (~65k gas) |
| **Second execution** | [`0xe4112b…5217`](https://sepolia.basescan.org/tx/0xe4112b29c4a80ad337ca45a1599d669fd9853a3a7a8977d52251ce4e8c0e5217) — fresh mandate, different `jti` |
| **Replay rejected** | `MandateAlreadySpent()` selector `0xffa64355` — chain refused a duplicate |
| **Verification scheme** | secp256k1 · EIP-712 · `ecrecover` (~3k gas per check) |
| **Off-chain verifier** | [`@veto/mandate-verifier`](https://github.com/veto-protocol/mandate-verifier) |

---

## Mandate format

The contract verifies an EIP-712 typed-data signature over:

```solidity
struct Mandate {
    bytes32 jti;        // single-use; same as JWT.jti
    uint256 exp;        // unix seconds
    address recipient;  // exact destination
    uint256 maxAmount;  // wei or ERC20 base units
    address token;      // address(0) = native ETH
}
```

**Domain separator** binds `name="Veto"`, `version="1"`, `block.chainid`, `address(this)`. A mandate signed for one `VetoGuardedAccount` cannot replay on a different one or on a different chain.

The off-chain JWT mandate ([`@veto/mandate-verifier`](https://github.com/veto-protocol/mandate-verifier)) carries the same `jti / exp / recipient / max_amount` fields — paired by `jti`. Veto issues both signatures. Each consumer picks the verification format that's cheapest in its environment.

---

## Why secp256k1 here vs Ed25519 in the JWT?

EVM has `ecrecover` as a precompile (~3k gas). It does not have a native Ed25519 precompile, so verifying the JWT directly on chain would cost ~1M gas through a Solidity library. The two-signature approach keeps each path cheap and idiomatic for its consumer.

---

## How it works

```solidity
function executeWithMandate(
    Mandate calldata m,
    bytes calldata signature,
    uint256 amount
) external {
    bytes32 digest = _hashMandate(m);
    if (_recover(digest, signature) != vetoSigner) revert BadSignature();

    if (spent[m.jti])              revert MandateAlreadySpent();
    if (block.timestamp >= m.exp)  revert MandateExpired();
    if (amount > m.maxAmount)      revert AmountOverCap();

    spent[m.jti] = true;
    emit MandateExecuted(m.jti, m.recipient, amount, m.token);

    // Native ETH or ERC20 transfer
    ...
}
```

Five checks: signature, replay, expiry, amount cap, and (implicit via the signed `recipient/token` fields) destination + asset. CEI pattern — `spent[jti] = true` is set BEFORE the external call. EIP-2 high-s rejection for malleability resistance.

---

## Run the tests

[Foundry](https://book.getfoundry.sh) required:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Then:

```bash
forge install foundry-rs/forge-std --no-commit
forge test -vv
```

Sixteen tests covering:

- Native ETH happy path + at-exact-cap
- ERC20 happy path + revert-on-failing-transfer
- Replay rejection (same `jti` → revert)
- Expiry (`vm.warp` past `exp` → revert)
- Amount over cap → revert
- Wrong signing key → revert
- Tampered recipient (sig kept, mandate field mutated) → revert
- Malformed signature length → revert
- Cross-contract anti-replay (same sig on different `VetoGuardedAccount`) → revert
- Owner controls — rotate signer, transfer ownership; non-owner blocked
- Zero-address constructor guard

---

## Deploy to Base Sepolia

```bash
export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
export PRIVATE_KEY=0x…           # deployer (faucet ETH first)
export VETO_SIGNER=0x…           # address Veto signs mandates with
export BASESCAN_API_KEY=…        # for verification

forge script script/Deploy.s.sol:Deploy \
    --rpc-url base_sepolia \
    --broadcast \
    --verify
```

Faucets: [Coinbase Developer Platform](https://portal.cdp.coinbase.com/products/faucet) · [Chainstack](https://faucet.chainstack.com/base-sepolia-faucet) · [Alchemy](https://www.alchemy.com/faucets/base-sepolia)

For an even simpler path, the [`veto-cli`](https://github.com/veto-protocol/veto-cli) deploys this contract for you from Python (no Foundry required on the user's machine) via `veto agent deploy`.

---

## Threat model

**Covered:**

- Replay across chains (chainId in domain separator)
- Replay across contract instances (verifyingContract in domain separator)
- Replay of the same mandate (jti single-use mapping)
- Mutated mandate fields (any tamper changes the digest → ecrecover yields a different address)
- Spend over the mandate's cap
- Spend after expiry
- Caller wiring the wrong recipient (recipient is in the signed mandate, not a tx parameter)
- Owner controls (rotateVetoSigner, transferOwnership)
- ECDSA malleability (high-s rejection per EIP-2)

**Not covered in v0.6, on the roadmap for v2:**

- Audit
- ERC-4337 integration (this is a standalone holder, not a 4337 account yet)
- Safe Guard variant (for multi-sig treasuries)
- Multi-key Veto signer (currently single secp256k1 address — rotation supported but no multisig yet)
- Solana variant (current contract is EVM-only)
- On-chain off-ramp for emergency unlock if Veto is permanently unreachable (compose with a separate timelock contract for now)
- Front-running protection (partial mitigations: jti single-use, exp window — but a public mempool could let an MEV bot front-run a settle. v2 considers private orderflow.)

---

## Status

- ✅ Contract drafted and locally compiled
- ✅ Foundry test suite — 16 paths covered, all green
- ✅ Deployed and proven on Base Sepolia (live deploy + replay-rejected on-chain)
- ⏳ Backend dual-signs mandates (Ed25519 JWT + secp256k1 EIP-712) — shipped in `veto-cli` v0.6
- ⏳ External audit — engagement scoping
- ⏳ Mainnet deploys — pending audit

---

## Public artifacts

| Artifact | Repository |
|----------|------------|
| Contracts (this repo) | [veto-protocol/contracts](https://github.com/veto-protocol/contracts) |
| Veto CLI (deploys this contract) | [veto-protocol/veto-cli](https://github.com/veto-protocol/veto-cli) |
| Off-chain mandate verifier | [veto-protocol/mandate-verifier](https://github.com/veto-protocol/mandate-verifier) |
| Open policy schema (APPS) | [veto-protocol/x402-policy-schema](https://github.com/veto-protocol/x402-policy-schema) |
| Documentation | [veto-protocol/docs](https://github.com/veto-protocol/docs) |
| Live contract | https://sepolia.basescan.org/address/0xCBbbC4b924AF40D29f135c3a88b6F650d55d92c5 |

---

## License

MIT.

---

<div align="center">

**The chain refuses, not just our SDK.**<br>
<sub>Any agent. Any payment rail. Safe transactions.</sub>

<br><br>

<sub>Built by <a href="https://veto-ai.com">Investech Global LLC</a> · part of the <a href="https://github.com/veto-protocol">veto-protocol</a> family.</sub>

</div>
