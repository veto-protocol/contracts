# Veto contracts (v0.6 stub)

> **Unaudited. Testnet only.** v2 ships with audited contracts and an ERC-4337 module.
> This stub exists to prove the chain-side enforcement primitive works end-to-end.

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

## Layout

```
contracts/
  src/VetoGuardedAccount.sol     # the stub
  test/VetoGuardedAccount.t.sol  # Foundry tests
  script/Deploy.s.sol            # `forge script` for Base Sepolia
  foundry.toml
```

## On-chain mandate format

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

Domain separator: `name="Veto", version="1", chainId=block.chainid, verifyingContract=address(this)`. This means a mandate signed for one `VetoGuardedAccount` cannot replay on a different one or on a different chain.

The off-chain JWT mandate (`@veto/mandate-verifier`) carries the same `jti, exp, recipient, max_amount` fields — they're paired by `jti`. The Veto backend signs both; consumers pick whichever signature matches their verification environment.

## Why secp256k1 here vs Ed25519 in the JWT?

EVM has `ecrecover` as a precompile (~3k gas). It does not have a native Ed25519 precompile, so verifying the JWT directly on chain would cost ~1M gas through a Solidity library. The two-signature approach keeps each path cheap and idiomatic for its consumer.

## Run the tests

Foundry required (one-time install):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Then in this directory:

```bash
forge install foundry-rs/forge-std --no-commit
forge test -vvv
```

## Deploy to Base Sepolia

```bash
export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
export PRIVATE_KEY=0x…           # deployer (gets a faucet ETH first)
export VETO_SIGNER=0x…            # address that will sign mandates on chain
export BASESCAN_API_KEY=…         # for verification

forge script script/Deploy.s.sol:Deploy \
    --rpc-url base_sepolia \
    --broadcast \
    --verify
```

Faucet for Base Sepolia ETH: https://www.alchemy.com/faucets/base-sepolia

## Threat model — what's covered, what's not

**Covered:**
- Replay across chains (chainId in domain separator)
- Replay across contract instances (verifyingContract in domain separator)
- Replay of the same mandate (jti single-use mapping)
- Mutated mandate fields (any tamper changes the digest → ecrecover yields a different address)
- Spend over the mandate's cap
- Spend after expiry
- Caller wiring the wrong recipient (recipient is in the signed mandate, not a tx parameter)
- Owner controls (rotateVetoSigner, transferOwnership)

**Not covered in v0.6, on the roadmap for v2:**
- Audit
- ERC-4337 integration (this is a standalone holder, not a 4337 account yet)
- Safe Guard variant (for multi-sig treasuries)
- Multi-key Veto signer (currently single secp256k1 address — rotation is supported but no multisig yet)
- On-chain off-ramp for emergency unlock if Veto is permanently unreachable (compose with a separate timelock contract for now)
- Front-running protection (partial mitigations: jti single-use, exp window — but a public mempool could let an MEV bot front-run a settle. v2 considers private orderflow.)

## Status

- ✅ Contract drafted and locally compiled
- ✅ Foundry test suite — all paths covered
- ⏳ Deploy to Base Sepolia
- ⏳ Backend dual-signs mandates (Ed25519 JWT + secp256k1 EIP-712) and returns both
- ⏳ Audit (post-v0.6, pre-mainnet)
