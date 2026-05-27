# Integration tests — bridging the Veto engine and the on-chain Guard

## Why this exists

The `VetoGuard.sol` test suite (`VetoGuard.t.sol`) proves the **on-chain** layer enforces "did Veto sign this transaction?" — 30 tests, including signature verification, replay protection, cross-chain isolation, signer rotation timelock, escape hatch, and a 256-run fuzz.

The Django backend's `safety/tests.py` + `gateway/tests.py` + `policies/tests.py` prove the **off-chain** engine correctly evaluates spends against policy (~150+ tests across the 8 engine stages, the authorize endpoint, and policy versioning).

What neither suite proves: **the bridge.** Specifically:

> When the engine returns `allow`, does the backend produce a signature that the Guard will accept? When the engine returns `deny`, does the backend refuse to produce that signature at all?

A policy bug that lets a spend slip through the engine → backend signs an out-of-policy mandate → the Guard happily accepts it (signature is valid). The on-chain layer is **not** a second policy check. It's a signature check. Off-chain policy correctness is load-bearing for the whole system.

## The integration test layer (to build)

Three test groups, ordered by setup cost:

### 1. End-to-end: same hash, both layers (HIGH leverage, LOW cost)

Single Python test (`gateway/test_guard_bridge.py`). For each `(policy, spend)` pair:

1. Build the Safe transaction the agent would submit.
2. Hash it with the same EIP-712 scheme the Guard uses (already implemented in `gateway/executors/crypto_signer.py`).
3. Call the engine via `gateway.views.AuthorizeActionView`.
4. If engine returns `allow`: backend's response includes a `safe_signature` field. Run `eth_keys.recover()` on it against the same hash. Assert recovered address == `vetoSigner`.
5. If engine returns `deny`: assert `safe_signature` is **absent** from the response.

This is a unit-level Python test — no Foundry, no fork. Cheap and fast. Covers the contract: *engine verdict ↔ presence/validity of on-chain-usable signature.*

**Critical test cases:**
- Allow within caps → signature recovers to vetoSigner
- Deny over daily cap → no signature field
- Deny on canonical-merchant typosquat → no signature field
- Escalate (over human-approval threshold) → no signature field (or marked as `pending`)
- Allow on a `tool_execution` action with `decision_only=true` → signature still issued for verifiable receipt, but caller knows not to settle
- Same hash signed twice with same engine state → same signature (deterministic; replay defense is the nonce, not the signing)

### 2. Foundry replay against a real engine response (MEDIUM cost)

A Foundry test that **doesn't** call into Python, but uses a real signature from the engine, captured ahead of time.

`test/VetoGuardBridge.t.sol`:

1. In a Python script (`scripts/capture_engine_signature.py`): run a known spend through the engine, dump the resulting `(safe_address, nonce, calldata_hash, signature)` to a JSON fixture.
2. In Foundry: load the fixture, simulate the Safe nonce, call `VetoGuard.checkTransaction` with the captured signature, assert it passes.
3. Mutate any field in the fixture (nonce, calldata, safe address) and assert the Guard now reverts.

This proves the **format** the backend produces matches what the Guard expects, byte-for-byte. Catches off-by-one, typehash drift, encoding mistakes.

### 3. Local fork: full Safe execution (HIGH cost, HIGH realism)

Run an Anvil fork of Base Sepolia. Deploy a real Safe contract owned by a generated EOA, install `VetoGuard` as a guard, fund with USDC, then drive a full end-to-end:

1. Agent (Python) requests authorize → gets signature.
2. Agent builds Safe transaction with `[ownerSig, vetoSig]` blob.
3. Agent calls `Safe.execTransaction` on the local fork.
4. Assert USDC transfers on success / reverts on engine-denied attempts.

This is the demo-shaped test. Catches integration issues between Safe's signature parsing, the Guard's checkTransaction hook, and the agent's transaction-building code.

Build cost: ~2 days. Worth it once the demo is the goal.

## Order of operations

1. **First:** group 1 (Python bridge test). One file, ~10 test cases. Can land alongside the backend mandate-signing work in Phase 3 of HARD_STOP_V1.
2. **Second:** group 2 (captured-fixture Foundry test). Adds a `scripts/capture_engine_signature.py`, one new test file. Land when the engine ↔ Guard wire format is locked.
3. **Third:** group 3 (fork integration). Land alongside Phase 4 (agent + CLI plumbing). This is what produces the demo video.

## What we are NOT building

- Property-based / generative tests that span both layers. The engine's space is too large to enumerate; we test it with policy fixtures, then test the bridge with hand-picked critical paths.
- A "veto-only" mode where the backend signs without engine evaluation. The bridge test makes it impossible to ship that without a failing test.
- Cross-chain integration in v1. The Guard is chain-aware via `block.chainid` (covered by `test_signature_from_other_chain_fails`); the bridge test extends to multi-chain when we deploy beyond Base.
