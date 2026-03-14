# Holder — EIP-712 Gasless Ownership Transfer with OTP Protection

## Why?
If somebody steals your private keys, they can't withdraw — funds are time-locked.
You can transfer ownership by using passwords to a fresh wallet via a gasless signed tx submitted
by anyone — even through the public mempool.

> **Lost your passwords?** No problem — `withdrawETH` and `withdrawERC20` require no password at all. Just wait for the unlock date (`holdTime`) to expire and withdraw with your wallet alone. The time-lock is always your last resort.

---

## Two Passwords — MEV Protection

A single password would be dangerous: a front-runner seeing your `setNewOwner`
tx in the mempool could use the exposed password to call `rescueETH` before your tx mines.
Two separate secrets eliminate this:

| Password | Used In | Exposed When |
|----------|---------|--------------|
| `transferPassword` | `setNewOwner` | Mempool — but rescue requires the other password |
| `rescuePassword` | `rescueETH` / `rescueERC20` | Only when funds already withdrawn |

Front-runner sees `transferPassword` → can't rescue (wrong password).  
Front-runner tries to redirect `newOwner` → signature invalid (committed to specific address).  
Front-runner tries to rotate `transferPassword` → blocked by 7-day delay.

---

## Front-Run Protection — Password Rotation Delay

Even if a front-runner sees `transferPassword` in the mempool, they **cannot** call
`setTransferPassword` to invalidate it — because password rotation requires a
**7-day timelock**:

```
1. owner calls applyNewPassword(newPassHash)   ← announces intent on-chain
2. wait 7 days
3. owner calls setTransferPassword(oldPass, newPassHash)  ← rotation executes
```

A front-runner seeing `transferPassword` in the mempool has no pre-submitted
`applyNewPassword` request, so `setTransferPassword` reverts with `No request found`.

Same 7-day delay applies to `setRescuePassword`.

---

## Whitelist — New Owner Must Be Pre-Approved

`setNewOwner` only accepts a `newOwner` address that was whitelisted at least **7 days** before:

```
1. owner calls applyNewWLOwner(newWallet)   ← announces intent on-chain
2. wait 7 days
3. owner calls setNewWLOwner(newWallet)     ← address added to whitelist
4. owner signs + anyone submits setNewOwner(newWallet, password, signature)
```

This means even if a front-runner somehow bypasses everything else, they can't
redirect ownership to their own address — it's not whitelisted.  
The 7-day window gives the legitimate owner time to detect suspicious
`applyNewWLOwner` activity and respond.

One address is whitelisted at deploy time via the `_whiteListedOwner` constructor argument.

---

## How Ownership Transfer Works

```
owner signs off-chain: { newOwner, hash(transferPassword) }
anyone submits on-chain: setNewOwner(newOwner, transferPassword, signature)
contract verifies:
  - newOwner is whitelisted
  - hash(password) matches transferPasswordHash
  - signature is from current owner
  - OTP not already used
```

- Swapping `newOwner`, wrong password, or replaying the signature all revert
- Signature is bound to `chainId` + `verifyingContract` — can't be used elsewhere
- OTP burned after use — rotate via `setTransferPassword` (requires 7-day delay) to rearm

---

## Recovery Paths

```
Keys stolen + you know transferPassword → setNewOwner to whitelisted wallet (mempool is safe)
Keys stolen + forgot transferPassword   → wait for holdTime to expire → withdrawETH
Urgent + keys safe                      → rescueETH(rescuePassword) — bypasses holdTime
Lost ALL passwords                      → wait for holdTime to expire → withdrawETH (wallet only)
```

> **Lost your passwords?** Don't panic — the time-lock is your last resort.
> `withdrawETH` and `withdrawERC20` only require `onlyOwner`, no password at all.
> Wait for `holdTime` to expire, then withdraw with your wallet alone.
> No password, no signature, no OTP — just the key.

---

## ⚠️ If You Overslept the 7-Day Window

If you missed the monitoring window and the attacker's `applyNewPassword` or
`applyNewWLOwner` request has already matured — **do not submit your recovery tx
through the public mempool**. The attacker is watching and will front-run any tx
that exposes your password or triggers an ownership transfer.

**Use a private RPC instead:**

| Provider | Endpoint |
|----------|----------|
| Flashbots Protect | `https://rpc.flashbots.net` |
| MEV Blocker | `https://rpc.mevblocker.io` |
| Beaverbuild Private | `https://rpc.beaverbuild.org` |

Private RPCs route your tx directly to block builders, bypassing the public
mempool entirely. Your calldata — including the plaintext password — is never
visible to searchers or front-runners.

**Step-by-step:**
```
1. Switch your wallet RPC to a private endpoint (e.g. Flashbots Protect)
2. Submit one of:
   - setNewOwner(yourWhitelistedWallet, transferPassword, signature)
   - rescueETH(rescuePassword)  ← if you need funds out immediately
3. Tx lands in the next block with zero mempool exposure
```

> Even if the attacker's `setNewWLOwner` or `setTransferPassword` tx is pending —
> your `setNewOwner` or `rescueETH` using the **current valid password** still
> executes correctly as long as their tx hasn't confirmed yet.
> Submitting via private RPC wins the race without a bidding war.

---

## Deploy

Constructor arguments:

| Argument | Description |
|----------|-------------|
| `_initialOwner` | Address that receives ownership immediately at deploy |
| `_transferPasswordHash` | `keccak256(transferPassword)` — computed off-chain |
| `_rescuePasswordHash` | `keccak256(rescuePassword)` — computed off-chain |
| `_whiteListedOwner` | First address pre-approved as a valid `newOwner` target |

`_initialOwner` and `_whiteListedOwner` can be the same address.

---

## Full Attack Surface — What Fails and Why

| Attack | Result |
|--------|--------|
| Front-run `rescueETH` with `transferPassword` | ❌ Wrong password |
| Front-run `setTransferPassword` with exposed password | ❌ No `applyNewPassword` request → reverts |
| Submit `applyNewPassword` then immediately rotate | ❌ 7-day delay not satisfied |
| Redirect `newOwner` to attacker address | ❌ Not whitelisted |
| Redirect `newOwner` to different whitelisted address | ❌ Signature committed to original `newOwner` |
| Replay used OTP signature | ❌ `isTPassUsed == true` |
| Use signature on different chain or contract | ❌ EIP-712 binds `chainId` + `verifyingContract` |
| `applyNewWLOwner(attackerWallet)` — owner detects in time | ✅ Migrate before 7 days expire |
| Owner misses 7-day window, attacker request matures | ⚠️ Use private RPC to submit recovery tx |

---

## Run

```bash
nvm use 22
npm i
npx hardhat test
```

## Flatten for deploy

```bash
npx hardhat flatten contracts/Holder.sol > Holder_flat.sol
```