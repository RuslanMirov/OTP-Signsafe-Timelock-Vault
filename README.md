# Holder — EIP-712 Gasless Ownership Transfer with OTP Protection

## Why?
If somebody steals your private keys, they can't withdraw — funds are time-locked.
You can transfer ownership using passwords to a fresh wallet via a gasless signed tx submitted
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

A front-runner who sees `setNewOwner` calldata in the mempool gains nothing:

- **Cannot use `transferPassword` to drain funds** — `rescueETH` and `rescueERC20` require a completely separate `rescuePassword`. Seeing the transfer password gives zero access to the rescue path.
- **Cannot redirect `newOwner`** — the EIP-712 signature commits to a specific address. Swapping it reverts with `OTP: invalid signature`.
- **Cannot block the password rotation** — `setTransferPassword` requires a pre-submitted `applyNewPassword` request plus a 7-day delay. A front-runner with no prior request is immediately rejected with `No request found`.
- **Cannot replay the signature** — `isTPassUsed` is set to `true` on the first successful call. Any replay reverts with `OTP: already used`.
- **Cannot use the signature on another chain or contract** — EIP-712 binds the signature to `chainId` and `verifyingContract`. It is useless anywhere else.

The only thing a front-runner can do is submit the exact same transaction the victim intended — which lands `newOwner` as the new owner exactly as planned. The front-runner gains nothing.

---

## Password Rotation Delay

Password rotation requires a **7-day timelock**, so a front-runner who sees `transferPassword` in the mempool cannot invalidate it before the transfer lands:

```
1. owner calls applyNewPassword(newPassHash)   ← announces intent on-chain
2. wait 7 days
3. owner calls setTransferPassword(oldPass, newPassHash)  ← rotation executes
```

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

One address is whitelisted at deploy time via the `_whiteListedOwner` constructor argument — this is your unconditional escape hatch.

### Why There Is No `removeFromWhitelist`

Removing whitelist entries would be a critical vulnerability, not a feature. If an attacker steals the owner's private key, they could call `removeFromWhitelist` on every pre-approved address, permanently destroying the only safe transfer path. With no whitelisted destination, `setNewOwner` becomes impossible — the attacker then simply waits for `holdTime` to expire and calls `withdrawETH`.

The whitelist is intentionally **append-only**. An attacker with stolen keys can queue their own address via `applyNewWLOwner`, but the 7-day delay gives the legitimate owner time to call `setNewOwner` to a pre-whitelisted address before the attacker's request matures. Once ownership transfers, the attacker's keys are worthless — every `onlyOwner` function reverts instantly. The pre-whitelisted address set at deploy time is an escape hatch the attacker can never close.

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

---

## ⚠️ If You Overslept the 7-Day Window — Use a Private RPC

If you missed the monitoring window and the attacker's `applyNewPassword` or
`applyNewWLOwner` request has already matured, **do not submit your recovery tx
through the public mempool**. The attacker is watching and will front-run any tx
that exposes your password.

If you suspect one of your whitelisted addresses was also compromised, use a private RPC for all recovery transactions.

| Provider | Endpoint |
|----------|----------|
| Flashbots Protect | `https://rpc.flashbots.net` |
| MEV Blocker | `https://rpc.mevblocker.io` |
| Beaverbuild Private | `https://rpc.beaverbuild.org` |

Private RPCs route your tx directly to block builders, bypassing the public mempool entirely. Your calldata — including the plaintext password — is never visible to searchers or front-runners.

```
1. Switch to private endpoint in transferOwnershipOTP.js script
2. Submit: setNewOwner(yourWhitelistedWallet, transferPassword, signature)
3. New owner can now rescueETH immediately or wait for holdTime to withdraw normally
```

> Even if the attacker's `setNewWLOwner` or `setTransferPassword` tx is pending —
> your `setNewOwner` using the **current valid password** still executes correctly
> as long as their tx hasn't confirmed yet. Private RPC wins the race without a bidding war.

---

## Deploy

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
| Remove victim's whitelisted address | ❌ No `removeFromWhitelist` function exists |
| `applyNewWLOwner(attackerWallet)` — owner detects in time | ✅ Migrate before 7 days expire |
| Owner misses 7-day window, attacker request matures | ⚠️ Use private RPC to submit recovery tx |

---

## Run

```bash
nvm use 22
npm i
npx hardhat test
```

## Flatten for Deploy

```bash
npx hardhat flatten contracts/Holder.sol > Holder_flat.sol
```