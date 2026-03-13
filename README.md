# Holder — EIP-712 Gasless Ownership Transfer with OTP Protection

## Why?
If somebody steals your private keys, they can't withdraw — funds are time-locked.
You can transfer ownership to a fresh wallet via a gasless signed tx submitted
by anyone — even through the public mempool.

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

## How Ownership Transfer Works
```
owner signs off-chain: { newOwner, hash(transferPassword) }
anyone submits on-chain: setNewOwner(newOwner, transferPassword, signature)
contract verifies: hash(password) matches + signature is from owner + OTP not used
```
- Swapping `newOwner`, wrong password, or replaying the signature all revert
- Signature is bound to `chainId` + `verifyingContract` — can't be used elsewhere
- OTP burned after use — rotate via `setTransferPassword(oldPass, newHash)` to rearm

## Recovery Paths
```
Keys stolen + you know passwords → setNewOwner to fresh wallet (public mempool is safe)
Keys stolen + forgot password    → wait for holdTime to expire → withdrawETH
Urgent + keys safe               → rescueETH(rescuePassword) — bypasses holdTime
```

## Run
```bash
nvm use 22
npm i
npx hardhat test
```

## Flatt for deploy 

```
npx hardhat flatten contracts/Holder.sol > Holder_flat.sol
```