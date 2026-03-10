# Why need extra password ?

```
This is part of another big project for case if somebody steal owner private keys he can change owner by send gas less tx + flashbots RPC
for avoid get password in mempool from listen bots with his stolen keys
```

# EIP-712 Ownership Transfer with One-Time Password
```

Transfer ownership gaslessly — owner signs off-chain, anyone can submit the tx.

How it works

The owner signs a typed EIP-712 struct committing to a specific `newOwner` and a `passwordHash`.
To execute, the submitter must provide the matching plain-text password.
The password is hashed on-chain and compared. Once used, the OTP is burned forever.

```

```

owner signs: { newOwner, hash(password) }
anyone calls: transferOwnership(newOwner, password, signature)
contract checks: hash(password) matches + signature is from owner + not already used

Swapping `newOwner`, using a wrong password, or replaying the same signature all revert.
The signature is also bound to `chainId` and `verifyingContract` so it can't be used elsewhere.

To rotate: owner calls `setPassword(newPassword)` which resets the OTP for a fresh transfer.
```

## Run

```bash
nvm use 22
npm i
npx hardhat test
```


