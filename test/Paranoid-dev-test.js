import { expect } from "chai";
import hre from "hardhat";
const { ethers } = hre;

// ─── EIP-712 helpers ───────────────────────────────────────────────
async function buildDomain(contract) {
  const { chainId } = await ethers.provider.getNetwork();
  return {
    name: "Holder",
    version: "1",
    chainId,
    verifyingContract: await contract.getAddress(),
  };
}

const TYPES = {
  TransferOwnership: [
    { name: "newOwner",     type: "address" },
    { name: "passwordHash", type: "bytes32" },
  ],
};

async function signTransfer(signer, domain, newOwner, password) {
  const passwordHash = ethers.keccak256(ethers.toUtf8Bytes(password));
  const signature = await signer.signTypedData(domain, TYPES, { newOwner, passwordHash });
  return { signature, passwordHash };
}

function passHash(pass) {
  return ethers.keccak256(ethers.toUtf8Bytes(pass));
}
// ───────────────────────────────────────────────────────────────────

describe("Holder — PARANOID ADVERSARIAL SUITE", function () {
  const TRANSFER_PASS     = "transfer-secret-123";
  const RESCUE_PASS       = "rescue-secret-456";
  const NEW_TRANSFER_PASS = "new-transfer-secret";
  const NEW_RESCUE_PASS   = "new-rescue-secret";

  let holder, token;
  let owner, userTwo, userThree, attacker;
  let domain;

  const TEN_ETH = ethers.parseEther("10");
  const HUNDRED = ethers.parseEther("100");
  const DAY     = 86400n;
  const WEEK    = DAY * 7n;
  const YEAR    = DAY * 365n;
  const DAYS_90 = DAY * 90n;

  async function applyAndWaitPassword(h, newPassHash) {
    await h.applyNewPassword(newPassHash);
    await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
    await ethers.provider.send("evm_mine", []);
  }

  async function applyAndWaitWL(h, addr) {
    await h.applyNewWLOwner(addr);
    await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
    await ethers.provider.send("evm_mine", []);
    await h.setNewWLOwner(addr);
  }

  async function deployAll() {
    [owner, userTwo, userThree, attacker] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("USDT");
    token = await TokenFactory.deploy(HUNDRED);
    await token.waitForDeployment();

    const HolderFactory = await ethers.getContractFactory("Holder");
    holder = await HolderFactory.connect(owner).deploy(
      owner.address,
      passHash(TRANSFER_PASS),
      passHash(RESCUE_PASS),
      userTwo.address
    );
    await holder.waitForDeployment();

    domain = await buildDomain(holder);

    await owner.sendTransaction({ to: await holder.getAddress(), value: TEN_ETH });
    await token.transfer(await holder.getAddress(), HUNDRED);
  }

  beforeEach(deployAll);

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 1: reLock — infinite lockup with stolen keys
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — reLock permanent lockup (stolen keys)", function () {

    it("ATTACK: attacker with stolen keys calls reLock in a loop — withdrawETH permanently blocked", async function () {
      // Simulate: attacker has owner keys, calls reLock every 90 days
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      // First reLock — blocks withdraw for 90 more days
      await holder.reLock(); // attacker has keys
      await expect(holder.withdrawETH()).to.be.revertedWith("EARLY");

      // Second reLock — 90 days later, blocks again
      await ethers.provider.send("evm_increaseTime", [Number(DAYS_90 + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.reLock();
      await expect(holder.withdrawETH()).to.be.revertedWith("EARLY");

      // ONLY ESCAPE: rescueETH — requires rescuePassword that attacker doesn't have
      await holder.rescueETH(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });

    it("ATTACK: reLock blocks ERC20 withdrawal too, but rescueERC20 still works", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.reLock();
      await expect(holder.withdrawERC20(await token.getAddress())).to.be.revertedWith("EARLY");
      // rescue path unaffected
      await holder.rescueERC20(RESCUE_PASS, await token.getAddress());
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);
    });

    it("ATTACK: reLock can be called before holdTime too — extending an already locked vault", async function () {
      // vault is locked (initial year not elapsed)
      await holder.reLock();
      const holdTime = await holder.holdTime();
      const block = await ethers.provider.getBlock("latest");
      // holdTime should be ~90 days from now (less than original 365-day lock)
      expect(holdTime).to.be.lt(BigInt(block.timestamp) + YEAR);
      expect(holdTime).to.be.gte(BigInt(block.timestamp) + DAYS_90 - DAY);
    });

    it("DEFENSE: rescueETH is the only escape from reLock loop — verify it bypasses holdTime check", async function () {
      for (let i = 0; i < 5; i++) {
        await holder.reLock();
        await ethers.provider.send("evm_increaseTime", [Number(DAYS_90 + DAY)]);
        await ethers.provider.send("evm_mine", []);
      }
      // 5 reLocks later, withdrawETH should still be blocked
      await holder.reLock();
      await expect(holder.withdrawETH()).to.be.revertedWith("EARLY");
      // rescueETH has NO holdTime check
      await holder.rescueETH(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 2: Password exposed on-chain (calldata history)
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — passwords permanently visible in calldata after use", function () {

    it("ATTACK: rescueETH calldata exposes rescuePass permanently — refund then instant drain", async function () {
      // Step 1: owner uses rescueETH — password now on-chain forever
      await holder.rescueETH(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);

      // Step 2: owner refunds the contract (deposits again)
      await owner.sendTransaction({ to: await holder.getAddress(), value: TEN_ETH });

      // Step 3: attacker with stolen keys + observed calldata calls rescueETH again
      // rescuePassword is NOT invalidated after use — still valid
      await holder.rescueETH(RESCUE_PASS); // DRAINS AGAIN
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      // NOTE: This documents that rescuePassword must be rotated after every use
    });

    it("ATTACK: setNewOwner calldata exposes transferPass — old owner gets keys back, rescues with that pass?", async function () {
      // transferPass exposed in setNewOwner calldata
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);

      // isTPassUsed = true, so setNewOwner can't be replayed
      await expect(
        holder.connect(userTwo).setNewOwner(userTwo.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: already used");

      // Can exposed transferPass be used for rescueETH? NO — different password
      await expect(
        holder.connect(userTwo).rescueETH(TRANSFER_PASS)
      ).to.be.revertedWith("WRONG PASS");
    });

    it("ATTACK: setTransferPassword exposes OLD password in calldata — can it be replayed?", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_TRANSFER_PASS));
      await holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));
      // TRANSFER_PASS is now on-chain in setTransferPassword calldata
      // But it's no longer valid as transferPasswordHash
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(
        holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: wrong password");
    });

    it("ATTACK: setRescuePassword exposes OLD rescue password — immediately try rescueETH with it", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_RESCUE_PASS));
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      // RESCUE_PASS is on-chain, but it's no longer valid
      await expect(holder.rescueETH(RESCUE_PASS)).to.be.revertedWith("WRONG PASS");
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 3: Same password for both transfer and rescue
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — identical transfer and rescue password hashes", function () {
    let h, d;

    beforeEach(async function () {
      const SAME_PASS = "same-password-for-both";
      const HolderFactory = await ethers.getContractFactory("Holder");
      h = await HolderFactory.connect(owner).deploy(
        owner.address,
        passHash(SAME_PASS), // transferPasswordHash
        passHash(SAME_PASS), // rescuePasswordHash — SAME!
        userTwo.address
      );
      await h.waitForDeployment();
      d = await buildDomain(h);
      await owner.sendTransaction({ to: await h.getAddress(), value: TEN_ETH });
    });

    it("ATTACK: revealing transferPass in setNewOwner mempool also reveals rescuePass", async function () {
      const SAME_PASS = "same-password-for-both";
      // attacker sees setNewOwner calldata, extracts SAME_PASS
      // can now call rescueETH with that same password
      await h.rescueETH(SAME_PASS);
      expect(await ethers.provider.getBalance(await h.getAddress())).to.equal(0n);
      // Documents why transfer and rescue passwords MUST differ
    });

    it("ATTACK: transferPass and rescuePass are interchangeable when identical hashes", async function () {
      const SAME_PASS = "same-password-for-both";
      const { signature } = await signTransfer(owner, d, userTwo.address, SAME_PASS);
      // setNewOwner with rescuePass works because hash == hash
      await h.setNewOwner(userTwo.address, SAME_PASS, signature);
      expect(await h.owner()).to.equal(userTwo.address);
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 4: applyNewPassword timestamp reset
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — applyNewPassword timestamp overwrite (7-day reset attack)", function () {

    it("ATTACK: calling applyNewPassword twice for same hash resets the 7-day clock", async function () {
      await holder.applyNewPassword(passHash(NEW_TRANSFER_PASS));
      // 6 days pass — almost ready
      await ethers.provider.send("evm_increaseTime", [Number(DAY * 6n)]);
      await ethers.provider.send("evm_mine", []);

      // Owner re-calls applyNewPassword (maybe by accident or to "confirm")
      await holder.applyNewPassword(passHash(NEW_TRANSFER_PASS)); // resets timestamp!

      // 2 more days pass (total 8 from first call, but only 2 from second)
      await ethers.provider.send("evm_increaseTime", [Number(DAY * 2n)]);
      await ethers.provider.send("evm_mine", []);

      // Should still fail — clock was reset
      await expect(
        holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("Too early");
    });

    it("ATTACK: attacker with owner keys uses applyNewPassword to indefinitely delay password rotation", async function () {
      // Victim queues password rotation
      await holder.applyNewPassword(passHash(NEW_TRANSFER_PASS));
      // 6 days pass
      await ethers.provider.send("evm_increaseTime", [Number(DAY * 6n)]);
      await ethers.provider.send("evm_mine", []);
      // Attacker resets the request (has owner keys)
      await holder.applyNewPassword(passHash(NEW_TRANSFER_PASS));
      // The rotation is blocked for another 7 days
      await expect(
        holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("Too early");
    });

    it("ATTACK: applyNewWLOwner timestamp overwrite — same pattern blocks whitelist additions", async function () {
      await holder.applyNewWLOwner(userThree.address);
      await ethers.provider.send("evm_increaseTime", [Number(DAY * 6n)]);
      await ethers.provider.send("evm_mine", []);
      // Reset clock
      await holder.applyNewWLOwner(userThree.address);
      await ethers.provider.send("evm_increaseTime", [Number(DAY * 2n)]);
      await ethers.provider.send("evm_mine", []);
      await expect(holder.setNewWLOwner(userThree.address)).to.be.revertedWith("Too early");
    });

    it("ATTACK: two different newPassHashes queued — only one can be consumed, other stays", async function () {
      const hash1 = passHash(NEW_TRANSFER_PASS);
      const hash2 = passHash(NEW_RESCUE_PASS);
      await holder.applyNewPassword(hash1);
      await holder.applyNewPassword(hash2);
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);

      // Consume hash1
      await holder.setTransferPassword(TRANSFER_PASS, hash1);
      // hash2 still in passwordRequests
      const ts = await holder.passwordRequests(hash2);
      expect(ts).to.be.gt(0n);
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 5: Whitelist — stolen keys whitelist attacker
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — attacker whitelists themselves with stolen owner keys", function () {

    it("ATTACK: stolen keys → applyNewWLOwner(attacker) → 7-day window to detect and respond", async function () {
      // Attacker has stolen keys, submits applyNewWLOwner
      // whiteListTime is private — we verify the effect indirectly:
      // before 7 days setNewWLOwner reverts, proving the request was registered
      await holder.connect(owner).applyNewWLOwner(attacker.address); // owner keys stolen

      // Immediately after applyNewWLOwner — request exists but delay not met yet
      await expect(
        holder.setNewWLOwner(attacker.address)
      ).to.be.revertedWith("Too early");

      // Victim has 7 days to transfer ownership via setNewOwner before attacker's request matures
      // During this window, setNewOwner still works (password not exposed yet)
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);

      // Attacker's request matures but new owner can delete it (if removeFromWhitelist existed)
      // Instead: even after maturation, setNewWLOwner is onlyOwner (now userTwo)
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      // Attacker cannot call setNewWLOwner — not owner
      await expect(
        holder.connect(attacker).setNewWLOwner(attacker.address)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("ATTACK: attacker's 7-day window matures — they can whitelist themselves if keys still stolen", async function () {
      await holder.applyNewWLOwner(attacker.address);
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      // Attacker still has keys (victim missed the window)
      await holder.setNewWLOwner(attacker.address);
      expect(await holder.whiteList(attacker.address)).to.equal(true);
      // "Stolen keys" in hardhat = attacker controls owner's private key
      // represented by signing with `owner` signer but submitting from `attacker` account
      // Contract checks: signer == owner() → owner.address — matches because attacker has owner's key
      const { signature } = await signTransfer(owner, domain, attacker.address, TRANSFER_PASS);
      await holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(attacker.address);
      // CRITICAL: if attacker has owner keys + knows transferPass + waited 7 days → they win
    });

    it("ATTACK: already-whitelisted address — re-applying does nothing harmful", async function () {
      // userTwo is already whitelisted from deploy
      await holder.applyNewWLOwner(userTwo.address);
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      await holder.setNewWLOwner(userTwo.address);
      // Still whitelisted — no change
      expect(await holder.whiteList(userTwo.address)).to.equal(true);
    });

    it("ATTACK: zero address whitelisted — setNewOwner(0x0) blocked by OTP zero check first", async function () {
      await holder.applyNewWLOwner(ethers.ZeroAddress);
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      await holder.setNewWLOwner(ethers.ZeroAddress);
      expect(await holder.whiteList(ethers.ZeroAddress)).to.equal(true);
      // setNewOwner with 0x0 should fail on zero address check
      const { signature } = await signTransfer(owner, domain, ethers.ZeroAddress, TRANSFER_PASS);
      await expect(
        holder.setNewOwner(ethers.ZeroAddress, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: zero address");
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 6: Signature attacks
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — EIP-712 signature manipulation", function () {

    it("ATTACK: cross-contract replay — sig from this contract fails on different contract", async function () {
      // Deploy second holder
      const HolderFactory = await ethers.getContractFactory("Holder");
      const holder2 = await HolderFactory.connect(owner).deploy(
        owner.address,
        passHash(TRANSFER_PASS),
        passHash(RESCUE_PASS),
        userTwo.address
      );
      await holder2.waitForDeployment();

      // Sign for holder1
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);

      // Try to replay on holder2 — domain separator differs (verifyingContract)
      await expect(
        holder2.setNewOwner(userTwo.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: invalid signature");
    });

    it("ATTACK: tampered newOwner in calldata while keeping original sig — sig mismatch", async function () {
      await applyAndWaitWL(holder, userThree.address);
      // Sign for userTwo
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      // Submit with userThree — sig committed to userTwo
      await expect(
        holder.setNewOwner(userThree.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: invalid signature");
    });

    it("ATTACK: tampered password in calldata while keeping original sig — password hash mismatch", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      // Submit with wrong password (different from what sig was built with)
      // Also fails password check before sig check
      await expect(
        holder.setNewOwner(userTwo.address, "tampered-password", signature)
      ).to.be.revertedWith("OTP: wrong password");
    });

    it("ATTACK: attacker submits a valid pending tx before owner (front-run) — same result, no benefit", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      // Front-runner submits the exact same tx — newOwner is STILL userTwo, not attacker
      await holder.connect(attacker).setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
      // Attacker gained nothing — they don't control userTwo
    });

    it("ATTACK: malleable signature (v=27 vs v=28 swap) — ECDSA library rejects", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      const sigBytes = ethers.getBytes(signature);
      // Flip v
      sigBytes[64] = sigBytes[64] === 27 ? 28 : 27;
      const malleableSig = ethers.hexlify(sigBytes);
      await expect(
        holder.setNewOwner(userTwo.address, TRANSFER_PASS, malleableSig)
      ).to.be.revertedWith("OTP: invalid signature");
    });

    it("ATTACK: truncated signature (< 65 bytes) — ECDSA reverts", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      const truncated = signature.slice(0, -4); // remove 2 bytes
      await expect(
        holder.setNewOwner(userTwo.address, TRANSFER_PASS, truncated)
      ).to.be.reverted;
    });

    it("ATTACK: zero signature — ECDSA reverts", async function () {
      const zeroSig = "0x" + "00".repeat(65);
      await expect(
        holder.setNewOwner(userTwo.address, TRANSFER_PASS, zeroSig)
      ).to.be.reverted;
    });

    it("ATTACK: old owner tries to transfer after already being replaced", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);

      // OTP burned, new owner is userTwo
      // Can old owner build a new sig to transfer again? No — isTPassUsed
      await expect(
        holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: already used");

      // Even with new sig — OTP still burned
      const { signature: sig2 } = await signTransfer(userTwo, domain, userThree.address, TRANSFER_PASS);
      await expect(
        holder.setNewOwner(userThree.address, TRANSFER_PASS, sig2)
      ).to.be.revertedWith("OTP: already used");
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 7: Password rotation edge cases
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — password rotation manipulation", function () {

    it("ATTACK: rotate transferPassword to the same hash (no-op rotation consumes OTP slot)", async function () {
      // No check that newPassHash != current
      const currentHash = passHash(TRANSFER_PASS);
      await applyAndWaitPassword(holder, currentHash);
      await holder.setTransferPassword(TRANSFER_PASS, currentHash); // rotates to same value
      // OTP reset (isTPassUsed = false) but password unchanged
      expect(await holder.isTPassUsed()).to.equal(false);
      // Old sig still works since password unchanged
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
    });

    it("ATTACK: setTransferPassword with wrong old pass — blocked even after delay", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_TRANSFER_PASS));
      await expect(
        holder.setTransferPassword("not-the-real-pass", passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });

    it("ATTACK: setRescuePassword with transfer password — blocked", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_RESCUE_PASS));
      await expect(
        holder.setRescuePassword(TRANSFER_PASS, passHash(NEW_RESCUE_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });

    it("ATTACK: queue 0x00 as new password hash — borderline request", async function () {
      const zeroHash = ethers.ZeroHash;
      await holder.applyNewPassword(zeroHash);
      const ts = await holder.passwordRequests(zeroHash);
      expect(ts).to.be.gt(0n);
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      // Can we rotate to zero hash?
      await holder.setTransferPassword(TRANSFER_PASS, zeroHash);
      // Now transferPasswordHash is 0x00 — keccak256("") == 0xc5d2... not zero
      // Any non-empty string will fail, only the string whose keccak is 0 would work (none)
      await expect(
        holder.setNewOwner(userTwo.address, "", ethers.ZeroHash)
      ).to.be.reverted;
    });

    it("ATTACK: passwordRequests not cleaned up after failed setTransferPassword — request stays", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_TRANSFER_PASS));
      // Fail with wrong pass
      await expect(
        holder.setTransferPassword("wrongpass", passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("WRONG PASS");
      // Request is still there — can retry with correct pass
      const ts = await holder.passwordRequests(passHash(NEW_TRANSFER_PASS));
      expect(ts).to.be.gt(0n);
      await holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 8: ETH / ERC20 withdrawal edge cases
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — withdrawal edge cases", function () {

    it("ATTACK: withdrawETH on zero balance — succeeds (no revert on 0 ETH transfer)", async function () {
      // Drain first
      await holder.rescueETH(RESCUE_PASS);
      // Now try withdrawETH after holdTime on empty contract
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await expect(holder.withdrawETH()).to.not.be.reverted;
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });

    it("ATTACK: withdrawERC20 on zero token balance — succeeds (transfer of 0)", async function () {
      // Drain tokens first
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.withdrawERC20(await token.getAddress());
      // Second call — balance is 0
      await expect(holder.withdrawERC20(await token.getAddress())).to.not.be.reverted;
    });

    it("ATTACK: rescueETH drains, rescueERC20 called separately — both work independently", async function () {
      await holder.rescueETH(RESCUE_PASS);
      await holder.rescueERC20(RESCUE_PASS, await token.getAddress());
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);
    });

    it("ATTACK: non-owner tries withdrawETH after holdTime — always blocked by onlyOwner", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      for (const user of [userTwo, userThree, attacker]) {
        await expect(holder.connect(user).withdrawETH())
          .to.be.revertedWith("Ownable: caller is not the owner");
      }
    });

    it("ATTACK: non-owner tries rescueETH with correct password — blocked by onlyOwner", async function () {
      for (const user of [userTwo, userThree, attacker]) {
        await expect(holder.connect(user).rescueETH(RESCUE_PASS))
          .to.be.revertedWith("Ownable: caller is not the owner");
      }
    });

    it("ATTACK: rescueERC20 with malicious token (reverts on transfer) — SafeERC20Transfer reverts cleanly", async function () {
      const MaliciousToken = await ethers.getContractFactory("RevertingToken");
      const bad = await MaliciousToken.deploy();
      await bad.waitForDeployment();
      await expect(
        holder.rescueERC20(RESCUE_PASS, await bad.getAddress())
      ).to.be.reverted;
      // Holder ETH and legitimate token unaffected
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(TEN_ETH);
    });

    it("ATTACK: withdrawERC20 with token returning false (no-revert style) — SafeERC20 catches it", async function () {
      const FalseToken = await ethers.getContractFactory("FalseReturningToken");
      const bad = await FalseToken.deploy();
      await bad.waitForDeployment();
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await expect(
        holder.withdrawERC20(await bad.getAddress())
      ).to.be.reverted;
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 9: setNewOwner — newOwner is current owner
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — transfer to self / edge case owners", function () {

    it("ATTACK: setNewOwner where newOwner == current owner (if owner is whitelisted)", async function () {
      // Whitelist the current owner
      await applyAndWaitWL(holder, owner.address);
      const { signature } = await signTransfer(owner, domain, owner.address, TRANSFER_PASS);
      await holder.setNewOwner(owner.address, TRANSFER_PASS, signature);
      // Ownership "transferred" to same address — isTPassUsed burned, password rotation needed
      expect(await holder.owner()).to.equal(owner.address);
      expect(await holder.isTPassUsed()).to.equal(true);
      // OTP is now burned — cannot transfer again without rotation
      const { signature: sig2 } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(
        holder.setNewOwner(userTwo.address, TRANSFER_PASS, sig2)
      ).to.be.revertedWith("OTP: already used");
    });

    it("ATTACK: setNewOwner where newOwner is a contract address (whitelisted)", async function () {
      const TokenAddr = await token.getAddress();
      await applyAndWaitWL(holder, TokenAddr);
      const { signature } = await signTransfer(owner, domain, TokenAddr, TRANSFER_PASS);
      await holder.setNewOwner(TokenAddr, TRANSFER_PASS, signature);
      // Owner is now a contract — withdrawETH would call token.receive()
      expect(await holder.owner()).to.equal(TokenAddr);
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 10: Access control completeness
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — access control completeness check", function () {
    const onlyOwnerFns = [
      ["applyNewPassword", (h) => h.connect(attacker).applyNewPassword(passHash(NEW_TRANSFER_PASS))],
      ["applyNewWLOwner",  (h) => h.connect(attacker).applyNewWLOwner(attacker.address)],
      ["setNewWLOwner",    (h) => h.connect(attacker).setNewWLOwner(userTwo.address)],
      ["setTransferPassword", (h) => h.connect(attacker).setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS))],
      ["setRescuePassword",   (h) => h.connect(attacker).setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS))],
      ["withdrawETH",     (h) => h.connect(attacker).withdrawETH()],
      ["withdrawERC20",   async (h) => h.connect(attacker).withdrawERC20(await token.getAddress())],
      ["rescueETH",       (h) => h.connect(attacker).rescueETH(RESCUE_PASS)],
      ["rescueERC20",     async (h) => h.connect(attacker).rescueERC20(RESCUE_PASS, await token.getAddress())],
      ["reLock",          (h) => h.connect(attacker).reLock()],
    ];

    for (const [name, fn] of onlyOwnerFns) {
      it(`ATTACK: non-owner cannot call ${name}`, async function () {
        await expect(fn(holder)).to.be.revertedWith("Ownable: caller is not the owner");
      });
    }
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 11: viewData / getDigest information leakage
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — public information leakage", function () {

    it("ATTACK: getDigest is callable by anyone — attacker can pre-compute any digest", async function () {
      const attackerDigest = await holder.connect(attacker).getDigest(
        attacker.address,
        passHash(TRANSFER_PASS)
      );
      // Digest is computable, but useless without: whitelist + valid sig from owner + correct password
      expect(attackerDigest).to.not.equal(ethers.ZeroHash);
    });

    it("ATTACK: whiteList mapping is public — attacker knows which addresses are valid targets", async function () {
      expect(await holder.whiteList(userTwo.address)).to.equal(true);
      expect(await holder.whiteList(attacker.address)).to.equal(false);
      // Information itself doesn't enable attack — still need sig + password
    });

    it("ATTACK: passwordRequests mapping is public — attacker can monitor pending rotations", async function () {
      await holder.applyNewPassword(passHash(NEW_TRANSFER_PASS));
      const ts = await holder.passwordRequests(passHash(NEW_TRANSFER_PASS));
      expect(ts).to.be.gt(0n);
      // Attacker knows rotation is pending and when it matures
    });

    it("ATTACK: CHANGE_DELAY constant is public — attacker knows exact timing windows", async function () {
      const delay = await holder.CHANGE_DELAY();
      expect(delay).to.equal(WEEK);
    });

    it("ATTACK: isTPassUsed public — attacker knows if OTP is armed or burned", async function () {
      expect(await holder.isTPassUsed()).to.equal(false);
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.isTPassUsed()).to.equal(true);
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 12: Reentrancy via receive()
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — reentrancy via ETH transfer to owner contract", function () {

    it("ATTACK: reentrancy on withdrawETH — balance drained in first call, reentrant call gets 0", async function () {
      const ReentrantFactory = await ethers.getContractFactory("ReentrantReceiver");
      const reentrant = await ReentrantFactory.deploy(await holder.getAddress());
      await reentrant.waitForDeployment();

      // Transfer ownership to the reentrant contract
      await applyAndWaitWL(holder, await reentrant.getAddress());
      const { signature } = await signTransfer(owner, domain, await reentrant.getAddress(), TRANSFER_PASS);
      await holder.setNewOwner(await reentrant.getAddress(), TRANSFER_PASS, signature);

      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      // withdrawETH to reentrant contract — reentrant call should get 0 ETH (balance already 0)
      await reentrant.triggerWithdraw();
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      // No double-drain possible — balance cleared on first call
    });

    it("ATTACK: reentrancy on rescueETH — same protection via balance drain", async function () {
      const ReentrantFactory = await ethers.getContractFactory("ReentrantReceiver");
      const reentrant = await ReentrantFactory.deploy(await holder.getAddress());
      await reentrant.waitForDeployment();

      await applyAndWaitWL(holder, await reentrant.getAddress());
      const { signature } = await signTransfer(owner, domain, await reentrant.getAddress(), TRANSFER_PASS);
      await holder.setNewOwner(await reentrant.getAddress(), TRANSFER_PASS, signature);

      await reentrant.triggerRescue(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });
  });

  // ══════════════════════════════════════════════════════════════════
  //  ATTACK SURFACE 13: Combined / chained attack scenarios
  // ══════════════════════════════════════════════════════════════════
  describe("ATTACK — multi-step chained attack scenarios", function () {

    it("ATTACK: full stolen-key scenario without password knowledge — last resort path", async function () {
      // Attacker has ONLY owner keys, NO passwords
      // They can: reLock, applyNewWLOwner, applyNewPassword

      // Step 1: attacker reLocks to prevent withdrawETH
      await holder.reLock(); // attacker = owner (stolen keys)

      // Step 2: attacker queues own address in whitelist
      await holder.applyNewWLOwner(attacker.address);

      // Step 3: victim detects within 7 days, uses rescueETH (no password needed from attacker side)
      await holder.rescueETH(RESCUE_PASS); // victim knows rescuePass
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      await holder.rescueERC20(RESCUE_PASS, await token.getAddress());
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);

      // Attacker's whitelist request matures but contract is empty
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      await holder.setNewWLOwner(attacker.address); // attacker whitelisted but vault is empty
      expect(await holder.whiteList(attacker.address)).to.equal(true);
    });

    it("ATTACK: stolen keys + known transferPass (both compromised) — whitelist delay is last defense", async function () {
      // Attacker has keys AND transferPass — still blocked by whitelist requirement
      // attacker.address is NOT whitelisted
      const { signature } = await signTransfer(
        owner,   // attacker has owner keys, signs as owner
        domain,
        attacker.address,
        TRANSFER_PASS
      );
      await expect(
        holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("Not in White List");
      // Whitelist is the last line of defense when both key and password are stolen
    });

    it("ATTACK: stolen keys + known transferPass + 7 days elapsed for attacker's WL request", async function () {
      // Attacker has keys and pass, and has waited 7 days for their WL request
      await holder.applyNewWLOwner(attacker.address); // attacker has keys
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      await holder.setNewWLOwner(attacker.address);

      // Now attacker can transfer ownership to themselves
      const { signature } = await signTransfer(owner, domain, attacker.address, TRANSFER_PASS);
      await holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(attacker.address);
      // CONCLUSION: If attacker has keys + pass + waits 7 days undetected → they win
      // The 7-day window is the ONLY protection in this scenario
    });

    it("SCENARIO: keys stolen, rescuePassword safe, victim recovers via setNewOwner then drains", async function () {
      // Keys stolen, rescuePass secure, transferPass secure
      // Victim's plan: transfer to fresh wallet via setNewOwner, then rescue funds

      // Step 1: transfer to fresh wallet (userThree — whitelisted after delay)
      await holder.applyNewWLOwner(userThree.address);
      await ethers.provider.send("evm_increaseTime", [Number(WEEK + 1n)]);
      await ethers.provider.send("evm_mine", []);
      await holder.setNewWLOwner(userThree.address);

      const { signature } = await signTransfer(owner, domain, userThree.address, TRANSFER_PASS);
      await holder.setNewOwner(userThree.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userThree.address);

      // Step 2: fresh owner rescues all funds
      await holder.connect(userThree).rescueETH(RESCUE_PASS);
      await holder.connect(userThree).rescueERC20(RESCUE_PASS, await token.getAddress());
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);
      expect(await ethers.provider.getBalance(userThree.address)).to.be.gt(TEN_ETH - ethers.parseEther("0.01"));
    });
  });
});