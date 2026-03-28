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
  const signature    = await signer.signTypedData(domain, TYPES, { newOwner, passwordHash });
  return { signature, passwordHash };
}

function passHash(pass) {
  return ethers.keccak256(ethers.toUtf8Bytes(pass));
}
// ───────────────────────────────────────────────────────────────────

describe("Holder — NFT (withdrawNFT + rescueNFT)", function () {
  const TRANSFER_PASS     = "transfer-secret-123";
  const RESCUE_PASS       = "rescue-secret-456";
  const NEW_RESCUE_PASS   = "new-rescue-secret";

  // Token IDs used across tests
  const ID_A = 1n;
  const ID_B = 2n;
  const ID_C = 3n;

  let holder, nft;
  let owner, userTwo, userThree, attacker;
  let domain;

  const DAY  = 86400n;
  const WEEK = DAY * 7n;
  const YEAR = DAY * 365n;

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

    // Deploy mock NFT
    const NFTFactory = await ethers.getContractFactory("MockNFT");
    nft = await NFTFactory.deploy();
    await nft.waitForDeployment();

    // Deploy Holder
    const HolderFactory = await ethers.getContractFactory("Holder");
    holder = await HolderFactory.connect(owner).deploy(
      owner.address,
      passHash(TRANSFER_PASS),
      passHash(RESCUE_PASS),
      userTwo.address
    );
    await holder.waitForDeployment();

    domain = await buildDomain(holder);

    // Mint three NFTs directly to Holder (simulates plain transferFrom deposit)
    const holderAddr = await holder.getAddress();
    await nft.mint(holderAddr, ID_A);
    await nft.mint(holderAddr, ID_B);
    await nft.mint(holderAddr, ID_C);
  }

  beforeEach(deployAll);

  // ──────────────────────────────────────────────────────────────────
  describe("INIT", function () {
    it("Holder owns all three minted NFTs", async function () {
      const holderAddr = await holder.getAddress();
      expect(await nft.ownerOf(ID_A)).to.equal(holderAddr);
      expect(await nft.ownerOf(ID_B)).to.equal(holderAddr);
      expect(await nft.ownerOf(ID_C)).to.equal(holderAddr);
      expect(await nft.balanceOf(holderAddr)).to.equal(3n);
    });

    it("owner starts with zero NFTs", async function () {
      expect(await nft.balanceOf(owner.address)).to.equal(0n);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("Accidental NFT deposit", function () {
    it("NFT sent via plain transferFrom is held by contract and recoverable", async function () {
      await nft.mint(owner.address, 99n);
      await nft.transferFrom(owner.address, await holder.getAddress(), 99n);
      expect(await nft.ownerOf(99n)).to.equal(await holder.getAddress());

      // Owner can still recover it via rescueNFT
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), 99n);
      expect(await nft.ownerOf(99n)).to.equal(owner.address);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("withdrawNFT — happy path", function () {
    it("owner can withdraw NFT after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await holder.withdrawNFT(await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });

    it("withdrawNFT decreases Holder balance by 1", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      const holderAddr = await holder.getAddress();
      await holder.withdrawNFT(await nft.getAddress(), ID_A);
      expect(await nft.balanceOf(holderAddr)).to.equal(2n);
      expect(await nft.balanceOf(owner.address)).to.equal(1n);
    });

    it("owner can withdraw multiple NFTs one by one after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await holder.withdrawNFT(await nft.getAddress(), ID_A);
      await holder.withdrawNFT(await nft.getAddress(), ID_B);
      await holder.withdrawNFT(await nft.getAddress(), ID_C);

      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
      expect(await nft.ownerOf(ID_B)).to.equal(owner.address);
      expect(await nft.ownerOf(ID_C)).to.equal(owner.address);
      expect(await nft.balanceOf(await holder.getAddress())).to.equal(0n);
    });

    it("withdrawNFT sends to current owner, not deployer", async function () {
      // Transfer ownership to userTwo first
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);

      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await holder.connect(userTwo).withdrawNFT(await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(userTwo.address);
      expect(await nft.balanceOf(owner.address)).to.equal(0n);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("withdrawNFT — access control", function () {
    it("owner cannot withdraw before holdTime", async function () {
      await expect(
        holder.withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("EARLY");
    });

    it("non-owner cannot withdraw after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await expect(
        holder.connect(attacker).withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("non-owner cannot withdraw before holdTime either", async function () {
      await expect(
        holder.connect(userThree).withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("whitelisted non-owner still cannot withdraw", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      // userTwo is whitelisted but not owner
      await expect(
        holder.connect(userTwo).withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("rescueNFT — happy path", function () {
    it("owner can rescue NFT before holdTime with correct rescue password", async function () {
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });

    it("rescueNFT bypasses holdTime — works immediately after deploy", async function () {
      // No time warp — holdTime not reached
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_B);
      expect(await nft.ownerOf(ID_B)).to.equal(owner.address);
    });

    it("rescueNFT works after holdTime too", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });

    it("all three NFTs can be rescued in sequence", async function () {
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_B);
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_C);

      expect(await nft.balanceOf(await holder.getAddress())).to.equal(0n);
      expect(await nft.balanceOf(owner.address)).to.equal(3n);
    });

    it("rescueNFT sends to current owner after ownership transfer", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);

      await holder.connect(userTwo).rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(userTwo.address);
      expect(await nft.balanceOf(owner.address)).to.equal(0n);
    });

    it("rescue works after rescue password rotation", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_RESCUE_PASS));
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));

      await holder.rescueNFT(NEW_RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("rescueNFT — access control + password", function () {
    it("wrong password reverts", async function () {
      await expect(
        holder.rescueNFT("wrongpass", await nft.getAddress(), ID_A)
      ).to.be.revertedWith("WRONG PASS");
    });

    it("empty password reverts", async function () {
      await expect(
        holder.rescueNFT("", await nft.getAddress(), ID_A)
      ).to.be.revertedWith("WRONG PASS");
    });

    it("transferPassword cannot be used for rescueNFT", async function () {
      await expect(
        holder.rescueNFT(TRANSFER_PASS, await nft.getAddress(), ID_A)
      ).to.be.revertedWith("WRONG PASS");
    });

    it("non-owner cannot rescueNFT even with correct password", async function () {
      await expect(
        holder.connect(attacker).rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("old rescue password fails after rotation", async function () {
      await applyAndWaitPassword(holder, passHash(NEW_RESCUE_PASS));
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));

      await expect(
        holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A)
      ).to.be.revertedWith("WRONG PASS");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("withdrawNFT vs rescueNFT — holdTime interaction", function () {
    it("rescueNFT works when withdrawNFT is blocked (before holdTime)", async function () {
      await expect(
        holder.withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("EARLY");

      // rescue bypasses holdTime
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });

    it("rescueNFT works during reLock period when withdrawNFT is blocked", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      // reLock resets holdTime to now + 90 days
      await holder.reLock();

      await expect(
        holder.withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("EARLY");

      // rescue still works
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });

    it("both withdrawNFT and rescueNFT work in same session after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await holder.withdrawNFT(await nft.getAddress(), ID_A);
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_B);

      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
      expect(await nft.ownerOf(ID_B)).to.equal(owner.address);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("NFT + ETH + ERC20 — mixed rescue scenario", function () {
    it("all asset types rescued in one session with same rescuePassword", async function () {
      const TEN_ETH = ethers.parseEther("10");
      const HUNDRED = ethers.parseEther("100");

      // Fund ETH and deploy a DAI mock
      await owner.sendTransaction({ to: await holder.getAddress(), value: TEN_ETH });

      const DAIFactory = await ethers.getContractFactory("DAI");
      const dai = await DAIFactory.deploy(HUNDRED);
      await dai.waitForDeployment();
      await dai.transfer(await holder.getAddress(), HUNDRED);

      // Rescue everything before holdTime
      await holder.rescueETH(RESCUE_PASS);
      await holder.rescueERC20(RESCUE_PASS, await dai.getAddress());
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_B);
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_C);

      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      expect(await dai.balanceOf(await holder.getAddress())).to.equal(0n);
      expect(await nft.balanceOf(await holder.getAddress())).to.equal(0n);
      expect(await nft.balanceOf(owner.address)).to.equal(3n);
    });

    it("ownership transfer then new owner rescues NFTs", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);

      await holder.connect(userTwo).rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      await holder.connect(userTwo).rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_B);

      expect(await nft.ownerOf(ID_A)).to.equal(userTwo.address);
      expect(await nft.ownerOf(ID_B)).to.equal(userTwo.address);
      expect(await nft.balanceOf(owner.address)).to.equal(0n);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("ATTACK — NFT-specific attack vectors", function () {
    it("ATTACK: non-owner cannot withdrawNFT even knowing tokenId", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      for (const signer of [userTwo, userThree, attacker]) {
        await expect(
          holder.connect(signer).withdrawNFT(await nft.getAddress(), ID_A)
        ).to.be.revertedWith("Ownable: caller is not the owner");
      }
    });

    it("ATTACK: non-owner cannot rescueNFT even with correct password", async function () {
      for (const signer of [userTwo, userThree, attacker]) {
        await expect(
          holder.connect(signer).rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A)
        ).to.be.revertedWith("Ownable: caller is not the owner");
      }
    });

    it("ATTACK: withdrawNFT with tokenId Holder does not own reverts", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      const unownedId = 999n;
      await nft.mint(attacker.address, unownedId);

      await expect(
        holder.withdrawNFT(await nft.getAddress(), unownedId)
      ).to.be.revertedWithCustomError(nft, "ERC721InsufficientApproval");
    });

    it("ATTACK: rescueNFT with tokenId Holder does not own reverts", async function () {
      const unownedId = 888n;
      await nft.mint(attacker.address, unownedId);

      await expect(
        holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), unownedId)
      ).to.be.revertedWithCustomError(nft, "ERC721InsufficientApproval");
    });

    it("ATTACK: double-rescue same tokenId — second call reverts (NFT already gone)", async function () {
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);

      await expect(
        holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A)
      ).to.be.revertedWithCustomError(nft, "ERC721InsufficientApproval");
    });

    it("ATTACK: double-withdraw same tokenId — second call reverts", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);

      await holder.withdrawNFT(await nft.getAddress(), ID_A);
      await expect(
        holder.withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWithCustomError(nft, "ERC721InsufficientApproval");
    });

    it("ATTACK: stolen keys + no rescuePassword → NFTs locked until holdTime", async function () {
      // Attacker has keys but not rescuePass — rescueNFT blocked
      await expect(
        holder.rescueNFT("stolen-key-guess", await nft.getAddress(), ID_A)
      ).to.be.revertedWith("WRONG PASS");

      // withdrawNFT also blocked — holdTime not reached
      await expect(
        holder.withdrawNFT(await nft.getAddress(), ID_A)
      ).to.be.revertedWith("EARLY");

      // Victim uses correct rescuePass to drain NFTs
      await holder.rescueNFT(RESCUE_PASS, await nft.getAddress(), ID_A);
      expect(await nft.ownerOf(ID_A)).to.equal(owner.address);
    });

    it("ATTACK: MEV — transferPassword cannot be used for rescueNFT", async function () {
      // Front-runner sees TRANSFER_PASS in mempool, tries to drain NFT
      await expect(
        holder.rescueNFT(TRANSFER_PASS, await nft.getAddress(), ID_A)
      ).to.be.revertedWith("WRONG PASS");
    });
  });
});