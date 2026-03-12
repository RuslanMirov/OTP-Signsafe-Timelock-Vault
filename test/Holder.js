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

describe("Holder", function () {
  // Two separate passwords — core MEV protection
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
  const YEAR    = DAY * 365n;

  async function deployAll() {
    [owner, userTwo, userThree, attacker] = await ethers.getSigners();

    const TokenFactory  = await ethers.getContractFactory("TestToken");
    token  = await TokenFactory.deploy(HUNDRED);
    await token.waitForDeployment();

    const HolderFactory = await ethers.getContractFactory("Holder");
    holder = await HolderFactory.connect(owner).deploy(
      passHash(TRANSFER_PASS),
      passHash(RESCUE_PASS)
    );
    await holder.waitForDeployment();

    domain = await buildDomain(holder);

    await owner.sendTransaction({ to: await holder.getAddress(), value: TEN_ETH });
    await token.transfer(await holder.getAddress(), HUNDRED);
  }

  beforeEach(deployAll);

  // ──────────────────────────────────────────────────────────────────
  describe("INIT", function () {
    it("correct owner", async function () {
      expect(await holder.owner()).to.equal(owner.address);
    });
    it("holds 10 ETH", async function () {
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(TEN_ETH);
    });
    it("holds 100 test tokens", async function () {
      expect(await token.balanceOf(await holder.getAddress())).to.equal(HUNDRED);
    });
    it("OTP not used on deploy", async function () {
      expect(await holder.isPassUsed()).to.equal(false);
    });
    it("isOwnerInitialized is false", async function () {
      expect(await holder.isOwnerInitialized()).to.equal(false);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("MEV Protection — two password separation", function () {

    it("transferPassword exposed in mempool cannot be used for rescueETH", async function () {
      // Front-runner sees TRANSFER_PASS in mempool — tries rescueETH → WRONG PASS
      await expect(holder.rescueETH(TRANSFER_PASS)).to.be.revertedWith("WRONG PASS");
    });

    it("rescuePassword exposed in mempool cannot be used for setNewOwner", async function () {
      // Front-runner sees RESCUE_PASS in mempool — tries setNewOwner → OTP: wrong password
      const { signature } = await signTransfer(attacker, domain, attacker.address, RESCUE_PASS);
      await expect(
        holder.connect(attacker).setNewOwner(attacker.address, RESCUE_PASS, signature)
      ).to.be.revertedWith("OTP: wrong password");
    });

    it("attacker cannot drain even knowing transferPassword — no valid sig", async function () {
      const { signature } = await signTransfer(attacker, domain, attacker.address, TRANSFER_PASS);
      await expect(
        holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, signature)
      ).to.be.revertedWith("OTP: invalid signature");
    });

    it("full MEV scenario: all attack vectors fail, original tx succeeds", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);

      // Attack A: rescueETH with transferPassword
      await expect(holder.rescueETH(TRANSFER_PASS)).to.be.revertedWith("WRONG PASS");

      // Attack B: rescueERC20 with transferPassword
      await expect(
        holder.rescueERC20(TRANSFER_PASS, await token.getAddress())
      ).to.be.revertedWith("WRONG PASS");

      // Attack C: setNewOwner to attacker wallet with their own sig
      const { signature: attackSig } = await signTransfer(attacker, domain, attacker.address, TRANSFER_PASS);
      await expect(
        holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, attackSig)
      ).to.be.revertedWith("OTP: invalid signature");

      // Original tx still valid — ownership transfers, funds intact
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(TEN_ETH);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("Withdraw ETH", function () {
    it("owner cannot withdraw before holdTime", async function () {
      await expect(holder.withdrawETH()).to.be.revertedWith("EARLY");
    });
    it("non-owner cannot withdraw after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await expect(holder.connect(userTwo).withdrawETH())
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("owner can withdraw after holdTime", async function () {
      const before = await ethers.provider.getBalance(owner.address);
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.withdrawETH();
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      expect(await ethers.provider.getBalance(owner.address)).to.be.gt(before - TEN_ETH);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("Withdraw ERC20", function () {
    it("owner cannot withdraw before holdTime", async function () {
      await expect(holder.withdrawERC20(await token.getAddress()))
        .to.be.revertedWith("EARLY");
    });
    it("non-owner cannot withdraw after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await expect(holder.connect(userTwo).withdrawERC20(await token.getAddress()))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("owner can withdraw after holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.withdrawERC20(await token.getAddress());
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);
      expect(await token.balanceOf(owner.address)).to.equal(HUNDRED);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("rescueETH — uses rescuePassword", function () {
    it("owner can rescue ETH before holdTime with correct rescue password", async function () {
      const before = await ethers.provider.getBalance(owner.address);
      await holder.rescueETH(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
      expect(await ethers.provider.getBalance(owner.address)).to.be.gt(before - TEN_ETH);
    });
    it("owner cannot rescue ETH with transferPassword", async function () {
      await expect(holder.rescueETH(TRANSFER_PASS)).to.be.revertedWith("WRONG PASS");
    });
    it("owner cannot rescue ETH with wrong password", async function () {
      await expect(holder.rescueETH("wrongpass")).to.be.revertedWith("WRONG PASS");
    });
    it("owner cannot rescue ETH with empty password", async function () {
      await expect(holder.rescueETH("")).to.be.revertedWith("WRONG PASS");
    });
    it("non-owner cannot rescue ETH even with correct rescue password", async function () {
      await expect(holder.connect(attacker).rescueETH(RESCUE_PASS))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("rescue works after rescue password rotation", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      await holder.rescueETH(NEW_RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });
    it("old rescue password fails after rotation", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      await expect(holder.rescueETH(RESCUE_PASS)).to.be.revertedWith("WRONG PASS");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("rescueERC20 — uses rescuePassword", function () {
    it("owner can rescue ERC20 before holdTime with correct rescue password", async function () {
      await holder.rescueERC20(RESCUE_PASS, await token.getAddress());
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);
      expect(await token.balanceOf(owner.address)).to.equal(HUNDRED);
    });
    it("owner cannot rescue ERC20 with transferPassword", async function () {
      await expect(
        holder.rescueERC20(TRANSFER_PASS, await token.getAddress())
      ).to.be.revertedWith("WRONG PASS");
    });
    it("owner cannot rescue ERC20 with wrong password", async function () {
      await expect(holder.rescueERC20("wrongpass", await token.getAddress()))
        .to.be.revertedWith("WRONG PASS");
    });
    it("owner cannot rescue ERC20 with empty password", async function () {
      await expect(holder.rescueERC20("", await token.getAddress()))
        .to.be.revertedWith("WRONG PASS");
    });
    it("non-owner cannot rescue ERC20 even with correct rescue password", async function () {
      await expect(holder.connect(attacker).rescueERC20(RESCUE_PASS, await token.getAddress()))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("rescue ERC20 works after rescue password rotation", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      await holder.rescueERC20(NEW_RESCUE_PASS, await token.getAddress());
      expect(await token.balanceOf(await holder.getAddress())).to.equal(0n);
    });
    it("old rescue password fails for ERC20 after rotation", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      await expect(
        holder.rescueERC20(RESCUE_PASS, await token.getAddress())
      ).to.be.revertedWith("WRONG PASS");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("setNewOwner — happy path", function () {
    it("transfers ownership with valid sig + transfer password", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
    });
    it("relayer (not owner, not newOwner) can submit", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.connect(userThree).setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
    });
    it("newOwner can submit their own transfer", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.connect(userTwo).setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
    });
    it("emits OwnershipTransferred", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature))
        .to.emit(holder, "OwnershipTransferred")
        .withArgs(owner.address, userTwo.address);
    });
    it("marks OTP as used after transfer", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.isPassUsed()).to.equal(true);
    });
  });

  describe("setNewOwner — wrong password", function () {
    it("reverts with wrong password", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(holder.setNewOwner(userTwo.address, "wrong", signature))
        .to.be.revertedWith("OTP: wrong password");
    });
    it("reverts with empty password", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(holder.setNewOwner(userTwo.address, "", signature))
        .to.be.revertedWith("OTP: wrong password");
    });
    it("reverts with rescue password instead of transfer password", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, RESCUE_PASS);
      await expect(holder.setNewOwner(userTwo.address, RESCUE_PASS, signature))
        .to.be.revertedWith("OTP: wrong password");
    });
  });

  describe("setNewOwner — invalid signature", function () {
    it("reverts when attacker signs", async function () {
      const { signature } = await signTransfer(attacker, domain, userTwo.address, TRANSFER_PASS);
      await expect(holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: invalid signature");
    });
    it("reverts when attacker signs for themselves with correct password", async function () {
      const { signature } = await signTransfer(attacker, domain, attacker.address, TRANSFER_PASS);
      await expect(holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: invalid signature");
    });
    it("reverts when attacker signs for themselves submitted via relayer", async function () {
      const { signature } = await signTransfer(attacker, domain, attacker.address, TRANSFER_PASS);
      await expect(holder.connect(userThree).setNewOwner(attacker.address, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: invalid signature");
    });
    it("reverts when newOwner is swapped", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(holder.connect(attacker).setNewOwner(attacker.address, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: invalid signature");
    });
    it("reverts with zero address", async function () {
      const { signature } = await signTransfer(owner, domain, ethers.ZeroAddress, TRANSFER_PASS);
      await expect(holder.setNewOwner(ethers.ZeroAddress, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: zero address");
    });
  });

  describe("setNewOwner — replay protection", function () {
    it("reverts on replay after success", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      await expect(holder.connect(userTwo).setNewOwner(userTwo.address, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: already used");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("setTransferPassword", function () {
    it("non-owner cannot change transfer password", async function () {
      await expect(
        holder.connect(userTwo).setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("owner cannot change with wrong old password", async function () {
      await expect(
        holder.setTransferPassword("wrongpass", passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });
    it("owner cannot change with empty old password", async function () {
      await expect(
        holder.setTransferPassword("", passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });
    it("owner can rotate transfer password with correct old password", async function () {
      await expect(
        holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS))
      ).to.not.be.reverted;
    });
    it("OTP resets after transfer password rotation", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.isPassUsed()).to.equal(true);
      await holder.connect(userTwo).setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));
      expect(await holder.isPassUsed()).to.equal(false);
    });
    it("old transfer password fails after rotation", async function () {
      await holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await expect(holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature))
        .to.be.revertedWith("OTP: wrong password");
    });
    it("new transfer password works after rotation", async function () {
      await holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));
      const { signature } = await signTransfer(owner, domain, userTwo.address, NEW_TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, NEW_TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
    });
    it("rotating transferPassword does not affect rescuePassword", async function () {
      await holder.setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));
      await holder.rescueETH(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });
    it("chain of transfers works", async function () {
      // transfer 1
      const { signature: sig1 } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, sig1);
      expect(await holder.owner()).to.equal(userTwo.address);

      // rotate transfer password
      await holder.connect(userTwo).setTransferPassword(TRANSFER_PASS, passHash(NEW_TRANSFER_PASS));

      // transfer 2
      const { signature: sig2 } = await signTransfer(userTwo, domain, userThree.address, NEW_TRANSFER_PASS);
      await holder.connect(userTwo).setNewOwner(userThree.address, NEW_TRANSFER_PASS, sig2);
      expect(await holder.owner()).to.equal(userThree.address);
    });
    it("cannot rotate without knowing old password even if owner", async function () {
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      await expect(
        holder.connect(userTwo).setTransferPassword("badguess", passHash(NEW_TRANSFER_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("setRescuePassword", function () {
    it("non-owner cannot change rescue password", async function () {
      await expect(
        holder.connect(userTwo).setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS))
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("owner cannot change with wrong old password", async function () {
      await expect(
        holder.setRescuePassword("wrongpass", passHash(NEW_RESCUE_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });
    it("owner cannot change with empty old password", async function () {
      await expect(
        holder.setRescuePassword("", passHash(NEW_RESCUE_PASS))
      ).to.be.revertedWith("WRONG PASS");
    });
    it("owner can rotate rescue password with correct old password", async function () {
      await expect(
        holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS))
      ).to.not.be.reverted;
    });
    it("old rescue password fails after rotation", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      await expect(holder.rescueETH(RESCUE_PASS)).to.be.revertedWith("WRONG PASS");
    });
    it("new rescue password works after rotation", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      await holder.rescueETH(NEW_RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });
    it("rotating rescuePassword does not affect transferPassword", async function () {
      await holder.setRescuePassword(RESCUE_PASS, passHash(NEW_RESCUE_PASS));
      const { signature } = await signTransfer(owner, domain, userTwo.address, TRANSFER_PASS);
      await holder.setNewOwner(userTwo.address, TRANSFER_PASS, signature);
      expect(await holder.owner()).to.equal(userTwo.address);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("reLock", function () {
    it("non-owner cannot reLock", async function () {
      await expect(holder.connect(userTwo).reLock())
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
    it("owner can reLock and extend holdTime by 90 days", async function () {
      await holder.reLock();
      const block = await ethers.provider.getBlock("latest");
      const after = await holder.holdTime();
      expect(after).to.be.gte(BigInt(block.timestamp) + DAY * 89n);
    });
    it("after reLock withdrawal is blocked even past original holdTime", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.reLock();
      await expect(holder.withdrawETH()).to.be.revertedWith("EARLY");
    });
    it("rescue still works during reLock period", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      await holder.reLock();
      await holder.rescueETH(RESCUE_PASS);
      expect(await ethers.provider.getBalance(await holder.getAddress())).to.equal(0n);
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("initializeOwner", function () {
    it("owner can initialize once", async function () {
      await holder.initializeOwner(userTwo.address);
      expect(await holder.owner()).to.equal(userTwo.address);
      expect(await holder.isOwnerInitialized()).to.equal(true);
    });
    it("cannot initialize twice", async function () {
      await holder.initializeOwner(userTwo.address);
      await expect(holder.connect(userTwo).initializeOwner(userThree.address))
        .to.be.revertedWith("INITIALIZED");
    });
    it("non-owner cannot initialize", async function () {
      await expect(holder.connect(userTwo).initializeOwner(userTwo.address))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  describe("viewData", function () {
    it("returns correct time info before unlock", async function () {
      const { _isOpen } = await holder.viewData();
      expect(_isOpen).to.equal(false);
    });
    it("returns isOpen=true after holdTime passed", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(YEAR + DAY)]);
      await ethers.provider.send("evm_mine", []);
      const { _isOpen } = await holder.viewData();
      expect(_isOpen).to.equal(true);
    });
  });
});