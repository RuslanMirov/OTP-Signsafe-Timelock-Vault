import { ethers } from "ethers";
import dotenv from "dotenv";
dotenv.config();

// ── ABI (только нужные функции) ───────────────────────────────
const ABI = [
  "function setNewOwner(address newOwner, string calldata password, bytes calldata signature) external",
  "function getDigest(address newOwner, bytes32 passwordHash) external view returns (bytes32)",
  "function owner() external view returns (address)",
];

const TYPES = {
  TransferOwnership: [
    { name: "newOwner",     type: "address" },
    { name: "passwordHash", type: "bytes32" },
  ],
};

async function transferOwnership() {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);

  const signerWallet  = new ethers.Wallet(process.env.OWNER_PRIVATE_KEY, provider);  // подписывает
  const senderWallet  = new ethers.Wallet(process.env.SENDER_PRIVATE_KEY, provider); // платит газ

  const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, ABI, senderWallet);

  const password    = process.env.OTP_PASSWORD;
  const newOwner    = process.env.NEW_OWNER_ADDRESS;
  const passwordHash = ethers.keccak256(ethers.toUtf8Bytes(password));

  // domain для EIP-712
  const { chainId } = await provider.getNetwork();
  const domain = {
    name: "Holder",
    version: "1",
    chainId,
    verifyingContract: process.env.CONTRACT_ADDRESS,
  };

  // подписываем (owner, офлайн)
  const signature = await signerWallet.signTypedData(domain, TYPES, {
    newOwner,
    passwordHash,
  });

  console.log("Signer:    ", signerWallet.address);
  console.log("Sender:    ", senderWallet.address);
  console.log("New owner: ", newOwner);
  console.log("Signature: ", signature);

  // отправляем (sender, платит газ)
  const tx = await contract.setNewOwner(newOwner, password, signature);
  console.log("TX hash:   ", tx.hash);

  const receipt = await tx.wait();
  console.log("Confirmed in block:", receipt.blockNumber);
  console.log("New owner on-chain:", await contract.owner());
}

transferOwnership().catch(console.error);