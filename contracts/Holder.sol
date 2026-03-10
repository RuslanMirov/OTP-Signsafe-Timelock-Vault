// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract OwnableLimited {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_owner == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract Holder is OwnableLimited, EIP712 {

    // ── OTP ────────────────────────────────────────────────
    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "TransferOwnership(address newOwner,bytes32 passwordHash)"
    );
    bytes32 private storedPasswordHash;
    bool public isPassUsed;
    // ───────────────────────────────────────────────────────

    uint256 public holdTime;
    bool public isOwnerInitialized;

    constructor(bytes32 _passwordHash)
        EIP712("Holder", "1")
    {
        holdTime = block.timestamp + 365 days;
        storedPasswordHash = _passwordHash;  // передаём уже хэш, не plaintext
    }

    function setNewOwner(
        address newOwner,
        string calldata password,
        bytes calldata signature
    ) external {
        require(!isPassUsed, "OTP: already used");
        require(newOwner != address(0), "OTP: zero address");

        bytes32 passwordHash = keccak256(abi.encodePacked(password));
        require(passwordHash == storedPasswordHash, "OTP: wrong password");

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(TRANSFER_TYPEHASH, newOwner, passwordHash))
        );
        address signer = ECDSA.recover(digest, signature);
        require(signer == owner(), "OTP: invalid signature");

        isPassUsed = true;
        _transferOwnership(newOwner);
    }
    // ───────────────────────────────────────────────────────

    function setNewPassword(bytes32 newPasswordHash) external onlyOwner {
        storedPasswordHash = newPasswordHash;
        isPassUsed = false;
    }

    function getDigest(address newOwner, bytes32 passwordHash) external view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(TRANSFER_TYPEHASH, newOwner, passwordHash))
        );
    }

    function viewData() external view returns (uint256 _now, uint256 _holdTime, bool _isOpen) {
        _now = block.timestamp;
        _holdTime = holdTime;
        _isOpen = _now > _holdTime;
    }

    function withdrawETH() external onlyOwner {
        require(block.timestamp > holdTime, "EARLY");
        payable(owner()).transfer(address(this).balance);
    }

    function withdrawERC20(address _token) external onlyOwner {
        require(block.timestamp > holdTime, "EARLY");
        uint256 amount = IERC20(_token).balanceOf(address(this));
        IERC20(_token).transfer(owner(), amount);
    }

    function reLock() external onlyOwner {
        holdTime = block.timestamp + 90 days;
    }

    function initializeOwner(address newOwner) external onlyOwner {
        require(!isOwnerInitialized, "INITIALIZED");
        _transferOwnership(newOwner);
        isOwnerInitialized = true;
    }

    receive() external payable {}
}