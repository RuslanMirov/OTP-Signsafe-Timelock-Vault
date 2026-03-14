// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

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
    using SafeERC20 for IERC20;

    // ── OTP ────────────────────────────────────────────────
    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "TransferOwnership(address newOwner,bytes32 passwordHash)"
    );

    // Two separate passwords — MEV protection:
    // transferPasswordHash → used ONLY in setNewOwner
    // rescuePasswordHash   → used ONLY in rescueETH/rescueERC20
    // Front-runner sees transferPassword in mempool → cannot call rescue
    bytes32 private transferPasswordHash;
    bytes32 private rescuePasswordHash;
    
    // if hacker see in mempool pwd in setNewOwner he cant call setTransferPassword
    // because its require 24 h time lock for new password
    // and also he cant replace new owner with his address because its also require 
    // 7 days wait, so if owner see atemption he can migrate to new wallet
    mapping(bytes32 => uint256) public passwordRequests; 
    uint256 public constant CHANGE_DELAY = 7 days;
    mapping(address => uint256) private whiteListTime;
    mapping(address => bool) public whiteList;

    bool public isTPassUsed;
    // ───────────────────────────────────────────────────────

    uint256 public holdTime;

    constructor(
        address _initialOwner, 
        bytes32 _transferPasswordHash, 
        bytes32 _rescuePasswordHash,
        address _whiteListedOwner
    )
        EIP712("Holder", "1")
    {
        holdTime = block.timestamp + 365 days;
        transferPasswordHash = _transferPasswordHash;
        rescuePasswordHash   = _rescuePasswordHash;
        _transferOwnership(_initialOwner);
        whiteList[_whiteListedOwner] = true;
    }

    function setNewOwner(
        address newOwner,
        string calldata password,
        bytes calldata signature
    ) external {
        require(!isTPassUsed, "OTP: already used");
        require(newOwner != address(0), "OTP: zero address");
        require(whiteList[newOwner], "Not in White List");

        bytes32 passwordHash = keccak256(abi.encodePacked(password));
        require(passwordHash == transferPasswordHash, "OTP: wrong password");

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(TRANSFER_TYPEHASH, newOwner, passwordHash))
        );
        address signer = ECDSA.recover(digest, signature);
        require(signer == owner(), "OTP: invalid signature");

        isTPassUsed = true;
        _transferOwnership(newOwner);
    }

    function applyNewPassword(bytes32 newPassHash) external onlyOwner {
        passwordRequests[newPassHash] = block.timestamp;
    }

    function setTransferPassword(string calldata oldPass, bytes32 newPassHash) external onlyOwner {
        require(keccak256(abi.encodePacked(oldPass)) == transferPasswordHash, "WRONG PASS");
    
        require(passwordRequests[newPassHash] != 0, "No request found");
        require(block.timestamp >= passwordRequests[newPassHash] + CHANGE_DELAY, "Too early");

        transferPasswordHash = newPassHash;
        isTPassUsed = false;
    
        delete passwordRequests[newPassHash];
    }

    function setRescuePassword(string calldata oldPass, bytes32 newPass) external onlyOwner {
        require(keccak256(abi.encodePacked(oldPass)) == rescuePasswordHash, "WRONG PASS");
        
        require(passwordRequests[newPass] != 0, "No request found");
        require(block.timestamp >= passwordRequests[newPass] + CHANGE_DELAY, "Too early");

        rescuePasswordHash = newPass;
        delete passwordRequests[newPass];
    }

    function applyNewWLOwner(address _newWLAddress) external onlyOwner {
        whiteListTime[_newWLAddress] = block.timestamp;
    }

    function setNewWLOwner(address _newWLAddress) external onlyOwner {
        require(whiteListTime[_newWLAddress] != 0, "No request found");
        require(block.timestamp >= whiteListTime[_newWLAddress] + CHANGE_DELAY, "Too early");
        whiteList[_newWLAddress] = true;
        delete whiteListTime[_newWLAddress];
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
        (bool ok,) = payable(owner()).call{value: address(this).balance}("");
        require(ok, "ETH transfer failed");
    }

    function withdrawERC20(address _token) external onlyOwner {
        require(block.timestamp > holdTime, "EARLY");
        uint256 amount = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(owner(), amount);
    }

    function rescueETH(string calldata _password) external onlyOwner {
        require(keccak256(abi.encodePacked(_password)) == rescuePasswordHash, "WRONG PASS");
        (bool ok,) = payable(owner()).call{value: address(this).balance}("");
        require(ok, "ETH transfer failed");
    }

    function rescueERC20(string calldata _password, address _token) external onlyOwner {
        require(keccak256(abi.encodePacked(_password)) == rescuePasswordHash, "WRONG PASS");
        uint256 amount = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(owner(), amount);
    }

    function reLock() external onlyOwner {
        holdTime = block.timestamp + 90 days;
    }

    receive() external payable {}
}