// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

// ── IERC20 ─────────────────────────────────────────────────────────────────────
interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// ── IERC5267 ───────────────────────────────────────────────────────────────────
interface IERC5267 {
    event EIP712DomainChanged();

    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}

// ── StorageSlot ────────────────────────────────────────────────────────────────
library StorageSlot {
    struct StringSlot {
        string value;
    }

    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }
}

// ── ShortStrings ───────────────────────────────────────────────────────────────
type ShortString is bytes32;

library ShortStrings {
    bytes32 private constant FALLBACK_SENTINEL =
        0x00000000000000000000000000000000000000000000000000000000000000FF;

    error StringTooLong(string str);
    error InvalidShortString();

    function toShortString(string memory str) internal pure returns (ShortString) {
        bytes memory bstr = bytes(str);
        if (bstr.length > 0x1f) revert StringTooLong(str);
        return ShortString.wrap(bytes32(uint256(bytes32(bstr)) | bstr.length));
    }

    function toString(ShortString sstr) internal pure returns (string memory) {
        uint256 len = byteLength(sstr);
        string memory str = new string(0x20);
        assembly ("memory-safe") {
            mstore(str, len)
            mstore(add(str, 0x20), sstr)
        }
        return str;
    }

    function byteLength(ShortString sstr) internal pure returns (uint256) {
        uint256 result = uint256(ShortString.unwrap(sstr)) & 0xFF;
        if (result > 0x1f) revert InvalidShortString();
        return result;
    }

    function toShortStringWithFallback(string memory value, string storage store)
        internal
        returns (ShortString)
    {
        if (bytes(value).length < 0x20) {
            return toShortString(value);
        } else {
            StorageSlot.getStringSlot(store).value = value;
            return ShortString.wrap(FALLBACK_SENTINEL);
        }
    }

    function toStringWithFallback(ShortString value, string storage store)
        internal
        pure
        returns (string memory)
    {
        if (ShortString.unwrap(value) != FALLBACK_SENTINEL) {
            return toString(value);
        } else {
            return store;
        }
    }
}

// ── MessageHashUtils (toTypedDataHash only) ────────────────────────────────────
library MessageHashUtils {
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, hex"19_01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
}

// ── EIP712 ─────────────────────────────────────────────────────────────────────
abstract contract EIP712 is IERC5267 {
    using ShortStrings for *;

    bytes32 private constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    address private immutable _cachedThis;

    bytes32 private immutable _hashedName;
    bytes32 private immutable _hashedVersion;

    ShortString private immutable _name;
    ShortString private immutable _version;
    string private _nameFallback;
    string private _versionFallback;

    constructor(string memory name, string memory version) {
        _name = name.toShortStringWithFallback(_nameFallback);
        _version = version.toShortStringWithFallback(_versionFallback);
        _hashedName = keccak256(bytes(name));
        _hashedVersion = keccak256(bytes(version));

        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();
        _cachedThis = address(this);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _cachedThis && block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        } else {
            return _buildDomainSeparator();
        }
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
    }

    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    function eip712Domain()
        public
        view
        virtual
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (
            hex"0f",
            _EIP712Name(),
            _EIP712Version(),
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }

    function _EIP712Name() internal view returns (string memory) {
        return _name.toStringWithFallback(_nameFallback);
    }

    function _EIP712Version() internal view returns (string memory) {
        return _version.toStringWithFallback(_versionFallback);
    }
}

// ── ECDSA (recover from bytes memory signature only) ──────────────────────────
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }

    error ECDSAInvalidSignature();
    error ECDSAInvalidSignatureLength(uint256 length);
    error ECDSAInvalidSignatureS(bytes32 s);

    function tryRecover(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address recovered, RecoverError err, bytes32 errArg)
    {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return _tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    function _tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        private
        pure
        returns (address recovered, RecoverError err, bytes32 errArg)
    {
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }
        return (signer, RecoverError.NoError, bytes32(0));
    }

    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) return;
        else if (error == RecoverError.InvalidSignature) revert ECDSAInvalidSignature();
        else if (error == RecoverError.InvalidSignatureLength) revert ECDSAInvalidSignatureLength(uint256(errorArg));
        else if (error == RecoverError.InvalidSignatureS) revert ECDSAInvalidSignatureS(errorArg);
    }
}

// ── SafeERC20Transfer ──────────────────────────────────────────────────────────
library SafeERC20Transfer {
    error SafeERC20FailedOperation(address token);

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(0x00, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(0x04, and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(0x24, value)
            let success := call(gas(), token, 0, 0x00, 0x44, 0x00, 0x20)
            if iszero(and(
                or(iszero(returndatasize()), and(gt(returndatasize(), 0x1f), eq(mload(0x00), 1))),
                success
            )) {
                mstore(fmp, 0x5274afe700000000000000000000000000000000000000000000000000000000)
                mstore(add(fmp, 0x04), token)
                revert(fmp, 0x24)
            }
            mstore(0x40, fmp)
        }
    }
}

// NFT 
interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

// ── OwnableLimited ─────────────────────────────────────────────────────────────
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

// ── Holder ─────────────────────────────────────────────────────────────────────
contract HolderOptimized is OwnableLimited, EIP712 {
    using SafeERC20Transfer for IERC20;

    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "TransferOwnership(address newOwner,bytes32 passwordHash)"
    );

    bytes32 private transferPasswordHash;
    bytes32 private rescuePasswordHash;

    mapping(bytes32 => uint256) public passwordRequests;
    uint256 public constant CHANGE_DELAY = 7 days;
    mapping(address => uint256) private whiteListTime;
    mapping(address => bool) public whiteList;

    bool public isTPassUsed;

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

    function withdrawNFT(address _collection, uint256 _tokenId) external onlyOwner {
        require(block.timestamp > holdTime, "EARLY");
        IERC721(_collection).transferFrom(address(this), owner(), _tokenId);
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

    function rescueNFT(string calldata _password, address _collection, uint256 _tokenId) external onlyOwner {
        require(keccak256(abi.encodePacked(_password)) == rescuePasswordHash, "WRONG PASS");
        IERC721(_collection).transferFrom(address(this), owner(), _tokenId);
    }

    function reLock() external onlyOwner {
        holdTime = block.timestamp + 90 days;
    }

    receive() external payable {}
}