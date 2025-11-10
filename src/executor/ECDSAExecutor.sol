// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account, ExecMode} from "../interfaces/IERC7579Account.sol";
import {MODULE_TYPE_EXECUTOR} from "../types/Constants.sol";

struct ECDSAExecutorStorage {
    address owner;
    mapping(uint192 => uint64) nonceSequenceNumber;
}

contract ECDSAExecutor is IExecutor, EIP712 {
    error InvalidNonce(address account, uint256 expected, uint256 actual);
    error SignatureExpired(address account, uint256 expiration);
    error InvalidSignature();
    error InvalidOwner();

    bytes32 constant EXECUTE_TYPEHASH = keccak256(
        "Execute(address account,uint256 mode,bytes executionCalldata,uint256 nonce,uint256 expiration)"
    );
    
    event OwnerRegistered(address indexed kernel, address indexed owner);
    event OwnerUnregistered(address indexed kernel, address indexed owner);
    event ExecutionRequested(address indexed kernel, bytes32 indexed executionHash);

    mapping(address => ECDSAExecutorStorage) internal ecdsaExecutorStorage;

    function onInstall(bytes calldata _data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        address owner = abi.decode(_data, (address));
        if (owner == address(0)) revert InvalidOwner();
        ecdsaExecutorStorage[msg.sender].owner = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address owner = ecdsaExecutorStorage[msg.sender].owner;
        delete ecdsaExecutorStorage[msg.sender];
        emit OwnerUnregistered(msg.sender, owner);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ecdsaExecutorStorage[smartAccount].owner != address(0);
    }

    function getOwner(address account) external view returns (address) {
        return ecdsaExecutorStorage[account].owner;
    }

    function getNonce(address account, uint192 key) external view returns (uint64) {
        return ecdsaExecutorStorage[account].nonceSequenceNumber[key];
    }

    function _packNonce(uint192 key, uint256 sequence) internal pure returns (uint256) {
        return (uint256(key) << 64) | sequence;
    }

    function _unpackNonce(uint256 nonce) internal pure returns (uint192 key, uint64 sequence) {
        key = uint192(nonce >> 64);
        sequence = uint64(nonce);
    }

    function incrementNonce(uint192 key) external {
        // Only the account itself can increment its nonce
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        ecdsaExecutorStorage[msg.sender].nonceSequenceNumber[key]++;
    }

    function execute(
        address account,
        ExecMode mode,
        bytes calldata executionCalldata,
        uint256 nonce,
        uint256 expiration,
        bytes calldata signature
    ) external payable returns (bytes[] memory returnData) {
        if (!_isInitialized(account)) revert NotInitialized(account);

        // Validate expiration
        if (block.timestamp > expiration) {
            revert SignatureExpired(account, expiration);
        }

        // Validate and update nonce
        _validateAndUpdateNonce(account, nonce);

        // Build EIP-712 struct hash
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                account,
                ExecMode.unwrap(mode),
                keccak256(executionCalldata),
                nonce,
                expiration
            )
        );

        bytes32 digest = _hashTypedData(structHash);

        emit ExecutionRequested(account, digest);

        // Verify signature using EIP-712 digest
        address owner = ecdsaExecutorStorage[account].owner;
        if (owner != ECDSA.recover(digest, signature)) {
            revert InvalidSignature();
        }

        return IERC7579Account(account).executeFromExecutor{value: msg.value}(mode, executionCalldata);
    }
    
    function _validateAndUpdateNonce(address account, uint256 nonce) internal {
        (uint192 key, uint256 sequence) = _unpackNonce(nonce);
        uint64 expectedSequence = ecdsaExecutorStorage[account].nonceSequenceNumber[key];
        if (sequence != expectedSequence) {
            revert InvalidNonce(account, _packNonce(key, expectedSequence), nonce);
        }
        ecdsaExecutorStorage[account].nonceSequenceNumber[key] = sequence + 1;
    }

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "ECDSAExecutor";
        version = "1";
    }
}
