// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account, ExecMode} from "../interfaces/IERC7579Account.sol";
import {MODULE_TYPE_EXECUTOR} from "../types/Constants.sol";

struct ECDSAExecutorStorage {
    address owner;
    mapping(uint192 => uint256) nonceSequenceNumber;
}

contract ECDSAExecutor is IExecutor {
    error InvalidNonce(address account, uint256 expected, uint256 actual);
    error SignatureExpired(address account, uint256 expiration);
    error InvalidSignature();
    error InvalidOwner();
    
    event OwnerRegistered(address indexed kernel, address indexed owner);
    event OwnerUnregistered(address indexed kernel, address indexed owner);
    event ExecutionRequested(address indexed kernel, bytes32 indexed executionHash);

    mapping(address => ECDSAExecutorStorage) internal ecdsaExecutorStorage;

    function onInstall(bytes calldata _data) external payable override {
        address owner = address(bytes20(_data[0:20]));
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

    function getNonce(address account, uint192 key) external view returns (uint256) {
        return ecdsaExecutorStorage[account].nonceSequenceNumber[key];
    }

    function _packNonce(uint192 key, uint256 sequence) internal pure returns (uint256) {
        return (uint256(key) << 64) | sequence;
    }

    function _unpackNonce(uint256 nonce) internal pure returns (uint192 key, uint256 sequence) {
        key = uint192(nonce >> 64);
        sequence = uint256(uint64(nonce));
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
        
        // Verify signature and execute
        bytes32 executionHash = keccak256(
            abi.encode(account, mode, executionCalldata, nonce, expiration, block.chainid)
        );
        
        emit ExecutionRequested(account, executionHash);
        
        address owner = ecdsaExecutorStorage[account].owner;
        if (owner == ECDSA.recover(executionHash, signature)) {
            return IERC7579Account(account).executeFromExecutor(mode, executionCalldata);
        }
        
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(executionHash);
        if (owner != ECDSA.recover(ethHash, signature)) {
            revert InvalidSignature();
        }
        
        return IERC7579Account(account).executeFromExecutor(mode, executionCalldata);
    }
    
    function _validateAndUpdateNonce(address account, uint256 nonce) internal {
        (uint192 key, uint256 sequence) = _unpackNonce(nonce);
        uint256 expectedSequence = ecdsaExecutorStorage[account].nonceSequenceNumber[key];
        if (sequence != expectedSequence) {
            revert InvalidNonce(account, _packNonce(key, expectedSequence), nonce);
        }
        ecdsaExecutorStorage[account].nonceSequenceNumber[key] = sequence + 1;
    }
}