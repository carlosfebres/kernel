// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";
import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account, ExecMode} from "../interfaces/IERC7579Account.sol";
import {MODULE_TYPE_EXECUTOR} from "../types/Constants.sol";

struct ECDSAExecutorStorage {
    address owner;
    mapping(uint192 => uint64) nonceSequenceNumber;
}

/**
 * @notice ECDSAExecutor enables external execution of transactions via ECDSA signatures
 * @dev This executor uses EIP-712 typed data signing which includes chainId in the domain separator.
 * Signatures are chain-specific and cannot be replayed across different chains.
 * If deploying on multiple chains, ensure each deployment uses unique nonces or different owners.
 *
 * Security features:
 * - EIP-712 domain separation (includes chainId)
 * - 2D nonce system for parallel execution
 * - Time-bound signatures with maximum 30-day validity
 * - Signature malleability protection
 * - Reentrancy guard protection
 * - Nonce preservation across reinstalls (prevents replay attacks)
 *
 * Nonce Behavior:
 * - "Replay-until-success" semantics: nonces only consumed on successful execution
 * - Failed executions allow retries with the same signature
 * - Nonces preserved across uninstall/reinstall to prevent replay attacks
 */
contract ECDSAExecutor is IExecutor, EIP712, ReentrancyGuard {
    error InvalidNonce(address account, uint256 expected, uint256 actual);
    error SignatureExpired(address account, uint256 expiration);
    error InvalidSignature();
    error InvalidOwner();
    error InvalidAccount();
    error MalleableSignature();
    error ExpirationTooFar(uint256 expiration);
    error SequenceOverflow(address account, uint192 key);

    bytes32 constant EXECUTE_TYPEHASH = keccak256(
        "Execute(address account,bytes32 mode,bytes executionCalldata,uint256 nonce,uint256 expiration)"
    );
    uint256 constant MAX_EXPIRATION_DURATION = 30 days;
    
    event OwnerRegistered(address indexed kernel, address indexed owner);
    event OwnerUnregistered(address indexed kernel, address indexed owner);
    event OwnerTransferred(address indexed account, address indexed oldOwner, address indexed newOwner);
    event ExecutionRequested(address indexed kernel, bytes32 indexed executionHash);
    event NonceIncremented(address indexed account, uint192 indexed key, uint64 newSequence);

    /// @dev Storage for each account's executor configuration
    /// Nonce keys should be derived using deriveNonceKey() to avoid collisions
    /// Common patterns:
    /// - Key 0: Default sequential execution
    /// - Key 1-999: Reserved for protocol use
    /// - Key 1000+: Application-specific channels
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

        // FIX: Only delete owner, preserve nonces to prevent replay attacks
        delete ecdsaExecutorStorage[msg.sender].owner;

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

    /// @notice Validates that a signature is not malleable (s <= N/2)
    /// @param signature The signature bytes to validate
    function _validateSignatureNotMalleable(bytes calldata signature) internal pure {
        // Extract 's' value from signature (bytes 32-63)
        bytes32 s;
        assembly {
            s := calldataload(add(signature.offset, 0x20))
        }
        // Check if s > N/2 (N is the secp256k1 curve order)
        // N/2 + 1 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert MalleableSignature();
        }
    }

    function getOwner(address account) external view returns (address) {
        return ecdsaExecutorStorage[account].owner;
    }

    /// @notice Transfers ownership to a new address
    /// @dev Can only be called by the account itself (not the owner)
    /// @param newOwner The address of the new owner
    function transferOwnership(address newOwner) external {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        if (newOwner == address(0)) revert InvalidOwner();

        address oldOwner = ecdsaExecutorStorage[msg.sender].owner;
        ecdsaExecutorStorage[msg.sender].owner = newOwner;

        emit OwnerTransferred(msg.sender, oldOwner, newOwner);
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

        uint64 currentSequence = ecdsaExecutorStorage[msg.sender].nonceSequenceNumber[key];
        if (currentSequence == type(uint64).max) {
            revert SequenceOverflow(msg.sender, key);
        }

        ecdsaExecutorStorage[msg.sender].nonceSequenceNumber[key]++;
        emit NonceIncremented(msg.sender, key, ecdsaExecutorStorage[msg.sender].nonceSequenceNumber[key]);
    }

    /// @notice Allows an owner to invalidate nonces for their account
    /// @dev Owner must specify the account address they own
    ///      This enables emergency signature cancellation by the owner
    /// @param account The smart account whose nonce should be incremented
    /// @param key The nonce key to increment
    function invalidateNonce(address account, uint192 key) external {
        if (!_isInitialized(account)) revert NotInitialized(account);

        address owner = ecdsaExecutorStorage[account].owner;
        if (msg.sender != owner) {
            revert InvalidOwner(); // Caller is not the owner
        }

        uint64 currentSequence = ecdsaExecutorStorage[account].nonceSequenceNumber[key];
        if (currentSequence == type(uint64).max) {
            revert SequenceOverflow(account, key);
        }

        ecdsaExecutorStorage[account].nonceSequenceNumber[key]++;
        emit NonceIncremented(account, key, ecdsaExecutorStorage[account].nonceSequenceNumber[key]);
    }

    /// @notice Derives a deterministic nonce key from a purpose identifier
    /// @dev Helps prevent nonce key collisions by using a hash-based derivation
    /// @param purposeSalt A unique identifier for the nonce channel purpose
    /// @return The derived nonce key
    function deriveNonceKey(bytes32 purposeSalt) external pure returns (uint192) {
        return uint192(uint256(keccak256(abi.encodePacked("ECDSAExecutor", purposeSalt))) >> 64);
    }

    /// @notice Computes the EIP-712 typed data hash for an execution request
    /// @dev This helper function is provided for off-chain signature generation
    /// @param account The smart account address
    /// @param mode The execution mode (ExecMode type will be unwrapped to bytes32)
    /// @param executionCalldata The encoded execution data
    /// @param nonce The 2D nonce (192-bit key + 64-bit sequence)
    /// @param expiration The signature expiration timestamp
    /// @return The EIP-712 digest ready for signing
    function getExecuteTypedDataHash(
        address account,
        ExecMode mode,
        bytes calldata executionCalldata,
        uint256 nonce,
        uint256 expiration
    ) external view returns (bytes32) {
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
        return _hashTypedData(structHash);
    }

    /// @notice Executes a transaction on behalf of the smart account with ECDSA signature authorization
    /// @dev Nonce Semantics: This implementation uses "replay-until-success" behavior.
    ///      The nonce is incremented before the external call to the smart account.
    ///      If the external call reverts, the entire transaction reverts, rolling back the nonce increment.
    ///      This means the same signed transaction can be retried indefinitely until it succeeds.
    ///
    ///      Security Implications:
    ///      - Signatures remain valid until successfully executed (not single-use on failure)
    ///      - Failed transactions do not consume the nonce
    ///      - Users should set appropriate expiration times to limit retry windows
    ///      - Signatures can be invalidated by calling incrementNonce() from the account
    ///
    /// @param account The smart account to execute on behalf of
    /// @param mode The execution mode (single or batch) as defined in ERC-7579
    /// @param executionCalldata The encoded execution data
    /// @param nonce The 2D nonce (192-bit key + 64-bit sequence)
    /// @param expiration The timestamp after which the signature expires (max 30 days)
    /// @param signature The ECDSA signature from the account owner
    /// @return returnData The return data from the executed transaction
    function execute(
        address account,
        ExecMode mode,
        bytes calldata executionCalldata,
        uint256 nonce,
        uint256 expiration,
        bytes calldata signature
    ) external payable nonReentrant returns (bytes[] memory returnData) {
        // Validate account is not zero address
        if (account == address(0)) revert InvalidAccount();
        if (!_isInitialized(account)) revert NotInitialized(account);

        // Validate expiration is within allowed range
        if (expiration > block.timestamp + MAX_EXPIRATION_DURATION) {
            revert ExpirationTooFar(expiration);
        }
        if (block.timestamp > expiration) {
            revert SignatureExpired(account, expiration);
        }

        // Validate and update nonce
        _validateAndUpdateNonce(account, nonce);

        // Validate signature is not malleable
        _validateSignatureNotMalleable(signature);

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

        // Check for overflow before incrementing
        if (expectedSequence == type(uint64).max) {
            revert SequenceOverflow(account, key);
        }

        ecdsaExecutorStorage[account].nonceSequenceNumber[key] = uint64(sequence + 1);
        emit NonceIncremented(account, key, uint64(sequence + 1));
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
