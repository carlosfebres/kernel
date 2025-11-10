# ECDSAExecutor Module

## Overview

The ECDSAExecutor is an ERC-7579 executor module that enables off-chain transaction authorization for smart accounts using ECDSA signatures. It allows a designated EOA (Externally Owned Account) owner to sign and execute transactions on behalf of a smart account without requiring on-chain transactions from the owner's address.

## Key Features

### 🔐 Secure Signature Verification
- **EIP-712 Typed Data Signing**: Uses structured data signing for enhanced security and better wallet UX
- **Owner-based Authorization**: Only the designated owner's signature can authorize executions
- **Signature Expiration**: Time-bound signatures prevent replay attacks on old authorizations

### 🔄 Advanced Nonce Management
- **2D Nonce System**: Supports parallel execution paths with independent nonce sequences
  - 192-bit key space for different channels/contexts
  - 64-bit sequence number per key
- **Replay Protection**: Each nonce can only be used once
- **Nonce Invalidation**: Ability to increment nonces to invalidate pre-signed transactions

### 🏗️ ERC-7579 Compatibility
- Fully compliant with the ERC-7579 modular account standard
- Supports both single and batch execution modes
- Seamless installation/uninstallation on compatible smart accounts

## Architecture

### Storage Structure
```solidity
struct ECDSAExecutorStorage {
    address owner;                               // EOA that can sign transactions
    mapping(uint192 => uint64) nonceSequenceNumber; // 2D nonce tracking
}
```

### Nonce System
The nonce is packed as a 256-bit value:
- **Upper 192 bits**: Key/channel identifier (allows parallel sequences)
- **Lower 64 bits**: Sequential counter for that key

This design enables:
- Multiple independent signing contexts (e.g., different dApps, sessions)
- Parallel transaction processing without nonce conflicts
- Efficient gas usage through bit packing

## Usage

### Installation
```solidity
// Install the executor on a smart account
bytes memory installData = abi.encode(ownerAddress);
account.installModule(MODULE_TYPE_EXECUTOR, executorAddress, installData);
```

### Executing Transactions
```solidity
// 1. Prepare execution data
ExecMode mode = ...; // Single or batch mode
bytes memory executionCalldata = ...; // Encoded call data
uint256 nonce = 0; // Key 0, sequence 0
uint256 expiration = block.timestamp + 1 hours;

// 2. Create EIP-712 signature (off-chain)
bytes32 digest = executor.getEIP712Digest(
    account,
    mode,
    executionCalldata,
    nonce,
    expiration
);
bytes memory signature = sign(digest); // Sign with owner's private key

// 3. Execute (can be called by anyone)
executor.execute(
    account,
    mode,
    executionCalldata,
    nonce,
    expiration,
    signature
);
```

### Parallel Nonces Example
```solidity
// Channel A: nonce with key 0
uint256 nonceA = 0; // key=0, sequence=0

// Channel B: nonce with key 1 (independent of Channel A)
uint256 nonceB = uint256(1) << 64; // key=1, sequence=0

// Both can be executed in parallel without conflicts
```

## Security Considerations

### ✅ Built-in Protections
- **Replay Protection**: Nonces prevent transaction replay
- **Expiration Timestamps**: Time-limited signature validity
- **EIP-712 Domain Separation**: Prevents cross-chain/cross-contract replay
- **Owner Validation**: Only designated owner can authorize executions

### ⚠️ Important Notes
1. **Owner Key Security**: The owner's private key must be kept secure as it controls the smart account
2. **Signature Expiration**: Set appropriate expiration times - too long increases risk, too short may cause UX issues
3. **Nonce Management**: Track used nonces off-chain to prevent submission failures
4. **Initialization Check**: Module prevents double-initialization on the same account

## Gas Optimization

The module is optimized for gas efficiency:
- Uses Solady's optimized ECDSA and EIP712 libraries
- Bit-packed nonce storage (192-bit key + 64-bit sequence)
- Minimal storage operations
- Efficient signature verification

## Integration Example

```solidity
// Example: Integrating with a smart account
contract MySmartAccount is IERC7579Account {
    // Install ECDSAExecutor during account setup
    function setUp(address owner) external {
        ECDSAExecutor executor = new ECDSAExecutor();
        bytes memory data = abi.encode(owner);
        this.installModule(MODULE_TYPE_EXECUTOR, address(executor), data);
    }

    // The executor can now authorize transactions with owner's signature
}
```

## Events

- `OwnerRegistered(address indexed kernel, address indexed owner)`: Emitted when executor is installed
- `OwnerUnregistered(address indexed kernel, address indexed owner)`: Emitted when executor is uninstalled
- `ExecutionRequested(address indexed kernel, bytes32 indexed executionHash)`: Emitted before execution

## Error Codes

- `InvalidNonce`: Nonce doesn't match expected value
- `SignatureExpired`: Signature timestamp has expired
- `InvalidSignature`: Signature doesn't match owner
- `InvalidOwner`: Attempting to set zero address as owner
- `AlreadyInitialized`: Module already installed on account
- `NotInitialized`: Module not installed on account

## Dependencies

- [Solady](https://github.com/vectorized/solady): Optimized Solidity libraries
  - `ECDSA`: Efficient signature verification
  - `EIP712`: Typed structured data hashing and signing
- ERC-7579: Modular smart account standard interfaces