// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {ECDSAExecutor} from "../src/executor/ECDSAExecutor.sol";
import {IModule} from "../src/interfaces/IERC7579Modules.sol";
import {IERC7579Account, ExecMode} from "../src/interfaces/IERC7579Account.sol";
import {ExecLib} from "../src/utils/ExecLib.sol";
import {MODULE_TYPE_EXECUTOR, CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, CALLTYPE_BATCH, CallType} from "../src/types/Constants.sol";
import {ExecModePayload} from "../src/types/Types.sol";
import {Execution} from "../src/types/Structs.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "../src/interfaces/PackedUserOperation.sol";

contract MockTarget {
    uint256 public value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
}

// Mock account for testing
contract MockAccount is IERC7579Account {
    mapping(address => bool) public isExecutor;
    
    function installModule(uint256, address module, bytes calldata data) external payable {
        isExecutor[module] = true;
        IModule(module).onInstall(data);
    }
    
    function uninstallModule(uint256, address module, bytes calldata data) external payable {
        isExecutor[module] = false;
        IModule(module).onUninstall(data);
    }
    
    function executeFromExecutor(ExecMode mode, bytes calldata executionCalldata) external payable returns (bytes[] memory returnData) {
        require(isExecutor[msg.sender], "Not authorized executor");
        
        // For testing purposes, just execute whatever calls are encoded
        // This is a simplified mock that doesn't need to handle all edge cases
        
        (CallType callType,,, ) = ExecLib.decode(mode);
        
        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes memory data) = ExecLib.decodeSingle(executionCalldata);
            (bool success, bytes memory result) = target.call{value: value}(data);
            require(success, "Execution failed");
            returnData = new bytes[](1);
            returnData[0] = result;
        } else {
            // For batch test - ExecLib.encodeBatch just does abi.encode(executions)
            Execution[] memory executions = abi.decode(executionCalldata, (Execution[]));
            returnData = new bytes[](executions.length);
            
            for (uint256 i = 0; i < executions.length; i++) {
                (bool success, bytes memory result) = executions[i].target.call{value: executions[i].value}(executions[i].callData);
                require(success, "Batch execution failed");
                returnData[i] = result;
            }
        }
    }
    
    function execute(ExecMode, bytes calldata) external payable {}
    function executeUserOp(PackedUserOperation calldata, bytes32) external payable {}
    function validateUserOp(PackedUserOperation calldata, bytes32, uint256) external payable returns (uint256) {}
    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {}
    function supportsExecutionMode(ExecMode) external view returns (bool) { return true; }
    function supportsModule(uint256) external view returns (bool) { return true; }
    function isModuleInstalled(uint256, address, bytes calldata) external view returns (bool) {}
    function accountId() external view returns (string memory) {}
}

contract ECDSAExecutorTest is Test {
    using ECDSA for bytes32;
    using ExecLib for bytes;
    
    // Event declarations for testing
    event OwnerRegistered(address indexed kernel, address indexed owner);
    event OwnerUnregistered(address indexed kernel, address indexed owner);

    ECDSAExecutor executor;
    MockAccount account;
    MockTarget target;

    address owner;
    uint256 ownerKey;

    function setUp() public {
        // Deploy contracts
        executor = new ECDSAExecutor();
        target = new MockTarget();
        account = new MockAccount();
        
        (owner, ownerKey) = makeAddrAndKey("owner");
        
        // Install the ECDSA executor module
        bytes memory installData = abi.encode(owner);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), installData);
    }

    function testInstallExecutor() public {
        // First uninstall the executor to test fresh install
        vm.prank(address(account));
        account.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), bytes(""));
        
        assertFalse(executor.isInitialized(address(account)));
        
        // Now test install with event
        bytes memory installData = abi.encode(owner);
        
        // Expect the OwnerRegistered event
        vm.expectEmit(true, true, false, true, address(executor));
        emit OwnerRegistered(address(account), owner);
        
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), installData);
        
        assertTrue(executor.isInitialized(address(account)));
        assertEq(executor.getOwner(address(account)), owner);
    }

    function testExecuteWithValidSignature() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);

        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);

        uint256 nonce = 0; // Using key 0, sequence 0
        uint256 expiration = block.timestamp + 1 hours;

        // Build EIP-712 digest
        bytes32 digest = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata,
            nonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);

        assertEq(target.getValue(), newValue);
    }

    function _getEIP712Digest(
        address account,
        ExecMode mode,
        bytes memory executionCalldata,
        uint256 nonce,
        uint256 expiration
    ) internal view returns (bytes32) {
        // Compute EIP-712 digest matching Solady's EIP712 implementation
        bytes32 DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
        bytes32 EXECUTE_TYPEHASH = keccak256(
            "Execute(address account,uint256 mode,bytes executionCalldata,uint256 nonce,uint256 expiration)"
        );

        // Build domain separator matching Solady's approach
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("ECDSAExecutor"),
                keccak256("1"),
                block.chainid,
                address(executor)
            )
        );

        // Build struct hash
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

        // Combine into final digest
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function testExecuteWithInvalidSignature() public {
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        uint256 newValue = 50;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);
        
        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);
        
        uint256 nonce = 0; // Using key 0, sequence 0
        uint256 expiration = block.timestamp + 1 hours;
        
        bytes32 digest = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata,
            nonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.InvalidSignature.selector));
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);
    }

    function testUninstallExecutor() public {
        assertTrue(executor.isInitialized(address(account)));
        
        // Expect the OwnerUnregistered event
        vm.expectEmit(true, true, false, true, address(executor));
        emit OwnerUnregistered(address(account), owner);
        
        vm.prank(address(account));
        account.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), bytes(""));
        
        assertFalse(executor.isInitialized(address(account)));
    }

    function testExecuteBatch() public {
        MockTarget target2 = new MockTarget();
        
        uint256 value1 = 100;
        uint256 value2 = 200;
        
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: address(target),
            value: 0,
            callData: abi.encodeWithSelector(MockTarget.setValue.selector, value1)
        });
        executions[1] = Execution({
            target: address(target2),
            value: 0,
            callData: abi.encodeWithSelector(MockTarget.setValue.selector, value2)
        });
        
        ExecMode mode = ExecLib.encode(CALLTYPE_BATCH, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeBatch(executions);
        
        uint256 nonce = 0; // Using key 0, sequence 0
        uint256 expiration = block.timestamp + 1 hours;
        
        bytes32 digest = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata,
            nonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);
        
        assertEq(target.getValue(), value1);
        assertEq(target2.getValue(), value2);
    }

    function testInvalidNonce() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);
        
        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);
        
        uint256 wrongNonce = 1; // Should be 0 for first transaction
        uint256 expiration = block.timestamp + 1 hours;
        
        bytes32 digest = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata,
            wrongNonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.InvalidNonce.selector, address(account), 0, wrongNonce));
        executor.execute(address(account), mode, executionCalldata, wrongNonce, expiration, signature);
    }

    function testParallelNonces() public {
        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        uint256 expiration = block.timestamp + 1 hours;
        
        // Execute with key 0
        uint256 nonce1 = 0; // key 0, sequence 0
        bytes memory executionCalldata1 = ExecLib.encodeSingle(
            address(target), 
            0, 
            abi.encodeWithSelector(MockTarget.setValue.selector, 100)
        );
        
        bytes32 digest1 = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata1,
            nonce1,
            expiration
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest1);
        
        executor.execute(address(account), mode, executionCalldata1, nonce1, expiration, abi.encodePacked(r, s, v));
        assertEq(target.getValue(), 100);
        
        // Execute with key 1 (can execute in parallel)
        uint256 nonce2 = uint256(1) << 64; // key 1, sequence 0
        bytes memory executionCalldata2 = ExecLib.encodeSingle(
            address(target), 
            0, 
            abi.encodeWithSelector(MockTarget.setValue.selector, 200)
        );
        
        bytes32 digest2 = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata2,
            nonce2,
            expiration
        );
        (v, r, s) = vm.sign(ownerKey, digest2);
        
        executor.execute(address(account), mode, executionCalldata2, nonce2, expiration, abi.encodePacked(r, s, v));
        assertEq(target.getValue(), 200);
        
        // Check nonces
        assertEq(executor.getNonce(address(account), 0), 1);
        assertEq(executor.getNonce(address(account), 1), 1);
    }

    function testIncrementNonce() public {
        uint192 key = 5;
        
        // Check initial nonce
        assertEq(executor.getNonce(address(account), key), 0);
        
        // Increment nonce
        vm.prank(address(account));
        executor.incrementNonce(key);
        
        // Check incremented nonce
        assertEq(executor.getNonce(address(account), key), 1);
        
        // Increment again
        vm.prank(address(account));
        executor.incrementNonce(key);
        
        // Check nonce
        assertEq(executor.getNonce(address(account), key), 2);
    }

    function testReplayProtection() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);
        
        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);
        
        uint256 nonce = 0;
        uint256 expiration = block.timestamp + 1 hours;
        
        bytes32 digest = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata,
            nonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // First execution should succeed
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);
        assertEq(target.getValue(), newValue);
        
        // Replay should fail
        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.InvalidNonce.selector, address(account), 1, nonce));
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);
    }

    function testExpiredSignature() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);
        
        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);
        
        uint256 nonce = 0;
        uint256 expiration = block.timestamp - 1; // Already expired
        
        bytes32 digest = _getEIP712Digest(
            address(account),
            mode,
            executionCalldata,
            nonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Should revert with SignatureExpired error
        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.SignatureExpired.selector, address(account), expiration));
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);
    }

    function testInvalidOwnerAddress() public {
        // Create a new account for this test
        MockAccount newAccount = new MockAccount();
        
        // Try to install with zero address as owner
        bytes memory invalidInstallData = abi.encode(address(0));
        
        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.InvalidOwner.selector));
        newAccount.installModule(MODULE_TYPE_EXECUTOR, address(executor), invalidInstallData);
    }

    function testIsModuleType() public {
        // Test that MODULE_TYPE_EXECUTOR returns true
        assertTrue(executor.isModuleType(MODULE_TYPE_EXECUTOR));
        
        // Test that other module types return false
        assertFalse(executor.isModuleType(1)); // MODULE_TYPE_VALIDATOR
        assertFalse(executor.isModuleType(3)); // MODULE_TYPE_HOOK
        assertFalse(executor.isModuleType(4)); // MODULE_TYPE_POLICY
        assertFalse(executor.isModuleType(5)); // MODULE_TYPE_SIGNER
        assertFalse(executor.isModuleType(6)); // MODULE_TYPE_ACTION
        assertFalse(executor.isModuleType(999)); // Random type
    }

    function testUninstallNotInitialized() public {
        // Create a new account that hasn't installed the executor
        MockAccount newAccount = new MockAccount();
        
        // Try to uninstall without having installed first
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, address(newAccount)));
        vm.prank(address(newAccount));
        executor.onUninstall(bytes(""));
    }

    function testIncrementNonceNotInitialized() public {
        // Create a new account that hasn't installed the executor
        MockAccount newAccount = new MockAccount();
        
        // Try to increment nonce without being initialized
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, address(newAccount)));
        vm.prank(address(newAccount));
        executor.incrementNonce(0);
    }

    function testExecuteNotInitialized() public {
        // Create a new account that hasn't installed the executor
        MockAccount newAccount = new MockAccount();
        
        // Prepare execution data
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, 42);
        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);
        
        uint256 nonce = 0;
        uint256 expiration = block.timestamp + 1 hours;
        
        bytes32 digest = _getEIP712Digest(
            address(newAccount),
            mode,
            executionCalldata,
            nonce,
            expiration
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Should revert because account is not initialized
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, address(newAccount)));
        executor.execute(address(newAccount), mode, executionCalldata, nonce, expiration, signature);
    }

    function testSignatureMalleability() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);

        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);

        uint256 nonce = 0;
        uint256 expiration = block.timestamp + 1 hours;

        bytes32 digest = _getEIP712Digest(address(account), mode, executionCalldata, nonce, expiration);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        // Create malleable signature (s' = N - s)
        uint256 N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
        bytes32 malleableS = bytes32(N - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;

        bytes memory malleableSignature = abi.encodePacked(r, malleableS, malleableV);

        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.MalleableSignature.selector));
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, malleableSignature);
    }

    function testMaximumExpiration() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);

        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);

        uint256 nonce = 0;
        uint256 expiration = block.timestamp + 31 days; // Too far in future

        bytes32 digest = _getEIP712Digest(address(account), mode, executionCalldata, nonce, expiration);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.ExpirationTooFar.selector, expiration));
        executor.execute(address(account), mode, executionCalldata, nonce, expiration, signature);
    }

    function testOwnerTransfer() public {
        address newOwner = makeAddr("newOwner");

        // Only account can transfer ownership
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, address(this)));
        executor.transferOwnership(newOwner);

        // Account transfers ownership
        vm.prank(address(account));
        vm.expectEmit(true, true, true, true);
        emit ECDSAExecutor.OwnerTransferred(address(account), owner, newOwner);
        executor.transferOwnership(newOwner);

        assertEq(executor.getOwner(address(account)), newOwner);

        // Cannot transfer to zero address
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.InvalidOwner.selector));
        executor.transferOwnership(address(0));
    }

    function testNonceIncrementEvent() public {
        uint192 key = 5;

        vm.prank(address(account));
        vm.expectEmit(true, true, false, true);
        emit ECDSAExecutor.NonceIncremented(address(account), key, 1);
        executor.incrementNonce(key);

        assertEq(executor.getNonce(address(account), key), 1);
    }

    function testZeroAddressAccount() public {
        uint256 newValue = 42;
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, newValue);

        ExecMode mode = ExecLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0));
        bytes memory executionCalldata = ExecLib.encodeSingle(address(target), 0, callData);

        uint256 nonce = 0;
        uint256 expiration = block.timestamp + 1 hours;

        bytes32 digest = _getEIP712Digest(address(0), mode, executionCalldata, nonce, expiration);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(ECDSAExecutor.InvalidAccount.selector));
        executor.execute(address(0), mode, executionCalldata, nonce, expiration, signature);
    }

    function testDeriveNonceKey() public {
        bytes32 salt1 = keccak256("channel1");
        bytes32 salt2 = keccak256("channel2");

        uint192 key1 = executor.deriveNonceKey(salt1);
        uint192 key2 = executor.deriveNonceKey(salt2);

        // Keys should be different for different salts
        assertTrue(key1 != key2);

        // Keys should be deterministic
        assertEq(key1, executor.deriveNonceKey(salt1));
    }
}

contract MaliciousReentrant {
    ECDSAExecutor executor;
    bool attacked;

    constructor(ECDSAExecutor _executor) {
        executor = _executor;
    }

    function attack() external {
        if (!attacked) {
            attacked = true;
            // Attempt reentrancy
            executor.execute(address(this), ExecMode.wrap(0), "", 0, 0, "");
        }
    }
}
