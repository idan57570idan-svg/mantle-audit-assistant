// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * GasWastefulStorage — intentionally gas-inefficient contract for testing gas optimizer.
 * Demonstrates patterns that are especially costly on Mantle L2.
 */
contract GasWastefulStorage {
    // Gas waste: separate storage slots instead of bit-packing
    uint256 public userAge;        // wastes full slot for small value
    uint256 public userScore;      // another full slot
    bool public isActive;          // another full slot — should pack with others
    address public userAddress;    // another full slot — could pack with bool

    // Gas waste: non-immutable constants
    uint256 public MAX_SUPPLY = 10000;     // should be constant/immutable
    address public TOKEN_ADDRESS;          // set in constructor — should be immutable
    string public TOKEN_NAME = "Token";   // should be constant

    // Gas waste: not indexed events (extra calldata on L2)
    event Transfer(address from, address to, uint256 amount);
    event Deposit(address user, uint256 amount, uint256 timestamp);

    mapping(address => uint256) private _balances;
    address[] private _allUsers;

    constructor(address tokenAddress) {
        TOKEN_ADDRESS = tokenAddress;
    }

    // Gas waste: reading storage in a loop (SLOAD per iteration)
    function getTotalBalance() external view returns (uint256 total) {
        for (uint256 i = 0; i < _allUsers.length; i++) {
            total += _balances[_allUsers[i]];  // expensive: SLOAD in loop
        }
    }

    // Gas waste: memory vs calldata for external read-only functions
    function processAmounts(uint256[] memory amounts) external pure returns (uint256 sum) {
        // BUG: should be calldata not memory for external functions
        for (uint256 i = 0; i < amounts.length; i++) {
            sum += amounts[i];
        }
    }

    // Gas waste: redundant storage reads
    function deposit(uint256 amount) external {
        _balances[msg.sender] = _balances[msg.sender] + amount;  // reads twice
        isActive = true;
        userAddress = msg.sender;
        emit Deposit(msg.sender, amount, block.timestamp);  // timestamp in calldata → L1 cost

        if (_balances[msg.sender] > 0 && !isActive) {  // redundant: isActive just set to true
            isActive = true;
        }
    }

    // Gas waste: unnecessary storage writes
    function updateUser(uint256 age, uint256 score) external {
        userAge = age;
        userScore = score;
        isActive = true;
        userAge = age;    // duplicate write
    }

    // Gas waste: string comparison (very expensive)
    function checkName(string calldata name) external view returns (bool) {
        return keccak256(bytes(TOKEN_NAME)) == keccak256(bytes(name));  // ok pattern but TOKEN_NAME shouldn't be storage
    }

    // Gas waste: tracking all users (unbounded array)
    function registerUser(address user) external {
        _allUsers.push(user);
        _balances[user] = 0;
    }
}
