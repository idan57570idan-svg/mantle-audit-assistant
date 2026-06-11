// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * VulnerableBank — intentionally insecure contract for testing the audit assistant.
 * Contains: reentrancy, tx.origin misuse, block.timestamp dependency,
 *           integer overflow (unsafe cast), missing access control.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public lastWithdrawTime;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability 1: tx.origin for authentication (phishing attack vector)
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerability 2: Classic reentrancy — state updated AFTER external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // BUG: External call before state update — reentrancy vulnerability
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;  // Too late — attacker already re-entered
    }

    // Vulnerability 3: block.timestamp for rate limiting (sequencer can manipulate on L2)
    function timedWithdraw(uint256 amount) external {
        require(block.timestamp >= lastWithdrawTime + 1 hours, "Too soon");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        lastWithdrawTime = block.timestamp;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Vulnerability 4: Unsafe integer cast (overflow on conversion)
    function batchDeposit(uint256[] calldata amounts) external payable {
        uint8 count = uint8(amounts.length);  // BUG: overflow if amounts.length > 255
        for (uint8 i = 0; i < count; i++) {
            balances[msg.sender] += amounts[i];
        }
    }

    // Vulnerability 5: Missing access control on critical function
    function emergencyWithdrawAll(address payable recipient) external {
        // BUG: No access control — anyone can drain the contract
        recipient.transfer(address(this).balance);
    }

    // Vulnerability 6: Unprotected selfdestruct
    function destroy() external onlyOwner {
        // Uses tx.origin (see modifier) + selfdestruct
        selfdestruct(payable(owner));
    }

    receive() external payable {}
}
