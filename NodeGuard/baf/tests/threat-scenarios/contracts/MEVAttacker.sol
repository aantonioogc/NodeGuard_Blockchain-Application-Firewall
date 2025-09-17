// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MEVAttacker {
    // Front-running attack simulation
    function frontrunAttack(address target, bytes calldata data) public payable {
        // Monitor mempool for profitable transactions
        // Submit same transaction with higher gas price
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "Front-run failed");
    }
    
    // Sandwich attack simulation
    function sandwichAttack(
        address[] calldata targets,
        bytes[] calldata frontData,
        bytes[] calldata backData
    ) public payable {
        // Front transaction
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].call{value: msg.value / targets.length}(frontData[i]);
        }
        
        // Back transaction (to be submitted after victim)
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].call{value: msg.value / targets.length}(backData[i]);
        }
    }
}
