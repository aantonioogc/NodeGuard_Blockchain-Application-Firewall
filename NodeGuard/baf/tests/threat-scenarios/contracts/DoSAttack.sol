// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract DoSAttacker {
    // Infinite loop to cause DoS
    function infiniteLoop() public pure {
        while (true) {
            // This will consume all gas and cause DoS
        }
    }
    
    // Gas bomb
    function gasBomb() public {
        for (uint256 i = 0; i < 2**255; i++) {
            // Consume maximum gas
        }
    }
    
    // Storage spam
    function storageSpam() public {
        for (uint256 i = 0; i < 1000; i++) {
            assembly {
                sstore(i, i)
            }
        }
    }
}
