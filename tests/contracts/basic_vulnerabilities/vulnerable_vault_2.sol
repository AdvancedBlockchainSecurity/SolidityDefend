// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Recall-regression fixture (Apogee 2026-05-22). Seeded vulnerabilities:
//   (A) deposit(to)            — missing zero-address check (HIGH, not always caught)
//   (B) withdraw(amount)       — classic reentrancy CEI violation (CRITICAL)
//   (C) mint(to, amount)       — missing access control (HIGH)
//   (D) withdrawToAddress      — unchecked low-level call with discarded tuple (MEDIUM)
//   (E) changeOwner(newOwner)  — missing access control (CRITICAL)
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    function deposit(address to) public payable {
        balances[to] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        totalSupply += amount;
    }

    function withdrawToAddress(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        recipient.call{value: amount}("");
    }

    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    function emergencyWithdraw() public {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
}
