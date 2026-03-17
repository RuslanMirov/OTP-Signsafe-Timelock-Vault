// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Mock: token that always reverts on transfer ──────────────────────
// NOTE: TestToken (USDT-style, void transfer) is in contracts/TestToken.sol
// This file only contains mocks needed for adversarial tests.

// ── Mock: token that always reverts on transfer ───────────────────────
contract RevertingToken {
    function balanceOf(address) external pure returns (uint256) {
        return 1e18;
    }

    function transfer(address, uint256) external pure returns (bool) {
        revert("RevertingToken: always fails");
    }
}

// ── Mock: token that returns false instead of reverting ───────────────
contract FalseReturningToken {
    function balanceOf(address) external pure returns (uint256) {
        return 1e18;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

// ── Mock: malicious owner contract that reenters on receive() ─────────
interface IHolderReentrant {
    function withdrawETH() external;
    function rescueETH(string calldata _password) external;
}

contract ReentrantReceiver {
    IHolderReentrant public holder;
    uint256 public callCount;
    string  public storedPassword;
    bool    public doRescue;

    constructor(address _holder) {
        holder = IHolderReentrant(_holder);
    }

    function triggerWithdraw() external {
        holder.withdrawETH();
    }

    function triggerRescue(string calldata _password) external {
        storedPassword = _password;
        doRescue = true;
        holder.rescueETH(_password);
    }

    receive() external payable {
        callCount++;
        if (callCount < 3) {
            if (doRescue) {
                try holder.rescueETH(storedPassword) {} catch {}
            } else {
                try holder.withdrawETH() {} catch {}
            }
        }
    }
}