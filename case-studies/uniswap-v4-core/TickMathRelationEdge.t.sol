// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TickMathTest} from "src/test/TickMathTest.sol";
import {TickMath} from "src/libraries/TickMath.sol";

/// @notice The top edge of `test_fuzz_getTickAtSqrtPrice_getSqrtPriceAtTick_relation` (test/libraries/TickMath.t.sol).
///         That test bounds `tick` to [MIN_TICK, MAX_TICK - 1] and checks, last, that the price of `tick + 1` maps back
///         to `tick + 1`. For `tick = MAX_TICK - 1` that price is `MAX_SQRT_PRICE`, which `getTickAtSqrtPrice` rejects
///         by design (its range is [MIN_SQRT_PRICE, MAX_SQRT_PRICE)): the assertion can't hold, so the test fails on a
///         valid input once the fuzzer draws it. forge 1.8.6 does, with the repo's seed, from the out-of-range draw
///         -887273 that forge-std's `bound` wraps to MAX_TICK - 1. CI's forge 1.3.6 happens not to.
///         Found by formalmind/concolity's run on this suite (case-studies/uniswap-v4-core/REPORT-2026-10-31.md).
contract TickMathRelationEdgeTest is Test {
    TickMathTest tickMath;

    function setUp() public {
        tickMath = new TickMathTest();
    }

    /// @dev What the existing test asks for at its top edge, and why it reverts.
    function test_relation_asWritten_revertsAtMaxTickSubOne() public {
        int24 tick = TickMath.MAX_TICK - 1;
        uint160 priceAtNextTick = tickMath.getSqrtPriceAtTick(tick + 1);
        assertEq(priceAtNextTick, TickMath.MAX_SQRT_PRICE, "the next tick is MAX_TICK, whose price is the maximum");
        vm.expectRevert(abi.encodeWithSelector(TickMath.InvalidSqrtPrice.selector, priceAtNextTick));
        tickMath.getTickAtSqrtPrice(priceAtNextTick);
    }

    /// @dev The fuzzer's draw that reaches it: -887273 is below MIN_TICK, and `bound` wraps it to the top of the range.
    function test_relation_theDrawThatReachesIt() public pure {
        int24 wrapped = int24(bound(int256(-887273), TickMath.MIN_TICK, TickMath.MAX_TICK - 1));
        assertEq(wrapped, TickMath.MAX_TICK - 1, "bound wraps an out-of-range input to the far edge");
    }

    /// @dev The relation, bounded one tick lower, so the price of `tick + 1` is always in `getTickAtSqrtPrice`'s range.
    ///      The last tick's lower price is checked on its own below.
    function test_fuzz_relation_boundedBelowMaxTick(int24 tick) public view {
        tick = int24(bound(tick, TickMath.MIN_TICK, TickMath.MAX_TICK - 2));
        int24 nextTick = tick + 1;
        uint160 priceAtTick = tickMath.getSqrtPriceAtTick(tick);
        uint160 priceAtNextTick = tickMath.getSqrtPriceAtTick(nextTick);
        assertEq(tickMath.getTickAtSqrtPrice(priceAtTick), tick, "lower price");
        assertEq(
            tickMath.getTickAtSqrtPrice(uint160((uint256(priceAtTick) + uint256(priceAtNextTick)) / 2)),
            tick,
            "mid price"
        );
        assertEq(tickMath.getTickAtSqrtPrice(priceAtNextTick - 1), tick, "upper price");
        assertEq(tickMath.getTickAtSqrtPrice(priceAtNextTick), nextTick, "lower price of the next tick");
    }

    /// @dev The top tick: its lower price maps back to it; its upper bound is MAX_SQRT_PRICE - 1.
    function test_relation_atMaxTickSubOne() public view {
        int24 tick = TickMath.MAX_TICK - 1;
        uint160 priceAtTick = tickMath.getSqrtPriceAtTick(tick);
        assertEq(tickMath.getTickAtSqrtPrice(priceAtTick), tick, "lower price");
        assertEq(
            tickMath.getTickAtSqrtPrice(TickMath.MAX_SQRT_PRICE - 1), tick, "the last valid price is in the last tick"
        );
    }
}
