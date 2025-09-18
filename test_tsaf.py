#!/usr/bin/env python3
"""
TSAF Testing Script
Demonstrates the automated security testing capabilities.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tsaf.testing.test_runner import SecurityTestRunner


async def run_demo_tests():
    """Run demonstration security tests."""
    print("🔒 TSAF Security Testing Framework Demo")
    print("=" * 50)

    # Initialize test runner
    runner = SecurityTestRunner()

    try:
        print("📋 Initializing test framework...")
        await runner.initialize()

        print("✅ Test framework initialized successfully!")

        # Validate framework
        print("\n🔍 Validating framework...")
        validation = await runner.validate_framework()

        if validation["framework_status"] == "healthy":
            print("✅ Framework validation passed!")
        else:
            print(f"⚠️  Framework validation issues: {validation['issues']}")

        # List available tests
        print("\n📊 Available tests:")
        stats = await runner.list_tests()

        # Run a small test suite
        print(f"\n🚀 Running injection tests...")
        try:
            suite_result = await runner.run_suite(
                suite_name="injection_tests",
                parallel=True,
                max_concurrent=5
            )

            print(f"\n📈 Test Results Summary:")
            print(f"  - Total: {suite_result.total_tests}")
            print(f"  - Passed: {suite_result.passed_tests}")
            print(f"  - Failed: {suite_result.failed_tests}")

            success_rate = (suite_result.passed_tests / suite_result.total_tests) * 100
            print(f"  - Success Rate: {success_rate:.1f}%")

        except Exception as e:
            print(f"❌ Test suite execution failed: {e}")

        # Run a single test
        print(f"\n🎯 Running single test...")
        try:
            await runner.run_single_test("sql_injection_basic")
        except Exception as e:
            print(f"❌ Single test failed: {e}")

    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        print("\n🔚 Shutting down...")
        await runner.shutdown()
        print("👋 Demo completed!")


if __name__ == "__main__":
    print("Starting TSAF Security Testing Demo...")
    asyncio.run(run_demo_tests())