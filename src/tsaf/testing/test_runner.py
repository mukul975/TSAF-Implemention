"""
Security Test Runner
Command-line interface and automation for security testing.
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

import structlog

from tsaf.core.config import load_config
from tsaf.core.engine import TSAFEngine
from tsaf.testing.security_test_framework import SecurityTestFramework, TestSuiteResult

logger = structlog.get_logger(__name__)


class SecurityTestRunner:
    """Security test execution runner."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = load_config()
        if config_path:
            self.config = self.config.from_file(config_path)

        self.engine = None
        self.framework = None

    async def initialize(self) -> None:
        """Initialize the test runner."""
        logger.info("Initializing security test runner")

        # Initialize TSAF engine
        self.engine = TSAFEngine(self.config)
        await self.engine.initialize()

        # Initialize test framework
        self.framework = SecurityTestFramework(self.config)

        logger.info("Security test runner initialized")

    async def run_suite(
        self,
        suite_name: str,
        parallel: bool = True,
        max_concurrent: int = 10,
        output_file: Optional[str] = None
    ) -> TestSuiteResult:
        """Run a security test suite."""
        if not self.framework or not self.engine:
            raise RuntimeError("Test runner not initialized")

        logger.info(
            "Starting security test suite",
            suite_name=suite_name,
            parallel=parallel,
            max_concurrent=max_concurrent
        )

        # Run the test suite
        result = await self.framework.run_test_suite(
            suite_name=suite_name,
            analyzer_func=self.engine.analyze_message,
            parallel=parallel,
            max_concurrent=max_concurrent
        )

        # Generate report
        report = self.framework.generate_test_report(result)

        # Save to file if specified
        if output_file:
            await self._save_report(report, output_file)

        # Print summary
        self._print_summary(result)

        return result

    async def run_single_test(self, test_id: str) -> Dict[str, Any]:
        """Run a single test case."""
        if not self.framework or not self.engine:
            raise RuntimeError("Test runner not initialized")

        logger.info("Running single test case", test_id=test_id)

        result = await self.framework.run_test_case(test_id, self.engine.analyze_message)

        # Print result
        print(f"\nTest: {result.test_name}")
        print(f"Result: {'PASS' if result.passed else 'FAIL'}")
        print(f"Risk Score: {result.risk_score:.2f}")
        print(f"Vulnerabilities: {[v.value for v in result.detected_vulnerabilities]}")
        print(f"Execution Time: {result.execution_time_ms:.2f}ms")

        if result.error_message:
            print(f"Error: {result.error_message}")

        return {
            "test_id": test_id,
            "result": result,
            "passed": result.passed
        }

    async def list_tests(self) -> Dict[str, Any]:
        """List available tests and suites."""
        if not self.framework:
            raise RuntimeError("Test runner not initialized")

        stats = self.framework.get_test_statistics()

        print("\n=== Available Test Cases ===")
        for test_id, test_case in self.framework.test_cases.items():
            print(f"  {test_id}: {test_case.name} ({test_case.category.value}, {test_case.severity.value})")

        print("\n=== Available Test Suites ===")
        for suite_name, test_ids in self.framework.test_suites.items():
            print(f"  {suite_name}: {len(test_ids)} tests")

        print(f"\n=== Statistics ===")
        print(f"  Total Tests: {stats['total_test_cases']}")
        print(f"  Total Suites: {stats['total_test_suites']}")

        return stats

    async def validate_framework(self) -> Dict[str, Any]:
        """Validate the testing framework setup."""
        if not self.framework or not self.engine:
            raise RuntimeError("Test runner not initialized")

        logger.info("Validating security test framework")

        validation_results = {
            "framework_status": "healthy",
            "engine_status": "healthy",
            "test_cases_loaded": len(self.framework.test_cases),
            "test_suites_loaded": len(self.framework.test_suites),
            "issues": []
        }

        try:
            # Test engine responsiveness
            from tsaf.analyzer.models import AnalysisRequest, ProtocolType
            test_request = AnalysisRequest(
                message='{"test": "validation"}',
                protocol=ProtocolType.MCP,
                agent_id="validation_test"
            )

            response = await self.engine.analyze_message(test_request)
            if not response:
                validation_results["issues"].append("Engine failed to respond to test request")
                validation_results["engine_status"] = "unhealthy"

        except Exception as e:
            validation_results["issues"].append(f"Engine validation failed: {str(e)}")
            validation_results["engine_status"] = "unhealthy"

        # Validate test cases
        for test_id, test_case in self.framework.test_cases.items():
            if not test_case.payload:
                validation_results["issues"].append(f"Test case {test_id} has empty payload")

            if not test_case.expected_vulnerabilities:
                validation_results["issues"].append(f"Test case {test_id} has no expected vulnerabilities")

        # Validate test suites
        for suite_name, test_ids in self.framework.test_suites.items():
            invalid_ids = [tid for tid in test_ids if tid not in self.framework.test_cases]
            if invalid_ids:
                validation_results["issues"].append(f"Suite {suite_name} references invalid test IDs: {invalid_ids}")

        if validation_results["issues"]:
            validation_results["framework_status"] = "degraded"

        logger.info(
            "Framework validation completed",
            status=validation_results["framework_status"],
            issues_found=len(validation_results["issues"])
        )

        return validation_results

    async def _save_report(self, report: Dict[str, Any], output_file: str) -> None:
        """Save test report to file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Add metadata
        report["generated_at"] = datetime.utcnow().isoformat()
        report["generator"] = "TSAF Security Test Runner"

        if output_file.endswith('.json'):
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        else:
            # Generate markdown report
            markdown_content = self._generate_markdown_report(report)
            with open(output_path, 'w') as f:
                f.write(markdown_content)

        logger.info("Test report saved", output_file=output_file)

    def _generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """Generate markdown test report."""
        md_lines = []

        # Header
        md_lines.append("# TSAF Security Test Report")
        md_lines.append("")
        md_lines.append(f"**Generated:** {report.get('generated_at', 'Unknown')}")
        md_lines.append("")

        # Summary
        summary = report["test_suite_summary"]
        md_lines.append("## Test Suite Summary")
        md_lines.append("")
        md_lines.append(f"- **Suite Name:** {summary['suite_name']}")
        md_lines.append(f"- **Total Tests:** {summary['total_tests']}")
        md_lines.append(f"- **Passed:** {summary['passed_tests']}")
        md_lines.append(f"- **Failed:** {summary['failed_tests']}")
        md_lines.append(f"- **Skipped:** {summary['skipped_tests']}")
        md_lines.append(f"- **Success Rate:** {summary['success_rate']:.1f}%")
        md_lines.append("")

        # Performance Metrics
        perf = report["performance_metrics"]
        md_lines.append("## Performance Metrics")
        md_lines.append("")
        md_lines.append(f"- **Average Execution Time:** {perf['avg_execution_time_ms']:.2f}ms")
        md_lines.append(f"- **Total Execution Time:** {perf['total_execution_time_ms']:.2f}ms")
        md_lines.append("")

        # Vulnerability Detection
        md_lines.append("## Vulnerability Detection")
        md_lines.append("")
        md_lines.append("| Category | Detected | Avg Confidence |")
        md_lines.append("|----------|----------|----------------|")

        for category, stats in report["vulnerability_detection"].items():
            md_lines.append(f"| {category} | {stats['detected_count']} | {stats['avg_confidence']:.2f} |")

        md_lines.append("")

        # Detailed Results
        md_lines.append("## Detailed Results")
        md_lines.append("")
        md_lines.append("| Test | Result | Risk Score | Vulnerabilities | Time (ms) |")
        md_lines.append("|------|--------|------------|-----------------|-----------|")

        for result in report["detailed_results"]:
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            vulns = ", ".join(result["vulnerabilities"]) if result["vulnerabilities"] else "None"
            md_lines.append(f"| {result['test_name']} | {status} | {result['risk_score']:.2f} | {vulns} | {result['execution_time_ms']:.1f} |")

        return "\n".join(md_lines)

    def _print_summary(self, result: TestSuiteResult) -> None:
        """Print test suite summary to console."""
        print("\n" + "="*80)
        print(f"TSAF Security Test Suite: {result.suite_name}")
        print("="*80)

        print(f"Total Tests:     {result.total_tests}")
        print(f"Passed:          {result.passed_tests} ✅")
        print(f"Failed:          {result.failed_tests} ❌")
        print(f"Skipped:         {result.skipped_tests} ⏭️")

        success_rate = (result.passed_tests / result.total_tests) * 100 if result.total_tests > 0 else 0
        print(f"Success Rate:    {success_rate:.1f}%")

        print(f"Execution Time:  {result.total_execution_time_ms:.2f}ms")

        # Print failed tests
        if result.failed_tests > 0:
            print("\n" + "-"*40)
            print("FAILED TESTS:")
            print("-"*40)

            failed_tests = [r for r in result.test_results if not r.passed]
            for test in failed_tests:
                print(f"❌ {test.test_name}")
                if test.error_message:
                    print(f"   Error: {test.error_message}")
                else:
                    print(f"   Expected vulnerabilities not detected")

        print("\n" + "="*80)

    async def shutdown(self) -> None:
        """Shutdown the test runner."""
        if self.engine:
            await self.engine.shutdown()

        logger.info("Security test runner shutdown completed")


async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="TSAF Security Test Runner")

    parser.add_argument("command", choices=["run", "list", "validate", "single"],
                       help="Command to execute")
    parser.add_argument("--suite", help="Test suite name (for run command)")
    parser.add_argument("--test", help="Test case ID (for single command)")
    parser.add_argument("--parallel", action="store_true", default=True,
                       help="Run tests in parallel")
    parser.add_argument("--sequential", action="store_true",
                       help="Run tests sequentially")
    parser.add_argument("--max-concurrent", type=int, default=10,
                       help="Maximum concurrent tests")
    parser.add_argument("--output", help="Output file for test report")
    parser.add_argument("--config", help="Configuration file path")

    args = parser.parse_args()

    # Configure logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer()
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Initialize runner
    runner = SecurityTestRunner(args.config)

    try:
        await runner.initialize()

        if args.command == "run":
            if not args.suite:
                print("Error: --suite is required for run command")
                sys.exit(1)

            parallel = args.parallel and not args.sequential
            await runner.run_suite(
                suite_name=args.suite,
                parallel=parallel,
                max_concurrent=args.max_concurrent,
                output_file=args.output
            )

        elif args.command == "single":
            if not args.test:
                print("Error: --test is required for single command")
                sys.exit(1)

            await runner.run_single_test(args.test)

        elif args.command == "list":
            await runner.list_tests()

        elif args.command == "validate":
            validation_result = await runner.validate_framework()
            print(f"\nFramework Status: {validation_result['framework_status']}")
            print(f"Engine Status: {validation_result['engine_status']}")

            if validation_result["issues"]:
                print("\nIssues Found:")
                for issue in validation_result["issues"]:
                    print(f"  - {issue}")
            else:
                print("\nNo issues found ✅")

    except KeyboardInterrupt:
        print("\nTest execution interrupted by user")
    except Exception as e:
        logger.error("Test runner failed", error=str(e))
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        await runner.shutdown()


if __name__ == "__main__":
    asyncio.run(main())