"""
Automated Security Testing Framework
Comprehensive security testing suite for TSAF framework.
"""

import asyncio
import hashlib
import json
import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass
from enum import Enum

import structlog

from tsaf.core.config import TSAFConfig
from tsaf.core.exceptions import TSAFException
from tsaf.analyzer.models import (
    ProtocolType, VulnerabilityCategory, SeverityLevel,
    AnalysisRequest, AnalysisResponse
)

logger = structlog.get_logger(__name__)


class TestCategory(str, Enum):
    """Security test categories."""
    INJECTION = "injection"
    PROTOCOL_FUZZING = "protocol_fuzzing"
    DENIAL_OF_SERVICE = "denial_of_service"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_ESCALATION = "authorization_escalation"
    DATA_LEAKAGE = "data_leakage"
    CRYPTOGRAPHIC = "cryptographic"
    BUSINESS_LOGIC = "business_logic"


class TestSeverity(str, Enum):
    """Test severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityTestCase:
    """Individual security test case."""
    id: str
    name: str
    description: str
    category: TestCategory
    severity: TestSeverity
    protocol: ProtocolType
    payload: str
    expected_vulnerabilities: List[VulnerabilityCategory]
    expected_risk_score_min: float
    metadata: Dict[str, Any]

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())


@dataclass
class TestResult:
    """Test execution result."""
    test_case_id: str
    test_name: str
    passed: bool
    detected_vulnerabilities: List[VulnerabilityCategory]
    risk_score: float
    confidence: float
    execution_time_ms: float
    error_message: Optional[str] = None
    analysis_response: Optional[AnalysisResponse] = None


@dataclass
class TestSuiteResult:
    """Test suite execution result."""
    suite_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    total_execution_time_ms: float
    test_results: List[TestResult]
    coverage_report: Dict[str, Any]
    started_at: datetime
    completed_at: datetime


class SecurityTestFramework:
    """
    Automated security testing framework for TSAF.

    Provides comprehensive security testing capabilities including:
    - Vulnerability detection testing
    - Protocol fuzzing
    - Performance testing
    - Regression testing
    """

    def __init__(self, config: TSAFConfig):
        self.config = config
        self.test_cases: Dict[str, SecurityTestCase] = {}
        self.test_suites: Dict[str, List[str]] = {}
        self._load_default_test_cases()

    def _load_default_test_cases(self) -> None:
        """Load default security test cases."""

        # SQL Injection Tests
        self.add_test_case(SecurityTestCase(
            id="sql_injection_basic",
            name="Basic SQL Injection",
            description="Test detection of basic SQL injection patterns",
            category=TestCategory.INJECTION,
            severity=TestSeverity.HIGH,
            protocol=ProtocolType.MCP,
            payload='{"method": "query", "params": {"sql": "SELECT * FROM users WHERE id = 1 OR 1=1"}}',
            expected_vulnerabilities=[VulnerabilityCategory.ISV],
            expected_risk_score_min=0.7,
            metadata={"attack_type": "sql_injection", "variant": "union"}
        ))

        self.add_test_case(SecurityTestCase(
            id="sql_injection_union",
            name="SQL Injection with UNION",
            description="Test detection of UNION-based SQL injection",
            category=TestCategory.INJECTION,
            severity=TestSeverity.CRITICAL,
            protocol=ProtocolType.A2A,
            payload='{"task": "data_query", "parameters": {"query": "SELECT username FROM users UNION SELECT password FROM admin_users"}}',
            expected_vulnerabilities=[VulnerabilityCategory.ISV],
            expected_risk_score_min=0.8,
            metadata={"attack_type": "sql_injection", "variant": "union"}
        ))

        # Command Injection Tests
        self.add_test_case(SecurityTestCase(
            id="command_injection_basic",
            name="Basic Command Injection",
            description="Test detection of command injection patterns",
            category=TestCategory.INJECTION,
            severity=TestSeverity.CRITICAL,
            protocol=ProtocolType.MCP,
            payload='{"method": "execute", "params": {"command": "ls -la; cat /etc/passwd"}}',
            expected_vulnerabilities=[VulnerabilityCategory.CEV],
            expected_risk_score_min=0.9,
            metadata={"attack_type": "command_injection", "variant": "semicolon"}
        ))

        # XSS Tests
        self.add_test_case(SecurityTestCase(
            id="xss_reflected",
            name="Reflected XSS",
            description="Test detection of reflected XSS patterns",
            category=TestCategory.INJECTION,
            severity=TestSeverity.MEDIUM,
            protocol=ProtocolType.FIPA_ACL,
            payload='(inform :sender agent :receiver client :content "<script>alert(\'XSS\')</script>")',
            expected_vulnerabilities=[VulnerabilityCategory.ISV],
            expected_risk_score_min=0.6,
            metadata={"attack_type": "xss", "variant": "reflected"}
        ))

        # Protocol Fuzzing Tests
        self.add_test_case(SecurityTestCase(
            id="malformed_json",
            name="Malformed JSON",
            description="Test handling of malformed JSON messages",
            category=TestCategory.PROTOCOL_FUZZING,
            severity=TestSeverity.MEDIUM,
            protocol=ProtocolType.MCP,
            payload='{"method": "test", "params": {"data": }',  # Malformed JSON
            expected_vulnerabilities=[VulnerabilityCategory.PIV],
            expected_risk_score_min=0.4,
            metadata={"attack_type": "malformed_data", "variant": "json"}
        ))

        # Buffer Overflow Tests
        self.add_test_case(SecurityTestCase(
            id="buffer_overflow_large_payload",
            name="Large Payload Buffer Overflow",
            description="Test handling of extremely large payloads",
            category=TestCategory.DENIAL_OF_SERVICE,
            severity=TestSeverity.HIGH,
            protocol=ProtocolType.ACP,
            payload=json.dumps({
                "id": "test",
                "from_agent": "attacker",
                "to_agent": "victim",
                "message_type": "request",
                "content": {"data": "A" * 1000000}  # 1MB of data
            }),
            expected_vulnerabilities=[VulnerabilityCategory.SCV],
            expected_risk_score_min=0.5,
            metadata={"attack_type": "buffer_overflow", "size": 1000000}
        ))

        # Path Traversal Tests
        self.add_test_case(SecurityTestCase(
            id="path_traversal_basic",
            name="Basic Path Traversal",
            description="Test detection of path traversal attacks",
            category=TestCategory.INJECTION,
            severity=TestSeverity.HIGH,
            protocol=ProtocolType.A2A,
            payload='{"task": "file_read", "parameters": {"path": "../../../etc/passwd"}}',
            expected_vulnerabilities=[VulnerabilityCategory.ISV],
            expected_risk_score_min=0.7,
            metadata={"attack_type": "path_traversal", "variant": "unix"}
        ))

        # Cryptographic Tests
        self.add_test_case(SecurityTestCase(
            id="weak_crypto_key",
            name="Weak Cryptographic Key",
            description="Test detection of weak cryptographic keys",
            category=TestCategory.CRYPTOGRAPHIC,
            severity=TestSeverity.MEDIUM,
            protocol=ProtocolType.MCP,
            payload='{"method": "encrypt", "params": {"key": "12345", "algorithm": "DES"}}',
            expected_vulnerabilities=[VulnerabilityCategory.TIV],
            expected_risk_score_min=0.6,
            metadata={"attack_type": "weak_crypto", "algorithm": "DES"}
        ))

        # Protocol-specific Tests
        self._load_protocol_specific_tests()

    def _load_protocol_specific_tests(self) -> None:
        """Load protocol-specific test cases."""

        # MCP-specific tests
        self.add_test_case(SecurityTestCase(
            id="mcp_method_override",
            name="MCP Method Override",
            description="Test MCP method override vulnerabilities",
            category=TestCategory.BUSINESS_LOGIC,
            severity=TestSeverity.HIGH,
            protocol=ProtocolType.MCP,
            payload='{"jsonrpc": "2.0", "method": "system.shutdown", "id": 1}',
            expected_vulnerabilities=[VulnerabilityCategory.CEV],
            expected_risk_score_min=0.8,
            metadata={"protocol_specific": True, "method": "system.shutdown"}
        ))

        # FIPA-ACL specific tests
        self.add_test_case(SecurityTestCase(
            id="fipa_acl_ontology_injection",
            name="FIPA-ACL Ontology Injection",
            description="Test FIPA-ACL ontology injection vulnerabilities",
            category=TestCategory.INJECTION,
            severity=TestSeverity.MEDIUM,
            protocol=ProtocolType.FIPA_ACL,
            payload='(request :sender evil-agent :receiver target :content (action (delete-all-data)) :ontology malicious-ontology)',
            expected_vulnerabilities=[VulnerabilityCategory.PIV],
            expected_risk_score_min=0.6,
            metadata={"protocol_specific": True, "ontology": "malicious"}
        ))

        # Create test suites
        self._create_test_suites()

    def _create_test_suites(self) -> None:
        """Create predefined test suites."""

        # Injection test suite
        injection_tests = [
            "sql_injection_basic",
            "sql_injection_union",
            "command_injection_basic",
            "xss_reflected",
            "path_traversal_basic"
        ]
        self.add_test_suite("injection_tests", injection_tests)

        # Protocol fuzzing suite
        fuzzing_tests = [
            "malformed_json",
            "buffer_overflow_large_payload"
        ]
        self.add_test_suite("fuzzing_tests", fuzzing_tests)

        # Critical vulnerabilities suite
        critical_tests = [
            test_id for test_id, test_case in self.test_cases.items()
            if test_case.severity == TestSeverity.CRITICAL
        ]
        self.add_test_suite("critical_tests", critical_tests)

        # Protocol-specific suites
        for protocol in ProtocolType:
            protocol_tests = [
                test_id for test_id, test_case in self.test_cases.items()
                if test_case.protocol == protocol
            ]
            self.add_test_suite(f"{protocol.value}_tests", protocol_tests)

        # Complete test suite
        all_tests = list(self.test_cases.keys())
        self.add_test_suite("all_tests", all_tests)

    def add_test_case(self, test_case: SecurityTestCase) -> None:
        """Add a security test case."""
        self.test_cases[test_case.id] = test_case
        logger.debug("Added test case", test_id=test_case.id, test_name=test_case.name)

    def add_test_suite(self, suite_name: str, test_case_ids: List[str]) -> None:
        """Add a test suite."""
        # Validate that all test case IDs exist
        invalid_ids = [tid for tid in test_case_ids if tid not in self.test_cases]
        if invalid_ids:
            raise TSAFException(f"Invalid test case IDs: {invalid_ids}")

        self.test_suites[suite_name] = test_case_ids
        logger.debug("Added test suite", suite_name=suite_name, test_count=len(test_case_ids))

    async def run_test_case(
        self,
        test_case_id: str,
        analyzer_func: Callable[[AnalysisRequest], AnalysisResponse]
    ) -> TestResult:
        """Run a single test case."""
        if test_case_id not in self.test_cases:
            raise TSAFException(f"Test case not found: {test_case_id}")

        test_case = self.test_cases[test_case_id]
        start_time = time.time()

        try:
            logger.info("Running test case", test_id=test_case_id, test_name=test_case.name)

            # Create analysis request
            analysis_request = AnalysisRequest(
                message=test_case.payload,
                protocol=test_case.protocol,
                agent_id="security_test_agent",
                metadata=test_case.metadata
            )

            # Execute analysis
            analysis_response = await analyzer_func(analysis_request)
            execution_time = (time.time() - start_time) * 1000

            # Extract detected vulnerabilities
            detected_vulns = [vuln.category for vuln in analysis_response.vulnerabilities]

            # Evaluate test result
            passed = self._evaluate_test_result(test_case, analysis_response)

            result = TestResult(
                test_case_id=test_case_id,
                test_name=test_case.name,
                passed=passed,
                detected_vulnerabilities=detected_vulns,
                risk_score=analysis_response.risk_score,
                confidence=analysis_response.confidence,
                execution_time_ms=execution_time,
                analysis_response=analysis_response
            )

            logger.info(
                "Test case completed",
                test_id=test_case_id,
                passed=passed,
                risk_score=analysis_response.risk_score,
                vulnerabilities_found=len(detected_vulns)
            )

            return result

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error("Test case failed", test_id=test_case_id, error=str(e))

            return TestResult(
                test_case_id=test_case_id,
                test_name=test_case.name,
                passed=False,
                detected_vulnerabilities=[],
                risk_score=0.0,
                confidence=0.0,
                execution_time_ms=execution_time,
                error_message=str(e)
            )

    def _evaluate_test_result(
        self,
        test_case: SecurityTestCase,
        analysis_response: AnalysisResponse
    ) -> bool:
        """Evaluate whether a test case passed."""

        # Check if expected vulnerabilities were detected
        detected_categories = {vuln.category for vuln in analysis_response.vulnerabilities}
        expected_categories = set(test_case.expected_vulnerabilities)

        # Test passes if:
        # 1. All expected vulnerabilities are detected
        # 2. Risk score meets minimum threshold

        vulnerabilities_detected = expected_categories.issubset(detected_categories)
        risk_score_adequate = analysis_response.risk_score >= test_case.expected_risk_score_min

        return vulnerabilities_detected and risk_score_adequate

    async def run_test_suite(
        self,
        suite_name: str,
        analyzer_func: Callable[[AnalysisRequest], AnalysisResponse],
        parallel: bool = True,
        max_concurrent: int = 10
    ) -> TestSuiteResult:
        """Run a test suite."""
        if suite_name not in self.test_suites:
            raise TSAFException(f"Test suite not found: {suite_name}")

        test_case_ids = self.test_suites[suite_name]
        start_time = datetime.utcnow()

        logger.info(
            "Starting test suite",
            suite_name=suite_name,
            test_count=len(test_case_ids),
            parallel=parallel
        )

        # Execute tests
        if parallel:
            test_results = await self._run_tests_parallel(
                test_case_ids, analyzer_func, max_concurrent
            )
        else:
            test_results = await self._run_tests_sequential(test_case_ids, analyzer_func)

        end_time = datetime.utcnow()
        total_execution_time = (end_time - start_time).total_seconds() * 1000

        # Calculate results
        passed_tests = len([r for r in test_results if r.passed])
        failed_tests = len([r for r in test_results if not r.passed and not r.error_message])
        skipped_tests = len([r for r in test_results if r.error_message])

        # Generate coverage report
        coverage_report = self._generate_coverage_report(test_results)

        suite_result = TestSuiteResult(
            suite_name=suite_name,
            total_tests=len(test_case_ids),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=skipped_tests,
            total_execution_time_ms=total_execution_time,
            test_results=test_results,
            coverage_report=coverage_report,
            started_at=start_time,
            completed_at=end_time
        )

        logger.info(
            "Test suite completed",
            suite_name=suite_name,
            total_tests=suite_result.total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            execution_time_ms=total_execution_time
        )

        return suite_result

    async def _run_tests_parallel(
        self,
        test_case_ids: List[str],
        analyzer_func: Callable,
        max_concurrent: int
    ) -> List[TestResult]:
        """Run tests in parallel with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_with_semaphore(test_id: str) -> TestResult:
            async with semaphore:
                return await self.run_test_case(test_id, analyzer_func)

        tasks = [run_with_semaphore(test_id) for test_id in test_case_ids]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _run_tests_sequential(
        self,
        test_case_ids: List[str],
        analyzer_func: Callable
    ) -> List[TestResult]:
        """Run tests sequentially."""
        results = []
        for test_id in test_case_ids:
            result = await self.run_test_case(test_id, analyzer_func)
            results.append(result)
        return results

    def _generate_coverage_report(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Generate test coverage report."""

        # Category coverage
        categories_tested = set()
        protocols_tested = set()
        severities_tested = set()

        for result in test_results:
            if result.test_case_id in self.test_cases:
                test_case = self.test_cases[result.test_case_id]
                categories_tested.add(test_case.category.value)
                protocols_tested.add(test_case.protocol.value)
                severities_tested.add(test_case.severity.value)

        # Vulnerability detection coverage
        vulnerability_coverage = {}
        for category in VulnerabilityCategory:
            detected_count = sum(
                1 for result in test_results
                if category in result.detected_vulnerabilities
            )
            total_count = sum(
                1 for test_id in [r.test_case_id for r in test_results]
                if test_id in self.test_cases and
                category in self.test_cases[test_id].expected_vulnerabilities
            )

            if total_count > 0:
                vulnerability_coverage[category.value] = {
                    "detected": detected_count,
                    "total": total_count,
                    "coverage_percentage": (detected_count / total_count) * 100
                }

        return {
            "categories_tested": list(categories_tested),
            "protocols_tested": list(protocols_tested),
            "severities_tested": list(severities_tested),
            "vulnerability_detection_coverage": vulnerability_coverage,
            "overall_coverage": {
                "categories": len(categories_tested) / len(TestCategory) * 100,
                "protocols": len(protocols_tested) / len(ProtocolType) * 100,
                "severities": len(severities_tested) / len(TestSeverity) * 100
            }
        }

    def generate_test_report(self, suite_result: TestSuiteResult) -> Dict[str, Any]:
        """Generate comprehensive test report."""

        # Vulnerability detection statistics
        vuln_stats = {}
        for category in VulnerabilityCategory:
            detected = [r for r in suite_result.test_results if category in r.detected_vulnerabilities]
            vuln_stats[category.value] = {
                "detected_count": len(detected),
                "avg_confidence": sum(r.confidence for r in detected) / len(detected) if detected else 0
            }

        # Performance statistics
        execution_times = [r.execution_time_ms for r in suite_result.test_results if r.execution_time_ms > 0]
        performance_stats = {
            "avg_execution_time_ms": sum(execution_times) / len(execution_times) if execution_times else 0,
            "min_execution_time_ms": min(execution_times) if execution_times else 0,
            "max_execution_time_ms": max(execution_times) if execution_times else 0,
            "total_execution_time_ms": suite_result.total_execution_time_ms
        }

        # Risk score distribution
        risk_scores = [r.risk_score for r in suite_result.test_results if r.risk_score > 0]
        risk_distribution = {
            "avg_risk_score": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "min_risk_score": min(risk_scores) if risk_scores else 0,
            "max_risk_score": max(risk_scores) if risk_scores else 0,
            "high_risk_count": len([r for r in risk_scores if r >= 0.7]),
            "medium_risk_count": len([r for r in risk_scores if 0.3 <= r < 0.7]),
            "low_risk_count": len([r for r in risk_scores if r < 0.3])
        }

        return {
            "test_suite_summary": {
                "suite_name": suite_result.suite_name,
                "total_tests": suite_result.total_tests,
                "passed_tests": suite_result.passed_tests,
                "failed_tests": suite_result.failed_tests,
                "skipped_tests": suite_result.skipped_tests,
                "success_rate": (suite_result.passed_tests / suite_result.total_tests) * 100,
                "started_at": suite_result.started_at.isoformat(),
                "completed_at": suite_result.completed_at.isoformat()
            },
            "vulnerability_detection": vuln_stats,
            "performance_metrics": performance_stats,
            "risk_assessment": risk_distribution,
            "coverage_report": suite_result.coverage_report,
            "detailed_results": [
                {
                    "test_id": r.test_case_id,
                    "test_name": r.test_name,
                    "passed": r.passed,
                    "risk_score": r.risk_score,
                    "vulnerabilities": [v.value for v in r.detected_vulnerabilities],
                    "execution_time_ms": r.execution_time_ms,
                    "error": r.error_message
                }
                for r in suite_result.test_results
            ]
        }

    def get_test_statistics(self) -> Dict[str, Any]:
        """Get framework test statistics."""
        category_counts = {}
        protocol_counts = {}
        severity_counts = {}

        for test_case in self.test_cases.values():
            category_counts[test_case.category.value] = category_counts.get(test_case.category.value, 0) + 1
            protocol_counts[test_case.protocol.value] = protocol_counts.get(test_case.protocol.value, 0) + 1
            severity_counts[test_case.severity.value] = severity_counts.get(test_case.severity.value, 0) + 1

        return {
            "total_test_cases": len(self.test_cases),
            "total_test_suites": len(self.test_suites),
            "distribution": {
                "by_category": category_counts,
                "by_protocol": protocol_counts,
                "by_severity": severity_counts
            },
            "test_suites": {
                name: len(test_ids) for name, test_ids in self.test_suites.items()
            }
        }