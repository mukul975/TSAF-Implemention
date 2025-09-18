"""
Metrics Collection and Monitoring
Prometheus-compatible metrics for TSAF framework.
"""

import time
from typing import Dict, Any, Optional
from collections import defaultdict
from functools import wraps

from prometheus_client import (
    Counter, Histogram, Gauge, Info, Enum,
    CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
)
import structlog

logger = structlog.get_logger(__name__)


class TSAFMetrics:
    """
    TSAF metrics collector using Prometheus client.

    Provides comprehensive metrics for:
    - Request/response tracking
    - Analysis performance
    - Vulnerability detection
    - Translation success rates
    - System health
    """

    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        self._setup_metrics()

    def _setup_metrics(self):
        """Initialize all metric collectors."""

        # Application info
        self.app_info = Info(
            'tsaf_application_info',
            'TSAF application information',
            registry=self.registry
        )

        # Request metrics
        self.http_requests_total = Counter(
            'tsaf_http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )

        self.http_request_duration = Histogram(
            'tsaf_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry
        )

        self.http_request_size = Histogram(
            'tsaf_http_request_size_bytes',
            'HTTP request size in bytes',
            ['method', 'endpoint'],
            buckets=[100, 1000, 10000, 100000, 1000000, 10000000],
            registry=self.registry
        )

        # Analysis metrics
        self.messages_analyzed_total = Counter(
            'tsaf_messages_analyzed_total',
            'Total messages analyzed',
            ['protocol', 'agent_id'],
            registry=self.registry
        )

        self.analysis_duration = Histogram(
            'tsaf_analysis_duration_seconds',
            'Message analysis duration in seconds',
            ['protocol', 'analysis_type'],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
            registry=self.registry
        )

        self.vulnerabilities_detected_total = Counter(
            'tsaf_vulnerabilities_detected_total',
            'Total vulnerabilities detected',
            ['category', 'severity', 'protocol'],
            registry=self.registry
        )

        self.risk_score_distribution = Histogram(
            'tsaf_risk_score_distribution',
            'Distribution of risk scores',
            ['protocol'],
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            registry=self.registry
        )

        self.malicious_messages_total = Counter(
            'tsaf_malicious_messages_total',
            'Total malicious messages detected',
            ['protocol', 'confidence_level'],
            registry=self.registry
        )

        # Translation metrics
        self.translations_total = Counter(
            'tsaf_translations_total',
            'Total protocol translations',
            ['source_protocol', 'target_protocol', 'status'],
            registry=self.registry
        )

        self.translation_duration = Histogram(
            'tsaf_translation_duration_seconds',
            'Translation duration in seconds',
            ['source_protocol', 'target_protocol'],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
            registry=self.registry
        )

        self.semantic_similarity = Histogram(
            'tsaf_semantic_similarity_score',
            'Semantic similarity scores for translations',
            ['source_protocol', 'target_protocol'],
            buckets=[0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98, 0.99, 1.0],
            registry=self.registry
        )

        # Verification metrics
        self.verifications_total = Counter(
            'tsaf_verifications_total',
            'Total formal verifications',
            ['tool', 'status'],
            registry=self.registry
        )

        self.verification_duration = Histogram(
            'tsaf_verification_duration_seconds',
            'Formal verification duration in seconds',
            ['tool'],
            buckets=[1, 5, 10, 30, 60, 120, 300, 600],
            registry=self.registry
        )

        # Agent metrics
        self.active_agents = Gauge(
            'tsaf_active_agents',
            'Number of active agents',
            registry=self.registry
        )

        self.agent_reputation = Gauge(
            'tsaf_agent_reputation_score',
            'Agent reputation scores',
            ['agent_id', 'trust_level'],
            registry=self.registry
        )

        self.agent_interactions_total = Counter(
            'tsaf_agent_interactions_total',
            'Total agent interactions',
            ['agent_id', 'result'],
            registry=self.registry
        )

        # System metrics
        self.system_health = Enum(
            'tsaf_system_health',
            'System health status',
            states=['healthy', 'degraded', 'unhealthy'],
            registry=self.registry
        )

        self.component_status = Enum(
            'tsaf_component_status',
            'Component status',
            ['component'],
            states=['up', 'down', 'degraded'],
            registry=self.registry
        )

        self.database_connections = Gauge(
            'tsaf_database_connections',
            'Database connection pool metrics',
            ['pool', 'state'],
            registry=self.registry
        )

        self.memory_usage = Gauge(
            'tsaf_memory_usage_bytes',
            'Memory usage in bytes',
            ['type'],
            registry=self.registry
        )

        self.cpu_usage = Gauge(
            'tsaf_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )

        # Testing metrics
        self.security_tests_total = Counter(
            'tsaf_security_tests_total',
            'Total security tests executed',
            ['test_suite', 'result'],
            registry=self.registry
        )

        self.test_duration = Histogram(
            'tsaf_test_duration_seconds',
            'Security test duration in seconds',
            ['test_suite'],
            buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0],
            registry=self.registry
        )

        # Error metrics
        self.errors_total = Counter(
            'tsaf_errors_total',
            'Total errors by type',
            ['error_type', 'component'],
            registry=self.registry
        )

        # Cache metrics
        self.cache_operations_total = Counter(
            'tsaf_cache_operations_total',
            'Total cache operations',
            ['operation', 'result'],
            registry=self.registry
        )

        self.cache_hit_ratio = Gauge(
            'tsaf_cache_hit_ratio',
            'Cache hit ratio',
            ['cache_type'],
            registry=self.registry
        )

        # Set application info
        self.app_info.info({
            'version': '1.0.0',
            'name': 'TSAF',
            'description': 'Translation Security Analysis Framework'
        })

        logger.info("TSAF metrics initialized")

    def record_http_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration: float,
        request_size: int = 0
    ):
        """Record HTTP request metrics."""
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code)
        ).inc()

        self.http_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)

        if request_size > 0:
            self.http_request_size.labels(
                method=method,
                endpoint=endpoint
            ).observe(request_size)

    def record_analysis(
        self,
        protocol: str,
        agent_id: str,
        duration: float,
        analysis_type: str,
        vulnerabilities: list,
        risk_score: float,
        is_malicious: bool,
        confidence: float
    ):
        """Record message analysis metrics."""
        self.messages_analyzed_total.labels(
            protocol=protocol,
            agent_id=agent_id
        ).inc()

        self.analysis_duration.labels(
            protocol=protocol,
            analysis_type=analysis_type
        ).observe(duration)

        # Record vulnerabilities
        for vuln in vulnerabilities:
            self.vulnerabilities_detected_total.labels(
                category=vuln.get('category', 'unknown'),
                severity=vuln.get('severity', 'unknown'),
                protocol=protocol
            ).inc()

        # Record risk score
        self.risk_score_distribution.labels(protocol=protocol).observe(risk_score)

        # Record malicious detection
        if is_malicious:
            confidence_level = 'high' if confidence > 0.8 else 'medium' if confidence > 0.5 else 'low'
            self.malicious_messages_total.labels(
                protocol=protocol,
                confidence_level=confidence_level
            ).inc()

    def record_translation(
        self,
        source_protocol: str,
        target_protocol: str,
        duration: float,
        semantic_similarity: float,
        success: bool
    ):
        """Record translation metrics."""
        status = 'success' if success else 'failure'

        self.translations_total.labels(
            source_protocol=source_protocol,
            target_protocol=target_protocol,
            status=status
        ).inc()

        self.translation_duration.labels(
            source_protocol=source_protocol,
            target_protocol=target_protocol
        ).observe(duration)

        if success and semantic_similarity is not None:
            self.semantic_similarity.labels(
                source_protocol=source_protocol,
                target_protocol=target_protocol
            ).observe(semantic_similarity)

    def record_verification(
        self,
        tool: str,
        duration: float,
        success: bool
    ):
        """Record formal verification metrics."""
        status = 'success' if success else 'failure'

        self.verifications_total.labels(
            tool=tool,
            status=status
        ).inc()

        self.verification_duration.labels(tool=tool).observe(duration)

    def update_agent_metrics(self, agent_id: str, reputation: float, trust_level: str):
        """Update agent-related metrics."""
        self.agent_reputation.labels(
            agent_id=agent_id,
            trust_level=trust_level
        ).set(reputation)

    def record_agent_interaction(self, agent_id: str, success: bool):
        """Record agent interaction."""
        result = 'success' if success else 'failure'
        self.agent_interactions_total.labels(
            agent_id=agent_id,
            result=result
        ).inc()

    def update_system_health(self, status: str):
        """Update system health status."""
        self.system_health.state(status)

    def update_component_status(self, component: str, status: str):
        """Update component status."""
        self.component_status.labels(component=component).state(status)

    def update_database_metrics(self, pool_metrics: Dict[str, int]):
        """Update database connection metrics."""
        for state, count in pool_metrics.items():
            self.database_connections.labels(pool='main', state=state).set(count)

    def record_security_test(self, test_suite: str, duration: float, success: bool):
        """Record security test metrics."""
        result = 'pass' if success else 'fail'

        self.security_tests_total.labels(
            test_suite=test_suite,
            result=result
        ).inc()

        self.test_duration.labels(test_suite=test_suite).observe(duration)

    def record_error(self, error_type: str, component: str):
        """Record error occurrence."""
        self.errors_total.labels(
            error_type=error_type,
            component=component
        ).inc()

    def record_cache_operation(self, operation: str, success: bool):
        """Record cache operation."""
        result = 'hit' if success and operation == 'get' else 'miss' if operation == 'get' else 'success' if success else 'failure'

        self.cache_operations_total.labels(
            operation=operation,
            result=result
        ).inc()

    def update_cache_hit_ratio(self, cache_type: str, ratio: float):
        """Update cache hit ratio."""
        self.cache_hit_ratio.labels(cache_type=cache_type).set(ratio)

    def get_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        """Get Prometheus metrics content type."""
        return CONTENT_TYPE_LATEST


# Global metrics instance
_metrics_instance: Optional[TSAFMetrics] = None


def get_metrics() -> TSAFMetrics:
    """Get global metrics instance."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = TSAFMetrics()
    return _metrics_instance


def metrics_middleware(func):
    """Decorator for automatic metrics collection."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        metrics = get_metrics()

        try:
            result = await func(*args, **kwargs)

            # Record success metrics based on function type
            duration = time.time() - start_time

            if hasattr(func, '__name__'):
                if 'analyze' in func.__name__:
                    # Analysis function - record specific analysis metrics
                    self.analysis_duration.labels(
                        protocol=kwargs.get('protocol', 'unknown'),
                        analysis_type=kwargs.get('analysis_type', 'security')
                    ).observe(duration)
                    if success:
                        self.messages_analyzed_total.labels(
                            protocol=kwargs.get('protocol', 'unknown'),
                            agent_id=kwargs.get('agent_id', 'unknown')
                        ).inc()
                elif 'translate' in func.__name__:
                    # Translation function - record translation metrics
                    self.translation_duration.labels(
                        from_protocol=kwargs.get('from_protocol', 'unknown'),
                        to_protocol=kwargs.get('to_protocol', 'unknown')
                    ).observe(duration)
                    self.translations_total.labels(
                        from_protocol=kwargs.get('from_protocol', 'unknown'),
                        to_protocol=kwargs.get('to_protocol', 'unknown'),
                        status='success' if success else 'failure'
                    ).inc()
                elif 'verify' in func.__name__:
                    # Verification function - record verification metrics
                    self.verification_duration.labels(
                        tool=kwargs.get('tool', 'unknown'),
                        verification_type=kwargs.get('verification_type', 'security')
                    ).observe(duration)
                    self.verifications_total.labels(
                        tool=kwargs.get('tool', 'unknown'),
                        status='success' if success else 'failure'
                    ).inc()

            return result

        except Exception as e:
            # Record error metrics
            metrics.record_error(
                error_type=type(e).__name__,
                component=func.__module__ or 'unknown'
            )
            raise

    return wrapper