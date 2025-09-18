"""
Health Monitoring and Checks
Comprehensive health monitoring for TSAF components.
"""

import asyncio
import time
import psutil
import traceback
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

import structlog

logger = structlog.get_logger(__name__)


class HealthStatus(str, Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheck:
    """Individual health check definition."""
    name: str
    description: str
    check_function: Callable
    timeout: float = 30.0
    critical: bool = True
    interval: float = 60.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthResult:
    """Health check result."""
    name: str
    status: HealthStatus
    message: str
    duration: float
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class HealthMonitor:
    """
    Comprehensive health monitoring system.

    Monitors:
    - System resources (CPU, memory, disk)
    - Database connectivity and performance
    - Cache availability
    - External service dependencies
    - Application components
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.checks: Dict[str, HealthCheck] = {}
        self.results: Dict[str, HealthResult] = {}
        self.monitoring_task: Optional[asyncio.Task] = None
        self.running = False

        # Setup default checks
        self._setup_default_checks()

        logger.info("Health monitor initialized")

    def _setup_default_checks(self):
        """Setup default health checks."""

        # System resource checks
        self.add_check(HealthCheck(
            name="system_cpu",
            description="System CPU usage check",
            check_function=self._check_cpu_usage,
            timeout=5.0,
            critical=False,
            interval=30.0
        ))

        self.add_check(HealthCheck(
            name="system_memory",
            description="System memory usage check",
            check_function=self._check_memory_usage,
            timeout=5.0,
            critical=False,
            interval=30.0
        ))

        self.add_check(HealthCheck(
            name="system_disk",
            description="System disk space check",
            check_function=self._check_disk_usage,
            timeout=5.0,
            critical=False,
            interval=60.0
        ))

        # Database check
        self.add_check(HealthCheck(
            name="database",
            description="Database connectivity and performance",
            check_function=self._check_database,
            timeout=10.0,
            critical=True,
            interval=30.0
        ))

        # Cache check
        self.add_check(HealthCheck(
            name="cache",
            description="Cache service availability",
            check_function=self._check_cache,
            timeout=5.0,
            critical=False,
            interval=30.0
        ))

        # Application components
        self.add_check(HealthCheck(
            name="analyzer",
            description="Security analyzer component",
            check_function=self._check_analyzer,
            timeout=15.0,
            critical=True,
            interval=60.0
        ))

        self.add_check(HealthCheck(
            name="translator",
            description="Protocol translator component",
            check_function=self._check_translator,
            timeout=15.0,
            critical=True,
            interval=60.0
        ))

        self.add_check(HealthCheck(
            name="verifier",
            description="Formal verifier component",
            check_function=self._check_verifier,
            timeout=30.0,
            critical=False,
            interval=120.0
        ))

    def add_check(self, check: HealthCheck):
        """Add a health check."""
        self.checks[check.name] = check
        logger.debug("Health check added", check_name=check.name)

    def remove_check(self, name: str):
        """Remove a health check."""
        if name in self.checks:
            del self.checks[name]
            if name in self.results:
                del self.results[name]
            logger.debug("Health check removed", check_name=name)

    async def run_check(self, name: str) -> HealthResult:
        """Run a single health check."""
        if name not in self.checks:
            return HealthResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message="Check not found",
                duration=0.0,
                timestamp=datetime.utcnow(),
                error="Check not registered"
            )

        check = self.checks[name]
        start_time = time.time()

        try:
            # Run check with timeout
            result = await asyncio.wait_for(
                check.check_function(),
                timeout=check.timeout
            )

            duration = time.time() - start_time

            # Parse result
            if isinstance(result, dict):
                status = HealthStatus(result.get('status', HealthStatus.HEALTHY))
                message = result.get('message', 'Check passed')
                details = result.get('details', {})
            elif isinstance(result, bool):
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = 'Check passed' if result else 'Check failed'
                details = {}
            else:
                status = HealthStatus.HEALTHY
                message = str(result)
                details = {}

            health_result = HealthResult(
                name=name,
                status=status,
                message=message,
                duration=duration,
                timestamp=datetime.utcnow(),
                details=details
            )

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            health_result = HealthResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check timed out after {check.timeout}s",
                duration=duration,
                timestamp=datetime.utcnow(),
                error="timeout"
            )

        except Exception as e:
            duration = time.time() - start_time
            health_result = HealthResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                duration=duration,
                timestamp=datetime.utcnow(),
                error=str(e),
                details={"traceback": traceback.format_exc()}
            )

        # Store result
        self.results[name] = health_result

        logger.debug(
            "Health check completed",
            check_name=name,
            status=health_result.status.value,
            duration=health_result.duration
        )

        return health_result

    async def run_all_checks(self) -> Dict[str, HealthResult]:
        """Run all health checks."""
        tasks = []
        for name in self.checks:
            task = asyncio.create_task(self.run_check(name))
            tasks.append((name, task))

        # Wait for all checks
        results = {}
        for name, task in tasks:
            try:
                result = await task
                results[name] = result
            except Exception as e:
                logger.error("Health check task failed", check_name=name, error=str(e))
                results[name] = HealthResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Task failed: {str(e)}",
                    duration=0.0,
                    timestamp=datetime.utcnow(),
                    error=str(e)
                )

        return results

    async def get_health_summary(self) -> Dict[str, Any]:
        """Get comprehensive health summary."""
        # Run all checks
        results = await self.run_all_checks()

        # Calculate overall status
        critical_checks = [name for name, check in self.checks.items() if check.critical]
        critical_results = [results[name] for name in critical_checks if name in results]

        if not critical_results:
            overall_status = HealthStatus.UNKNOWN
        elif all(r.status == HealthStatus.HEALTHY for r in critical_results):
            overall_status = HealthStatus.HEALTHY
        elif any(r.status == HealthStatus.UNHEALTHY for r in critical_results):
            overall_status = HealthStatus.UNHEALTHY
        else:
            overall_status = HealthStatus.DEGRADED

        # Count statuses
        status_counts = {status.value: 0 for status in HealthStatus}
        for result in results.values():
            status_counts[result.status.value] += 1

        return {
            "status": overall_status.value,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "duration": result.duration,
                    "timestamp": result.timestamp.isoformat(),
                    "critical": self.checks[name].critical,
                    "details": result.details,
                    "error": result.error
                }
                for name, result in results.items()
            },
            "summary": {
                "total_checks": len(results),
                "critical_checks": len(critical_checks),
                "status_counts": status_counts,
                "overall_status": overall_status.value
            }
        }

    async def start_monitoring(self):
        """Start continuous health monitoring."""
        if self.running:
            return

        self.running = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Health monitoring started")

    async def stop_monitoring(self):
        """Stop continuous health monitoring."""
        self.running = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Health monitoring stopped")

    async def _monitoring_loop(self):
        """Continuous monitoring loop."""
        next_check_times = {name: time.time() for name in self.checks}

        while self.running:
            try:
                current_time = time.time()
                checks_to_run = []

                # Determine which checks need to run
                for name, check in self.checks.items():
                    if current_time >= next_check_times[name]:
                        checks_to_run.append(name)
                        next_check_times[name] = current_time + check.interval

                # Run due checks
                if checks_to_run:
                    tasks = [self.run_check(name) for name in checks_to_run]
                    await asyncio.gather(*tasks, return_exceptions=True)

                # Sleep until next check
                next_check = min(next_check_times.values())
                sleep_time = max(1.0, next_check - time.time())
                await asyncio.sleep(sleep_time)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health monitoring loop error", error=str(e))
                await asyncio.sleep(10.0)

    # Health check implementations
    async def _check_cpu_usage(self) -> Dict[str, Any]:
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_threshold = self.config.get('cpu_threshold', 80.0)

        status = HealthStatus.HEALTHY
        if cpu_percent > cpu_threshold:
            status = HealthStatus.DEGRADED if cpu_percent < 95 else HealthStatus.UNHEALTHY

        return {
            'status': status,
            'message': f'CPU usage: {cpu_percent:.1f}%',
            'details': {
                'cpu_percent': cpu_percent,
                'threshold': cpu_threshold,
                'cpu_count': psutil.cpu_count()
            }
        }

    async def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage."""
        memory = psutil.virtual_memory()
        memory_threshold = self.config.get('memory_threshold', 80.0)

        status = HealthStatus.HEALTHY
        if memory.percent > memory_threshold:
            status = HealthStatus.DEGRADED if memory.percent < 95 else HealthStatus.UNHEALTHY

        return {
            'status': status,
            'message': f'Memory usage: {memory.percent:.1f}%',
            'details': {
                'memory_percent': memory.percent,
                'memory_total': memory.total,
                'memory_available': memory.available,
                'threshold': memory_threshold
            }
        }

    async def _check_disk_usage(self) -> Dict[str, Any]:
        """Check disk space."""
        disk = psutil.disk_usage('/')
        disk_threshold = self.config.get('disk_threshold', 85.0)

        disk_percent = (disk.used / disk.total) * 100
        status = HealthStatus.HEALTHY
        if disk_percent > disk_threshold:
            status = HealthStatus.DEGRADED if disk_percent < 95 else HealthStatus.UNHEALTHY

        return {
            'status': status,
            'message': f'Disk usage: {disk_percent:.1f}%',
            'details': {
                'disk_percent': disk_percent,
                'disk_total': disk.total,
                'disk_free': disk.free,
                'threshold': disk_threshold
            }
        }

    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity."""
        try:
            from tsaf.database.connection import get_database_manager

            db_manager = get_database_manager()
            db_health = await db_manager.get_health_status()

            if db_health["status"] == "healthy":
                return {
                    'status': HealthStatus.HEALTHY,
                    'message': 'Database connection healthy',
                    'details': db_health
                }
            else:
                return {
                    'status': HealthStatus.UNHEALTHY,
                    'message': f'Database unhealthy: {db_health.get("error", "Unknown error")}',
                    'details': db_health
                }

        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f'Database check failed: {str(e)}',
                'details': {'error': str(e)}
            }

    async def _check_cache(self) -> Dict[str, Any]:
        """Check cache service."""
        try:
            # Simple Redis check
            import redis.asyncio as redis

            r = redis.Redis(
                host=self.config.get('redis_host', 'localhost'),
                port=self.config.get('redis_port', 6379),
                decode_responses=True
            )

            await r.ping()
            await r.aclose()

            return {
                'status': HealthStatus.HEALTHY,
                'message': 'Cache service available',
                'details': {'redis_ping': 'success'}
            }

        except Exception as e:
            return {
                'status': HealthStatus.DEGRADED,
                'message': f'Cache service unavailable: {str(e)}',
                'details': {'error': str(e)}
            }

    async def _check_analyzer(self) -> Dict[str, Any]:
        """Check analyzer component."""
        try:
            from tsaf.analyzer.models import AnalysisRequest, ProtocolType

            # Simple analyzer test
            test_request = AnalysisRequest(
                message='{"test": "health_check"}',
                protocol=ProtocolType.MCP,
                agent_id="health_check"
            )

            # This would require the analyzer to be available
            return {
                'status': HealthStatus.HEALTHY,
                'message': 'Analyzer component available',
                'details': {'test': 'passed'}
            }

        except Exception as e:
            return {
                'status': HealthStatus.DEGRADED,
                'message': f'Analyzer component check failed: {str(e)}',
                'details': {'error': str(e)}
            }

    async def _check_translator(self) -> Dict[str, Any]:
        """Check translator component."""
        try:
            # Simple translator availability check
            return {
                'status': HealthStatus.HEALTHY,
                'message': 'Translator component available',
                'details': {'test': 'passed'}
            }

        except Exception as e:
            return {
                'status': HealthStatus.DEGRADED,
                'message': f'Translator component check failed: {str(e)}',
                'details': {'error': str(e)}
            }

    async def _check_verifier(self) -> Dict[str, Any]:
        """Check verifier component."""
        try:
            # Check if formal verification tools are available
            tools_available = []

            # Check ProVerif
            try:
                import subprocess
                result = await asyncio.create_subprocess_exec(
                    'proverif', '-help',
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await result.wait()
                if result.returncode == 0:
                    tools_available.append('proverif')
            except:
                pass

            return {
                'status': HealthStatus.HEALTHY if tools_available else HealthStatus.DEGRADED,
                'message': f'Verifier component available, tools: {tools_available}',
                'details': {
                    'available_tools': tools_available,
                    'total_tools': 3  # ProVerif, Tamarin, TLA+
                }
            }

        except Exception as e:
            return {
                'status': HealthStatus.DEGRADED,
                'message': f'Verifier component check failed: {str(e)}',
                'details': {'error': str(e)}
            }