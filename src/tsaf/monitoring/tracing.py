"""
Distributed Tracing and Observability
OpenTelemetry-based tracing for TSAF framework.
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager
from functools import wraps

from opentelemetry import trace, metrics as otel_metrics
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

import structlog

logger = structlog.get_logger(__name__)


class TSAFTracer:
    """
    TSAF distributed tracing implementation.

    Provides comprehensive tracing for:
    - HTTP requests and responses
    - Database operations
    - Cache operations
    - Analysis workflows
    - Translation processes
    - Verification tasks
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.service_name = config.get('service_name', 'tsaf')
        self.service_version = config.get('service_version', '1.0.0')
        self.environment = config.get('environment', 'production')

        # Initialize tracing
        self._setup_tracing()
        self._setup_instrumentation()

        self.tracer = trace.get_tracer(__name__)
        self.meter = otel_metrics.get_meter(__name__)

        logger.info("TSAF tracing initialized")

    def _setup_tracing(self):
        """Setup OpenTelemetry tracing."""
        # Create resource
        resource = Resource.create({
            ResourceAttributes.SERVICE_NAME: self.service_name,
            ResourceAttributes.SERVICE_VERSION: self.service_version,
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.environment,
            ResourceAttributes.SERVICE_NAMESPACE: "tsaf",
        })

        # Setup tracer provider
        tracer_provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(tracer_provider)

        # Setup Jaeger exporter
        if self.config.get('jaeger_enabled', True):
            jaeger_exporter = JaegerExporter(
                agent_host_name=self.config.get('jaeger_host', 'localhost'),
                agent_port=self.config.get('jaeger_port', 6831),
            )

            # Add span processor
            span_processor = BatchSpanProcessor(jaeger_exporter)
            tracer_provider.add_span_processor(span_processor)

        # Setup metrics
        if self.config.get('prometheus_enabled', True):
            prometheus_reader = PrometheusMetricReader()
            meter_provider = MeterProvider(
                resource=resource,
                metric_readers=[prometheus_reader]
            )
            otel_metrics.set_meter_provider(meter_provider)

    def _setup_instrumentation(self):
        """Setup automatic instrumentation."""
        # Instrument FastAPI
        if self.config.get('instrument_fastapi', True):
            FastAPIInstrumentor().instrument()

        # Instrument SQLAlchemy
        if self.config.get('instrument_sqlalchemy', True):
            SQLAlchemyInstrumentor().instrument()

        # Instrument Redis
        if self.config.get('instrument_redis', True):
            RedisInstrumentor().instrument()

        # Instrument HTTP requests
        if self.config.get('instrument_requests', True):
            RequestsInstrumentor().instrument()

    @asynccontextmanager
    async def trace_analysis(
        self,
        message_id: str,
        protocol: str,
        agent_id: Optional[str] = None,
        analysis_type: str = "security"
    ):
        """Context manager for tracing message analysis."""
        with self.tracer.start_as_current_span(
            "tsaf.analysis",
            attributes={
                "tsaf.message.id": message_id,
                "tsaf.protocol": protocol,
                "tsaf.agent.id": agent_id or "unknown",
                "tsaf.analysis.type": analysis_type,
            }
        ) as span:
            start_time = time.time()
            try:
                yield span
                span.set_status(trace.Status(trace.StatusCode.OK))
            except Exception as e:
                span.set_status(
                    trace.Status(
                        trace.StatusCode.ERROR,
                        description=str(e)
                    )
                )
                span.record_exception(e)
                raise
            finally:
                duration = time.time() - start_time
                span.set_attribute("tsaf.analysis.duration", duration)

    @asynccontextmanager
    async def trace_translation(
        self,
        source_protocol: str,
        target_protocol: str,
        message_id: str
    ):
        """Context manager for tracing protocol translation."""
        with self.tracer.start_as_current_span(
            "tsaf.translation",
            attributes={
                "tsaf.translation.source_protocol": source_protocol,
                "tsaf.translation.target_protocol": target_protocol,
                "tsaf.message.id": message_id,
            }
        ) as span:
            start_time = time.time()
            try:
                yield span
                span.set_status(trace.Status(trace.StatusCode.OK))
            except Exception as e:
                span.set_status(
                    trace.Status(
                        trace.StatusCode.ERROR,
                        description=str(e)
                    )
                )
                span.record_exception(e)
                raise
            finally:
                duration = time.time() - start_time
                span.set_attribute("tsaf.translation.duration", duration)

    @asynccontextmanager
    async def trace_verification(
        self,
        tool: str,
        specification_type: str,
        verification_id: str
    ):
        """Context manager for tracing formal verification."""
        with self.tracer.start_as_current_span(
            "tsaf.verification",
            attributes={
                "tsaf.verification.tool": tool,
                "tsaf.verification.type": specification_type,
                "tsaf.verification.id": verification_id,
            }
        ) as span:
            start_time = time.time()
            try:
                yield span
                span.set_status(trace.Status(trace.StatusCode.OK))
            except Exception as e:
                span.set_status(
                    trace.Status(
                        trace.StatusCode.ERROR,
                        description=str(e)
                    )
                )
                span.record_exception(e)
                raise
            finally:
                duration = time.time() - start_time
                span.set_attribute("tsaf.verification.duration", duration)

    @asynccontextmanager
    async def trace_vulnerability_detection(
        self,
        detector_name: str,
        detection_method: str,
        message_id: str
    ):
        """Context manager for tracing vulnerability detection."""
        with self.tracer.start_as_current_span(
            "tsaf.vulnerability_detection",
            attributes={
                "tsaf.detector.name": detector_name,
                "tsaf.detector.method": detection_method,
                "tsaf.message.id": message_id,
            }
        ) as span:
            start_time = time.time()
            vulnerabilities_found = 0
            try:
                yield span
                span.set_status(trace.Status(trace.StatusCode.OK))
            except Exception as e:
                span.set_status(
                    trace.Status(
                        trace.StatusCode.ERROR,
                        description=str(e)
                    )
                )
                span.record_exception(e)
                raise
            finally:
                duration = time.time() - start_time
                span.set_attribute("tsaf.detection.duration", duration)
                span.set_attribute("tsaf.vulnerabilities.count", vulnerabilities_found)

    def trace_database_operation(
        self,
        operation: str,
        table: str,
        query_type: str = "select"
    ):
        """Trace database operations."""
        return self.tracer.start_as_current_span(
            "tsaf.database",
            attributes={
                "tsaf.db.operation": operation,
                "tsaf.db.table": table,
                "tsaf.db.query_type": query_type,
            }
        )

    def trace_cache_operation(
        self,
        operation: str,
        cache_type: str,
        key: str
    ):
        """Trace cache operations."""
        return self.tracer.start_as_current_span(
            "tsaf.cache",
            attributes={
                "tsaf.cache.operation": operation,
                "tsaf.cache.type": cache_type,
                "tsaf.cache.key": key,
            }
        )

    def add_span_attributes(self, attributes: Dict[str, Any]):
        """Add attributes to current span."""
        current_span = trace.get_current_span()
        if current_span:
            for key, value in attributes.items():
                current_span.set_attribute(key, value)

    def add_span_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add event to current span."""
        current_span = trace.get_current_span()
        if current_span:
            current_span.add_event(name, attributes or {})

    def record_exception(self, exception: Exception):
        """Record exception in current span."""
        current_span = trace.get_current_span()
        if current_span:
            current_span.record_exception(exception)


def trace_async_function(
    operation_name: str,
    component: str = "tsaf",
    attributes: Optional[Dict[str, Any]] = None
):
    """Decorator for tracing async functions."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = trace.get_tracer(__name__)

            span_attributes = {
                "tsaf.component": component,
                "tsaf.function": func.__name__,
            }

            if attributes:
                span_attributes.update(attributes)

            # Add function arguments as attributes
            if args:
                span_attributes["tsaf.args.count"] = len(args)

            if kwargs:
                for key, value in kwargs.items():
                    if isinstance(value, (str, int, float, bool)):
                        span_attributes[f"tsaf.kwargs.{key}"] = str(value)

            with tracer.start_as_current_span(
                operation_name,
                attributes=span_attributes
            ) as span:
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    span.set_status(trace.Status(trace.StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(
                        trace.Status(
                            trace.StatusCode.ERROR,
                            description=str(e)
                        )
                    )
                    span.record_exception(e)
                    raise
                finally:
                    duration = time.time() - start_time
                    span.set_attribute("tsaf.duration", duration)

        return wrapper
    return decorator


def trace_sync_function(
    operation_name: str,
    component: str = "tsaf",
    attributes: Optional[Dict[str, Any]] = None
):
    """Decorator for tracing sync functions."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = trace.get_tracer(__name__)

            span_attributes = {
                "tsaf.component": component,
                "tsaf.function": func.__name__,
            }

            if attributes:
                span_attributes.update(attributes)

            with tracer.start_as_current_span(
                operation_name,
                attributes=span_attributes
            ) as span:
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    span.set_status(trace.Status(trace.StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(
                        trace.Status(
                            trace.StatusCode.ERROR,
                            description=str(e)
                        )
                    )
                    span.record_exception(e)
                    raise
                finally:
                    duration = time.time() - start_time
                    span.set_attribute("tsaf.duration", duration)

        return wrapper
    return decorator


# Global tracer instance
_tracer_instance: Optional[TSAFTracer] = None


def get_tracer() -> Optional[TSAFTracer]:
    """Get global tracer instance."""
    return _tracer_instance


def initialize_tracing(config: Dict[str, Any]) -> TSAFTracer:
    """Initialize global tracing."""
    global _tracer_instance
    _tracer_instance = TSAFTracer(config)
    return _tracer_instance


def shutdown_tracing():
    """Shutdown tracing."""
    global _tracer_instance
    if _tracer_instance:
        # Cleanup if needed
        _tracer_instance = None
        logger.info("Tracing shutdown completed")