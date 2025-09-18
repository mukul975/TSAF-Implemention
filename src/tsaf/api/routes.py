"""
API Routes
FastAPI routes for TSAF framework endpoints.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Path, Body, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

import structlog

from tsaf.core.engine import TSAFEngine
from tsaf.analyzer.models import (
    AnalysisRequest, AnalysisResponse, ProtocolType, VulnerabilityCategory
)
from tsaf.translator.models import TranslationResponse
from tsaf.database.connection import get_database_manager
from tsaf.database.repositories import (
    AgentRepository, MessageRepository, VulnerabilityRepository,
    TranslationRepository, SecurityEventRepository, MetricsRepository
)

logger = structlog.get_logger(__name__)

# Create routers
analysis_router = APIRouter(prefix="/api/v1/analysis", tags=["Analysis"])
agents_router = APIRouter(prefix="/api/v1/agents", tags=["Agents"])
vulnerabilities_router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
translations_router = APIRouter(prefix="/api/v1/translations", tags=["Translations"])
security_router = APIRouter(prefix="/api/v1/security", tags=["Security"])
metrics_router = APIRouter(prefix="/api/v1/metrics", tags=["Metrics"])
admin_router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


# Pydantic models for API
class MessageAnalyzeRequest(BaseModel):
    """Request model for message analysis."""
    message: str
    protocol: ProtocolType
    agent_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class TranslationRequest(BaseModel):
    """Request model for protocol translation."""
    message: str
    source_protocol: ProtocolType
    target_protocol: ProtocolType
    agent_id: Optional[str] = None
    preserve_semantics: bool = True
    verify_security: bool = True
    enable_formal_verification: bool = False
    metadata: Optional[Dict[str, Any]] = None


class BulkAnalysisRequest(BaseModel):
    """Request model for bulk message analysis."""
    messages: List[MessageAnalyzeRequest]
    parallel_processing: bool = True
    max_concurrent: int = 10


class AgentRegistrationRequest(BaseModel):
    """Request model for agent registration."""
    agent_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    protocol_types: List[ProtocolType] = []


class SecurityEventResponse(BaseModel):
    """Response model for security events."""
    event_id: str
    event_type: str
    severity: str
    title: str
    description: str
    occurred_at: datetime
    agent_id: Optional[str] = None
    message_id: Optional[str] = None


# Dependencies
def get_tsaf_engine(request: Request) -> TSAFEngine:
    """Get TSAF engine instance."""
    return request.app.state.tsaf_engine


async def get_db_session():
    """Get database session."""
    db_manager = get_database_manager()
    async with db_manager.get_async_session() as session:
        yield session


# Analysis endpoints
@analysis_router.post("/analyze", response_model=AnalysisResponse)
async def analyze_message(
    request: MessageAnalyzeRequest,
    engine: TSAFEngine = Depends(get_tsaf_engine)
) -> AnalysisResponse:
    """
    Analyze a single message for security vulnerabilities.

    - **message**: The message content to analyze
    - **protocol**: The protocol type of the message
    - **agent_id**: Optional agent identifier
    - **metadata**: Optional additional metadata
    """
    try:
        analysis_request = AnalysisRequest(
            message=request.message,
            protocol=request.protocol,
            agent_id=request.agent_id,
            metadata=request.metadata or {}
        )

        result = await engine.analyze_message(analysis_request)

        logger.info(
            "Message analyzed",
            protocol=request.protocol.value,
            agent_id=request.agent_id,
            is_malicious=result.is_malicious,
            risk_score=result.risk_score
        )

        return result

    except Exception as e:
        logger.error("Message analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@analysis_router.post("/analyze/bulk")
async def analyze_bulk_messages(
    request: BulkAnalysisRequest,
    engine: TSAFEngine = Depends(get_tsaf_engine)
) -> Dict[str, Any]:
    """
    Analyze multiple messages in bulk.

    - **messages**: List of messages to analyze
    - **parallel_processing**: Enable parallel processing
    - **max_concurrent**: Maximum concurrent analysis tasks
    """
    try:
        results = []
        start_time = datetime.utcnow()

        # Convert requests
        analysis_requests = [
            AnalysisRequest(
                message=msg.message,
                protocol=msg.protocol,
                agent_id=msg.agent_id,
                metadata=msg.metadata or {}
            )
            for msg in request.messages
        ]

        # Process messages
        if request.parallel_processing:
            # Parallel processing with semaphore for concurrency control
            import asyncio
            semaphore = asyncio.Semaphore(request.max_concurrent)

            async def analyze_with_semaphore(req):
                async with semaphore:
                    return await engine.analyze_message(req)

            tasks = [analyze_with_semaphore(req) for req in analysis_requests]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Sequential processing
            for req in analysis_requests:
                try:
                    result = await engine.analyze_message(req)
                    results.append(result)
                except Exception as e:
                    results.append({"error": str(e)})

        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Aggregate statistics
        successful_analyses = len([r for r in results if not isinstance(r, Exception) and not isinstance(r, dict) or "error" not in r])
        malicious_count = len([r for r in results if hasattr(r, 'is_malicious') and r.is_malicious])

        return {
            "total_messages": len(request.messages),
            "successful_analyses": successful_analyses,
            "malicious_detected": malicious_count,
            "processing_time_ms": processing_time,
            "results": [result.dict() if hasattr(result, 'dict') else result for result in results]
        }

    except Exception as e:
        logger.error("Bulk analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")


# Translation endpoints
@translations_router.post("/translate")
async def translate_message(
    request: TranslationRequest,
    engine: TSAFEngine = Depends(get_tsaf_engine)
) -> TranslationResponse:
    """
    Translate message between protocols using advanced Translation Engine.

    - **message**: Message content to translate
    - **source_protocol**: Source protocol type
    - **target_protocol**: Target protocol type
    - **preserve_semantics**: Ensure semantic preservation
    - **verify_security**: Verify security properties
    - **enable_formal_verification**: Enable formal verification
    """
    try:
        result = await engine.translate_message(
            message=request.message,
            source_protocol=request.source_protocol,
            target_protocol=request.target_protocol,
            preserve_semantics=request.preserve_semantics,
            verify_security=request.verify_security,
            enable_formal_verification=getattr(request, 'enable_formal_verification', False)
        )

        return result

    except Exception as e:
        logger.error("Translation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Translation failed: {str(e)}")


@translations_router.get("/statistics")
async def get_translation_statistics(
    hours: int = Query(24, ge=1, le=168),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get translation statistics for the specified time period."""
    try:
        repo = TranslationRepository(session)
        stats = await repo.get_translation_statistics(hours)
        return stats

    except Exception as e:
        logger.error("Failed to get translation statistics", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


# Agent endpoints
@agents_router.post("/register")
async def register_agent(
    request: AgentRegistrationRequest,
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Register a new agent in the system.

    - **agent_id**: Unique identifier for the agent
    - **name**: Human-readable name
    - **description**: Agent description
    - **protocol_types**: Supported protocols
    """
    try:
        repo = AgentRepository(session)

        # Check if agent already exists
        existing = await repo.get_agent_by_agent_id(request.agent_id)
        if existing:
            raise HTTPException(status_code=409, detail="Agent already registered")

        agent = await repo.create_agent(
            agent_id=request.agent_id,
            name=request.name,
            description=request.description,
            protocol_types=[p.value for p in request.protocol_types]
        )
        await repo.commit()

        return {
            "agent_id": agent.agent_id,
            "name": agent.name,
            "description": agent.description,
            "protocol_types": agent.protocol_types,
            "reputation_score": agent.reputation_score,
            "trust_level": agent.trust_level,
            "created_at": agent.created_at
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Agent registration failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@agents_router.get("/{agent_id}")
async def get_agent(
    agent_id: str = Path(..., description="Agent ID"),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get agent information by ID."""
    try:
        repo = AgentRepository(session)
        agent = await repo.get_agent_by_agent_id(agent_id)

        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        return {
            "agent_id": agent.agent_id,
            "name": agent.name,
            "description": agent.description,
            "protocol_types": agent.protocol_types,
            "reputation_score": agent.reputation_score,
            "trust_level": agent.trust_level,
            "interaction_count": agent.interaction_count,
            "successful_interactions": agent.successful_interactions,
            "failed_interactions": agent.failed_interactions,
            "security_violations": agent.security_violations,
            "last_seen": agent.last_seen,
            "created_at": agent.created_at
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get agent", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get agent: {str(e)}")


@agents_router.get("/")
async def list_agents(
    trust_level: Optional[str] = Query(None, description="Filter by trust level"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """List agents with optional filtering."""
    try:
        repo = AgentRepository(session)

        if trust_level:
            agents = await repo.get_agents_by_trust_level(trust_level)
        else:
            # Get all agents with pagination
            agents = await repo.get_all_agents_paginated(limit=limit, offset=offset)

        agent_list = []
        for agent in agents:
            agent_list.append({
                "agent_id": agent.agent_id,
                "name": agent.name,
                "trust_level": agent.trust_level,
                "reputation_score": agent.reputation_score,
                "interaction_count": agent.interaction_count,
                "last_seen": agent.last_seen
            })

        return {
            "agents": agent_list,
            "total": len(agent_list),
            "limit": limit,
            "offset": offset
        }

    except Exception as e:
        logger.error("Failed to list agents", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to list agents: {str(e)}")


@agents_router.get("/statistics/overview")
async def get_agent_statistics(
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get overall agent statistics."""
    try:
        repo = AgentRepository(session)
        stats = await repo.get_agent_statistics()
        return stats

    except Exception as e:
        logger.error("Failed to get agent statistics", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


# Vulnerability endpoints
@vulnerabilities_router.get("/")
async def list_vulnerabilities(
    category: Optional[VulnerabilityCategory] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(100, ge=1, le=1000),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """List vulnerabilities with filtering options."""
    try:
        repo = VulnerabilityRepository(session)

        if category:
            vulns = await repo.get_vulnerabilities_by_category(category.value, hours)
        else:
            # Get all vulnerabilities (would need more repository methods)
            vulns = []

        vulnerability_list = []
        for vuln in vulns:
            vulnerability_list.append({
                "id": str(vuln.id),
                "category": vuln.category,
                "severity": vuln.severity,
                "confidence": vuln.confidence,
                "title": vuln.title,
                "description": vuln.description,
                "detector_name": vuln.detector_name,
                "detected_at": vuln.detected_at
            })

        return {
            "vulnerabilities": vulnerability_list,
            "total": len(vulnerability_list),
            "filters": {
                "category": category.value if category else None,
                "severity": severity,
                "hours": hours
            }
        }

    except Exception as e:
        logger.error("Failed to list vulnerabilities", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to list vulnerabilities: {str(e)}")


@vulnerabilities_router.get("/trends")
async def get_vulnerability_trends(
    days: int = Query(7, ge=1, le=30),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get vulnerability trends over time."""
    try:
        repo = VulnerabilityRepository(session)
        trends = await repo.get_vulnerability_trends(days)
        return {"trends": trends, "period_days": days}

    except Exception as e:
        logger.error("Failed to get vulnerability trends", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {str(e)}")


# Security endpoints
@security_router.get("/events")
async def get_security_events(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=1000),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get security events."""
    try:
        repo = SecurityEventRepository(session)

        if severity:
            events = await repo.get_security_events_by_severity(severity, hours, limit)
        else:
            events = await repo.get_unresolved_events()

        event_list = []
        for event in events:
            event_list.append({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "title": event.title,
                "description": event.description,
                "occurred_at": event.occurred_at,
                "response_status": event.response_status,
                "agent_id": str(event.agent_id) if event.agent_id else None
            })

        return {
            "events": event_list,
            "total": len(event_list),
            "filters": {
                "severity": severity,
                "hours": hours
            }
        }

    except Exception as e:
        logger.error("Failed to get security events", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get events: {str(e)}")


# Metrics endpoints
@metrics_router.get("/system")
async def get_system_metrics(
    component: Optional[str] = Query(None, description="Filter by component"),
    hours: int = Query(1, ge=1, le=24),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get system metrics."""
    try:
        repo = MetricsRepository(session)

        # Get various metrics
        metrics = {}

        # Example metrics to fetch
        metric_names = [
            "message_processing_rate",
            "analysis_latency",
            "memory_usage",
            "cpu_utilization",
            "error_rate"
        ]

        for metric_name in metric_names:
            history = await repo.get_metric_history(metric_name, hours, component)
            if history:
                metrics[metric_name] = {
                    "current_value": history[0].value,
                    "history": [{"timestamp": m.timestamp, "value": m.value} for m in history]
                }

        return {
            "metrics": metrics,
            "component": component,
            "period_hours": hours
        }

    except Exception as e:
        logger.error("Failed to get system metrics", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")


# Admin endpoints
@admin_router.get("/health")
async def health_check() -> Dict[str, Any]:
    """System health check."""
    try:
        db_manager = get_database_manager()
        db_health = await db_manager.get_health_status()

        return {
            "status": "healthy",
            "timestamp": datetime.utcnow(),
            "database": db_health,
            "version": "1.0.0"
        }

    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow(),
            "error": str(e)
        }


@admin_router.get("/status")
async def get_system_status(
    engine: TSAFEngine = Depends(get_tsaf_engine)
) -> Dict[str, Any]:
    """Get detailed system status."""
    try:
        status = await engine.get_status()

        return {
            "system_status": status,
            "uptime": status.get("uptime_seconds", 0),
            "components": status.get("components", {}),
            "performance": status.get("performance", {})
        }

    except Exception as e:
        logger.error("Failed to get system status", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


@metrics_router.get("/dashboard")
async def get_monitoring_dashboard(
    time_range: str = Query("24h", description="Time range (1h, 6h, 24h, 7d)"),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get comprehensive monitoring dashboard data."""
    try:
        # Parse time range
        time_mapping = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7)
        }
        time_delta = time_mapping.get(time_range, timedelta(hours=24))
        start_time = datetime.utcnow() - time_delta

        # Get repositories
        agent_repo = AgentRepository(session)
        message_repo = MessageRepository(session)
        vuln_repo = VulnerabilityRepository(session)
        translation_repo = TranslationRepository(session)
        metrics_repo = MetricsRepository(session)

        # Get database manager for health check
        db_manager = get_database_manager()

        # Collect comprehensive metrics
        dashboard_data = {
            "time_range": time_range,
            "generated_at": datetime.utcnow().isoformat(),
            "system_health": await db_manager.get_health_status(),
            "summary": {
                "total_agents": await agent_repo.get_total_count(),
                "active_agents": await agent_repo.get_active_count(hours=24),
                "total_messages": await message_repo.get_total_count(),
                "messages_analyzed": await message_repo.get_analyzed_count(start_time),
                "total_vulnerabilities": await vuln_repo.get_total_count(),
                "high_severity_vulns": await vuln_repo.get_high_severity_count(start_time),
                "total_translations": await translation_repo.get_total_count(),
                "successful_translations": await translation_repo.get_successful_count(start_time)
            },
            "security_analytics": {
                "vulnerability_distribution": await vuln_repo.get_vulnerability_distribution(start_time),
                "threat_trends": await message_repo.get_threat_trends(start_time),
                "protocol_security": await message_repo.get_protocol_security_stats(start_time),
                "risk_score_distribution": await message_repo.get_risk_score_distribution(start_time)
            },
            "performance_metrics": {
                "analysis_performance": await metrics_repo.get_analysis_performance(start_time),
                "translation_performance": await metrics_repo.get_translation_performance(start_time),
                "system_resource_usage": await metrics_repo.get_resource_usage(start_time),
                "error_rates": await metrics_repo.get_error_rates(start_time)
            },
            "protocol_analytics": {
                "protocol_usage": await message_repo.get_protocol_usage_stats(start_time),
                "translation_flows": await translation_repo.get_translation_flows(start_time),
                "protocol_errors": await message_repo.get_protocol_error_stats(start_time)
            },
            "agent_analytics": {
                "agent_activity": await agent_repo.get_activity_stats(start_time),
                "reputation_distribution": await agent_repo.get_reputation_distribution(),
                "trust_level_stats": await agent_repo.get_trust_level_stats()
            }
        }

        return dashboard_data

    except Exception as e:
        logger.error("Failed to get monitoring dashboard", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")


@metrics_router.get("/prometheus")
async def get_prometheus_metrics():
    """Get Prometheus-formatted metrics."""
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        from tsaf.monitoring.metrics import get_metrics_registry

        registry = get_metrics_registry()
        metrics_data = generate_latest(registry)

        return Response(
            content=metrics_data,
            media_type=CONTENT_TYPE_LATEST
        )
    except Exception as e:
        logger.error("Failed to get Prometheus metrics", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")


@metrics_router.get("/alerts")
async def get_active_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    session = Depends(get_db_session)
) -> Dict[str, Any]:
    """Get active security alerts and notifications."""
    try:
        from tsaf.monitoring.alerting import AlertManager

        alert_manager = AlertManager()
        alerts = await alert_manager.get_active_alerts(severity_filter=severity)

        return {
            "active_alerts": alerts,
            "total_count": len(alerts),
            "severity_counts": {
                "critical": len([a for a in alerts if a.get("severity") == "critical"]),
                "high": len([a for a in alerts if a.get("severity") == "high"]),
                "medium": len([a for a in alerts if a.get("severity") == "medium"]),
                "low": len([a for a in alerts if a.get("severity") == "low"])
            }
        }
    except Exception as e:
        logger.error("Failed to get alerts", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")


# Combine all routers
def create_api_router() -> APIRouter:
    """Create and configure the main API router."""
    main_router = APIRouter()

    # Include all sub-routers
    main_router.include_router(analysis_router)
    main_router.include_router(agents_router)
    main_router.include_router(vulnerabilities_router)
    main_router.include_router(translations_router)
    main_router.include_router(security_router)
    main_router.include_router(metrics_router)
    main_router.include_router(admin_router)

    return main_router