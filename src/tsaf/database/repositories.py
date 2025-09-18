"""
Database Repositories
Data access layer for TSAF framework.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

import structlog
from sqlalchemy import func, and_, or_, desc, asc, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tsaf.database.models import (
    Agent, Message, Vulnerability, Translation, SecurityEvent,
    VerificationResult, AuditLog, SystemMetrics, Configuration,
    VulnerabilityCategoryDB, SeverityLevel
)
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class BaseRepository:
    """Base repository with common database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, model_class, record_id: uuid.UUID):
        """Get record by ID."""
        return await self.session.get(model_class, record_id)

    async def create(self, model_instance):
        """Create a new record."""
        self.session.add(model_instance)
        await self.session.flush()
        return model_instance

    async def update(self, model_instance):
        """Update an existing record."""
        await self.session.merge(model_instance)
        await self.session.flush()
        return model_instance

    async def delete(self, model_instance):
        """Delete a record."""
        await self.session.delete(model_instance)
        await self.session.flush()

    async def commit(self):
        """Commit the session."""
        await self.session.commit()

    async def rollback(self):
        """Rollback the session."""
        await self.session.rollback()


class AgentRepository(BaseRepository):
    """Repository for agent operations."""

    async def create_agent(
        self,
        agent_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        protocol_types: Optional[List[str]] = None
    ) -> Agent:
        """Create a new agent."""
        agent = Agent(
            agent_id=agent_id,
            name=name,
            description=description,
            protocol_types=protocol_types or []
        )
        return await self.create(agent)

    async def get_agent_by_agent_id(self, agent_id: str) -> Optional[Agent]:
        """Get agent by agent ID."""
        result = await self.session.execute(
            text("SELECT * FROM agents WHERE agent_id = :agent_id"),
            {"agent_id": agent_id}
        )
        return result.first()

    async def update_agent_reputation(
        self,
        agent_id: str,
        successful: bool,
        violation: bool = False
    ) -> Optional[Agent]:
        """Update agent reputation based on interaction outcome."""
        agent = await self.get_agent_by_agent_id(agent_id)
        if not agent:
            return None

        agent.interaction_count += 1
        agent.last_seen = datetime.utcnow()

        if successful:
            agent.successful_interactions += 1
        else:
            agent.failed_interactions += 1

        if violation:
            agent.security_violations += 1
            agent.last_violation_date = datetime.utcnow()

        # Calculate reputation score
        total_interactions = agent.interaction_count
        success_rate = agent.successful_interactions / max(total_interactions, 1)
        violation_penalty = min(agent.security_violations * 0.1, 0.5)
        agent.reputation_score = max(0.0, success_rate - violation_penalty)

        # Update trust level
        if agent.security_violations > 10:
            agent.trust_level = "compromised"
        elif agent.security_violations > 5:
            agent.trust_level = "suspicious"
        elif agent.reputation_score > 0.8:
            agent.trust_level = "trusted"
        else:
            agent.trust_level = "unknown"

        return await self.update(agent)

    async def get_agents_by_trust_level(self, trust_level: str) -> List[Agent]:
        """Get agents by trust level."""
        result = await self.session.execute(
            text("SELECT * FROM agents WHERE trust_level = :trust_level"),
            {"trust_level": trust_level}
        )
        return result.fetchall()

    async def get_all_agents_paginated(self, limit: int = 100, offset: int = 0) -> List[Agent]:
        """Get all agents with pagination."""
        result = await self.session.execute(
            text("""
                SELECT * FROM agents
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"limit": limit, "offset": offset}
        )
        return result.fetchall()

    async def get_agent_statistics(self) -> Dict[str, Any]:
        """Get agent statistics."""
        result = await self.session.execute(text("""
            SELECT
                COUNT(*) as total_agents,
                AVG(reputation_score) as avg_reputation,
                COUNT(CASE WHEN trust_level = 'trusted' THEN 1 END) as trusted_agents,
                COUNT(CASE WHEN trust_level = 'suspicious' THEN 1 END) as suspicious_agents,
                COUNT(CASE WHEN trust_level = 'compromised' THEN 1 END) as compromised_agents,
                SUM(interaction_count) as total_interactions,
                SUM(security_violations) as total_violations
            FROM agents
        """))

        row = result.first()
        return {
            "total_agents": row.total_agents or 0,
            "average_reputation": float(row.avg_reputation or 0),
            "trusted_agents": row.trusted_agents or 0,
            "suspicious_agents": row.suspicious_agents or 0,
            "compromised_agents": row.compromised_agents or 0,
            "total_interactions": row.total_interactions or 0,
            "total_violations": row.total_violations or 0
        }

    async def get_total_count(self) -> int:
        """Get total number of agents."""
        result = await self.session.execute(text("SELECT COUNT(*) as count FROM agents"))
        row = result.first()
        return row.count if row else 0

    async def get_active_count(self, hours: int = 24) -> int:
        """Get number of active agents in last N hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        result = await self.session.execute(
            text("SELECT COUNT(*) as count FROM agents WHERE last_seen >= :cutoff"),
            {"cutoff": cutoff}
        )
        row = result.first()
        return row.count if row else 0

    async def get_activity_stats(self, since: datetime) -> Dict[str, Any]:
        """Get agent activity statistics."""
        result = await self.session.execute(
            text("""
                SELECT
                    COUNT(*) as total_agents,
                    COUNT(CASE WHEN last_seen >= :since THEN 1 END) as active_agents,
                    AVG(reputation_score) as avg_reputation
                FROM agents
            """),
            {"since": since}
        )
        row = result.first()
        return {
            "total_agents": row.total_agents if row else 0,
            "active_agents": row.active_agents if row else 0,
            "avg_reputation": float(row.avg_reputation or 0)
        }

    async def get_reputation_distribution(self) -> Dict[str, int]:
        """Get reputation score distribution."""
        result = await self.session.execute(
            text("""
                SELECT
                    CASE
                        WHEN reputation_score >= 0.8 THEN 'high'
                        WHEN reputation_score >= 0.6 THEN 'medium'
                        WHEN reputation_score >= 0.4 THEN 'low'
                        ELSE 'very_low'
                    END as reputation_range,
                    COUNT(*) as count
                FROM agents
                GROUP BY reputation_range
            """)
        )
        return {row.reputation_range: row.count for row in result.fetchall()}

    async def get_trust_level_stats(self) -> Dict[str, int]:
        """Get trust level distribution."""
        result = await self.session.execute(
            text("SELECT trust_level, COUNT(*) as count FROM agents GROUP BY trust_level")
        )
        return {row.trust_level: row.count for row in result.fetchall()}


class MessageRepository(BaseRepository):
    """Repository for message operations."""

    async def create_message(
        self,
        message_id: str,
        agent_id: uuid.UUID,
        protocol_type: str,
        raw_content: str,
        parsed_content: Dict[str, Any],
        from_agent: Optional[str] = None,
        to_agent: Optional[str] = None,
        message_type: Optional[str] = None
    ) -> Message:
        """Create a new message record."""
        message = Message(
            message_id=message_id,
            agent_id=agent_id,
            protocol_type=protocol_type,
            raw_content=raw_content,
            parsed_content=parsed_content,
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            size_bytes=len(raw_content)
        )
        return await self.create(message)

    async def update_message_analysis(
        self,
        message_id: str,
        is_malicious: bool,
        risk_score: float,
        vulnerabilities_detected: List[str],
        security_flags: Dict[str, Any],
        processing_time_ms: float
    ) -> Optional[Message]:
        """Update message with analysis results."""
        result = await self.session.execute(
            text("SELECT * FROM messages WHERE message_id = :message_id"),
            {"message_id": message_id}
        )
        message = result.first()
        if not message:
            return None

        # Update analysis results
        import json
        await self.session.execute(
            text("""
                UPDATE messages SET
                    is_malicious = :is_malicious,
                    risk_score = :risk_score,
                    vulnerabilities_detected = :vulnerabilities,
                    security_flags = :security_flags,
                    processing_time_ms = :processing_time
                WHERE message_id = :message_id
            """),
            {
                "message_id": message_id,
                "is_malicious": is_malicious,
                "risk_score": risk_score,
                "vulnerabilities": json.dumps(vulnerabilities_detected),
                "security_flags": json.dumps(security_flags),
                "processing_time": processing_time_ms
            }
        )

        return message

    async def get_messages_by_protocol(
        self,
        protocol_type: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Message]:
        """Get messages by protocol type."""
        result = await self.session.execute(
            text("""
                SELECT * FROM messages
                WHERE protocol_type = :protocol_type
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {
                "protocol_type": protocol_type,
                "limit": limit,
                "offset": offset
            }
        )
        return result.fetchall()

    async def get_malicious_messages(
        self,
        hours: int = 24,
        min_risk_score: float = 0.5
    ) -> List[Message]:
        """Get malicious messages from the last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)

        result = await self.session.execute(
            text("""
                SELECT * FROM messages
                WHERE is_malicious = true
                AND risk_score >= :min_risk_score
                AND analysis_timestamp >= :since
                ORDER BY risk_score DESC, analysis_timestamp DESC
            """),
            {
                "min_risk_score": min_risk_score,
                "since": since
            }
        )
        return result.fetchall()

    async def get_message_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get message statistics for the last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)

        result = await self.session.execute(
            text("""
                SELECT
                    COUNT(*) as total_messages,
                    COUNT(CASE WHEN is_malicious = true THEN 1 END) as malicious_messages,
                    AVG(risk_score) as avg_risk_score,
                    AVG(processing_time_ms) as avg_processing_time,
                    protocol_type,
                    COUNT(*) as protocol_count
                FROM messages
                WHERE analysis_timestamp >= :since
                GROUP BY protocol_type
            """),
            {"since": since}
        )

        rows = result.fetchall()
        protocol_stats = {}
        total_messages = 0
        malicious_messages = 0
        avg_risk = 0.0
        avg_processing_time = 0.0

        for row in rows:
            protocol_stats[row.protocol_type] = {
                "count": row.protocol_count,
                "malicious": row.malicious_messages,
                "avg_risk_score": float(row.avg_risk_score or 0),
                "avg_processing_time_ms": float(row.avg_processing_time or 0)
            }
            total_messages += row.protocol_count
            malicious_messages += row.malicious_messages

        if rows:
            avg_risk = sum(stats["avg_risk_score"] for stats in protocol_stats.values()) / len(protocol_stats)
            avg_processing_time = sum(stats["avg_processing_time_ms"] for stats in protocol_stats.values()) / len(protocol_stats)

        return {
            "total_messages": total_messages,
            "malicious_messages": malicious_messages,
            "malicious_percentage": (malicious_messages / max(total_messages, 1)) * 100,
            "average_risk_score": avg_risk,
            "average_processing_time_ms": avg_processing_time,
            "protocol_statistics": protocol_stats
        }


class VulnerabilityRepository(BaseRepository):
    """Repository for vulnerability operations."""

    async def create_vulnerability(
        self,
        message_id: uuid.UUID,
        category: str,
        severity: str,
        confidence: float,
        detector_name: str,
        title: str,
        description: str,
        **kwargs
    ) -> Vulnerability:
        """Create a new vulnerability record."""
        vulnerability = Vulnerability(
            message_id=message_id,
            category=category,
            severity=severity,
            confidence=confidence,
            detector_name=detector_name,
            title=title,
            description=description,
            **kwargs
        )
        return await self.create(vulnerability)

    async def get_vulnerabilities_by_category(
        self,
        category: str,
        hours: int = 24
    ) -> List[Vulnerability]:
        """Get vulnerabilities by category."""
        since = datetime.utcnow() - timedelta(hours=hours)

        result = await self.session.execute(
            text("""
                SELECT v.*, m.message_id, m.protocol_type
                FROM vulnerabilities v
                JOIN messages m ON v.message_id = m.id
                WHERE v.category = :category
                AND v.detected_at >= :since
                ORDER BY v.confidence DESC, v.detected_at DESC
            """),
            {"category": category, "since": since}
        )
        return result.fetchall()

    async def get_vulnerability_trends(self, days: int = 7) -> Dict[str, Any]:
        """Get vulnerability trends over time."""
        since = datetime.utcnow() - timedelta(days=days)

        result = await self.session.execute(
            text("""
                SELECT
                    DATE(detected_at) as date,
                    category,
                    severity,
                    COUNT(*) as count
                FROM vulnerabilities
                WHERE detected_at >= :since
                GROUP BY DATE(detected_at), category, severity
                ORDER BY date DESC
            """),
            {"since": since}
        )

        trends = {}
        for row in result.fetchall():
            date_str = row.date.isoformat()
            if date_str not in trends:
                trends[date_str] = {}
            if row.category not in trends[date_str]:
                trends[date_str][row.category] = {}
            trends[date_str][row.category][row.severity] = row.count

        return trends


class TranslationRepository(BaseRepository):
    """Repository for translation operations."""

    async def create_translation(
        self,
        translation_id: str,
        source_message_id: uuid.UUID,
        source_protocol: str,
        source_content: Dict[str, Any],
        target_protocol: str,
        target_content: Dict[str, Any],
        target_raw: str,
        **kwargs
    ) -> Translation:
        """Create a new translation record."""
        translation = Translation(
            translation_id=translation_id,
            source_message_id=source_message_id,
            source_protocol=source_protocol,
            source_content=source_content,
            target_protocol=target_protocol,
            target_content=target_content,
            target_raw=target_raw,
            **kwargs
        )
        return await self.create(translation)

    async def get_translation_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get translation statistics."""
        since = datetime.utcnow() - timedelta(hours=hours)

        result = await self.session.execute(
            text("""
                SELECT
                    COUNT(*) as total_translations,
                    COUNT(CASE WHEN is_secure = true THEN 1 END) as secure_translations,
                    AVG(semantic_similarity) as avg_semantic_similarity,
                    AVG(translation_time_ms) as avg_translation_time,
                    source_protocol,
                    target_protocol,
                    COUNT(*) as translation_pair_count
                FROM translations
                WHERE translated_at >= :since
                GROUP BY source_protocol, target_protocol
            """),
            {"since": since}
        )

        translation_pairs = {}
        total_translations = 0
        secure_translations = 0

        for row in result.fetchall():
            pair_key = f"{row.source_protocol}_to_{row.target_protocol}"
            translation_pairs[pair_key] = {
                "count": row.translation_pair_count,
                "avg_semantic_similarity": float(row.avg_semantic_similarity or 0),
                "avg_translation_time_ms": float(row.avg_translation_time or 0)
            }
            total_translations += row.translation_pair_count
            secure_translations += row.secure_translations or 0

        return {
            "total_translations": total_translations,
            "secure_translations": secure_translations,
            "security_rate": (secure_translations / max(total_translations, 1)) * 100,
            "translation_pairs": translation_pairs
        }


class SecurityEventRepository(BaseRepository):
    """Repository for security event operations."""

    async def create_security_event(
        self,
        event_type: str,
        severity: str,
        title: str,
        description: str,
        agent_id: Optional[uuid.UUID] = None,
        message_id: Optional[uuid.UUID] = None,
        **kwargs
    ) -> SecurityEvent:
        """Create a new security event."""
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            title=title,
            description=description,
            agent_id=agent_id,
            message_id=message_id,
            **kwargs
        )
        return await self.create(event)

    async def get_security_events_by_severity(
        self,
        severity: str,
        hours: int = 24,
        limit: int = 100
    ) -> List[SecurityEvent]:
        """Get security events by severity."""
        since = datetime.utcnow() - timedelta(hours=hours)

        result = await self.session.execute(
            text("""
                SELECT * FROM security_events
                WHERE severity = :severity
                AND occurred_at >= :since
                ORDER BY occurred_at DESC
                LIMIT :limit
            """),
            {"severity": severity, "since": since, "limit": limit}
        )
        return result.fetchall()

    async def get_unresolved_events(self) -> List[SecurityEvent]:
        """Get unresolved security events."""
        result = await self.session.execute(
            text("""
                SELECT * FROM security_events
                WHERE response_status IN ('pending', 'acknowledged')
                ORDER BY severity DESC, occurred_at DESC
            """)
        )
        return result.fetchall()


class VerificationResultRepository(BaseRepository):
    """Repository for verification result operations."""

    async def create_verification_result(
        self,
        translation_id: uuid.UUID,
        verification_tool: str,
        verified: bool,
        properties_verified: List[str],
        properties_failed: List[str],
        tool_output: Dict[str, Any],
        **kwargs
    ) -> VerificationResult:
        """Create a new verification result."""
        result = VerificationResult(
            translation_id=translation_id,
            verification_tool=verification_tool,
            verified=verified,
            properties_verified=properties_verified,
            properties_failed=properties_failed,
            tool_output=tool_output,
            **kwargs
        )
        return await self.create(result)


class ConfigurationRepository(BaseRepository):
    """Repository for configuration operations."""

    async def get_config(self, key: str) -> Optional[Configuration]:
        """Get configuration by key."""
        result = await self.session.execute(
            text("SELECT * FROM configurations WHERE key = :key"),
            {"key": key}
        )
        return result.first()

    async def set_config(
        self,
        key: str,
        value: Any,
        category: Optional[str] = None,
        description: Optional[str] = None,
        is_sensitive: bool = False
    ) -> Configuration:
        """Set configuration value."""
        existing = await self.get_config(key)

        if existing:
            await self.session.execute(
                text("""
                    UPDATE configurations SET
                        value = :value,
                        updated_at = :updated_at
                    WHERE key = :key
                """),
                {
                    "key": key,
                    "value": value,
                    "updated_at": datetime.utcnow()
                }
            )
            return existing
        else:
            config = Configuration(
                key=key,
                value=value,
                category=category,
                description=description,
                is_sensitive=is_sensitive
            )
            return await self.create(config)

    async def get_configs_by_category(self, category: str) -> List[Configuration]:
        """Get all configurations in a category."""
        result = await self.session.execute(
            text("SELECT * FROM configurations WHERE category = :category"),
            {"category": category}
        )
        return result.fetchall()


class MetricsRepository(BaseRepository):
    """Repository for metrics operations."""

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        metric_type: str = "gauge",
        component: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None
    ) -> SystemMetrics:
        """Record a system metric."""
        metric = SystemMetrics(
            metric_name=metric_name,
            metric_type=metric_type,
            component=component,
            value=value,
            labels=labels or {}
        )
        return await self.create(metric)

    async def get_metric_history(
        self,
        metric_name: str,
        hours: int = 24,
        component: Optional[str] = None
    ) -> List[SystemMetrics]:
        """Get metric history."""
        since = datetime.utcnow() - timedelta(hours=hours)

        query = """
            SELECT * FROM system_metrics
            WHERE metric_name = :metric_name
            AND timestamp >= :since
        """
        params = {"metric_name": metric_name, "since": since}

        if component:
            query += " AND component = :component"
            params["component"] = component

        query += " ORDER BY timestamp DESC"

        result = await self.session.execute(text(query), params)
        return result.fetchall()