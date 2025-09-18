"""
Database Models
SQLAlchemy models for TSAF framework.
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Dict, List, Optional, Any

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID

Base = declarative_base()


class ProtocolTypeDB(PyEnum):
    """Database enum for protocol types."""
    MCP = "mcp"
    A2A = "a2a"
    FIPA_ACL = "fipa_acl"
    ACP = "acp"


class VulnerabilityCategoryDB(PyEnum):
    """Database enum for vulnerability categories."""
    ISV = "isv"  # Input Sanitization Vulnerability
    PIV = "piv"  # Protocol Injection Vulnerability
    SCV = "scv"  # State Corruption Vulnerability
    CPRV = "cprv"  # Cross-Protocol Relay Vulnerability
    TIV = "tiv"  # Translation Integrity Vulnerability
    CEV = "cev"  # Command Execution Vulnerability


class SeverityLevel(PyEnum):
    """Database enum for severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Agent(Base):
    """Agent model for tracking agent information and reputation."""
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255))
    description = Column(Text)
    protocol_types = Column(JSON)  # List of supported protocols

    # Reputation tracking
    reputation_score = Column(Float, default=0.0)
    interaction_count = Column(Integer, default=0)
    successful_interactions = Column(Integer, default=0)
    failed_interactions = Column(Integer, default=0)

    # Security metrics
    security_violations = Column(Integer, default=0)
    last_violation_date = Column(DateTime)
    trust_level = Column(String(50), default="unknown")  # unknown, trusted, suspicious, compromised

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    messages = relationship("Message", back_populates="agent")
    security_events = relationship("SecurityEvent", back_populates="agent")

    __table_args__ = (
        Index("idx_agent_reputation", "reputation_score"),
        Index("idx_agent_trust", "trust_level"),
    )


class Message(Base):
    """Message model for storing analyzed messages."""
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id = Column(String(255), unique=True, nullable=False, index=True)

    # Agent information
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    from_agent = Column(String(255))
    to_agent = Column(String(255))

    # Protocol information
    protocol_type = Column(String(50), nullable=False)  # ProtocolTypeDB enum
    protocol_version = Column(String(50))

    # Message content
    raw_content = Column(Text, nullable=False)
    parsed_content = Column(JSON)
    message_type = Column(String(100))

    # Analysis results
    analysis_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_malicious = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)

    # Security assessment
    vulnerabilities_detected = Column(JSON)  # List of vulnerability categories
    security_flags = Column(JSON)

    # Metadata
    size_bytes = Column(Integer)
    processing_time_ms = Column(Float)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    agent = relationship("Agent", back_populates="messages")
    vulnerabilities = relationship("Vulnerability", back_populates="message")
    translations = relationship("Translation", foreign_keys="Translation.source_message_id")

    __table_args__ = (
        Index("idx_message_timestamp", "analysis_timestamp"),
        Index("idx_message_protocol", "protocol_type"),
        Index("idx_message_malicious", "is_malicious"),
        Index("idx_message_risk", "risk_score"),
    )


class Vulnerability(Base):
    """Vulnerability detection model."""
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Message association
    message_id = Column(UUID(as_uuid=True), ForeignKey("messages.id"), nullable=False)

    # Vulnerability details
    category = Column(String(50), nullable=False)  # VulnerabilityCategoryDB enum
    subcategory = Column(String(100))
    severity = Column(String(50), nullable=False)  # SeverityLevel enum
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0

    # Detection information
    detector_name = Column(String(100), nullable=False)
    detection_method = Column(String(100))  # static, dynamic, ml, behavioral
    pattern_matched = Column(String(255))

    # Vulnerability description
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text)

    # Location information
    field_path = Column(String(255))  # JSON path to vulnerable field
    line_number = Column(Integer)

    # Evidence
    evidence = Column(JSON)
    context = Column(JSON)

    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    message = relationship("Message", back_populates="vulnerabilities")

    __table_args__ = (
        Index("idx_vulnerability_category", "category"),
        Index("idx_vulnerability_severity", "severity"),
        Index("idx_vulnerability_confidence", "confidence"),
        Index("idx_vulnerability_detected", "detected_at"),
    )


class Translation(Base):
    """Translation model for cross-protocol translations."""
    __tablename__ = "translations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    translation_id = Column(String(255), unique=True, nullable=False, index=True)

    # Source message
    source_message_id = Column(UUID(as_uuid=True), ForeignKey("messages.id"), nullable=False)
    source_protocol = Column(String(50), nullable=False)
    source_content = Column(JSON, nullable=False)

    # Target protocol
    target_protocol = Column(String(50), nullable=False)
    target_content = Column(JSON, nullable=False)
    target_raw = Column(Text)

    # Translation metadata
    translation_method = Column(String(100))
    semantic_similarity = Column(Float)  # 0.0 to 1.0
    security_preserved = Column(Boolean, default=True)

    # Analysis results
    is_secure = Column(Boolean, default=True)
    security_issues = Column(JSON)
    risk_score = Column(Float, default=0.0)

    # Performance metrics
    translation_time_ms = Column(Float)
    validation_time_ms = Column(Float)

    # Timestamps
    translated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    source_message = relationship("Message", foreign_keys=[source_message_id], overlaps="translations")
    verification_results = relationship("VerificationResult", back_populates="translation")

    __table_args__ = (
        Index("idx_translation_protocols", "source_protocol", "target_protocol"),
        Index("idx_translation_secure", "is_secure"),
        Index("idx_translation_timestamp", "translated_at"),
    )


class SecurityEvent(Base):
    """Security event model for tracking security incidents."""
    __tablename__ = "security_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(String(255), unique=True, nullable=False, index=True)

    # Event classification
    event_type = Column(String(100), nullable=False)  # attack_detected, policy_violation, etc.
    severity = Column(String(50), nullable=False)  # SeverityLevel enum
    category = Column(String(100))

    # Agent and message association
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"))
    message_id = Column(UUID(as_uuid=True), ForeignKey("messages.id"))

    # Event details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    source_ip = Column(String(45))  # IPv6 compatible

    # Context and evidence
    event_data = Column(JSON)
    attack_vector = Column(String(255))
    indicators = Column(JSON)

    # Response information
    response_action = Column(String(255))
    response_status = Column(String(100))  # pending, acknowledged, resolved
    resolved_at = Column(DateTime)

    # Timestamps
    occurred_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    agent = relationship("Agent", back_populates="security_events")

    __table_args__ = (
        Index("idx_event_type", "event_type"),
        Index("idx_event_severity", "severity"),
        Index("idx_event_timestamp", "occurred_at"),
        Index("idx_event_status", "response_status"),
    )


class VerificationResult(Base):
    """Formal verification result model."""
    __tablename__ = "verification_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Translation association
    translation_id = Column(UUID(as_uuid=True), ForeignKey("translations.id"))

    # Verification details
    verification_tool = Column(String(100), nullable=False)  # proverif, tamarin, tlaplus
    specification_type = Column(String(100))

    # Results
    verified = Column(Boolean, nullable=False)
    properties_verified = Column(JSON)
    properties_failed = Column(JSON)

    # Tool-specific results
    tool_output = Column(JSON)
    raw_output = Column(Text)

    # Performance metrics
    verification_time_ms = Column(Float)
    states_explored = Column(Integer)
    memory_used_mb = Column(Float)

    # Timestamps
    verified_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    translation = relationship("Translation", back_populates="verification_results")

    __table_args__ = (
        Index("idx_verification_tool", "verification_tool"),
        Index("idx_verification_result", "verified"),
        Index("idx_verification_timestamp", "verified_at"),
    )


class AuditLog(Base):
    """Audit log model for tracking system operations."""
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Operation details
    operation = Column(String(255), nullable=False)
    operation_type = Column(String(100), nullable=False)  # create, read, update, delete
    resource_type = Column(String(100))
    resource_id = Column(String(255))

    # User/system information
    user_id = Column(String(255))
    system_component = Column(String(100))
    source_ip = Column(String(45))

    # Request details
    request_data = Column(JSON)
    response_data = Column(JSON)
    status_code = Column(Integer)

    # Timing and performance
    duration_ms = Column(Float)

    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_audit_operation", "operation"),
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
    )


class SystemMetrics(Base):
    """System metrics model for performance monitoring."""
    __tablename__ = "system_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Metric identification
    metric_name = Column(String(255), nullable=False)
    metric_type = Column(String(100), nullable=False)  # counter, gauge, histogram
    component = Column(String(100))

    # Metric values
    value = Column(Float, nullable=False)
    unit = Column(String(50))

    # Labels and tags
    labels = Column(JSON)

    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_metrics_name", "metric_name"),
        Index("idx_metrics_timestamp", "timestamp"),
        Index("idx_metrics_component", "component"),
    )


class Configuration(Base):
    """Configuration model for system settings."""
    __tablename__ = "configurations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Configuration identification
    key = Column(String(255), unique=True, nullable=False, index=True)
    category = Column(String(100))

    # Configuration value
    value = Column(JSON, nullable=False)
    default_value = Column(JSON)

    # Metadata
    description = Column(Text)
    data_type = Column(String(50))  # string, integer, boolean, json, etc.
    is_sensitive = Column(Boolean, default=False)

    # Validation
    validation_rules = Column(JSON)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(255))

    __table_args__ = (
        Index("idx_config_category", "category"),
        Index("idx_config_sensitive", "is_sensitive"),
    )