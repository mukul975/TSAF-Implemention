"""
Translation Engine Models
Data models for protocol translation and analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
import uuid

from tsaf.analyzer.models import ProtocolType


class TranslationStatus(Enum):
    """Translation status enumeration."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SECURITY_VIOLATION = "security_violation"


class SemanticPreservationLevel(Enum):
    """Semantic preservation quality levels."""
    EXACT = "exact"          # 0.95+ similarity
    HIGH = "high"            # 0.85-0.94 similarity
    MEDIUM = "medium"        # 0.70-0.84 similarity
    LOW = "low"              # 0.50-0.69 similarity
    POOR = "poor"            # <0.50 similarity


@dataclass
class TranslationRequest:
    """Translation request model."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    message: str = ""
    source_protocol: ProtocolType = ProtocolType.MCP
    target_protocol: ProtocolType = ProtocolType.A2A
    preserve_semantics: bool = True
    verify_security: bool = True
    enable_formal_verification: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    agent_id: Optional[str] = None
    priority: int = 1  # 1=low, 5=high


@dataclass
class SemanticSimilarity:
    """Semantic similarity analysis results."""
    overall_similarity: float = 0.0
    bert_similarity: float = 0.0
    tfidf_similarity: float = 0.0
    jaccard_similarity: float = 0.0
    edit_distance_similarity: float = 0.0
    preservation_level: SemanticPreservationLevel = SemanticPreservationLevel.POOR
    confidence: float = 0.0
    analysis_method: str = "bert_ensemble"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityPreservation:
    """Security preservation analysis results."""
    is_preserved: bool = False
    preservation_score: float = 0.0
    vulnerabilities_added: int = 0
    vulnerabilities_removed: int = 0
    risk_score_change: float = 0.0
    security_properties_maintained: List[str] = field(default_factory=list)
    security_properties_lost: List[str] = field(default_factory=list)
    mitigation_required: bool = False
    analysis_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TranslationMetrics:
    """Translation performance metrics."""
    translation_time_ms: float = 0.0
    semantic_analysis_time_ms: float = 0.0
    security_analysis_time_ms: float = 0.0
    verification_time_ms: float = 0.0
    total_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0


@dataclass
class ProtocolAdapter:
    """Protocol adapter configuration."""
    protocol_type: ProtocolType
    parser_class: str
    formatter_class: str
    validation_rules: List[str] = field(default_factory=list)
    security_constraints: Dict[str, Any] = field(default_factory=dict)
    semantic_markers: List[str] = field(default_factory=list)


@dataclass
class TranslationResponse:
    """Complete translation response."""
    # Request information
    request_id: str = ""
    status: TranslationStatus = TranslationStatus.PENDING
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Translation results
    translated_message: str = ""
    source_protocol: ProtocolType = ProtocolType.MCP
    target_protocol: ProtocolType = ProtocolType.A2A
    translation_successful: bool = False

    # Analysis results
    semantic_similarity: SemanticSimilarity = field(default_factory=SemanticSimilarity)
    security_preservation: SecurityPreservation = field(default_factory=SecurityPreservation)

    # Verification results
    formal_verification_passed: bool = False
    verification_results: Dict[str, Any] = field(default_factory=dict)

    # Performance metrics
    metrics: TranslationMetrics = field(default_factory=TranslationMetrics)

    # Error handling
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    # Additional metadata
    translation_quality_score: float = 0.0
    recommended_actions: List[str] = field(default_factory=list)
    debug_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TranslationRule:
    """Protocol translation rule."""
    source_pattern: str
    target_template: str
    semantic_weight: float = 1.0
    security_critical: bool = False
    conditions: Dict[str, Any] = field(default_factory=dict)
    transformations: List[str] = field(default_factory=list)


@dataclass
class TranslationContext:
    """Translation context information."""
    session_id: Optional[str] = None
    agent_context: Dict[str, Any] = field(default_factory=dict)
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    security_policies: Dict[str, Any] = field(default_factory=dict)
    performance_constraints: Dict[str, Any] = field(default_factory=dict)