"""
Analyzer Models
Pydantic models for analysis requests and responses.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union

from pydantic import BaseModel, Field, validator


class ProtocolType(str, Enum):
    """Supported protocol types."""
    MCP = "mcp"
    A2A = "a2a"
    FIPA_ACL = "fipa_acl"
    ACP = "acp"


class VulnerabilityCategory(str, Enum):
    """Vulnerability categories in TSAF framework."""
    ISV = "isv"  # Input Sanitization Vulnerability
    PIV = "piv"  # Protocol Injection Vulnerability
    SCV = "scv"  # State Corruption Vulnerability
    CPRV = "cprv"  # Cross-Protocol Relay Vulnerability
    TIV = "tiv"  # Translation Integrity Vulnerability
    CEV = "cev"  # Command Execution Vulnerability


class SeverityLevel(str, Enum):
    """Severity levels for vulnerabilities."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionMethod(str, Enum):
    """Detection methods."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    ML = "ml"
    BEHAVIORAL = "behavioral"
    SIGNATURE = "signature"
    HEURISTIC = "heuristic"


class AnalysisRequest(BaseModel):
    """Request model for message analysis."""
    message: str = Field(..., description="Message content to analyze")
    protocol: ProtocolType = Field(..., description="Protocol type")
    agent_id: Optional[str] = Field(None, description="Agent identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    # Analysis options
    enable_static_analysis: bool = Field(default=True, description="Enable static analysis")
    enable_dynamic_analysis: bool = Field(default=True, description="Enable dynamic analysis")
    enable_ml_detection: bool = Field(default=True, description="Enable ML detection")
    enable_behavioral_analysis: bool = Field(default=True, description="Enable behavioral analysis")

    # Analysis parameters
    analysis_depth: str = Field(default="standard", description="Analysis depth: basic, standard, deep")
    timeout_seconds: int = Field(default=30, ge=1, le=300, description="Analysis timeout")

    class Config:
        json_encoders = {
            ProtocolType: lambda v: v.value
        }


class VulnerabilityDetail(BaseModel):
    """Detailed vulnerability information."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Vulnerability ID")
    category: VulnerabilityCategory = Field(..., description="Vulnerability category")
    subcategory: Optional[str] = Field(None, description="Subcategory")
    severity: SeverityLevel = Field(..., description="Severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")

    # Description
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    recommendation: Optional[str] = Field(None, description="Remediation recommendation")

    # Detection details
    detector_name: str = Field(..., description="Detector that found this vulnerability")
    detection_method: DetectionMethod = Field(..., description="Detection method")
    pattern_matched: Optional[str] = Field(None, description="Pattern that matched")

    # Location information
    field_path: Optional[str] = Field(None, description="JSON path to vulnerable field")
    line_number: Optional[int] = Field(None, description="Line number (if applicable)")
    start_pos: Optional[int] = Field(None, description="Start position in message")
    end_pos: Optional[int] = Field(None, description="End position in message")

    # Evidence
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")
    context: Dict[str, Any] = Field(default_factory=dict, description="Context information")

    # CVSS scoring (if applicable)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS base score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")

    class Config:
        json_encoders = {
            VulnerabilityCategory: lambda v: v.value,
            SeverityLevel: lambda v: v.value,
            DetectionMethod: lambda v: v.value
        }


class SecurityFlags(BaseModel):
    """Security flags and indicators."""
    contains_executable_code: bool = Field(default=False, description="Contains executable code")
    contains_sql_injection: bool = Field(default=False, description="Contains SQL injection patterns")
    contains_xss_payload: bool = Field(default=False, description="Contains XSS payload")
    contains_command_injection: bool = Field(default=False, description="Contains command injection")
    contains_path_traversal: bool = Field(default=False, description="Contains path traversal")
    contains_suspicious_urls: bool = Field(default=False, description="Contains suspicious URLs")
    contains_encoded_data: bool = Field(default=False, description="Contains encoded/obfuscated data")
    contains_crypto_keys: bool = Field(default=False, description="Contains cryptographic keys")
    violates_protocol_spec: bool = Field(default=False, description="Violates protocol specification")
    unusual_message_size: bool = Field(default=False, description="Unusual message size")
    high_entropy_content: bool = Field(default=False, description="High entropy content")


class AnalysisMetrics(BaseModel):
    """Analysis performance metrics."""
    total_time_ms: float = Field(..., description="Total analysis time in milliseconds")
    static_analysis_time_ms: Optional[float] = Field(None, description="Static analysis time")
    dynamic_analysis_time_ms: Optional[float] = Field(None, description="Dynamic analysis time")
    ml_analysis_time_ms: Optional[float] = Field(None, description="ML analysis time")
    behavioral_analysis_time_ms: Optional[float] = Field(None, description="Behavioral analysis time")

    # Resource usage
    memory_used_mb: Optional[float] = Field(None, description="Memory used in MB")
    cpu_time_ms: Optional[float] = Field(None, description="CPU time in milliseconds")

    # Detection statistics
    patterns_checked: int = Field(default=0, description="Number of patterns checked")
    signatures_matched: int = Field(default=0, description="Number of signatures matched")
    rules_evaluated: int = Field(default=0, description="Number of rules evaluated")


class AnalysisResponse(BaseModel):
    """Response model for message analysis."""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Analysis ID")
    message_hash: str = Field(..., description="SHA-256 hash of analyzed message")
    protocol: ProtocolType = Field(..., description="Protocol type")
    agent_id: Optional[str] = Field(None, description="Agent identifier")

    # Analysis results
    is_malicious: bool = Field(..., description="Whether message is malicious")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence")

    # Vulnerabilities
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list, description="Detected vulnerabilities")
    vulnerability_count: int = Field(default=0, description="Total vulnerability count")

    # Security assessment
    security_flags: SecurityFlags = Field(default_factory=SecurityFlags, description="Security flags")
    threat_indicators: List[str] = Field(default_factory=list, description="Threat indicators")

    # Analysis details
    analysis_methods_used: List[DetectionMethod] = Field(default_factory=list, description="Analysis methods used")
    detector_results: Dict[str, Any] = Field(default_factory=dict, description="Individual detector results")

    # Performance metrics
    metrics: AnalysisMetrics = Field(..., description="Analysis performance metrics")

    # Timestamps
    analyzed_at: datetime = Field(default_factory=datetime.utcnow, description="Analysis timestamp")
    expires_at: Optional[datetime] = Field(None, description="Result expiration timestamp")

    @validator("vulnerability_count", always=True)
    def set_vulnerability_count(cls, v, values):
        """Set vulnerability count based on vulnerabilities list."""
        if "vulnerabilities" in values:
            return len(values["vulnerabilities"])
        return v

    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in SeverityLevel}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    def get_category_counts(self) -> Dict[str, int]:
        """Get count of vulnerabilities by category."""
        counts = {category.value: 0 for category in VulnerabilityCategory}
        for vuln in self.vulnerabilities:
            counts[vuln.category.value] += 1
        return counts

    def get_highest_severity(self) -> Optional[SeverityLevel]:
        """Get the highest severity level found."""
        if not self.vulnerabilities:
            return None

        severity_order = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        highest = None

        for vuln in self.vulnerabilities:
            if highest is None or severity_order.index(vuln.severity) > severity_order.index(highest):
                highest = vuln.severity

        return highest

    class Config:
        json_encoders = {
            ProtocolType: lambda v: v.value,
            datetime: lambda v: v.isoformat()
        }


class BulkAnalysisRequest(BaseModel):
    """Request model for bulk analysis."""
    messages: List[AnalysisRequest] = Field(..., description="List of messages to analyze")
    analysis_mode: str = Field(default="parallel", description="Analysis mode: parallel, sequential")
    max_concurrent: int = Field(default=10, ge=1, le=100, description="Maximum concurrent analyses")
    fail_fast: bool = Field(default=False, description="Stop on first failure")


class BulkAnalysisResponse(BaseModel):
    """Response model for bulk analysis."""
    batch_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Batch ID")
    total_messages: int = Field(..., description="Total number of messages")
    successful_analyses: int = Field(..., description="Number of successful analyses")
    failed_analyses: int = Field(..., description="Number of failed analyses")

    # Results
    results: List[Union[AnalysisResponse, Dict[str, Any]]] = Field(default_factory=list, description="Analysis results")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Analysis errors")

    # Statistics
    total_vulnerabilities: int = Field(default=0, description="Total vulnerabilities found")
    malicious_messages: int = Field(default=0, description="Number of malicious messages")
    average_risk_score: float = Field(default=0.0, description="Average risk score")

    # Performance
    total_time_ms: float = Field(..., description="Total processing time")
    average_time_per_message_ms: float = Field(..., description="Average time per message")

    analyzed_at: datetime = Field(default_factory=datetime.utcnow, description="Analysis timestamp")


class ProtocolAnalysisResult(BaseModel):
    """Protocol-specific analysis results."""
    protocol: ProtocolType = Field(..., description="Protocol type")
    is_valid: bool = Field(..., description="Whether message is valid for protocol")
    validation_errors: List[str] = Field(default_factory=list, description="Validation errors")

    # Protocol-specific fields
    message_type: Optional[str] = Field(None, description="Message type")
    version: Optional[str] = Field(None, description="Protocol version")
    encoding: Optional[str] = Field(None, description="Message encoding")

    # Structure analysis
    structure_valid: bool = Field(default=True, description="Structure is valid")
    required_fields_present: bool = Field(default=True, description="Required fields present")
    unknown_fields: List[str] = Field(default_factory=list, description="Unknown fields found")

    # Security analysis
    security_compliant: bool = Field(default=True, description="Security compliant")
    security_violations: List[str] = Field(default_factory=list, description="Security violations")


class TranslationResult(BaseModel):
    """Translation result model."""
    translation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Translation ID")
    source_protocol: ProtocolType = Field(..., description="Source protocol")
    target_protocol: ProtocolType = Field(..., description="Target protocol")

    # Translation content
    source_message: str = Field(..., description="Original message")
    translated_message: str = Field(..., description="Translated message")

    # Quality metrics
    semantic_similarity: float = Field(..., ge=0.0, le=1.0, description="Semantic similarity score")
    translation_confidence: float = Field(..., ge=0.0, le=1.0, description="Translation confidence")

    # Security assessment
    security_preserved: bool = Field(..., description="Security properties preserved")
    security_issues: List[str] = Field(default_factory=list, description="Security issues found")

    # Verification results
    verification_results: Optional[Dict[str, Any]] = Field(None, description="Formal verification results")

    # Performance
    translation_time_ms: float = Field(..., description="Translation time")
    translated_at: datetime = Field(default_factory=datetime.utcnow, description="Translation timestamp")