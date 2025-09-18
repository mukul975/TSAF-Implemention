"""
Security Analyzer
Main component for security analysis coordination and threat detection.
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

import structlog

from tsaf.core.config import TSAFConfig
from tsaf.core.exceptions import TSAFException
from tsaf.analyzer.models import AnalysisRequest, AnalysisResponse, VulnerabilityCategory, SeverityLevel
from tsaf.detector.static_analyzer import StaticAnalyzer

logger = structlog.get_logger(__name__)


class SecurityAnalyzer:
    """
    Main security analyzer that coordinates different detection methods.

    Combines static analysis, pattern matching, and various security checks
    to provide comprehensive threat detection.
    """

    def __init__(self, config: TSAFConfig):
        self.config = config
        self.static_analyzer = None
        self.ml_detector = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize security analyzer components."""
        if self._initialized:
            return

        logger.info("Initializing Security Analyzer")

        try:
            # Initialize static analyzer
            detector_config = getattr(self.config, 'detector', {})
            if hasattr(detector_config, 'dict'):
                detector_config = detector_config.dict()
            elif not isinstance(detector_config, dict):
                detector_config = {}
            self.static_analyzer = StaticAnalyzer(detector_config)

            # Try to initialize ML detector if available
            try:
                from tsaf.detector.ml_detector import MLThreatDetector
                ml_config = getattr(self.config, 'detector', self.config)
                self.ml_detector = MLThreatDetector(ml_config)
                await self.ml_detector.initialize()
                logger.info("ML detector initialized successfully")
            except ImportError:
                logger.info("ML detector not available - using static analysis only")
            except Exception as e:
                logger.warning("ML detector initialization failed", error=str(e))

            self._initialized = True
            logger.info("Security Analyzer initialization completed")

        except Exception as e:
            logger.error("Security Analyzer initialization failed", error=str(e))
            raise TSAFException(f"Security Analyzer initialization failed: {str(e)}")

    async def analyze_message(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Perform comprehensive security analysis of a message.

        Args:
            request: Analysis request containing message and metadata

        Returns:
            Analysis response with vulnerabilities and risk assessment
        """
        if not self._initialized:
            raise TSAFException("Security Analyzer not initialized")

        start_time = datetime.utcnow()
        vulnerabilities = []

        try:
            # Static analysis
            static_vulns = self.static_analyzer.analyze_message(
                request.message,
                {"agent_id": request.agent_id, "protocol": request.protocol.value}
            )
            vulnerabilities.extend(static_vulns)

            # ML-based detection if available
            if self.ml_detector:
                try:
                    ml_vulns = await self.ml_detector.detect_threats(
                        request.message,
                        {"agent_id": request.agent_id, "protocol": request.protocol.value}
                    )
                    vulnerabilities.extend(ml_vulns)
                except Exception as e:
                    logger.warning("ML detection failed", error=str(e))

            # Calculate risk score
            risk_score = self._calculate_risk_score(vulnerabilities)

            # Create response
            response = AnalysisResponse(
                request_id=request.request_id,
                vulnerabilities=vulnerabilities,
                risk_score=risk_score,
                analysis_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
                analyzer_version="1.0.0",
                metadata={
                    "static_vulns": len(static_vulns),
                    "ml_vulns": len(ml_vulns) if self.ml_detector else 0,
                    "protocol": request.protocol.value,
                    "agent_id": request.agent_id
                }
            )

            logger.info(
                "Security analysis completed",
                request_id=request.request_id,
                vulnerabilities_found=len(vulnerabilities),
                risk_score=risk_score,
                analysis_time_ms=response.analysis_time_ms
            )

            return response

        except Exception as e:
            logger.error("Security analysis failed", request_id=request.request_id, error=str(e))
            # Return safe response with error
            return AnalysisResponse(
                request_id=request.request_id,
                vulnerabilities=[],
                risk_score=0.0,
                analysis_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
                analyzer_version="1.0.0",
                metadata={"error": str(e)}
            )

    def _calculate_risk_score(self, vulnerabilities: List[Any]) -> float:
        """Calculate overall risk score based on detected vulnerabilities."""
        if not vulnerabilities:
            return 0.0

        # Weight vulnerabilities by severity
        severity_weights = {
            SeverityLevel.LOW: 0.2,
            SeverityLevel.MEDIUM: 0.5,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.CRITICAL: 1.0
        }

        total_score = 0.0
        for vuln in vulnerabilities:
            # Handle both old and new vulnerability formats
            if hasattr(vuln, 'severity'):
                if isinstance(vuln.severity, str):
                    # Convert string severity to enum
                    try:
                        severity = SeverityLevel(vuln.severity.lower())
                    except ValueError:
                        severity = SeverityLevel.MEDIUM
                else:
                    severity = vuln.severity
            else:
                # Fallback for old format
                severity = SeverityLevel.MEDIUM

            weight = severity_weights.get(severity, 0.5)
            confidence = getattr(vuln, 'confidence', 0.8)
            total_score += weight * confidence

        # Normalize to 0-1 range (assume max of 5 critical vulns = 1.0 risk)
        normalized_score = min(total_score / 5.0, 1.0)
        return round(normalized_score, 3)

    async def get_supported_protocols(self) -> List[str]:
        """Get list of supported protocols for analysis."""
        return ["MCP", "A2A", "FIPA-ACL", "ACP"]

    async def get_analyzer_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics and health information."""
        return {
            "initialized": self._initialized,
            "static_analyzer_available": self.static_analyzer is not None,
            "ml_detector_available": self.ml_detector is not None,
            "supported_protocols": await self.get_supported_protocols(),
            "supported_languages": self.static_analyzer.get_supported_languages() if self.static_analyzer else []
        }

    async def shutdown(self) -> None:
        """Shutdown security analyzer and cleanup resources."""
        logger.info("Shutting down Security Analyzer")

        if self.ml_detector:
            try:
                await self.ml_detector.shutdown()
            except Exception as e:
                logger.warning("ML detector shutdown failed", error=str(e))

        self._initialized = False
        logger.info("Security Analyzer shutdown completed")