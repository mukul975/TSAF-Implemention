"""
Security Preservation Analyzer
Analyzes whether security properties are preserved during protocol translation.
"""

import asyncio
import time
from typing import Dict, Any, List, Set
import structlog

from .models import SecurityPreservation
from tsaf.analyzer.models import AnalysisRequest, ProtocolType, VulnerabilityCategory
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class SecurityPreservationAnalyzer:
    """
    Analyzes security property preservation during protocol translation.

    Ensures that translations do not introduce new vulnerabilities or
    compromise existing security properties.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.security_analyzer = None
        self._initialized = False

        # Security properties to monitor
        self.critical_properties = {
            'authentication',
            'authorization',
            'integrity',
            'confidentiality',
            'non_repudiation',
            'availability'
        }

        # Vulnerability severity weights
        self.severity_weights = {
            'critical': 4.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0
        }

    async def initialize(self, security_analyzer) -> None:
        """Initialize the security preservation analyzer."""
        if self._initialized:
            return

        logger.info("Initializing Security Preservation Analyzer")

        try:
            self.security_analyzer = security_analyzer
            self._initialized = True
            logger.info("Security Preservation Analyzer initialized successfully")

        except Exception as e:
            logger.error("Security Preservation Analyzer initialization failed", error=str(e))
            raise TSAFException(f"Security preservation analyzer initialization failed: {str(e)}")

    async def analyze_preservation(
        self,
        original_message: str,
        translated_message: str,
        source_protocol: ProtocolType,
        target_protocol: ProtocolType,
        context: Dict[str, Any] = None
    ) -> SecurityPreservation:
        """
        Analyze security preservation between original and translated messages.

        Args:
            original_message: Original message content
            translated_message: Translated message content
            source_protocol: Source protocol type
            target_protocol: Target protocol type
            context: Additional context for analysis

        Returns:
            SecurityPreservation analysis results
        """
        if not self._initialized:
            raise TSAFException("Security preservation analyzer not initialized")

        start_time = time.time()
        context = context or {}

        try:
            logger.info("Analyzing security preservation",
                       source_protocol=source_protocol.value,
                       target_protocol=target_protocol.value,
                       original_length=len(original_message),
                       translated_length=len(translated_message))

            # Analyze both messages for security properties
            original_analysis, translated_analysis = await asyncio.gather(
                self._analyze_message_security(original_message, source_protocol, context),
                self._analyze_message_security(translated_message, target_protocol, context)
            )

            # Compare security properties
            preservation_analysis = self._compare_security_properties(
                original_analysis, translated_analysis
            )

            # Calculate detailed preservation metrics
            preservation_score = self._calculate_preservation_score(
                original_analysis, translated_analysis
            )

            # Determine security properties changes
            properties_maintained, properties_lost = self._analyze_property_changes(
                original_analysis, translated_analysis
            )

            # Check for critical security violations
            mitigation_required = self._requires_mitigation(
                original_analysis, translated_analysis
            )

            # Create preservation result
            result = SecurityPreservation(
                is_preserved=preservation_analysis['is_preserved'],
                preservation_score=preservation_score,
                vulnerabilities_added=preservation_analysis['vulnerabilities_added'],
                vulnerabilities_removed=preservation_analysis['vulnerabilities_removed'],
                risk_score_change=preservation_analysis['risk_score_change'],
                security_properties_maintained=properties_maintained,
                security_properties_lost=properties_lost,
                mitigation_required=mitigation_required,
                analysis_details={
                    'analysis_time_ms': (time.time() - start_time) * 1000,
                    'original_vulnerabilities': len(original_analysis.get('vulnerabilities', [])),
                    'translated_vulnerabilities': len(translated_analysis.get('vulnerabilities', [])),
                    'original_risk_score': original_analysis.get('risk_score', 0.0),
                    'translated_risk_score': translated_analysis.get('risk_score', 0.0),
                    'security_degradation': preservation_analysis.get('security_degradation', False),
                    'critical_violations': preservation_analysis.get('critical_violations', []),
                    'recommendations': self._generate_recommendations(
                        original_analysis, translated_analysis
                    )
                }
            )

            logger.info("Security preservation analysis completed",
                       is_preserved=result.is_preserved,
                       preservation_score=result.preservation_score,
                       vulnerabilities_added=result.vulnerabilities_added,
                       mitigation_required=result.mitigation_required)

            return result

        except Exception as e:
            logger.error("Security preservation analysis failed", error=str(e))
            raise TSAFException(f"Security preservation analysis failed: {str(e)}")

    async def _analyze_message_security(
        self,
        message: str,
        protocol: ProtocolType,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze security properties of a single message."""
        try:
            # Create analysis request
            request = AnalysisRequest(
                message=message,
                protocol=protocol,
                metadata=context
            )

            # Use the security analyzer to analyze the message
            if self.security_analyzer:
                analysis_result = await self.security_analyzer.analyze_message(request)

                return {
                    'vulnerabilities': analysis_result.vulnerabilities,
                    'risk_score': analysis_result.risk_score,
                    'security_flags': analysis_result.security_flags.dict(),
                    'is_malicious': analysis_result.is_malicious,
                    'confidence': analysis_result.confidence,
                    'security_properties': self._extract_security_properties(analysis_result)
                }
            else:
                # Fallback analysis
                return await self._fallback_security_analysis(message, protocol)

        except Exception as e:
            logger.warning(f"Message security analysis failed: {e}")
            return await self._fallback_security_analysis(message, protocol)

    async def _fallback_security_analysis(self, message: str, protocol: ProtocolType) -> Dict[str, Any]:
        """Fallback security analysis when main analyzer is unavailable."""
        # Basic pattern-based security analysis
        suspicious_patterns = [
            'eval(', 'exec(', '<script', 'javascript:', 'data:text/html',
            'SELECT * FROM', 'DROP TABLE', 'UNION SELECT',
            '../../../', '..\\..\\..\\',
            'cmd.exe', '/bin/sh', 'powershell'
        ]

        vulnerabilities = []
        risk_score = 0.0
        message_lower = message.lower()

        for pattern in suspicious_patterns:
            if pattern in message_lower:
                vulnerabilities.append({
                    'category': 'ISV',
                    'severity': 'medium',
                    'pattern': pattern
                })
                risk_score += 0.3

        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': min(10.0, risk_score),
            'security_flags': {},
            'is_malicious': len(vulnerabilities) > 0,
            'confidence': 0.6,
            'security_properties': self._extract_basic_properties(message, protocol)
        }

    def _extract_security_properties(self, analysis_result) -> Set[str]:
        """Extract security properties from analysis result."""
        properties = set()

        # Check for authentication indicators
        if any('auth' in str(v).lower() for v in analysis_result.vulnerabilities):
            properties.add('authentication')

        # Check for authorization indicators
        if any('author' in str(v).lower() for v in analysis_result.vulnerabilities):
            properties.add('authorization')

        # Check for integrity indicators
        if analysis_result.security_flags.suspicious_encoding or \
           analysis_result.security_flags.contains_encoded_data:
            properties.add('integrity')

        # Check for confidentiality indicators
        if any('encrypt' in str(v).lower() or 'decrypt' in str(v).lower()
               for v in analysis_result.vulnerabilities):
            properties.add('confidentiality')

        # Default properties based on protocol
        if hasattr(analysis_result, 'protocol'):
            if analysis_result.protocol == ProtocolType.MCP:
                properties.update(['authentication', 'integrity'])
            elif analysis_result.protocol == ProtocolType.FIPA:
                properties.update(['authentication', 'authorization', 'integrity'])

        return properties

    def _extract_basic_properties(self, message: str, protocol: ProtocolType) -> Set[str]:
        """Extract basic security properties from message content."""
        properties = set()
        message_lower = message.lower()

        # Look for security-related keywords
        if any(keyword in message_lower for keyword in ['auth', 'login', 'credential']):
            properties.add('authentication')

        if any(keyword in message_lower for keyword in ['permit', 'allow', 'deny', 'access']):
            properties.add('authorization')

        if any(keyword in message_lower for keyword in ['encrypt', 'decrypt', 'secure']):
            properties.add('confidentiality')

        if any(keyword in message_lower for keyword in ['hash', 'checksum', 'verify']):
            properties.add('integrity')

        # Default properties by protocol
        if protocol == ProtocolType.MCP:
            properties.update(['authentication', 'integrity'])
        elif protocol == ProtocolType.FIPA:
            properties.update(['authentication', 'authorization'])

        return properties

    def _compare_security_properties(
        self,
        original_analysis: Dict[str, Any],
        translated_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compare security properties between original and translated messages."""
        original_vulns = original_analysis.get('vulnerabilities', [])
        translated_vulns = translated_analysis.get('vulnerabilities', [])

        # Count vulnerabilities by severity
        original_vuln_count = self._count_vulnerabilities_by_severity(original_vulns)
        translated_vuln_count = self._count_vulnerabilities_by_severity(translated_vulns)

        # Calculate changes
        vulnerabilities_added = max(0, len(translated_vulns) - len(original_vulns))
        vulnerabilities_removed = max(0, len(original_vulns) - len(translated_vulns))

        # Risk score changes
        original_risk = original_analysis.get('risk_score', 0.0)
        translated_risk = translated_analysis.get('risk_score', 0.0)
        risk_score_change = translated_risk - original_risk

        # Determine if security is preserved
        is_preserved = (
            vulnerabilities_added == 0 and
            risk_score_change <= 1.0 and  # Allow small increases
            not self._has_critical_degradation(original_vuln_count, translated_vuln_count)
        )

        # Check for security degradation
        security_degradation = (
            vulnerabilities_added > vulnerabilities_removed or
            risk_score_change > 2.0
        )

        # Identify critical violations
        critical_violations = self._identify_critical_violations(
            original_vulns, translated_vulns
        )

        return {
            'is_preserved': is_preserved,
            'vulnerabilities_added': vulnerabilities_added,
            'vulnerabilities_removed': vulnerabilities_removed,
            'risk_score_change': risk_score_change,
            'security_degradation': security_degradation,
            'critical_violations': critical_violations
        }

    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Any]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for vuln in vulnerabilities:
            if hasattr(vuln, 'severity'):
                severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            elif isinstance(vuln, dict):
                severity = vuln.get('severity', 'medium')
            else:
                severity = 'medium'

            severity = severity.lower()
            if severity in counts:
                counts[severity] += 1

        return counts

    def _has_critical_degradation(
        self,
        original_counts: Dict[str, int],
        translated_counts: Dict[str, int]
    ) -> bool:
        """Check if there's critical security degradation."""
        # Check for new critical or high severity vulnerabilities
        critical_increase = translated_counts['critical'] - original_counts['critical']
        high_increase = translated_counts['high'] - original_counts['high']

        return critical_increase > 0 or high_increase > 1

    def _identify_critical_violations(
        self,
        original_vulns: List[Any],
        translated_vulns: List[Any]
    ) -> List[str]:
        """Identify critical security violations in translation."""
        violations = []

        # Get vulnerability categories
        original_categories = set()
        translated_categories = set()

        for vuln in original_vulns:
            if hasattr(vuln, 'category'):
                category = vuln.category.value if hasattr(vuln.category, 'value') else str(vuln.category)
                original_categories.add(category)

        for vuln in translated_vulns:
            if hasattr(vuln, 'category'):
                category = vuln.category.value if hasattr(vuln.category, 'value') else str(vuln.category)
                translated_categories.add(category)

        # Check for new critical vulnerability categories
        new_categories = translated_categories - original_categories
        for category in new_categories:
            if category in ['CEV', 'PIV']:  # Command Execution, Protocol Injection
                violations.append(f"New {category} vulnerability introduced")

        return violations

    def _calculate_preservation_score(
        self,
        original_analysis: Dict[str, Any],
        translated_analysis: Dict[str, Any]
    ) -> float:
        """Calculate overall security preservation score (0-1)."""
        # Base score starts at 1.0 (perfect preservation)
        score = 1.0

        # Penalty for new vulnerabilities
        original_vulns = original_analysis.get('vulnerabilities', [])
        translated_vulns = translated_analysis.get('vulnerabilities', [])

        if len(translated_vulns) > len(original_vulns):
            new_vulns = len(translated_vulns) - len(original_vulns)
            score -= new_vulns * 0.1  # 10% penalty per new vulnerability

        # Penalty for risk score increase
        risk_increase = (translated_analysis.get('risk_score', 0.0) -
                        original_analysis.get('risk_score', 0.0))
        if risk_increase > 0:
            score -= risk_increase * 0.05  # 5% penalty per risk point increase

        # Penalty for lost security properties
        original_props = original_analysis.get('security_properties', set())
        translated_props = translated_analysis.get('security_properties', set())
        lost_props = original_props - translated_props
        score -= len(lost_props) * 0.15  # 15% penalty per lost property

        return max(0.0, min(1.0, score))

    def _analyze_property_changes(
        self,
        original_analysis: Dict[str, Any],
        translated_analysis: Dict[str, Any]
    ) -> tuple[List[str], List[str]]:
        """Analyze changes in security properties."""
        original_props = original_analysis.get('security_properties', set())
        translated_props = translated_analysis.get('security_properties', set())

        maintained = list(original_props.intersection(translated_props))
        lost = list(original_props - translated_props)

        return maintained, lost

    def _requires_mitigation(
        self,
        original_analysis: Dict[str, Any],
        translated_analysis: Dict[str, Any]
    ) -> bool:
        """Determine if mitigation is required."""
        # Mitigation required if:
        # 1. New critical/high vulnerabilities
        # 2. Significant risk score increase
        # 3. Loss of critical security properties

        original_vulns = self._count_vulnerabilities_by_severity(
            original_analysis.get('vulnerabilities', [])
        )
        translated_vulns = self._count_vulnerabilities_by_severity(
            translated_analysis.get('vulnerabilities', [])
        )

        # Check for new critical vulnerabilities
        if translated_vulns['critical'] > original_vulns['critical']:
            return True

        # Check for significant risk increase
        risk_increase = (translated_analysis.get('risk_score', 0.0) -
                        original_analysis.get('risk_score', 0.0))
        if risk_increase > 3.0:
            return True

        # Check for loss of critical properties
        original_props = original_analysis.get('security_properties', set())
        translated_props = translated_analysis.get('security_properties', set())
        critical_props_lost = {'authentication', 'authorization', 'confidentiality'}.intersection(
            original_props - translated_props
        )
        if critical_props_lost:
            return True

        return False

    def _generate_recommendations(
        self,
        original_analysis: Dict[str, Any],
        translated_analysis: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for security preservation."""
        recommendations = []

        # Check for specific issues and recommend fixes
        translated_vulns = translated_analysis.get('vulnerabilities', [])
        original_vulns = original_analysis.get('vulnerabilities', [])

        if len(translated_vulns) > len(original_vulns):
            recommendations.append("Review translation for introduced vulnerabilities")

        risk_increase = (translated_analysis.get('risk_score', 0.0) -
                        original_analysis.get('risk_score', 0.0))
        if risk_increase > 2.0:
            recommendations.append("Implement additional security controls for translated message")

        original_props = original_analysis.get('security_properties', set())
        translated_props = translated_analysis.get('security_properties', set())
        lost_props = original_props - translated_props
        if lost_props:
            recommendations.append(f"Restore lost security properties: {', '.join(lost_props)}")

        if not recommendations:
            recommendations.append("Security preservation is adequate")

        return recommendations

    async def shutdown(self) -> None:
        """Shutdown the security preservation analyzer."""
        logger.info("Shutting down Security Preservation Analyzer")
        self.security_analyzer = None
        self._initialized = False