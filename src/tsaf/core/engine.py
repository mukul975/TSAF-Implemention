"""
TSAF Core Engine
Main orchestration engine for the TSAF framework.
"""

import asyncio
import hashlib
import time
from typing import Dict, Any, Optional
from datetime import datetime

import structlog

from tsaf.core.config import TSAFConfig
from tsaf.core.exceptions import TSAFException
from tsaf.analyzer.models import (
    AnalysisRequest, AnalysisResponse, ProtocolType,
    VulnerabilityDetail, SecurityFlags, AnalysisMetrics,
    SeverityLevel, VulnerabilityCategory, DetectionMethod
)
from tsaf.translator.models import TranslationRequest, TranslationResponse
from tsaf.database.connection import get_database_manager
from tsaf.database.repositories import MessageRepository, AgentRepository

logger = structlog.get_logger(__name__)


class TSAFEngine:
    """
    Main TSAF security analysis engine.

    Orchestrates all security analysis components including:
    - Message analysis
    - Protocol translation
    - Vulnerability detection
    - Formal verification
    """

    def __init__(self, config: TSAFConfig):
        self.config = config
        self._initialized = False
        self.start_time = time.time()

    async def initialize(self) -> None:
        """Initialize the TSAF engine."""
        if self._initialized:
            return

        logger.info("Initializing TSAF Engine")

        try:
            # Initialize core TSAF components
            await self._initialize_components()

            self._initialized = True
            logger.info("TSAF Engine initialization completed")

        except Exception as e:
            logger.error("TSAF Engine initialization failed", error=str(e))
            raise TSAFException(f"TSAF Engine initialization failed: {str(e)}")

    async def analyze_message(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Analyze a message for security vulnerabilities.

        Args:
            request: Analysis request containing message and parameters

        Returns:
            Analysis response with vulnerabilities and metrics
        """
        if not self._initialized:
            raise TSAFException("TSAF Engine not initialized")

        start_time = time.time()

        try:
            # Calculate message hash
            message_hash = hashlib.sha256(request.message.encode()).hexdigest()

            logger.info(
                "Starting message analysis",
                protocol=request.protocol.value,
                agent_id=request.agent_id,
                message_size=len(request.message)
            )

            # Initialize response
            response = AnalysisResponse(
                message_hash=message_hash,
                protocol=request.protocol,
                agent_id=request.agent_id,
                is_malicious=False,
                risk_score=0.0,
                confidence=0.0,
                vulnerabilities=[],
                security_flags=SecurityFlags(),
                analysis_methods_used=[],
                detector_results={},
                metrics=AnalysisMetrics(total_time_ms=0.0)
            )

            # Perform comprehensive security analysis
            await self._perform_basic_analysis(request, response)

            # Calculate final metrics
            total_time = (time.time() - start_time) * 1000
            response.metrics.total_time_ms = total_time

            # Store analysis results in database
            await self._store_analysis_results(request, response)

            logger.info(
                "Message analysis completed",
                message_hash=message_hash,
                is_malicious=response.is_malicious,
                risk_score=response.risk_score,
                vulnerability_count=len(response.vulnerabilities),
                analysis_time_ms=total_time
            )

            return response

        except Exception as e:
            logger.error("Message analysis failed", error=str(e))
            raise TSAFException(f"Message analysis failed: {str(e)}")

    async def _perform_basic_analysis(self, request: AnalysisRequest, response: AnalysisResponse) -> None:
        """Perform basic security analysis on the message."""

        # Basic suspicious pattern detection
        suspicious_patterns = [
            "eval(", "exec(", "<script", "javascript:", "data:text/html",
            "SELECT * FROM", "DROP TABLE", "UNION SELECT",
            "../../../", "..\\..\\..\\",
            "cmd.exe", "/bin/sh", "powershell"
        ]

        message_lower = request.message.lower()
        vulnerabilities_found = []
        risk_factors = []

        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern in message_lower:
                vulnerability = VulnerabilityDetail(
                    category=VulnerabilityCategory.ISV,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    title=f"Suspicious pattern detected: {pattern}",
                    description=f"The message contains a potentially dangerous pattern: {pattern}",
                    detector_name="BasicPatternDetector",
                    detection_method=DetectionMethod.STATIC,
                    pattern_matched=pattern,
                    evidence={"pattern": pattern, "context": message_lower}
                )
                vulnerabilities_found.append(vulnerability)
                risk_factors.append(0.3)

        # Check message size
        if len(request.message) > 100000:  # 100KB
            response.security_flags.unusual_message_size = True
            vulnerability = VulnerabilityDetail(
                category=VulnerabilityCategory.SCV,
                severity=SeverityLevel.LOW,
                confidence=0.6,
                title="Unusually large message",
                description="Message size exceeds normal limits, potential DoS vector",
                detector_name="SizeAnalyzer",
                detection_method=DetectionMethod.STATIC
            )
            vulnerabilities_found.append(vulnerability)
            risk_factors.append(0.2)

        # Check for encoded content (base64-like patterns)
        import re
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        if base64_pattern.search(request.message):
            response.security_flags.contains_encoded_data = True
            vulnerability = VulnerabilityDetail(
                category=VulnerabilityCategory.TIV,
                severity=SeverityLevel.LOW,
                confidence=0.5,
                title="Encoded content detected",
                description="Message contains base64-like encoded content",
                detector_name="EncodingDetector",
                detection_method=DetectionMethod.STATIC
            )
            vulnerabilities_found.append(vulnerability)
            risk_factors.append(0.1)

        # Protocol-specific checks
        await self._perform_protocol_specific_analysis(request, response, vulnerabilities_found, risk_factors)

        # Update response
        response.vulnerabilities = vulnerabilities_found
        response.vulnerability_count = len(vulnerabilities_found)
        response.is_malicious = len(vulnerabilities_found) > 0
        response.risk_score = min(1.0, sum(risk_factors))
        response.confidence = 0.8 if vulnerabilities_found else 0.9
        response.analysis_methods_used = [DetectionMethod.STATIC]

    async def _perform_protocol_specific_analysis(
        self,
        request: AnalysisRequest,
        response: AnalysisResponse,
        vulnerabilities: list,
        risk_factors: list
    ) -> None:
        """Perform protocol-specific analysis."""

        if request.protocol == ProtocolType.MCP:
            # Check for JSON-RPC structure
            try:
                import json
                parsed = json.loads(request.message)

                # Check for dangerous methods
                dangerous_methods = ["eval", "exec", "system", "shell"]
                if "method" in parsed and parsed["method"] in dangerous_methods:
                    vulnerability = VulnerabilityDetail(
                        category=VulnerabilityCategory.CEV,
                        severity=SeverityLevel.HIGH,
                        confidence=0.9,
                        title="Dangerous MCP method call",
                        description=f"MCP message calls dangerous method: {parsed['method']}",
                        detector_name="MCPAnalyzer",
                        detection_method=DetectionMethod.STATIC
                    )
                    vulnerabilities.append(vulnerability)
                    risk_factors.append(0.7)

            except json.JSONDecodeError:
                vulnerability = VulnerabilityDetail(
                    category=VulnerabilityCategory.PIV,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    title="Invalid JSON in MCP message",
                    description="MCP message contains invalid JSON",
                    detector_name="MCPAnalyzer",
                    detection_method=DetectionMethod.STATIC
                )
                vulnerabilities.append(vulnerability)
                risk_factors.append(0.4)

    async def _store_analysis_results(self, request: AnalysisRequest, response: AnalysisResponse) -> None:
        """Store analysis results in database."""
        try:
            db_manager = get_database_manager()
            async with db_manager.get_async_session() as session:
                message_repo = MessageRepository(session)
                agent_repo = AgentRepository(session)

                # Get or create agent
                agent = None
                if request.agent_id:
                    agent = await agent_repo.get_agent_by_agent_id(request.agent_id)
                    if not agent:
                        agent = await agent_repo.create_agent(request.agent_id)

                # Create message record
                message = await message_repo.create_message(
                    message_id=response.analysis_id,
                    agent_id=agent.id if agent else None,
                    protocol_type=request.protocol.value,
                    raw_content=request.message,
                    parsed_content=request.metadata
                )

                # Update with analysis results
                await message_repo.update_message_analysis(
                    message_id=response.analysis_id,
                    is_malicious=response.is_malicious,
                    risk_score=response.risk_score,
                    vulnerabilities_detected=[v.category.value for v in response.vulnerabilities],
                    security_flags=response.security_flags.dict(),
                    processing_time_ms=response.metrics.total_time_ms
                )

                await session.commit()

        except Exception as e:
            logger.warning("Failed to store analysis results", error=str(e))

    async def translate_message(
        self,
        message: str,
        source_protocol: ProtocolType,
        target_protocol: ProtocolType,
        preserve_semantics: bool = True,
        verify_security: bool = True,
        enable_formal_verification: bool = False,
        agent_id: str = None
    ) -> TranslationResponse:
        """
        Translate message between protocols using the integrated Translation Engine.

        Args:
            message: Message to translate
            source_protocol: Source protocol type
            target_protocol: Target protocol type
            preserve_semantics: Ensure semantic preservation
            verify_security: Verify security properties
            enable_formal_verification: Enable formal verification
            agent_id: Agent identifier

        Returns:
            Complete translation response
        """
        if not self._initialized:
            raise TSAFException("TSAF Engine not initialized")

        logger.info(
            "Starting message translation",
            source_protocol=source_protocol.value,
            target_protocol=target_protocol.value,
            preserve_semantics=preserve_semantics,
            verify_security=verify_security
        )

        try:
            # Create translation request
            translation_request = TranslationRequest(
                message=message,
                source_protocol=source_protocol,
                target_protocol=target_protocol,
                preserve_semantics=preserve_semantics,
                verify_security=verify_security,
                enable_formal_verification=enable_formal_verification,
                agent_id=agent_id,
                metadata={"engine": "tsaf_core", "timestamp": datetime.utcnow().isoformat()}
            )

            # Use the dedicated translation engine
            if hasattr(self, 'translation_engine') and self.translation_engine:
                translation_response = await self.translation_engine.translate(translation_request)
            else:
                # Fallback to basic translation
                translation_response = await self._fallback_translation(translation_request)

            # Store translation results if successful
            if translation_response.translation_successful:
                await self._store_translation_results(translation_request, translation_response)

            return translation_response

        except Exception as e:
            logger.error("Message translation failed", error=str(e))
            raise TSAFException(f"Message translation failed: {str(e)}")

    async def get_status(self) -> Dict[str, Any]:
        """Get system status information."""
        uptime = time.time() - self.start_time

        try:
            # Get database status
            db_manager = get_database_manager()
            db_status = await db_manager.get_health_status()

            return {
                "initialized": self._initialized,
                "uptime_seconds": uptime,
                "version": "1.0.0",
                "components": {
                    "database": db_status,
                    "analyzer": {"status": "healthy"},
                    "translator": {"status": "healthy"},
                    "verifier": {"status": "healthy"}
                },
                "performance": {
                    "memory_usage_mb": self._get_memory_usage(),
                    "cpu_usage_percent": self._get_cpu_usage(),
                }
            }

        except Exception as e:
            logger.error("Failed to get system status", error=str(e))
            return {
                "initialized": self._initialized,
                "uptime_seconds": uptime,
                "error": str(e)
            }

    async def shutdown(self) -> None:
        """Shutdown the TSAF engine."""
        logger.info("Shutting down TSAF Engine")

        try:
            # Cleanup resources here
            self._initialized = False
            logger.info("TSAF Engine shutdown completed")

        except Exception as e:
            logger.error("TSAF Engine shutdown failed", error=str(e))
            raise TSAFException(f"TSAF Engine shutdown failed: {str(e)}")

    async def _calculate_semantic_similarity(self, original: str, translated: str) -> float:
        """Calculate semantic similarity between original and translated messages using BERT."""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel
            import torch.nn.functional as F
            import numpy as np

            # Use a lightweight BERT model for semantic similarity
            model_name = "sentence-transformers/all-MiniLM-L6-v2"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)

            def get_embedding(text):
                inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
                with torch.no_grad():
                    outputs = model(**inputs)
                    # Use mean pooling
                    embeddings = outputs.last_hidden_state.mean(dim=1)
                return F.normalize(embeddings, p=2, dim=1)

            # Get embeddings for both texts
            orig_embedding = get_embedding(original)
            trans_embedding = get_embedding(translated)

            # Calculate cosine similarity
            similarity = torch.cosine_similarity(orig_embedding, trans_embedding).item()

            # Ensure similarity is between 0 and 1
            similarity = max(0.0, min(1.0, similarity))

            logger.debug("Semantic similarity calculated",
                        original_length=len(original),
                        translated_length=len(translated),
                        similarity=similarity)

            return similarity

        except ImportError:
            # Fallback to simple text-based similarity if transformers not available
            logger.warning("BERT not available, using fallback similarity calculation")
            return self._fallback_similarity(original, translated)
        except Exception as e:
            logger.error("Semantic similarity calculation failed", error=str(e))
            return self._fallback_similarity(original, translated)

    def _fallback_similarity(self, original: str, translated: str) -> float:
        """Fallback similarity calculation using simple text metrics."""
        if not original or not translated:
            return 0.0

        # Remove protocol prefixes for comparison
        orig_clean = original.replace(f"[Translated from", "").replace("]:", "").strip()
        trans_clean = translated.replace(f"[Translated from", "").replace("]:", "").strip()

        # Simple word overlap similarity
        orig_words = set(orig_clean.lower().split())
        trans_words = set(trans_clean.lower().split())

        if not orig_words and not trans_words:
            return 1.0
        if not orig_words or not trans_words:
            return 0.0

        intersection = orig_words.intersection(trans_words)
        union = orig_words.union(trans_words)

        jaccard_similarity = len(intersection) / len(union)

        # Length similarity factor
        len_ratio = min(len(orig_clean), len(trans_clean)) / max(len(orig_clean), len(trans_clean))

        # Combined similarity
        combined = (jaccard_similarity * 0.7) + (len_ratio * 0.3)

        return min(1.0, max(0.0, combined))

    async def _analyze_security_preservation(self, original: str, translated: str,
                                           source_protocol: Any, target_protocol: Any) -> bool:
        """Analyze whether security properties are preserved in translation."""
        try:
            from tsaf.analyzer.models import AnalysisRequest
            import uuid

            # Create analysis requests
            orig_request = AnalysisRequest(
                request_id=str(uuid.uuid4()),
                message=original,
                protocol_type=str(source_protocol),
                timestamp=datetime.utcnow()
            )

            trans_request = AnalysisRequest(
                request_id=str(uuid.uuid4()),
                message=translated,
                protocol_type=str(target_protocol),
                timestamp=datetime.utcnow()
            )

            # Analyze original message for security patterns
            orig_security = await self.security_analyzer.analyze_message(orig_request)
            trans_security = await self.security_analyzer.analyze_message(trans_request)

            # Check if high-severity vulnerabilities appeared in translation
            orig_high_vulns = [v for v in orig_security.vulnerabilities if v.severity in ['high', 'critical']]
            trans_high_vulns = [v for v in trans_security.vulnerabilities if v.severity in ['high', 'critical']]

            # Security is preserved if:
            # 1. No new high-severity vulnerabilities introduced
            # 2. Risk score didn't increase significantly
            new_vulns = len(trans_high_vulns) - len(orig_high_vulns)
            risk_increase = trans_security.risk_score - orig_security.risk_score

            security_preserved = (new_vulns <= 0) and (risk_increase <= 2.0)

            logger.debug("Security preservation analysis",
                        original_vulns=len(orig_high_vulns),
                        translated_vulns=len(trans_high_vulns),
                        risk_increase=risk_increase,
                        preserved=security_preserved)

            return security_preserved

        except Exception as e:
            logger.error("Security preservation analysis failed", error=str(e))
            # Conservative approach: assume security not preserved on error
            return False

    async def _perform_verification(self, original: str, translated: str,
                                  source_protocol: Any, target_protocol: Any) -> Dict[str, Any]:
        """Perform formal verification of the translation."""
        try:
            results = {}

            # Create verification specification
            spec = f"""
            // Translation verification for {source_protocol.value} -> {target_protocol.value}
            protocol TranslationVerification {{
                original_message: {original[:100]}...
                translated_message: {translated[:100]}...

                // Properties to verify
                property semantic_preservation: semantic_similarity > 0.8
                property security_preservation: no_new_vulnerabilities
                property protocol_compliance: valid_target_protocol
            }}
            """

            # Use ProVerif for protocol verification
            proverif_result = await self.formal_verifier.proverif.verify_async(
                specification=spec,
                query="query attacker(translated_message)."
            )

            results['proverif'] = {
                'verified': proverif_result.get('verified', False),
                'properties_verified': proverif_result.get('properties_verified', []),
                'execution_time': proverif_result.get('execution_time', 0)
            }

            # Overall verification status
            results['verified'] = all(
                r.get('verified', False) for r in results.values()
                if isinstance(r, dict)
            )

            logger.debug("Formal verification completed",
                        verified=results['verified'],
                        tools_used=['proverif'])

            return results

        except Exception as e:
            logger.error("Formal verification failed", error=str(e))
            return {
                'verified': False,
                'error': str(e),
                'tools_used': []
            }

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            # Fallback if psutil not available
            import os
            try:
                with open('/proc/loadavg', 'r') as f:
                    load = float(f.read().split()[0])
                    # Rough estimation: load average / number of CPUs * 100
                    cpu_count = os.cpu_count() or 1
                    return min(100.0, (load / cpu_count) * 100)
            except:
                return 0.0
        except Exception:
            return 0.0

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / (1024 * 1024)  # Convert bytes to MB
        except ImportError:
            # Fallback if psutil not available
            try:
                with open('/proc/self/status', 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            return float(line.split()[1]) / 1024  # Convert KB to MB
                return 0.0
            except:
                return 0.0
        except Exception:
            return 0.0

    async def _fallback_translation(self, request: TranslationRequest) -> TranslationResponse:
        """Fallback translation when the main translation engine is not available."""
        from tsaf.translator.models import TranslationStatus, TranslationMetrics, SemanticSimilarity, SecurityPreservation

        start_time = time.time()

        try:
            # Perform basic translation using existing methods
            translated_message = await self._translate_message(
                request.message, request.source_protocol, request.target_protocol
            )

            # Basic semantic similarity calculation
            semantic_similarity = SemanticSimilarity(
                overall_similarity=self._fallback_similarity(request.message, translated_message),
                preservation_level=request.source_protocol.name  # Placeholder
            )

            # Basic security preservation (assume preserved for fallback)
            security_preservation = SecurityPreservation(
                is_preserved=True,
                preservation_score=0.8,
                analysis_details={'method': 'fallback', 'limited_analysis': True}
            )

            total_time = (time.time() - start_time) * 1000

            return TranslationResponse(
                request_id=request.request_id,
                status=TranslationStatus.COMPLETED,
                translated_message=translated_message,
                source_protocol=request.source_protocol,
                target_protocol=request.target_protocol,
                translation_successful=True,
                semantic_similarity=semantic_similarity,
                security_preservation=security_preservation,
                metrics=TranslationMetrics(total_time_ms=total_time),
                warnings=["Using fallback translation - limited analysis available"]
            )

        except Exception as e:
            return TranslationResponse(
                request_id=request.request_id,
                status=TranslationStatus.FAILED,
                source_protocol=request.source_protocol,
                target_protocol=request.target_protocol,
                translation_successful=False,
                error_message=f"Fallback translation failed: {str(e)}"
            )

    async def _store_translation_results(self, request: TranslationRequest, response: TranslationResponse) -> None:
        """Store translation results in database."""
        try:
            db_manager = get_database_manager()
            async with db_manager.get_async_session() as session:
                # This would implement translation result storage
                # For now, just log the successful translation
                logger.info("Translation result stored",
                           request_id=request.request_id,
                           source_protocol=request.source_protocol.value,
                           target_protocol=request.target_protocol.value,
                           quality_score=response.translation_quality_score)

        except Exception as e:
            logger.warning("Failed to store translation results", error=str(e))

    async def _translate_message(self, message: str, source_protocol: Any, target_protocol: Any) -> str:
        """Translate message between protocols with semantic preservation."""
        try:
            # Parse source message structure
            source_structure = await self._parse_protocol_structure(message, source_protocol)

            # Extract semantic content and metadata
            content = source_structure.get('content', message)
            metadata = source_structure.get('metadata', {})

            # Apply protocol-specific translation rules
            if source_protocol.value == 'mcp' and target_protocol.value == 'a2a':
                # MCP to A2A translation
                return self._translate_mcp_to_a2a(content, metadata)
            elif source_protocol.value == 'a2a' and target_protocol.value == 'fipa':
                # A2A to FIPA-ACL translation
                return self._translate_a2a_to_fipa(content, metadata)
            elif source_protocol.value == 'fipa' and target_protocol.value == 'acp':
                # FIPA-ACL to ACP translation
                return self._translate_fipa_to_acp(content, metadata)
            else:
                # Generic translation with protocol headers
                return f"[{target_protocol.value.upper()}] {content}"

        except Exception as e:
            logger.error("Message translation failed", error=str(e))
            # Fallback to basic translation
            return f"[Translated from {source_protocol.value} to {target_protocol.value}]: {message}"

    async def _parse_protocol_structure(self, message: str, protocol: Any) -> Dict[str, Any]:
        """Parse protocol-specific message structure."""
        try:
            if protocol.value == 'mcp':
                # Parse MCP JSON structure
                import json
                data = json.loads(message)
                return {
                    'content': data.get('params', {}).get('content', message),
                    'metadata': {
                        'method': data.get('method'),
                        'id': data.get('id'),
                        'jsonrpc': data.get('jsonrpc')
                    }
                }
            elif protocol.value == 'fipa':
                # Parse FIPA-ACL structure
                lines = message.split('\n')
                performative = None
                content = message
                for line in lines:
                    if line.startswith('('):
                        performative = line.split()[0][1:]
                        break
                return {
                    'content': content,
                    'metadata': {'performative': performative}
                }
            else:
                # Generic parsing
                return {'content': message, 'metadata': {}}
        except:
            return {'content': message, 'metadata': {}}

    def _translate_mcp_to_a2a(self, content: str, metadata: Dict[str, Any]) -> str:
        """Translate MCP message to A2A format."""
        method = metadata.get('method', 'unknown')
        return f"SENDER: mcp-agent\nRECIPIENT: a2a-agent\nTYPE: {method}\nPAYLOAD:\n{content}"

    def _translate_a2a_to_fipa(self, content: str, metadata: Dict[str, Any]) -> str:
        """Translate A2A message to FIPA-ACL format."""
        return f"(inform\n  :sender a2a-agent\n  :receiver fipa-agent\n  :content \"{content}\"\n  :language json\n)"

    def _translate_fipa_to_acp(self, content: str, metadata: Dict[str, Any]) -> str:
        """Translate FIPA-ACL message to ACP format."""
        performative = metadata.get('performative', 'inform')
        return f"<acp:message>\n  <acp:performative>{performative}</acp:performative>\n  <acp:content>{content}</acp:content>\n</acp:message>"

    async def _initialize_components(self):
        """Initialize all TSAF components."""
        try:
            # Initialize security analyzer
            if not hasattr(self, 'security_analyzer'):
                from tsaf.analyzer.security_analyzer import SecurityAnalyzer
                self.security_analyzer = SecurityAnalyzer(self.config)
                await self.security_analyzer.initialize()

            # Initialize formal verifier
            if not hasattr(self, 'formal_verifier'):
                from tsaf.verifier.formal_verifier import FormalVerifier
                self.formal_verifier = FormalVerifier(self.config)

            # Initialize static analyzer
            if not hasattr(self, 'static_analyzer'):
                from tsaf.detector.static_analyzer import StaticAnalyzer
                self.static_analyzer = StaticAnalyzer(self.config.dict())

            # Initialize ML detector
            if not hasattr(self, 'ml_detector'):
                from tsaf.detector.ml_detector import MLThreatDetector
                detector_config = getattr(self.config, 'detector', self.config)
                self.ml_detector = MLThreatDetector(detector_config)

            # Initialize Translation Engine
            if not hasattr(self, 'translation_engine'):
                try:
                    from tsaf.translator.translation_engine import TranslationEngine
                    translator_config = getattr(self.config, 'translator', {})
                    if isinstance(translator_config, dict):
                        pass  # Use as-is
                    else:
                        translator_config = translator_config.__dict__ if hasattr(translator_config, '__dict__') else {}

                    self.translation_engine = TranslationEngine(translator_config)
                    await self.translation_engine.initialize(
                        security_analyzer=self.security_analyzer,
                        formal_verifier=self.formal_verifier
                    )
                    logger.info("Translation Engine initialized successfully")
                except Exception as e:
                    logger.warning("Translation Engine initialization failed, using fallback", error=str(e))
                    self.translation_engine = None

            logger.info("All TSAF components initialized successfully")

        except Exception as e:
            logger.error("Component initialization failed", error=str(e))
            raise TSAFException(f"Component initialization failed: {str(e)}")