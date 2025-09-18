"""
TSAF Translation Engine
Complete protocol translation with semantic preservation and security validation.
"""

import asyncio
import hashlib
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import structlog

from .models import (
    TranslationRequest, TranslationResponse, TranslationStatus,
    TranslationMetrics, ProtocolAdapter, TranslationRule
)
from .semantic_analyzer import SemanticSimilarityAnalyzer
from .security_preservator import SecurityPreservationAnalyzer
from tsaf.analyzer.models import ProtocolType
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class TranslationEngine:
    """
    Complete protocol translation engine with advanced security and semantic analysis.

    Features:
    - Multi-protocol translation (MCP, A2A, FIPA-ACL, ACP)
    - Semantic similarity preservation using BERT
    - Security property validation
    - Formal verification integration
    - Performance optimization with caching
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._initialized = False

        # Core components
        self.semantic_analyzer = None
        self.security_preservator = None
        self.formal_verifier = None
        self.security_analyzer = None

        # Protocol adapters
        self.protocol_adapters = {}
        self.translation_rules = {}

        # Performance optimization
        self._translation_cache = {}
        self._cache_size_limit = 1000

        # Statistics
        self.stats = {
            'total_translations': 0,
            'successful_translations': 0,
            'failed_translations': 0,
            'cached_translations': 0,
            'avg_translation_time_ms': 0.0
        }

    async def initialize(self, security_analyzer=None, formal_verifier=None) -> None:
        """Initialize the translation engine."""
        if self._initialized:
            return

        logger.info("Initializing Translation Engine")

        try:
            # Store dependencies
            self.security_analyzer = security_analyzer
            self.formal_verifier = formal_verifier

            # Initialize semantic analyzer
            self.semantic_analyzer = SemanticSimilarityAnalyzer(
                self.config.get('semantic_analyzer', {})
            )
            await self.semantic_analyzer.initialize()

            # Initialize security preservation analyzer
            self.security_preservator = SecurityPreservationAnalyzer(
                self.config.get('security_preservator', {})
            )
            await self.security_preservator.initialize(self.security_analyzer)

            # Initialize protocol adapters
            await self._initialize_protocol_adapters()

            # Load translation rules
            await self._load_translation_rules()

            self._initialized = True
            logger.info("Translation Engine initialized successfully")

        except Exception as e:
            logger.error("Translation Engine initialization failed", error=str(e))
            raise TSAFException(f"Translation Engine initialization failed: {str(e)}")

    async def translate(self, request: TranslationRequest) -> TranslationResponse:
        """
        Perform complete protocol translation with analysis.

        Args:
            request: Translation request with message and parameters

        Returns:
            Complete translation response with analysis results
        """
        if not self._initialized:
            raise TSAFException("Translation Engine not initialized")

        start_time = time.time()

        # Initialize response
        response = TranslationResponse(
            request_id=request.request_id,
            status=TranslationStatus.IN_PROGRESS,
            source_protocol=request.source_protocol,
            target_protocol=request.target_protocol,
            timestamp=datetime.utcnow()
        )

        try:
            logger.info("Starting protocol translation",
                       request_id=request.request_id,
                       source_protocol=request.source_protocol.value,
                       target_protocol=request.target_protocol.value,
                       message_length=len(request.message))

            # Check cache first
            cache_key = self._generate_cache_key(request)
            if cache_key in self._translation_cache and self.config.get('enable_caching', True):
                cached_response = self._translation_cache[cache_key]
                cached_response.request_id = request.request_id
                cached_response.timestamp = datetime.utcnow()
                self.stats['cached_translations'] += 1
                logger.info("Returning cached translation result")
                return cached_response

            # Perform core translation
            translation_start = time.time()
            translated_message = await self._perform_translation(request)
            translation_time = (time.time() - translation_start) * 1000

            response.translated_message = translated_message
            response.translation_successful = True

            # Perform semantic similarity analysis
            if request.preserve_semantics:
                semantic_start = time.time()
                semantic_result = await self.semantic_analyzer.analyze_similarity(
                    request.message, translated_message
                )
                semantic_time = (time.time() - semantic_start) * 1000
                response.semantic_similarity = semantic_result
            else:
                semantic_time = 0.0

            # Perform security preservation analysis
            if request.verify_security:
                security_start = time.time()
                security_result = await self.security_preservator.analyze_preservation(
                    request.message, translated_message,
                    request.source_protocol, request.target_protocol,
                    request.metadata
                )
                security_time = (time.time() - security_start) * 1000
                response.security_preservation = security_result
            else:
                security_time = 0.0

            # Perform formal verification if enabled
            verification_time = 0.0
            if request.enable_formal_verification and self.formal_verifier:
                verification_start = time.time()
                verification_result = await self._perform_formal_verification(
                    request.message, translated_message,
                    request.source_protocol, request.target_protocol
                )
                verification_time = (time.time() - verification_start) * 1000
                response.verification_results = verification_result
                response.formal_verification_passed = verification_result.get('verified', False)

            # Calculate total time and metrics
            total_time = (time.time() - start_time) * 1000
            response.metrics = TranslationMetrics(
                translation_time_ms=translation_time,
                semantic_analysis_time_ms=semantic_time,
                security_analysis_time_ms=security_time,
                verification_time_ms=verification_time,
                total_time_ms=total_time,
                memory_usage_mb=self._get_memory_usage(),
                cpu_usage_percent=self._get_cpu_usage()
            )

            # Calculate quality score
            response.translation_quality_score = self._calculate_quality_score(response)

            # Generate recommendations
            response.recommended_actions = self._generate_recommendations(response)

            # Determine final status
            if response.translation_successful:
                if request.verify_security and not response.security_preservation.is_preserved:
                    response.status = TranslationStatus.SECURITY_VIOLATION
                    response.warnings.append("Security properties not preserved in translation")
                else:
                    response.status = TranslationStatus.COMPLETED
            else:
                response.status = TranslationStatus.FAILED

            # Update statistics
            self._update_statistics(response, total_time)

            # Cache successful translations
            if response.status == TranslationStatus.COMPLETED:
                self._cache_translation(cache_key, response)

            logger.info("Protocol translation completed",
                       request_id=request.request_id,
                       status=response.status.value,
                       quality_score=response.translation_quality_score,
                       total_time_ms=total_time)

            return response

        except Exception as e:
            logger.error("Protocol translation failed",
                        request_id=request.request_id,
                        error=str(e))

            response.status = TranslationStatus.FAILED
            response.error_message = str(e)
            response.translation_successful = False

            # Update failure statistics
            self.stats['failed_translations'] += 1
            self.stats['total_translations'] += 1

            return response

    async def _perform_translation(self, request: TranslationRequest) -> str:
        """Perform the core protocol translation."""
        source_adapter = self.protocol_adapters.get(request.source_protocol)
        target_adapter = self.protocol_adapters.get(request.target_protocol)

        if not source_adapter or not target_adapter:
            raise TSAFException(f"Unsupported protocol translation: {request.source_protocol.value} -> {request.target_protocol.value}")

        # Parse source message
        parsed_content = await self._parse_message(request.message, source_adapter)

        # Apply translation rules
        transformed_content = await self._apply_translation_rules(
            parsed_content, request.source_protocol, request.target_protocol
        )

        # Format for target protocol
        translated_message = await self._format_message(transformed_content, target_adapter)

        return translated_message

    async def _parse_message(self, message: str, adapter: ProtocolAdapter) -> Dict[str, Any]:
        """Parse message using protocol-specific adapter."""
        try:
            if adapter.protocol_type == ProtocolType.MCP:
                return await self._parse_mcp_message(message)
            elif adapter.protocol_type == ProtocolType.A2A:
                return await self._parse_a2a_message(message)
            elif adapter.protocol_type == ProtocolType.FIPA:
                return await self._parse_fipa_message(message)
            elif adapter.protocol_type == ProtocolType.ACP:
                return await self._parse_acp_message(message)
            else:
                return {'content': message, 'metadata': {}}

        except Exception as e:
            logger.warning(f"Message parsing failed: {e}")
            return {'content': message, 'metadata': {}, 'parse_error': str(e)}

    async def _parse_mcp_message(self, message: str) -> Dict[str, Any]:
        """Parse MCP JSON-RPC message."""
        import json

        try:
            data = json.loads(message)
            return {
                'content': data.get('params', {}).get('content', message),
                'method': data.get('method'),
                'id': data.get('id'),
                'jsonrpc': data.get('jsonrpc', '2.0'),
                'params': data.get('params', {}),
                'metadata': {
                    'protocol': 'mcp',
                    'method': data.get('method'),
                    'message_id': data.get('id')
                }
            }
        except json.JSONDecodeError:
            return {'content': message, 'metadata': {'protocol': 'mcp', 'parse_error': 'invalid_json'}}

    async def _parse_a2a_message(self, message: str) -> Dict[str, Any]:
        """Parse A2A message format."""
        lines = message.strip().split('\n')
        parsed = {'content': message, 'metadata': {'protocol': 'a2a'}}

        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                parsed[key.strip().lower()] = value.strip()

        if 'payload' in parsed:
            parsed['content'] = parsed['payload']

        return parsed

    async def _parse_fipa_message(self, message: str) -> Dict[str, Any]:
        """Parse FIPA-ACL message."""
        content = message
        performative = None
        sender = None
        receiver = None

        # Simple FIPA-ACL parsing
        lines = message.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('('):
                performative = line.split()[0][1:]
            elif ':content' in line:
                content_start = line.find('"')
                content_end = line.rfind('"')
                if content_start != -1 and content_end != -1 and content_start < content_end:
                    content = line[content_start+1:content_end]
            elif ':sender' in line:
                sender = line.split(':sender')[1].strip()
            elif ':receiver' in line:
                receiver = line.split(':receiver')[1].strip()

        return {
            'content': content,
            'performative': performative,
            'sender': sender,
            'receiver': receiver,
            'metadata': {
                'protocol': 'fipa',
                'performative': performative
            }
        }

    async def _parse_acp_message(self, message: str) -> Dict[str, Any]:
        """Parse ACP XML message."""
        import re

        # Simple XML-like parsing for ACP
        performative_match = re.search(r'<acp:performative>(.*?)</acp:performative>', message)
        content_match = re.search(r'<acp:content>(.*?)</acp:content>', message)

        performative = performative_match.group(1) if performative_match else None
        content = content_match.group(1) if content_match else message

        return {
            'content': content,
            'performative': performative,
            'metadata': {
                'protocol': 'acp',
                'performative': performative
            }
        }

    async def _apply_translation_rules(
        self,
        content: Dict[str, Any],
        source_protocol: ProtocolType,
        target_protocol: ProtocolType
    ) -> Dict[str, Any]:
        """Apply protocol-specific translation rules."""
        rule_key = f"{source_protocol.value}_to_{target_protocol.value}"
        rules = self.translation_rules.get(rule_key, [])

        transformed_content = content.copy()

        for rule in rules:
            try:
                transformed_content = await self._apply_rule(transformed_content, rule)
            except Exception as e:
                logger.warning(f"Translation rule application failed: {e}")

        return transformed_content

    async def _apply_rule(self, content: Dict[str, Any], rule: TranslationRule) -> Dict[str, Any]:
        """Apply a single translation rule."""
        # Simple rule application - could be extended with more sophisticated pattern matching
        if rule.source_pattern in str(content.get('content', '')):
            content['content'] = str(content['content']).replace(
                rule.source_pattern, rule.target_template
            )

        return content

    async def _format_message(self, content: Dict[str, Any], adapter: ProtocolAdapter) -> str:
        """Format message for target protocol."""
        try:
            if adapter.protocol_type == ProtocolType.MCP:
                return await self._format_mcp_message(content)
            elif adapter.protocol_type == ProtocolType.A2A:
                return await self._format_a2a_message(content)
            elif adapter.protocol_type == ProtocolType.FIPA:
                return await self._format_fipa_message(content)
            elif adapter.protocol_type == ProtocolType.ACP:
                return await self._format_acp_message(content)
            else:
                return str(content.get('content', ''))

        except Exception as e:
            logger.warning(f"Message formatting failed: {e}")
            return f"[{adapter.protocol_type.value.upper()}] {content.get('content', '')}"

    async def _format_mcp_message(self, content: Dict[str, Any]) -> str:
        """Format as MCP JSON-RPC message."""
        import json

        mcp_message = {
            'jsonrpc': content.get('jsonrpc', '2.0'),
            'method': content.get('method', 'translated_message'),
            'id': content.get('id', 1),
            'params': {
                'content': content.get('content', ''),
                'metadata': content.get('metadata', {})
            }
        }

        return json.dumps(mcp_message, indent=2)

    async def _format_a2a_message(self, content: Dict[str, Any]) -> str:
        """Format as A2A message."""
        sender = content.get('sender', 'translated-agent')
        recipient = content.get('recipient', 'target-agent')
        message_type = content.get('method', 'message')
        payload = content.get('content', '')

        return f"""SENDER: {sender}
RECIPIENT: {recipient}
TYPE: {message_type}
PAYLOAD:
{payload}"""

    async def _format_fipa_message(self, content: Dict[str, Any]) -> str:
        """Format as FIPA-ACL message."""
        performative = content.get('performative', 'inform')
        sender = content.get('sender', 'translated-agent')
        receiver = content.get('receiver', 'target-agent')
        message_content = content.get('content', '')

        return f"""({performative}
  :sender {sender}
  :receiver {receiver}
  :content "{message_content}"
  :language json
)"""

    async def _format_acp_message(self, content: Dict[str, Any]) -> str:
        """Format as ACP XML message."""
        performative = content.get('performative', 'inform')
        message_content = content.get('content', '')

        return f"""<acp:message>
  <acp:performative>{performative}</acp:performative>
  <acp:content>{message_content}</acp:content>
</acp:message>"""

    async def _perform_formal_verification(
        self,
        original: str,
        translated: str,
        source_protocol: ProtocolType,
        target_protocol: ProtocolType
    ) -> Dict[str, Any]:
        """Perform formal verification of translation."""
        if not self.formal_verifier:
            return {'verified': False, 'error': 'Formal verifier not available'}

        try:
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

            # Use ProVerif for verification
            result = await self.formal_verifier.proverif.verify_async(
                specification=spec,
                query="query attacker(translated_message)."
            )

            return {
                'verified': result.get('verified', False),
                'properties_verified': result.get('properties_verified', []),
                'execution_time': result.get('execution_time', 0),
                'tool': 'proverif'
            }

        except Exception as e:
            logger.error(f"Formal verification failed: {e}")
            return {'verified': False, 'error': str(e)}

    def _calculate_quality_score(self, response: TranslationResponse) -> float:
        """Calculate overall translation quality score."""
        score = 0.0
        weights = {'translation': 0.2, 'semantic': 0.4, 'security': 0.3, 'verification': 0.1}

        # Translation success
        if response.translation_successful:
            score += weights['translation']

        # Semantic similarity
        if response.semantic_similarity:
            score += response.semantic_similarity.overall_similarity * weights['semantic']

        # Security preservation
        if response.security_preservation:
            score += response.security_preservation.preservation_score * weights['security']

        # Formal verification
        if response.formal_verification_passed:
            score += weights['verification']

        return min(1.0, max(0.0, score))

    def _generate_recommendations(self, response: TranslationResponse) -> List[str]:
        """Generate recommendations based on translation results."""
        recommendations = []

        if response.semantic_similarity and response.semantic_similarity.overall_similarity < 0.7:
            recommendations.append("Review translation for semantic accuracy")

        if response.security_preservation and not response.security_preservation.is_preserved:
            recommendations.append("Address security property violations")

        if response.translation_quality_score < 0.8:
            recommendations.append("Consider manual review of translation")

        if not recommendations:
            recommendations.append("Translation meets quality standards")

        return recommendations

    async def _initialize_protocol_adapters(self) -> None:
        """Initialize protocol adapters."""
        self.protocol_adapters = {
            ProtocolType.MCP: ProtocolAdapter(
                protocol_type=ProtocolType.MCP,
                parser_class="MCPParser",
                formatter_class="MCPFormatter"
            ),
            ProtocolType.A2A: ProtocolAdapter(
                protocol_type=ProtocolType.A2A,
                parser_class="A2AParser",
                formatter_class="A2AFormatter"
            ),
            ProtocolType.FIPA: ProtocolAdapter(
                protocol_type=ProtocolType.FIPA,
                parser_class="FIPAParser",
                formatter_class="FIPAFormatter"
            ),
            ProtocolType.ACP: ProtocolAdapter(
                protocol_type=ProtocolType.ACP,
                parser_class="ACPParser",
                formatter_class="ACPFormatter"
            )
        }

    async def _load_translation_rules(self) -> None:
        """Load protocol translation rules."""
        # Basic translation rules - could be loaded from configuration
        self.translation_rules = {
            'mcp_to_a2a': [
                TranslationRule(
                    source_pattern='{"method"',
                    target_template='TYPE:',
                    semantic_weight=1.0
                )
            ],
            'a2a_to_fipa': [
                TranslationRule(
                    source_pattern='TYPE:',
                    target_template='(inform',
                    semantic_weight=1.0
                )
            ]
        }

    def _generate_cache_key(self, request: TranslationRequest) -> str:
        """Generate cache key for translation request."""
        key_data = f"{request.message}{request.source_protocol.value}{request.target_protocol.value}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _cache_translation(self, key: str, response: TranslationResponse) -> None:
        """Cache translation response."""
        if len(self._translation_cache) >= self._cache_size_limit:
            # Remove oldest entry
            oldest_key = next(iter(self._translation_cache))
            del self._translation_cache[oldest_key]

        self._translation_cache[key] = response

    def _update_statistics(self, response: TranslationResponse, execution_time: float) -> None:
        """Update translation statistics."""
        self.stats['total_translations'] += 1

        if response.status == TranslationStatus.COMPLETED:
            self.stats['successful_translations'] += 1
        else:
            self.stats['failed_translations'] += 1

        # Update average execution time
        total_time = self.stats['avg_translation_time_ms'] * (self.stats['total_translations'] - 1)
        self.stats['avg_translation_time_ms'] = (total_time + execution_time) / self.stats['total_translations']

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except ImportError:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            return 0.0

    async def get_statistics(self) -> Dict[str, Any]:
        """Get translation engine statistics."""
        return {
            'statistics': self.stats.copy(),
            'cache_size': len(self._translation_cache),
            'protocol_adapters': len(self.protocol_adapters),
            'translation_rules': sum(len(rules) for rules in self.translation_rules.values()),
            'initialized': self._initialized
        }

    async def shutdown(self) -> None:
        """Shutdown the translation engine."""
        logger.info("Shutting down Translation Engine")

        try:
            if self.semantic_analyzer:
                await self.semantic_analyzer.shutdown()

            if self.security_preservator:
                await self.security_preservator.shutdown()

            self._translation_cache.clear()
            self._initialized = False

            logger.info("Translation Engine shutdown completed")

        except Exception as e:
            logger.error("Translation Engine shutdown failed", error=str(e))
            raise TSAFException(f"Translation Engine shutdown failed: {str(e)}")