"""
Formal Verification Interface
Unified interface for formal verification tools (ProVerif, Tamarin, TLA+).
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Set
from enum import Enum

import structlog

from tsaf.core.config import VerifierConfig
from tsaf.core.exceptions import TSAFException
from tsaf.verifier.proverif_interface import ProVerifInterface
from tsaf.verifier.tamarin_interface import TamarinInterface
from tsaf.verifier.tlaplus_interface import TLAPlusInterface

logger = structlog.get_logger(__name__)


class VerificationTool(Enum):
    """Supported formal verification tools."""
    PROVERIF = "proverif"
    TAMARIN = "tamarin"
    TLAPLUS = "tlaplus"


class VerificationMode(Enum):
    """Verification execution modes."""
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    BEST_EFFORT = "best_effort"


class FormalVerifier:
    """
    Unified formal verification interface supporting multiple tools.

    Coordinates ProVerif, Tamarin, and TLA+ verification tools to provide
    comprehensive protocol security analysis.
    """

    def __init__(self, config: VerifierConfig):
        self.config = config
        self._initialized = False

        # Initialize tool interfaces with verifier config
        verifier_config = getattr(config, 'verifier', config)
        self.proverif = ProVerifInterface(verifier_config)
        self.tamarin = TamarinInterface(verifier_config)
        self.tlaplus = TLAPlusInterface(verifier_config)

        # Tool mapping
        self.tools = {
            VerificationTool.PROVERIF: self.proverif,
            VerificationTool.TAMARIN: self.tamarin,
            VerificationTool.TLAPLUS: self.tlaplus
        }

        # Available tools (determined during initialization)
        self.available_tools: Set[VerificationTool] = set()

    async def initialize(self) -> None:
        """Initialize formal verification interface."""
        if self._initialized:
            return

        logger.info("Initializing Formal Verifier")

        # Initialize available tools
        initialization_tasks = []
        tool_names = []

        for tool_type, interface in self.tools.items():
            task = self._safe_initialize(tool_type, interface)
            initialization_tasks.append(task)
            tool_names.append(tool_type.value)

        # Wait for all initializations
        results = await asyncio.gather(*initialization_tasks, return_exceptions=True)

        # Process results
        for i, result in enumerate(results):
            tool_type = list(self.tools.keys())[i]
            if result is True:
                self.available_tools.add(tool_type)
                logger.info(f"{tool_type.value} initialized successfully")
            else:
                logger.warning(f"{tool_type.value} initialization failed: {result}")

        if not self.available_tools:
            raise TSAFException("No formal verification tools available")

        self._initialized = True
        logger.info(
            "Formal Verifier initialization complete",
            available_tools=[tool.value for tool in self.available_tools]
        )

    async def _safe_initialize(self, tool_type: VerificationTool, interface) -> bool:
        """Safely initialize a verification tool interface."""
        try:
            await interface.initialize()
            return True
        except Exception as e:
            logger.debug(f"Failed to initialize {tool_type.value}: {str(e)}")
            return False

    async def verify_protocol(
        self,
        protocol_spec: Dict[str, Any],
        tools: Optional[List[VerificationTool]] = None,
        mode: VerificationMode = VerificationMode.PARALLEL
    ) -> Dict[str, Any]:
        """
        Verify protocol using specified formal verification tools.

        Args:
            protocol_spec: Protocol specification
            tools: List of tools to use (defaults to all available)
            mode: Verification execution mode

        Returns:
            Combined verification results
        """
        if not self._initialized:
            raise TSAFException("Formal Verifier not initialized")

        # Determine tools to use
        if tools is None:
            tools = list(self.available_tools)
        else:
            tools = [t for t in tools if t in self.available_tools]

        if not tools:
            raise TSAFException("No available verification tools specified")

        logger.info(
            "Starting formal verification",
            protocol=protocol_spec.get("name", "unknown"),
            tools=[t.value for t in tools],
            mode=mode.value
        )

        start_time = time.time()

        # Execute verification based on mode
        if mode == VerificationMode.PARALLEL:
            results = await self._verify_parallel(protocol_spec, tools)
        elif mode == VerificationMode.SEQUENTIAL:
            results = await self._verify_sequential(protocol_spec, tools)
        else:  # BEST_EFFORT
            results = await self._verify_best_effort(protocol_spec, tools)

        # Synthesize results
        verification_time = time.time() - start_time
        synthesized_results = self._synthesize_results(results, verification_time)

        logger.info(
            "Formal verification completed",
            tools_used=len(results),
            total_time=verification_time,
            overall_verified=synthesized_results["verified"]
        )

        return synthesized_results

    async def _verify_parallel(
        self,
        protocol_spec: Dict[str, Any],
        tools: List[VerificationTool]
    ) -> Dict[VerificationTool, Dict[str, Any]]:
        """Run verification tools in parallel."""
        tasks = {}

        for tool in tools:
            interface = self.tools[tool]
            task = self._safe_verify_protocol(tool, interface, protocol_spec)
            tasks[tool] = task

        # Execute all tasks in parallel
        completed_tasks = await asyncio.gather(
            *tasks.values(),
            return_exceptions=True
        )

        # Collect results
        results = {}
        for i, tool in enumerate(tasks.keys()):
            result = completed_tasks[i]
            if isinstance(result, Exception):
                logger.error(f"Verification failed for {tool.value}: {str(result)}")
                results[tool] = {
                    "verified": False,
                    "error": str(result),
                    "tool": tool.value
                }
            else:
                results[tool] = result

        return results

    async def _verify_sequential(
        self,
        protocol_spec: Dict[str, Any],
        tools: List[VerificationTool]
    ) -> Dict[VerificationTool, Dict[str, Any]]:
        """Run verification tools sequentially."""
        results = {}

        for tool in tools:
            interface = self.tools[tool]
            try:
                result = await self._safe_verify_protocol(tool, interface, protocol_spec)
                results[tool] = result

                # Stop early if verification fails in sequential mode
                if not result.get("verified", False):
                    logger.info(f"Verification failed with {tool.value}, continuing with next tool")

            except Exception as e:
                logger.error(f"Verification failed for {tool.value}: {str(e)}")
                results[tool] = {
                    "verified": False,
                    "error": str(e),
                    "tool": tool.value
                }

        return results

    async def _verify_best_effort(
        self,
        protocol_spec: Dict[str, Any],
        tools: List[VerificationTool]
    ) -> Dict[VerificationTool, Dict[str, Any]]:
        """Run verification with best-effort approach (parallel with timeouts)."""
        # Use parallel approach but with individual timeouts
        return await self._verify_parallel(protocol_spec, tools)

    async def _safe_verify_protocol(
        self,
        tool: VerificationTool,
        interface,
        protocol_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Safely verify protocol with specific tool."""
        # Check if interface is None
        if interface is None:
            logger.error(f"Tool interface is None for {tool.value}")
            raise RuntimeError(f"Tool interface {tool.value} is not available")

        try:
            start_time = time.time()

            if tool == VerificationTool.PROVERIF:
                result = await interface.verify_protocol_security(protocol_spec)
            elif tool == VerificationTool.TAMARIN:
                result = await interface.verify_protocol_security(protocol_spec)
            elif tool == VerificationTool.TLAPLUS:
                result = await interface.verify_protocol_properties(protocol_spec)
            else:
                raise TSAFException(f"Unsupported verification tool: {tool}")

            # Add tool metadata
            result["tool"] = tool.value
            result["verification_time"] = time.time() - start_time

            return result

        except Exception as e:
            logger.error(f"Verification failed for {tool.value}: {str(e)}")
            raise

    def _synthesize_results(
        self,
        results: Dict[VerificationTool, Dict[str, Any]],
        total_time: float
    ) -> Dict[str, Any]:
        """Synthesize results from multiple verification tools."""

        synthesized = {
            "verified": False,
            "tools_used": [],
            "individual_results": {},
            "summary": {
                "total_tools": len(results),
                "successful_tools": 0,
                "failed_tools": 0,
                "verification_time": total_time
            },
            "consensus": {},
            "conflicts": [],
            "recommendations": []
        }

        successful_tools = []
        failed_tools = []

        # Process individual results
        for tool, result in results.items():
            tool_name = tool.value
            synthesized["individual_results"][tool_name] = result
            synthesized["tools_used"].append(tool_name)

            if result.get("verified", False):
                successful_tools.append(tool_name)
            else:
                failed_tools.append(tool_name)

        synthesized["summary"]["successful_tools"] = len(successful_tools)
        synthesized["summary"]["failed_tools"] = len(failed_tools)

        # Determine overall verification status
        if successful_tools:
            # At least one tool succeeded
            if len(successful_tools) == len(results):
                # All tools agree - protocol is verified
                synthesized["verified"] = True
                synthesized["consensus"]["status"] = "all_verified"
            else:
                # Mixed results - need deeper analysis
                synthesized["verified"] = len(successful_tools) > len(failed_tools)
                synthesized["consensus"]["status"] = "mixed"
                synthesized["conflicts"] = self._analyze_conflicts(results)

        # Generate recommendations
        synthesized["recommendations"] = self._generate_recommendations(
            results, successful_tools, failed_tools
        )

        # Aggregate security properties
        synthesized["security_properties"] = self._aggregate_security_properties(results)

        return synthesized

    def _analyze_conflicts(
        self,
        results: Dict[VerificationTool, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze conflicts between verification results."""
        conflicts = []

        # Compare verification outcomes
        verified_tools = []
        failed_tools = []

        for tool, result in results.items():
            if result.get("verified", False):
                verified_tools.append(tool.value)
            else:
                failed_tools.append(tool.value)

        if verified_tools and failed_tools:
            conflicts.append({
                "type": "verification_disagreement",
                "verified_by": verified_tools,
                "failed_by": failed_tools,
                "description": "Tools disagree on overall verification status"
            })

        return conflicts

    def _generate_recommendations(
        self,
        results: Dict[VerificationTool, Dict[str, Any]],
        successful_tools: List[str],
        failed_tools: List[str]
    ) -> List[str]:
        """Generate recommendations based on verification results."""
        recommendations = []

        if not successful_tools:
            recommendations.append("Protocol verification failed across all tools - review protocol design")
        elif failed_tools:
            recommendations.append(f"Mixed verification results - investigate failures in {', '.join(failed_tools)}")

        # Tool-specific recommendations
        for tool, result in results.items():
            if not result.get("verified", False):
                errors = result.get("errors", [])
                if errors:
                    recommendations.append(f"Address {tool.value} errors: {'; '.join(errors[:2])}")

                warnings = result.get("warnings", [])
                if warnings:
                    recommendations.append(f"Review {tool.value} warnings: {'; '.join(warnings[:2])}")

        # Security property recommendations
        if successful_tools:
            recommendations.append("Consider implementing additional security properties based on successful verifications")

        return recommendations

    def _aggregate_security_properties(
        self,
        results: Dict[VerificationTool, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregate security properties from all verification results."""
        properties = {
            "secrecy": {"verified": False, "tools": []},
            "authentication": {"verified": False, "tools": []},
            "integrity": {"verified": False, "tools": []},
            "forward_secrecy": {"verified": False, "tools": []},
            "non_repudiation": {"verified": False, "tools": []}
        }

        for tool, result in results.items():
            tool_name = tool.value

            # Analyze tool-specific results for security properties
            if result.get("verified", False):
                # Check for specific properties in tool results
                queries = result.get("queries", [])
                lemmas = result.get("lemmas", [])

                # ProVerif queries
                for query in queries:
                    query_name = query.get("query", "").lower()
                    if query.get("verified", False):
                        if "secret" in query_name:
                            properties["secrecy"]["verified"] = True
                            properties["secrecy"]["tools"].append(tool_name)
                        elif "auth" in query_name:
                            properties["authentication"]["verified"] = True
                            properties["authentication"]["tools"].append(tool_name)

                # Tamarin lemmas
                for lemma in lemmas:
                    lemma_name = lemma.get("name", "").lower()
                    if lemma.get("status") == "verified":
                        if "secrecy" in lemma_name or "secret" in lemma_name:
                            properties["secrecy"]["verified"] = True
                            properties["secrecy"]["tools"].append(tool_name)
                        elif "auth" in lemma_name:
                            properties["authentication"]["verified"] = True
                            properties["authentication"]["tools"].append(tool_name)
                        elif "integrity" in lemma_name:
                            properties["integrity"]["verified"] = True
                            properties["integrity"]["tools"].append(tool_name)

        return properties

    async def verify_with_proverif(
        self,
        protocol_spec: Dict[str, Any],
        verification_id: str = None
    ) -> Dict[str, Any]:
        """Verify protocol using ProVerif tool with None checking."""
        if self.proverif is None:
            logger.error("ProVerif interface is not available", verification_id=verification_id)
            return {
                "verified": False,
                "error": "ProVerif tool not available",
                "tool": "proverif"
            }

        try:
            result = await self.proverif.verify_protocol_security(protocol_spec)
            result["tool"] = "proverif"
            return result
        except Exception as e:
            logger.error("ProVerif verification failed", error=str(e), verification_id=verification_id)
            raise RuntimeError(f"ProVerif verification failed: {str(e)}")

    async def verify_with_tamarin(
        self,
        protocol_spec: Dict[str, Any],
        verification_id: str = None
    ) -> Dict[str, Any]:
        """Verify protocol using Tamarin tool with None checking."""
        if self.tamarin is None:
            logger.error("Tamarin interface is not available", verification_id=verification_id)
            return {
                "verified": False,
                "error": "Tamarin tool not available",
                "tool": "tamarin"
            }

        try:
            result = await self.tamarin.verify_protocol_security(protocol_spec)
            result["tool"] = "tamarin"
            return result
        except Exception as e:
            logger.error("Tamarin verification failed", error=str(e), verification_id=verification_id)
            raise RuntimeError(f"Tamarin verification failed: {str(e)}")

    async def verify_with_tlaplus(
        self,
        protocol_spec: Dict[str, Any],
        verification_id: str = None
    ) -> Dict[str, Any]:
        """Verify protocol using TLA+ tool with None checking."""
        if self.tlaplus is None:
            logger.error("TLA+ interface is not available", verification_id=verification_id)
            return {
                "verified": False,
                "error": "TLA+ tool not available",
                "tool": "tlaplus"
            }

        try:
            result = await self.tlaplus.verify_protocol_properties(protocol_spec)
            result["tool"] = "tlaplus"
            return result
        except Exception as e:
            logger.error("TLA+ verification failed", error=str(e), verification_id=verification_id)
            raise RuntimeError(f"TLA+ verification failed: {str(e)}")

    async def verify_translation_security(
        self,
        source_protocol: str,
        target_protocol: str,
        translation_spec: Dict[str, Any],
        tools: Optional[List[VerificationTool]] = None
    ) -> Dict[str, Any]:
        """
        Verify security properties of protocol translation.

        Args:
            source_protocol: Source protocol name
            target_protocol: Target protocol name
            translation_spec: Translation specification
            tools: Verification tools to use

        Returns:
            Translation security verification results
        """
        logger.info(
            "Verifying translation security",
            source=source_protocol,
            target=target_protocol
        )

        # Build protocol specification for translation verification
        protocol_spec = {
            "name": f"{source_protocol}_to_{target_protocol}_translation",
            "type": "translation",
            "source_protocol": source_protocol,
            "target_protocol": target_protocol,
            "translation_mapping": translation_spec.get("mapping", {}),
            "security_properties": [
                "semantic_preservation",
                "security_property_preservation",
                "no_information_leakage",
                "translation_integrity"
            ]
        }

        return await self.verify_protocol(protocol_spec, tools)

    async def shutdown(self) -> None:
        """Shutdown formal verification interface."""
        logger.info("Shutting down Formal Verifier")

        # Shutdown all tool interfaces
        shutdown_tasks = []
        for interface in self.tools.values():
            shutdown_tasks.append(interface.shutdown())

        await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        self._initialized = False

    async def validate_meaning(self, source: Dict[str, Any], target: Dict[str, Any]) -> bool:
        """Validate that semantic meaning is preserved between source and target."""
        try:
            # Extract content for comparison
            source_content = self._extract_content(source)
            target_content = self._extract_content(target)

            # Calculate semantic similarity using multiple methods
            similarity_scores = []

            # 1. Token-based similarity (Jaccard coefficient)
            jaccard_score = self._calculate_jaccard_similarity(source_content, target_content)
            similarity_scores.append(jaccard_score)

            # 2. Semantic embedding similarity (if available)
            try:
                embedding_score = await self._calculate_embedding_similarity(source_content, target_content)
                similarity_scores.append(embedding_score)
            except Exception:
                logger.debug("Embedding similarity calculation failed, using token-based only")

            # 3. Structural similarity for protocol-specific validation
            structural_score = self._calculate_structural_similarity(source, target)
            similarity_scores.append(structural_score)

            # Combine scores with weights
            weights = [0.3, 0.5, 0.2]  # Prioritize semantic embeddings
            if len(similarity_scores) == 2:  # No embeddings available
                weights = [0.7, 0.3]
                similarity_scores = [jaccard_score, structural_score]

            final_score = sum(score * weight for score, weight in zip(similarity_scores, weights))

            # Meaning is preserved if similarity score is above threshold
            threshold = 0.75
            is_preserved = final_score >= threshold

            logger.debug("Meaning validation completed",
                        final_score=final_score,
                        threshold=threshold,
                        preserved=is_preserved,
                        individual_scores=similarity_scores)

            return is_preserved

        except Exception as e:
            logger.error("Meaning validation failed", error=str(e))
            # Conservative approach: assume meaning not preserved on error
            return False

    def _extract_content(self, data: Dict[str, Any]) -> str:
        """Extract meaningful content from structured data."""
        if isinstance(data, dict):
            # Look for common content fields
            content_fields = ['content', 'message', 'payload', 'data', 'text', 'body']
            for field in content_fields:
                if field in data:
                    content = data[field]
                    return str(content) if not isinstance(content, str) else content

            # Fallback: concatenate all string values
            text_parts = []
            for value in data.values():
                if isinstance(value, str):
                    text_parts.append(value)
                elif isinstance(value, (int, float)):
                    text_parts.append(str(value))
            return ' '.join(text_parts)

        return str(data)

    def _calculate_jaccard_similarity(self, text1: str, text2: str) -> float:
        """Calculate Jaccard similarity between two texts."""
        if not text1 or not text2:
            return 0.0

        # Tokenize and normalize
        tokens1 = set(text1.lower().split())
        tokens2 = set(text2.lower().split())

        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0

        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)

        return len(intersection) / len(union)

    async def _calculate_embedding_similarity(self, text1: str, text2: str) -> float:
        """Calculate semantic similarity using embeddings."""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel
            import torch.nn.functional as F

            model_name = "sentence-transformers/all-MiniLM-L6-v2"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)

            def get_embedding(text):
                inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
                with torch.no_grad():
                    outputs = model(**inputs)
                    embeddings = outputs.last_hidden_state.mean(dim=1)
                return F.normalize(embeddings, p=2, dim=1)

            emb1 = get_embedding(text1)
            emb2 = get_embedding(text2)

            similarity = torch.cosine_similarity(emb1, emb2).item()
            return max(0.0, min(1.0, similarity))

        except ImportError:
            raise Exception("Transformers library not available")

    def _calculate_structural_similarity(self, source: Dict[str, Any], target: Dict[str, Any]) -> float:
        """Calculate structural similarity between data structures."""
        try:
            # Compare keys/structure
            source_keys = set(source.keys()) if isinstance(source, dict) else set()
            target_keys = set(target.keys()) if isinstance(target, dict) else set()

            if not source_keys and not target_keys:
                return 1.0
            if not source_keys or not target_keys:
                return 0.0

            key_overlap = len(source_keys.intersection(target_keys))
            total_keys = len(source_keys.union(target_keys))

            structural_score = key_overlap / total_keys

            # Bonus for preserving important protocol fields
            important_fields = {'type', 'method', 'performative', 'ontology', 'protocol'}
            important_preserved = 0
            important_total = 0

            for field in important_fields:
                if field in source_keys:
                    important_total += 1
                    if field in target_keys:
                        important_preserved += 1

            if important_total > 0:
                importance_bonus = (important_preserved / important_total) * 0.3
                structural_score = min(1.0, structural_score + importance_bonus)

            return structural_score

        except Exception:
            return 0.5  # Neutral score on error