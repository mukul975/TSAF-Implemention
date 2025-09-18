"""
Tamarin Prover Interface
Handles interaction with Tamarin security protocol verification tool.
"""

import asyncio
import tempfile
import os
import json
import re
from typing import Dict, List, Optional, Any
from pathlib import Path

import structlog

from tsaf.core.config import VerifierConfig
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class TamarinInterface:
    """Interface for Tamarin security protocol verification tool."""

    def __init__(self, config: VerifierConfig):
        self.config = config
        self.tamarin_path = config.tamarin_path or "tamarin-prover"
        self.timeout = config.tamarin_timeout or 300  # Tamarin can be slow
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize Tamarin interface."""
        if self._initialized:
            return

        logger.info("Initializing Tamarin interface")

        # Check if Tamarin is available
        try:
            result = await asyncio.create_subprocess_exec(
                self.tamarin_path, "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(result.wait(), timeout=10)

            if result.returncode == 0:
                self._initialized = True
                logger.info("Tamarin interface initialized successfully")
            else:
                raise TSAFException("Tamarin not available or not working properly")

        except (asyncio.TimeoutError, FileNotFoundError) as e:
            logger.warning(f"Tamarin not available: {str(e)}")
            raise TSAFException(f"Tamarin initialization failed: {str(e)}")

    async def verify(self, specification: str, lemmas: List[str]) -> Dict[str, Any]:
        """
        Verify protocol specification using Tamarin.

        Args:
            specification: Tamarin theory specification
            lemmas: List of lemmas to verify

        Returns:
            Verification results
        """
        if not self._initialized:
            raise TSAFException("Tamarin interface not initialized")

        # Create complete Tamarin theory
        theory = self._build_tamarin_theory(specification, lemmas)

        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spthy', delete=False) as f:
            f.write(theory)
            temp_path = f.name

        try:
            # Run Tamarin verification
            result = await self._run_tamarin(temp_path)

            # Parse results
            return self._parse_tamarin_output(result)

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    def _build_tamarin_theory(self, specification: str, lemmas: List[str]) -> str:
        """Build complete Tamarin theory with lemmas."""

        # Standard Tamarin theory header
        header = """
theory Protocol
begin

// Built-in functions and rules
builtins: diffie-hellman, signing, hashing, symmetric-encryption, asymmetric-encryption

// Standard message rules
rule Setup:
    []
    --[ Setup() ]->
    []

rule Fresh:
    []
    --[ Fresh($x) ]->
    [ !F($x) ]

rule Out:
    [ !F(x) ]
    --[ Out(x) ]->
    [ Out(x) ]

rule In:
    [ In(x) ]
    --[ In(x) ]->
    []

"""

        # Combine header, specification, and lemmas
        lemma_section = "\n".join(f"lemma {lemma}" for lemma in lemmas)

        return f"{header}\n{specification}\n\n{lemma_section}\n\nend"

    async def _run_tamarin(self, file_path: str) -> str:
        """Run Tamarin on theory file."""
        try:
            # Run with JSON output for easier parsing
            process = await asyncio.create_subprocess_exec(
                self.tamarin_path, "--prove", "--output=json", file_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )

            output = stdout.decode('utf-8') + stderr.decode('utf-8')

            return output

        except asyncio.TimeoutError:
            logger.error(f"Tamarin verification timed out after {self.timeout}s")
            raise TSAFException("Tamarin verification timed out")
        except Exception as e:
            logger.error(f"Tamarin execution failed: {str(e)}")
            raise TSAFException(f"Tamarin execution failed: {str(e)}")

    def _parse_tamarin_output(self, output: str) -> Dict[str, Any]:
        """Parse Tamarin output and extract results."""
        results = {
            "verified": False,
            "lemmas": [],
            "warnings": [],
            "errors": [],
            "statistics": {},
            "raw_output": output
        }

        # Try to parse JSON output first
        try:
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                json_data = json.loads(json_match.group(0))
                return self._parse_json_results(json_data, output)
        except (json.JSONDecodeError, AttributeError):
            pass

        # Fall back to text parsing
        lines = output.split('\n')

        for line in lines:
            line = line.strip()

            # Parse lemma results
            if "verified" in line.lower():
                lemma_match = re.search(r'lemma (\w+).*verified', line, re.IGNORECASE)
                if lemma_match:
                    results["lemmas"].append({
                        "name": lemma_match.group(1),
                        "status": "verified",
                        "time": self._extract_time(line)
                    })

            elif "falsified" in line.lower():
                lemma_match = re.search(r'lemma (\w+).*falsified', line, re.IGNORECASE)
                if lemma_match:
                    results["lemmas"].append({
                        "name": lemma_match.group(1),
                        "status": "falsified",
                        "time": self._extract_time(line)
                    })

            elif "analysis incomplete" in line.lower():
                lemma_match = re.search(r'lemma (\w+).*incomplete', line, re.IGNORECASE)
                if lemma_match:
                    results["lemmas"].append({
                        "name": lemma_match.group(1),
                        "status": "incomplete",
                        "time": self._extract_time(line)
                    })

            # Parse warnings
            if "warning" in line.lower():
                results["warnings"].append(line)

            # Parse errors
            if "error" in line.lower() or "parse error" in line.lower():
                results["errors"].append(line)

            # Parse statistics
            if "time:" in line.lower():
                time_match = re.search(r'time:\s*([\d.]+)', line)
                if time_match:
                    results["statistics"]["total_time"] = float(time_match.group(1))

        # Overall verification status
        if results["lemmas"]:
            verified_count = len([l for l in results["lemmas"] if l["status"] == "verified"])
            results["verified"] = verified_count == len(results["lemmas"])

        # Summary statistics
        results["summary"] = {
            "total_lemmas": len(results["lemmas"]),
            "verified_lemmas": len([l for l in results["lemmas"] if l["status"] == "verified"]),
            "falsified_lemmas": len([l for l in results["lemmas"] if l["status"] == "falsified"]),
            "incomplete_lemmas": len([l for l in results["lemmas"] if l["status"] == "incomplete"]),
            "warnings": len(results["warnings"]),
            "errors": len(results["errors"])
        }

        logger.info(
            "Tamarin verification completed",
            verified=results["verified"],
            lemmas=results["summary"]["total_lemmas"],
            warnings=len(results["warnings"]),
            errors=len(results["errors"])
        )

        return results

    def _parse_json_results(self, json_data: Dict[str, Any], raw_output: str) -> Dict[str, Any]:
        """Parse JSON results from Tamarin."""
        results = {
            "verified": False,
            "lemmas": [],
            "warnings": [],
            "errors": [],
            "statistics": json_data.get("statistics", {}),
            "raw_output": raw_output
        }

        # Parse lemma results from JSON
        lemmas = json_data.get("lemmas", [])
        for lemma in lemmas:
            results["lemmas"].append({
                "name": lemma.get("name", "unknown"),
                "status": lemma.get("status", "unknown"),
                "time": lemma.get("time", 0),
                "steps": lemma.get("steps", 0)
            })

        # Parse warnings and errors
        results["warnings"] = json_data.get("warnings", [])
        results["errors"] = json_data.get("errors", [])

        # Overall status
        verified_count = len([l for l in results["lemmas"] if l["status"] == "verified"])
        results["verified"] = verified_count == len(results["lemmas"])

        # Summary
        results["summary"] = {
            "total_lemmas": len(results["lemmas"]),
            "verified_lemmas": verified_count,
            "falsified_lemmas": len([l for l in results["lemmas"] if l["status"] == "falsified"]),
            "incomplete_lemmas": len([l for l in results["lemmas"] if l["status"] == "incomplete"]),
            "warnings": len(results["warnings"]),
            "errors": len(results["errors"])
        }

        return results

    def _extract_time(self, line: str) -> float:
        """Extract timing information from line."""
        time_match = re.search(r'([\d.]+)s', line)
        if time_match:
            return float(time_match.group(1))
        return 0.0

    async def verify_protocol_security(self, protocol_spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify protocol security properties using Tamarin.

        Args:
            protocol_spec: Protocol specification with security properties

        Returns:
            Verification results for security properties
        """
        # Extract protocol information
        protocol_name = protocol_spec.get("name", "unknown")
        roles = protocol_spec.get("roles", [])
        messages = protocol_spec.get("messages", [])
        security_properties = protocol_spec.get("security_properties", [])

        # Generate Tamarin specification
        specification = self._generate_tamarin_specification(protocol_name, roles, messages)

        # Generate lemmas
        lemmas = self._generate_security_lemmas(security_properties)

        # Verify
        return await self.verify(specification, lemmas)

    def _generate_tamarin_specification(
        self,
        name: str,
        roles: List[Dict[str, Any]],
        messages: List[Dict[str, Any]]
    ) -> str:
        """Generate Tamarin theory specification from protocol description."""

        spec_lines = [f"// Protocol: {name}"]
        spec_lines.append("")

        # Generate rules for each role
        for role in roles:
            role_name = role.get("name", "UnknownRole")
            actions = role.get("actions", [])

            spec_lines.append(f"rule {role_name}:")
            spec_lines.append("  [")

            # Prerequisites
            prereqs = role.get("prerequisites", [])
            if prereqs:
                spec_lines.append(f"    {', '.join(prereqs)}")

            spec_lines.append("  ]")
            spec_lines.append("  --[")

            # Actions
            if actions:
                spec_lines.append(f"    {', '.join(actions)}")

            spec_lines.append("  ]->")
            spec_lines.append("  [")

            # Results
            results = role.get("results", [])
            if results:
                spec_lines.append(f"    {', '.join(results)}")

            spec_lines.append("  ]")
            spec_lines.append("")

        # Generate message passing rules
        for i, msg in enumerate(messages):
            sender = msg.get("sender", "Alice")
            receiver = msg.get("receiver", "Bob")
            content = msg.get("content", f"msg{i}")

            spec_lines.append(f"rule Send_Msg_{i+1}:")
            spec_lines.append(f"  [ {sender}(x) ]")
            spec_lines.append(f"  --[ Send({sender}, {receiver}, {content}) ]->")
            spec_lines.append(f"  [ Out({content}), {sender}(x) ]")
            spec_lines.append("")

            spec_lines.append(f"rule Recv_Msg_{i+1}:")
            spec_lines.append(f"  [ In(x), {receiver}(y) ]")
            spec_lines.append(f"  --[ Recv({receiver}, {sender}, x) ]->")
            spec_lines.append(f"  [ {receiver}(y) ]")
            spec_lines.append("")

        return "\n".join(spec_lines)

    def _generate_security_lemmas(self, properties: List[str]) -> List[str]:
        """Generate Tamarin lemmas for security properties."""
        lemmas = []

        for prop in properties:
            prop_lower = prop.lower()

            if "secrecy" in prop_lower:
                lemmas.append(
                    'secret_key:\n'
                    '  "All x #i. Secret(x) @i ==> not (Ex #j. K(x) @j)"'
                )

            elif "authentication" in prop_lower:
                lemmas.append(
                    'authentication:\n'
                    '  "All a b x #i. Commit(a,b,x) @i\n'
                    '   ==> (Ex #j. Running(b,a,x) @j & j < i)\n'
                    '       | (Ex #r. Reveal(a) @r)\n'
                    '       | (Ex #r. Reveal(b) @r)"'
                )

            elif "integrity" in prop_lower:
                lemmas.append(
                    'message_integrity:\n'
                    '  "All x #i. Recv(x) @i ==> Ex #j. Send(x) @j & j < i"'
                )

            elif "forward_secrecy" in prop_lower:
                lemmas.append(
                    'perfect_forward_secrecy:\n'
                    '  "All a b x #i.\n'
                    '   Secret(a,b,x) @i ==> \n'
                    '   not (Ex #j. K(x) @j)\n'
                    '       | (Ex #r. Reveal(a) @r & Honest(a) @i & r < i)\n'
                    '       | (Ex #r. Reveal(b) @r & Honest(b) @i & r < i)"'
                )

            elif "non_repudiation" in prop_lower:
                lemmas.append(
                    'non_repudiation:\n'
                    '  "All a b m #i.\n'
                    '   Recv(a, b, m) @i ==> Ex #j. Send(b, a, m) @j"'
                )

        # Default lemma if no specific properties
        if not lemmas:
            lemmas.append(
                'executable:\n'
                '  "Ex #i. Setup() @i"'
            )

        return lemmas

    async def shutdown(self) -> None:
        """Shutdown Tamarin interface."""
        logger.info("Shutting down Tamarin interface")
        self._initialized = False