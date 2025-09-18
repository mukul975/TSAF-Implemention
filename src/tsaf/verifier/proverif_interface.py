"""
ProVerif Interface
Handles interaction with ProVerif cryptographic protocol verifier.
"""

import asyncio
import tempfile
import os
import re
from typing import Dict, List, Optional, Any
from pathlib import Path

import structlog

from tsaf.core.config import VerifierConfig
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class ProVerifInterface:
    """Interface for ProVerif cryptographic protocol verifier."""

    def __init__(self, config: VerifierConfig):
        self.config = config
        self.proverif_path = config.proverif_path or "proverif"
        self.timeout = config.proverif_timeout or 60
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize ProVerif interface."""
        if self._initialized:
            return

        logger.info("Initializing ProVerif interface")

        # Check if ProVerif is available
        try:
            result = await asyncio.create_subprocess_exec(
                self.proverif_path, "-help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(result.wait(), timeout=5)

            if result.returncode == 0:
                self._initialized = True
                logger.info("ProVerif interface initialized successfully")
            else:
                raise TSAFException("ProVerif not available or not working properly")

        except (asyncio.TimeoutError, FileNotFoundError) as e:
            logger.warning(f"ProVerif not available: {str(e)}")
            raise TSAFException(f"ProVerif initialization failed: {str(e)}")

    async def verify(self, specification: str, query: str) -> Dict[str, Any]:
        """
        Verify protocol specification using ProVerif.

        Args:
            specification: ProVerif protocol specification
            query: Security query to verify

        Returns:
            Verification results
        """
        if not self._initialized:
            raise TSAFException("ProVerif interface not initialized")

        # Create ProVerif input file
        proverif_code = self._build_proverif_specification(specification, query)

        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pv', delete=False) as f:
            f.write(proverif_code)
            temp_path = f.name

        try:
            # Run ProVerif
            result = await self._run_proverif(temp_path)

            # Parse results
            return self._parse_proverif_output(result)

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    def _build_proverif_specification(self, specification: str, query: str) -> str:
        """Build complete ProVerif specification with query."""

        # Standard ProVerif header for cryptographic primitives
        header = """
(* Standard cryptographic primitives *)
type host.
type nonce.
type pkey.
type skey.
type spkey.
type sskey.

fun pk(skey): pkey.
fun spk(sskey): spkey.

(* Symmetric encryption *)
fun senc(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; sdec(senc(m,k),k) = m.

(* Asymmetric encryption *)
fun aenc(bitstring, pkey): bitstring.
reduc forall m: bitstring, k: skey; adec(aenc(m,pk(k)),k) = m.

(* Digital signatures *)
fun sign(bitstring, sskey): bitstring.
reduc forall m: bitstring, k: sskey; checksign(sign(m,k),spk(k)) = m.
reduc forall m: bitstring, k: sskey; getmess(sign(m,k)) = m.

(* Hash functions *)
fun hash(bitstring): bitstring.

(* Constants *)
free c: channel.

"""

        # Combine header, specification, and query
        return f"{header}\n{specification}\n\n{query}"

    async def _run_proverif(self, file_path: str) -> str:
        """Run ProVerif on specification file."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.proverif_path, file_path,
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
            logger.error(f"ProVerif verification timed out after {self.timeout}s")
            raise TSAFException("ProVerif verification timed out")
        except Exception as e:
            logger.error(f"ProVerif execution failed: {str(e)}")
            raise TSAFException(f"ProVerif execution failed: {str(e)}")

    def _parse_proverif_output(self, output: str) -> Dict[str, Any]:
        """Parse ProVerif output and extract results."""
        results = {
            "verified": False,
            "queries": [],
            "warnings": [],
            "errors": [],
            "raw_output": output
        }

        lines = output.split('\n')
        current_query = None

        for line in lines:
            line = line.strip()

            # Parse query results
            if "Query" in line and ("not" in line.lower() or "cannot" in line.lower()):
                query_match = re.search(r'Query (.+?) is false', line)
                if query_match:
                    current_query = {
                        "query": query_match.group(1),
                        "result": "false",
                        "verified": True
                    }
                    results["queries"].append(current_query)
                    continue

                query_match = re.search(r'Query (.+?) is true', line)
                if query_match:
                    current_query = {
                        "query": query_match.group(1),
                        "result": "true",
                        "verified": True
                    }
                    results["queries"].append(current_query)
                    continue

                query_match = re.search(r'Query (.+?) cannot be proved', line)
                if query_match:
                    current_query = {
                        "query": query_match.group(1),
                        "result": "unknown",
                        "verified": False
                    }
                    results["queries"].append(current_query)
                    continue

            # Parse secrecy results
            if "RESULT" in line:
                if "not secret" in line.lower():
                    if current_query:
                        current_query["secrecy_violated"] = True
                elif "secret" in line.lower():
                    if current_query:
                        current_query["secrecy_preserved"] = True

            # Parse authentication results
            if "Authentication" in line:
                if current_query:
                    current_query["authentication"] = "verified" if "verified" in line.lower() else "failed"

            # Parse warnings
            if "Warning" in line:
                results["warnings"].append(line)

            # Parse errors
            if "Error" in line or "Syntax error" in line:
                results["errors"].append(line)

        # Overall verification status
        if results["queries"]:
            results["verified"] = all(q.get("verified", False) for q in results["queries"])

        # Summary statistics
        results["summary"] = {
            "total_queries": len(results["queries"]),
            "verified_queries": len([q for q in results["queries"] if q.get("verified", False)]),
            "failed_queries": len([q for q in results["queries"] if not q.get("verified", False)]),
            "warnings": len(results["warnings"]),
            "errors": len(results["errors"])
        }

        logger.info(
            "ProVerif verification completed",
            verified=results["verified"],
            queries=results["summary"]["total_queries"],
            warnings=len(results["warnings"]),
            errors=len(results["errors"])
        )

        return results

    async def verify_protocol_security(self, protocol_spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify protocol security properties.

        Args:
            protocol_spec: Protocol specification with security properties

        Returns:
            Verification results for security properties
        """
        # Extract protocol information
        protocol_name = protocol_spec.get("name", "unknown")
        messages = protocol_spec.get("messages", [])
        security_properties = protocol_spec.get("security_properties", [])

        # Generate ProVerif specification
        specification = self._generate_protocol_specification(protocol_name, messages)

        # Generate security queries
        queries = self._generate_security_queries(security_properties)

        # Combine queries
        full_query = "\n".join(queries)

        # Verify
        return await self.verify(specification, full_query)

    def _generate_protocol_specification(self, name: str, messages: List[Dict[str, Any]]) -> str:
        """Generate ProVerif protocol specification from message flow."""

        spec_lines = [f"(* Protocol: {name} *)"]

        # Generate processes for each message
        for i, msg in enumerate(messages):
            sender = msg.get("sender", f"A{i}")
            receiver = msg.get("receiver", f"B{i}")
            content = msg.get("content", f"msg{i}")

            # Simple process definition
            spec_lines.append(f"let {sender}_process =")
            spec_lines.append(f"  out(c, {content});")
            spec_lines.append(f"  0.")
            spec_lines.append("")

            spec_lines.append(f"let {receiver}_process =")
            spec_lines.append(f"  in(c, x: bitstring);")
            spec_lines.append(f"  0.")
            spec_lines.append("")

        # Main process
        processes = [f"{msg.get('sender', f'A{i}')}_process" for i, msg in enumerate(messages)]
        processes.extend([f"{msg.get('receiver', f'B{i}')}_process" for i, msg in enumerate(messages)])

        spec_lines.append("process")
        spec_lines.append(" | ".join(processes))

        return "\n".join(spec_lines)

    def _generate_security_queries(self, properties: List[str]) -> List[str]:
        """Generate ProVerif queries for security properties."""
        queries = []

        for prop in properties:
            prop_lower = prop.lower()

            if "secrecy" in prop_lower:
                queries.append("query secret key.")
            elif "authentication" in prop_lower:
                queries.append("query event(endA(x)) ==> event(beginB(x)).")
            elif "integrity" in prop_lower:
                queries.append("query event(received(x)) ==> event(sent(x)).")
            elif "forward_secrecy" in prop_lower:
                queries.append("query secret key [cv_onesession].")

        # Default query if no specific properties
        if not queries:
            queries.append("query secret key.")

        return queries

    async def verify_async(self, specification: str, query: str) -> Dict[str, Any]:
        """
        Async alias for verify method for compatibility.

        Args:
            specification: ProVerif protocol specification
            query: Security query to verify

        Returns:
            Verification results
        """
        return await self.verify(specification, query)

    async def shutdown(self) -> None:
        """Shutdown ProVerif interface."""
        logger.info("Shutting down ProVerif interface")
        self._initialized = False