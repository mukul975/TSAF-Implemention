"""
TLA+ Interface
Handles interaction with TLA+ specification and TLC model checker.
"""

import asyncio
import tempfile
import os
import re
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

import structlog

from tsaf.core.config import VerifierConfig
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class TLAPlusInterface:
    """Interface for TLA+ specification language and TLC model checker."""

    def __init__(self, config: VerifierConfig):
        self.config = config
        self.tlc_path = config.tlc_path or "tlc"
        self.tlaplus_path = config.tlaplus_path or "tla"
        self.timeout = config.tlaplus_timeout or 180
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize TLA+ interface."""
        if self._initialized:
            return

        logger.info("Initializing TLA+ interface")

        # Check if TLC is available
        try:
            result = await asyncio.create_subprocess_exec(
                self.tlc_path, "-h",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(result.wait(), timeout=5)

            if result.returncode == 0:
                self._initialized = True
                logger.info("TLA+ interface initialized successfully")
            else:
                raise TSAFException("TLC not available or not working properly")

        except (asyncio.TimeoutError, FileNotFoundError) as e:
            logger.warning(f"TLA+ not available: {str(e)}")
            raise TSAFException(f"TLA+ initialization failed: {str(e)}")

    async def verify(self, specification: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Verify TLA+ specification using TLC model checker.

        Args:
            specification: TLA+ specification
            config: TLC configuration options

        Returns:
            Verification results
        """
        if not self._initialized:
            raise TSAFException("TLA+ interface not initialized")

        config = config or {}

        # Create temporary files
        spec_file, cfg_file = await self._create_temp_files(specification, config)

        try:
            # Run TLC
            result = await self._run_tlc(spec_file, cfg_file)

            # Parse results
            return self._parse_tlc_output(result)

        finally:
            # Clean up temporary files
            for temp_file in [spec_file, cfg_file]:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass

    async def _create_temp_files(self, specification: str, config: Dict[str, Any]) -> Tuple[str, str]:
        """Create temporary TLA+ specification and configuration files."""

        # Create specification file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tla', delete=False) as f:
            f.write(specification)
            spec_file = f.name

        # Create configuration file
        cfg_content = self._build_tlc_config(config)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as f:
            f.write(cfg_content)
            cfg_file = f.name

        return spec_file, cfg_file

    def _build_tlc_config(self, config: Dict[str, Any]) -> str:
        """Build TLC configuration file content."""
        cfg_lines = []

        # Specification section
        spec_name = config.get("spec_name", "Spec")
        cfg_lines.append(f"SPECIFICATION {spec_name}")
        cfg_lines.append("")

        # Constants
        constants = config.get("constants", {})
        if constants:
            cfg_lines.append("CONSTANTS")
            for name, value in constants.items():
                cfg_lines.append(f"  {name} = {value}")
            cfg_lines.append("")

        # Initial predicate
        init = config.get("init")
        if init:
            cfg_lines.append(f"INIT {init}")
            cfg_lines.append("")

        # Next state relation
        next_state = config.get("next")
        if next_state:
            cfg_lines.append(f"NEXT {next_state}")
            cfg_lines.append("")

        # Invariants
        invariants = config.get("invariants", [])
        if invariants:
            cfg_lines.append("INVARIANT")
            for inv in invariants:
                cfg_lines.append(f"  {inv}")
            cfg_lines.append("")

        # Properties
        properties = config.get("properties", [])
        if properties:
            cfg_lines.append("PROPERTY")
            for prop in properties:
                cfg_lines.append(f"  {prop}")
            cfg_lines.append("")

        # View
        view = config.get("view")
        if view:
            cfg_lines.append(f"VIEW {view}")
            cfg_lines.append("")

        # Symmetry
        symmetry = config.get("symmetry")
        if symmetry:
            cfg_lines.append(f"SYMMETRY {symmetry}")
            cfg_lines.append("")

        return "\n".join(cfg_lines)

    async def _run_tlc(self, spec_file: str, cfg_file: str) -> str:
        """Run TLC model checker on specification."""
        try:
            # Build TLC command
            cmd = [
                self.tlc_path,
                "-config", cfg_file,
                "-cleanup",
                "-workers", "auto",
                spec_file
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
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
            logger.error(f"TLA+ verification timed out after {self.timeout}s")
            raise TSAFException("TLA+ verification timed out")
        except Exception as e:
            logger.error(f"TLA+ execution failed: {str(e)}")
            raise TSAFException(f"TLA+ execution failed: {str(e)}")

    def _parse_tlc_output(self, output: str) -> Dict[str, Any]:
        """Parse TLC output and extract results."""
        results = {
            "verified": False,
            "invariants": [],
            "properties": [],
            "states_explored": 0,
            "diameter": 0,
            "runtime": 0,
            "errors": [],
            "warnings": [],
            "deadlocks": [],
            "raw_output": output
        }

        lines = output.split('\n')

        for line in lines:
            line = line.strip()

            # Parse verification success
            if "Model checking completed. No error has been found." in line:
                results["verified"] = True

            # Parse state space exploration
            state_match = re.search(r'(\d+) states generated', line)
            if state_match:
                results["states_explored"] = int(state_match.group(1))

            # Parse diameter
            diameter_match = re.search(r'Diameter of the search: (\d+)', line)
            if diameter_match:
                results["diameter"] = int(diameter_match.group(1))

            # Parse runtime
            time_match = re.search(r'Finished in (\d+)ms', line)
            if time_match:
                results["runtime"] = int(time_match.group(1))

            # Parse invariant violations
            if "Invariant" in line and "violated" in line:
                inv_match = re.search(r'Invariant (.+?) is violated', line)
                if inv_match:
                    results["invariants"].append({
                        "name": inv_match.group(1),
                        "status": "violated"
                    })
                    results["verified"] = False

            # Parse property violations
            if "Property" in line and "violated" in line:
                prop_match = re.search(r'Property (.+?) is violated', line)
                if prop_match:
                    results["properties"].append({
                        "name": prop_match.group(1),
                        "status": "violated"
                    })
                    results["verified"] = False

            # Parse deadlocks
            if "Deadlock reached" in line:
                results["deadlocks"].append({
                    "description": line,
                    "state": self._extract_state_info(line)
                })
                results["verified"] = False

            # Parse errors
            if "Error:" in line or "TLC Bug" in line:
                results["errors"].append(line)

            # Parse warnings
            if "Warning:" in line:
                results["warnings"].append(line)

        # Summary statistics
        results["summary"] = {
            "states_explored": results["states_explored"],
            "diameter": results["diameter"],
            "runtime_ms": results["runtime"],
            "invariant_violations": len([i for i in results["invariants"] if i["status"] == "violated"]),
            "property_violations": len([p for p in results["properties"] if p["status"] == "violated"]),
            "deadlocks": len(results["deadlocks"]),
            "errors": len(results["errors"]),
            "warnings": len(results["warnings"])
        }

        logger.info(
            "TLA+ verification completed",
            verified=results["verified"],
            states=results["states_explored"],
            diameter=results["diameter"],
            runtime_ms=results["runtime"],
            errors=len(results["errors"])
        )

        return results

    def _extract_state_info(self, line: str) -> Dict[str, Any]:
        """Extract state information from error line."""
        # Simple state extraction - could be enhanced
        return {"description": line}

    async def verify_protocol_properties(self, protocol_spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify protocol properties using TLA+ specification.

        Args:
            protocol_spec: Protocol specification with properties

        Returns:
            Verification results
        """
        # Extract protocol information
        protocol_name = protocol_spec.get("name", "Protocol")
        states = protocol_spec.get("states", [])
        transitions = protocol_spec.get("transitions", [])
        invariants = protocol_spec.get("invariants", [])
        properties = protocol_spec.get("properties", [])

        # Generate TLA+ specification
        specification = self._generate_tla_specification(
            protocol_name, states, transitions, invariants, properties
        )

        # Generate configuration
        config = {
            "spec_name": f"{protocol_name}Spec",
            "init": f"{protocol_name}Init",
            "next": f"{protocol_name}Next",
            "invariants": invariants,
            "properties": properties
        }

        # Verify
        return await self.verify(specification, config)

    def _generate_tla_specification(
        self,
        name: str,
        states: List[str],
        transitions: List[Dict[str, Any]],
        invariants: List[str],
        properties: List[str]
    ) -> str:
        """Generate TLA+ specification from protocol description."""

        spec_lines = [
            f"---- MODULE {name} ----",
            "EXTENDS Naturals, Sequences, TLC",
            "",
            "VARIABLES"
        ]

        # Add state variables
        if states:
            spec_lines.extend([f"  {state}," for state in states[:-1]])
            spec_lines.append(f"  {states[-1]}")
        else:
            spec_lines.append("  state")

        spec_lines.extend([
            "",
            f"vars == << {', '.join(states) if states else 'state'} >>",
            "",
            f"{name}Init ==",
            "  /\\ TRUE  (* Add initialization conditions *)",
            "",
            f"{name}Next ==",
            "  /\\ TRUE  (* Add next-state relations *)",
        ])

        # Add transitions
        if transitions:
            spec_lines.append("")
            spec_lines.append("(* Protocol transitions *)")
            for i, transition in enumerate(transitions):
                trans_name = transition.get("name", f"Transition{i+1}")
                condition = transition.get("condition", "TRUE")
                action = transition.get("action", "UNCHANGED vars")

                spec_lines.extend([
                    f"{trans_name} ==",
                    f"  /\\ {condition}",
                    f"  /\\ {action}",
                    ""
                ])

        # Add invariants
        if invariants:
            spec_lines.append("(* Safety invariants *)")
            for i, invariant in enumerate(invariants):
                spec_lines.append(f"Invariant{i+1} == {invariant}")
            spec_lines.append("")

        # Add properties
        if properties:
            spec_lines.append("(* Liveness properties *)")
            for i, prop in enumerate(properties):
                spec_lines.append(f"Property{i+1} == {prop}")
            spec_lines.append("")

        # Add specification
        spec_lines.extend([
            f"{name}Spec == {name}Init /\\ [][{name}Next]_vars",
            "",
            f"THEOREM {name}Spec => []TypeOK",
            "",
            "===="
        ])

        return "\n".join(spec_lines)

    async def generate_tla_from_protocol(self, protocol_data: Dict[str, Any]) -> str:
        """
        Generate TLA+ specification from protocol description.

        Args:
            protocol_data: Protocol specification

        Returns:
            TLA+ specification string
        """
        name = protocol_data.get("name", "Protocol")
        agents = protocol_data.get("agents", [])
        messages = protocol_data.get("messages", [])
        security_props = protocol_data.get("security_properties", [])

        # Generate comprehensive TLA+ specification
        spec = f"""---- MODULE {name} ----
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
  Agents,           (* Set of agents *)
  Messages,         (* Set of possible messages *)
  Keys             (* Set of cryptographic keys *)

VARIABLES
  network,         (* Messages in transit *)
  agentState,      (* State of each agent *)
  knowledge        (* Knowledge of each agent *)

vars == << network, agentState, knowledge >>

(* Type invariant *)
TypeOK ==
  /\\ network \\subseteq Messages
  /\\ agentState \\in [Agents -> STRING]
  /\\ knowledge \\in [Agents -> SUBSET Messages]

(* Initial state *)
Init ==
  /\\ network = {{}}
  /\\ agentState = [a \\in Agents |-> "initial"]
  /\\ knowledge = [a \\in Agents |-> {{}}]

(* Message sending *)
SendMessage(sender, receiver, msg) ==
  /\\ agentState[sender] # "compromised"
  /\\ network' = network \\cup {{msg}}
  /\\ UNCHANGED << agentState, knowledge >>

(* Message receiving *)
ReceiveMessage(receiver, msg) ==
  /\\ msg \\in network
  /\\ knowledge' = [knowledge EXCEPT ![receiver] = @ \\cup {{msg}}]
  /\\ UNCHANGED << network, agentState >>

(* Agent compromise *)
CompromiseAgent(agent) ==
  /\\ agentState' = [agentState EXCEPT ![agent] = "compromised"]
  /\\ UNCHANGED << network, knowledge >>

(* Next state relation *)
Next ==
  \\/ \\E a1, a2 \\in Agents, m \\in Messages : SendMessage(a1, a2, m)
  \\/ \\E a \\in Agents, m \\in Messages : ReceiveMessage(a, m)
  \\/ \\E a \\in Agents : CompromiseAgent(a)

(* Specification *)
Spec == Init /\\ [][Next]_vars

(* Security Properties *)
"""

        # Add security properties
        for prop in security_props:
            if "secrecy" in prop.lower():
                spec += """
Secrecy ==
  \\A a \\in Agents : agentState[a] = "compromised" =>
    \\A secret \\in SecretMessages : secret \\notin knowledge[a]
"""
            elif "authentication" in prop.lower():
                spec += """
Authentication ==
  \\A sender, receiver \\in Agents, msg \\in Messages :
    (msg \\in knowledge[receiver] /\\ sender # receiver) =>
      \\E step \\in DOMAIN history :
        /\\ history[step].action = "send"
        /\\ history[step].sender = sender
        /\\ history[step].message = msg
"""

        spec += "\n====\n"

        return spec

    async def shutdown(self) -> None:
        """Shutdown TLA+ interface."""
        logger.info("Shutting down TLA+ interface")
        self._initialized = False