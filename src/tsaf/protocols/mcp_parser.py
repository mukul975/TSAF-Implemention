"""
MCP (Model Context Protocol) Parser
Parses and analyzes MCP communication messages for security threats.
"""

import json
import re
import hashlib
import math
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class MCPMessage:
    """Parsed MCP message structure."""
    jsonrpc: str
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class MCPParser:
    """
    Parser for Model Context Protocol (MCP) messages.

    Analyzes MCP JSON-RPC messages for security vulnerabilities and protocol compliance.
    """

    # Security thresholds and constants
    HIGH_RISK_THRESHOLD = 7
    MAX_PARAM_SIZE = 1024 * 1024  # 1MB
    DANGEROUS_METHODS = {
        'eval', 'exec', 'system', 'shell', 'subprocess',
        'import', 'compile', 'open', 'file', 'input',
        'raw_input', '__import__', 'getattr', 'setattr'
    }

    def __init__(self, config: Dict[str, Any]):
        """Initialize MCP parser with configuration."""
        self.config = config
        self.security_patterns = self._load_security_patterns()
        self.known_vulnerabilities = self._load_vulnerability_database()

        logger.info("MCP parser initialized", config_keys=list(config.keys()))

    def _load_security_patterns(self) -> Dict[str, re.Pattern]:
        """Load security patterns for threat detection."""
        patterns = {
            'code_injection': re.compile(r'(eval\s*\(|exec\s*\(|subprocess\.|os\.system)', re.IGNORECASE),
            'file_access': re.compile(r'(open\s*\(|file\s*\(|\.read\(\)|\.write\()', re.IGNORECASE),
            'import_injection': re.compile(r'(__import__\s*\(|importlib\.)', re.IGNORECASE),
            'path_traversal': re.compile(r'(\.\.\/|\.\.\\|%2e%2e%2f)', re.IGNORECASE),
            'sql_injection': re.compile(r'(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b)', re.IGNORECASE),
            'command_injection': re.compile(r'(\||;|&|`|\$\(|\${)', re.IGNORECASE),
            'xss_pattern': re.compile(r'<(script|iframe|object|embed|link)', re.IGNORECASE),
            'suspicious_base64': re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
        }
        return patterns

    def _load_vulnerability_database(self) -> Dict[str, Dict[str, Any]]:
        """Load known vulnerability signatures."""
        return {
            'dangerous_methods': {
                'patterns': list(self.DANGEROUS_METHODS),
                'risk_level': 9,
                'description': 'Dangerous method call detected in MCP message'
            },
            'sensitive_file_access': {
                'patterns': ['/etc/passwd', '/etc/shadow', '~/.ssh/', 'id_rsa', 'private_key'],
                'risk_level': 8,
                'description': 'Sensitive file access pattern detected'
            },
            'network_access': {
                'patterns': ['urllib', 'requests', 'http', 'socket', 'telnet', 'ftp'],
                'risk_level': 6,
                'description': 'Network access pattern detected'
            },
            'environment_access': {
                'patterns': ['os.environ', 'getenv', 'putenv', 'PATH=', 'LD_LIBRARY_PATH'],
                'risk_level': 7,
                'description': 'Environment variable access detected'
            }
        }

    def parse_message(self, raw_message: str) -> MCPMessage:
        """Parse raw MCP message into structured format."""
        try:
            data = json.loads(raw_message)

            # Validate JSON-RPC structure
            if 'jsonrpc' not in data:
                raise ValueError("Missing 'jsonrpc' field")

            if data['jsonrpc'] != '2.0':
                logger.warning("Non-standard JSON-RPC version", version=data['jsonrpc'])

            return MCPMessage(
                jsonrpc=data['jsonrpc'],
                method=data.get('method'),
                params=data.get('params'),
                result=data.get('result'),
                error=data.get('error'),
                id=data.get('id'),
                timestamp=datetime.utcnow()
            )

        except json.JSONDecodeError as e:
            logger.error("Failed to parse MCP JSON", error=str(e), message_preview=raw_message[:100])
            raise ValueError(f"Invalid JSON in MCP message: {e}")
        except Exception as e:
            logger.error("Failed to parse MCP message", error=str(e))
            raise ValueError(f"Invalid MCP message format: {e}")

    def analyze_security(self, message: MCPMessage) -> Dict[str, Any]:
        """Analyze MCP message for security vulnerabilities."""
        vulnerabilities = []
        risk_score = 0

        # Check method security
        if message.method:
            method_vulns = self._analyze_method_security(message.method)
            vulnerabilities.extend(method_vulns)

        # Check parameters security
        if message.params:
            param_vulns = self._analyze_params_security(message.params)
            vulnerabilities.extend(param_vulns)

        # Check message structure
        structure_vulns = self._analyze_message_structure(message)
        vulnerabilities.extend(structure_vulns)

        # Check for code injection patterns
        injection_vulns = self._analyze_injection_patterns(message)
        vulnerabilities.extend(injection_vulns)

        # Calculate overall risk score
        risk_score = sum(vuln.get('severity', 0) for vuln in vulnerabilities)

        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score,
            'is_secure': risk_score < self.HIGH_RISK_THRESHOLD,
            'recommendations': self._generate_recommendations(vulnerabilities)
        }

    def _analyze_method_security(self, method: str) -> List[Dict[str, Any]]:
        """Analyze MCP method for security issues."""
        vulnerabilities = []

        # Check for dangerous methods
        if method.lower() in self.DANGEROUS_METHODS:
            vulnerabilities.append({
                'type': 'dangerous_method',
                'description': f'Dangerous method call: {method}',
                'severity': 9,
                'location': 'method',
                'method': method
            })

        # Check for suspicious method patterns
        if re.search(r'(shell|cmd|execute|run|eval)', method, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'suspicious_method',
                'description': f'Potentially dangerous method pattern: {method}',
                'severity': 7,
                'location': 'method',
                'method': method
            })

        return vulnerabilities

    def _analyze_params_security(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze MCP parameters for security issues."""
        vulnerabilities = []
        params_str = json.dumps(params)

        # Check parameter size
        if len(params_str) > self.MAX_PARAM_SIZE:
            vulnerabilities.append({
                'type': 'oversized_params',
                'description': f'Parameters exceed size limit ({len(params_str)} bytes)',
                'severity': 6,
                'location': 'params'
            })

        # Check for known vulnerability patterns
        for vuln_type, vuln_info in self.known_vulnerabilities.items():
            for pattern in vuln_info['patterns']:
                if pattern.lower() in params_str.lower():
                    vulnerabilities.append({
                        'type': vuln_type,
                        'description': vuln_info['description'],
                        'severity': vuln_info['risk_level'],
                        'location': 'params',
                        'pattern': pattern
                    })

        # Check for security patterns
        for pattern_name, pattern in self.security_patterns.items():
            matches = pattern.findall(params_str)
            if matches:
                vulnerabilities.append({
                    'type': pattern_name,
                    'description': f'Suspicious {pattern_name} pattern detected',
                    'severity': 7,
                    'location': 'params',
                    'matches': matches[:5]  # Limit to first 5 matches
                })

        return vulnerabilities

    def _analyze_message_structure(self, message: MCPMessage) -> List[Dict[str, Any]]:
        """Analyze MCP message structure for issues."""
        vulnerabilities = []

        # Check for missing required fields for requests
        if message.method and not message.id:
            vulnerabilities.append({
                'type': 'missing_id',
                'description': 'Request missing ID field',
                'severity': 4,
                'location': 'structure'
            })

        # Check for conflicting fields
        if message.method and (message.result is not None or message.error is not None):
            vulnerabilities.append({
                'type': 'invalid_structure',
                'description': 'Request message contains result or error fields',
                'severity': 5,
                'location': 'structure'
            })

        if not message.method and message.result is None and message.error is None:
            vulnerabilities.append({
                'type': 'incomplete_response',
                'description': 'Response missing both result and error fields',
                'severity': 4,
                'location': 'structure'
            })

        return vulnerabilities

    def _analyze_injection_patterns(self, message: MCPMessage) -> List[Dict[str, Any]]:
        """Analyze for code injection patterns."""
        vulnerabilities = []

        # Combine all text content for analysis
        text_content = []
        if message.method:
            text_content.append(message.method)
        if message.params:
            text_content.append(json.dumps(message.params))
        if message.result:
            text_content.append(json.dumps(message.result))

        full_text = ' '.join(text_content)

        # Check for code injection patterns
        dangerous_patterns = [
            (r'eval\s*\(', 'code_injection', 'Python eval() detected'),
            (r'exec\s*\(', 'code_injection', 'Python exec() detected'),
            (r'__import__\s*\(', 'import_injection', 'Dynamic import detected'),
            (r'subprocess\.|os\.system', 'command_injection', 'System command execution'),
            (r'open\s*\([\'"][\/\w]+[\'"]', 'file_access', 'File access detected'),
        ]

        for pattern, vuln_type, description in dangerous_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                vulnerabilities.append({
                    'type': vuln_type,
                    'description': description,
                    'severity': 8,
                    'location': 'content'
                })

        return vulnerabilities

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on vulnerabilities."""
        recommendations = []
        vuln_types = {vuln['type'] for vuln in vulnerabilities}

        if 'dangerous_method' in vuln_types or 'code_injection' in vuln_types:
            recommendations.append("Implement strict method whitelisting and input validation")

        if 'oversized_params' in vuln_types:
            recommendations.append("Implement parameter size limits and validation")

        if 'file_access' in vuln_types:
            recommendations.append("Restrict file system access and implement sandboxing")

        if 'command_injection' in vuln_types:
            recommendations.append("Disable system command execution or use secure alternatives")

        if 'import_injection' in vuln_types:
            recommendations.append("Restrict dynamic imports and use import whitelisting")

        if any('injection' in vtype for vtype in vuln_types):
            recommendations.append("Implement comprehensive input sanitization")

        return recommendations

    def validate_protocol_compliance(self, message: MCPMessage) -> Dict[str, Any]:
        """Validate MCP protocol compliance."""
        compliance_issues = []

        # JSON-RPC 2.0 compliance
        if message.jsonrpc != '2.0':
            compliance_issues.append(f"Invalid JSON-RPC version: {message.jsonrpc}")

        # Message type validation
        is_request = bool(message.method)
        is_response = bool(message.result is not None or message.error is not None)
        is_notification = bool(message.method and message.id is None)

        if is_request and is_response:
            compliance_issues.append("Message cannot be both request and response")

        if is_request and not is_notification and not message.id:
            compliance_issues.append("Request missing required 'id' field")

        if is_response and not message.id:
            compliance_issues.append("Response missing required 'id' field")

        if message.error and message.result is not None:
            compliance_issues.append("Response cannot have both 'error' and 'result'")

        # Method name validation
        if message.method:
            if not isinstance(message.method, str):
                compliance_issues.append("Method name must be a string")
            elif message.method.startswith('rpc.'):
                compliance_issues.append("Method names starting with 'rpc.' are reserved")

        return {
            'is_compliant': len(compliance_issues) == 0,
            'issues': compliance_issues,
            'compliance_score': max(0, 10 - len(compliance_issues)),
            'message_type': 'notification' if is_notification else 'request' if is_request else 'response'
        }

    def extract_features(self, message: MCPMessage) -> Dict[str, Any]:
        """Extract features for ML-based analysis."""
        # Serialize message content
        content = json.dumps({
            'method': message.method,
            'params': message.params,
            'result': message.result,
            'error': message.error
        })

        return {
            'message_length': len(content),
            'content_entropy': self._calculate_entropy(content),
            'has_method': bool(message.method),
            'has_params': bool(message.params),
            'has_result': bool(message.result),
            'has_error': bool(message.error),
            'has_id': bool(message.id),
            'method_length': len(message.method) if message.method else 0,
            'params_size': len(json.dumps(message.params)) if message.params else 0,
            'params_depth': self._calculate_depth(message.params) if message.params else 0,
            'contains_dangerous_keywords': sum(1 for keyword in self.DANGEROUS_METHODS
                                             if keyword in content.lower()),
            'special_char_ratio': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', content)) / max(len(content), 1),
            'numeric_ratio': len(re.findall(r'\d', content)) / max(len(content), 1),
            'uppercase_ratio': len(re.findall(r'[A-Z]', content)) / max(len(content), 1)
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        length = len(text)
        entropy = 0.0

        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of an object."""
        if not isinstance(obj, (dict, list)):
            return current_depth

        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._calculate_depth(v, current_depth + 1) for v in obj.values())

        if isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._calculate_depth(item, current_depth + 1) for item in obj)

        return current_depth