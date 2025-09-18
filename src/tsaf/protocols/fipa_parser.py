"""
FIPA-ACL (Foundation for Intelligent Physical Agents - Agent Communication Language) Parser
Parses and analyzes FIPA-ACL communication messages for security threats.
"""

import re
import hashlib
import math
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class FIPAPerformative(Enum):
    """FIPA-ACL performatives."""
    ACCEPT_PROPOSAL = "accept-proposal"
    AGREE = "agree"
    CANCEL = "cancel"
    CFP = "cfp"  # Call for Proposal
    CONFIRM = "confirm"
    DISCONFIRM = "disconfirm"
    FAILURE = "failure"
    INFORM = "inform"
    INFORM_IF = "inform-if"
    INFORM_REF = "inform-ref"
    NOT_UNDERSTOOD = "not-understood"
    PROPOSE = "propose"
    QUERY_IF = "query-if"
    QUERY_REF = "query-ref"
    REFUSE = "refuse"
    REJECT_PROPOSAL = "reject-proposal"
    REQUEST = "request"
    REQUEST_WHEN = "request-when"
    REQUEST_WHENEVER = "request-whenever"
    SUBSCRIBE = "subscribe"


@dataclass
class FIPAMessage:
    """Parsed FIPA-ACL message structure."""
    performative: str
    sender: Optional[str] = None
    receiver: Optional[str] = None
    content: Optional[str] = None
    language: Optional[str] = None
    ontology: Optional[str] = None
    protocol: Optional[str] = None
    conversation_id: Optional[str] = None
    reply_with: Optional[str] = None
    in_reply_to: Optional[str] = None
    reply_by: Optional[datetime] = None
    reply_to: Optional[str] = None
    encoding: Optional[str] = None
    envelope: Optional[Dict[str, Any]] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class FIPAParser:
    """
    Parser for FIPA-ACL (Foundation for Intelligent Physical Agents) messages.

    Analyzes FIPA-ACL messages for security vulnerabilities and protocol compliance.
    """

    # Security thresholds
    HIGH_RISK_THRESHOLD = 7
    MAX_CONTENT_SIZE = 1024 * 1024  # 1MB
    MAX_CONVERSATION_AGE_HOURS = 24

    # Dangerous content patterns
    DANGEROUS_PATTERNS = {
        'code_execution': [
            'eval(', 'exec(', 'system(', 'shell(', 'subprocess.',
            'os.system', '__import__', 'compile('
        ],
        'file_access': [
            'open(', 'file(', 'read(', 'write(', '/etc/passwd',
            '/etc/shadow', '~/.ssh/', 'private_key'
        ],
        'network_access': [
            'urllib', 'requests', 'socket(', 'connect(',
            'bind(', 'listen(', 'http://', 'ftp://'
        ],
        'injection_attacks': [
            'union select', 'drop table', 'insert into',
            '<script>', 'javascript:', 'data:text/html'
        ]
    }

    def __init__(self, config: Dict[str, Any]):
        """Initialize FIPA parser with configuration."""
        self.config = config
        self.security_patterns = self._load_security_patterns()
        self.valid_performatives = {p.value for p in FIPAPerformative}

        logger.info("FIPA parser initialized", config_keys=list(config.keys()))

    def _load_security_patterns(self) -> Dict[str, re.Pattern]:
        """Load security patterns for threat detection."""
        patterns = {
            'sql_injection': re.compile(r'(\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\b)', re.IGNORECASE),
            'xss_pattern': re.compile(r'<(script|iframe|object|embed)[^>]*>', re.IGNORECASE),
            'command_injection': re.compile(r'(\||;|&|`|\$\(|\${)', re.IGNORECASE),
            'path_traversal': re.compile(r'(\.\.\/|\.\.\\|%2e%2e%2f)', re.IGNORECASE),
            'code_injection': re.compile(r'(eval\s*\(|exec\s*\(|system\s*\()', re.IGNORECASE),
            'agent_injection': re.compile(r'(agent://|urn:agent:|fipa-agent:)', re.IGNORECASE),
            'protocol_violation': re.compile(r'(protocol\s*=\s*["\']?[^"\'\s]*hack)', re.IGNORECASE),
            'suspicious_encoding': re.compile(r'(base64|hex|url|html)encode', re.IGNORECASE),
        }
        return patterns

    def parse_message(self, raw_message: str) -> FIPAMessage:
        """Parse raw FIPA-ACL message into structured format."""
        try:
            # Remove extra whitespace and normalize
            message = raw_message.strip()

            # Parse FIPA-ACL structure
            if message.startswith('(') and message.endswith(')'):
                return self._parse_structured_format(message)
            else:
                return self._parse_free_format(message)

        except Exception as e:
            logger.error("Failed to parse FIPA message", error=str(e), message_preview=raw_message[:100])
            raise ValueError(f"Invalid FIPA-ACL message format: {e}")

    def _parse_structured_format(self, message: str) -> FIPAMessage:
        """Parse structured FIPA-ACL format: (performative :param value ...)"""
        # Remove outer parentheses
        content = message[1:-1].strip()

        # Extract performative (first token)
        tokens = self._tokenize_fipa_message(content)
        if not tokens:
            raise ValueError("Empty message content")

        performative = tokens[0].lower()

        # Parse parameters
        params = self._parse_fipa_parameters(tokens[1:])

        return FIPAMessage(
            performative=performative,
            sender=params.get('sender'),
            receiver=params.get('receiver'),
            content=params.get('content'),
            language=params.get('language'),
            ontology=params.get('ontology'),
            protocol=params.get('protocol'),
            conversation_id=params.get('conversation-id'),
            reply_with=params.get('reply-with'),
            in_reply_to=params.get('in-reply-to'),
            reply_by=self._parse_datetime(params.get('reply-by')),
            reply_to=params.get('reply-to'),
            encoding=params.get('encoding'),
            envelope=params.get('envelope')
        )

    def _parse_free_format(self, message: str) -> FIPAMessage:
        """Parse free-form FIPA message."""
        lines = message.split('\n')
        performative = None
        content = []
        params = {}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if ':' in line and not performative:
                # First line might be performative
                if line.lower().startswith(tuple(self.valid_performatives)):
                    performative = line.split(':')[0].lower()
                    continue

            if ':' in line:
                key, value = line.split(':', 1)
                params[key.strip().lower()] = value.strip()
            else:
                content.append(line)

        return FIPAMessage(
            performative=performative or 'inform',
            content=' '.join(content) if content else params.get('content'),
            **params
        )

    def _tokenize_fipa_message(self, content: str) -> List[str]:
        """Tokenize FIPA message content."""
        tokens = []
        current_token = ""
        in_quotes = False
        quote_char = None

        for char in content:
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
                current_token += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                current_token += char
                quote_char = None
            elif char.isspace() and not in_quotes:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char

        if current_token:
            tokens.append(current_token)

        return tokens

    def _parse_fipa_parameters(self, tokens: List[str]) -> Dict[str, Any]:
        """Parse FIPA parameter tokens."""
        params = {}
        i = 0

        while i < len(tokens):
            if tokens[i].startswith(':'):
                param_name = tokens[i][1:]  # Remove ':'
                if i + 1 < len(tokens):
                    param_value = tokens[i + 1]
                    # Remove quotes if present
                    if param_value.startswith('"') and param_value.endswith('"'):
                        param_value = param_value[1:-1]
                    params[param_name] = param_value
                    i += 2
                else:
                    i += 1
            else:
                i += 1

        return params

    def _parse_datetime(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime string."""
        if not date_str:
            return None

        try:
            # Try ISO format first
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            try:
                # Try common formats
                return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
            except:
                return None

    def analyze_security(self, message: FIPAMessage) -> Dict[str, Any]:
        """Analyze FIPA message for security vulnerabilities."""
        vulnerabilities = []
        risk_score = 0

        # Check performative security
        perf_vulns = self._analyze_performative_security(message.performative)
        vulnerabilities.extend(perf_vulns)

        # Check content security
        if message.content:
            content_vulns = self._analyze_content_security(message.content)
            vulnerabilities.extend(content_vulns)

        # Check agent identity security
        identity_vulns = self._analyze_identity_security(message)
        vulnerabilities.extend(identity_vulns)

        # Check protocol security
        protocol_vulns = self._analyze_protocol_security(message)
        vulnerabilities.extend(protocol_vulns)

        # Check conversation security
        conv_vulns = self._analyze_conversation_security(message)
        vulnerabilities.extend(conv_vulns)

        # Calculate overall risk score
        risk_score = sum(vuln.get('severity', 0) for vuln in vulnerabilities)

        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score,
            'is_secure': risk_score < self.HIGH_RISK_THRESHOLD,
            'recommendations': self._generate_recommendations(vulnerabilities)
        }

    def _analyze_performative_security(self, performative: str) -> List[Dict[str, Any]]:
        """Analyze performative for security issues."""
        vulnerabilities = []

        if performative not in self.valid_performatives:
            vulnerabilities.append({
                'type': 'invalid_performative',
                'description': f'Unknown or invalid performative: {performative}',
                'severity': 5,
                'location': 'performative'
            })

        # Check for dangerous performatives
        dangerous_performatives = ['request', 'request-when', 'request-whenever']
        if performative in dangerous_performatives:
            vulnerabilities.append({
                'type': 'potentially_dangerous_performative',
                'description': f'Potentially dangerous performative: {performative}',
                'severity': 4,
                'location': 'performative'
            })

        return vulnerabilities

    def _analyze_content_security(self, content: str) -> List[Dict[str, Any]]:
        """Analyze message content for security issues."""
        vulnerabilities = []

        # Check content size
        if len(content) > self.MAX_CONTENT_SIZE:
            vulnerabilities.append({
                'type': 'oversized_content',
                'description': f'Content exceeds size limit ({len(content)} bytes)',
                'severity': 6,
                'location': 'content'
            })

        # Check for dangerous patterns
        for category, patterns in self.DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in content.lower():
                    vulnerabilities.append({
                        'type': f'dangerous_{category}',
                        'description': f'Dangerous {category} pattern detected: {pattern}',
                        'severity': 8,
                        'location': 'content',
                        'pattern': pattern
                    })

        # Check security patterns
        for pattern_name, pattern in self.security_patterns.items():
            matches = pattern.findall(content)
            if matches:
                vulnerabilities.append({
                    'type': pattern_name,
                    'description': f'Suspicious {pattern_name} pattern detected',
                    'severity': 7,
                    'location': 'content',
                    'matches': matches[:3]  # Limit to first 3 matches
                })

        return vulnerabilities

    def _analyze_identity_security(self, message: FIPAMessage) -> List[Dict[str, Any]]:
        """Analyze agent identity security."""
        vulnerabilities = []

        # Check for missing sender/receiver
        if not message.sender:
            vulnerabilities.append({
                'type': 'missing_sender',
                'description': 'Message missing sender identity',
                'severity': 6,
                'location': 'identity'
            })

        if not message.receiver:
            vulnerabilities.append({
                'type': 'missing_receiver',
                'description': 'Message missing receiver identity',
                'severity': 4,
                'location': 'identity'
            })

        # Check for suspicious agent identifiers
        suspicious_patterns = ['admin', 'root', 'system', 'debug', 'test']
        for field_name, field_value in [('sender', message.sender), ('receiver', message.receiver)]:
            if field_value and any(pattern in field_value.lower() for pattern in suspicious_patterns):
                vulnerabilities.append({
                    'type': 'suspicious_agent_id',
                    'description': f'Suspicious agent identifier in {field_name}: {field_value}',
                    'severity': 5,
                    'location': 'identity'
                })

        return vulnerabilities

    def _analyze_protocol_security(self, message: FIPAMessage) -> List[Dict[str, Any]]:
        """Analyze protocol-specific security issues."""
        vulnerabilities = []

        # Check for protocol tampering
        if message.protocol and 'hack' in message.protocol.lower():
            vulnerabilities.append({
                'type': 'protocol_tampering',
                'description': f'Suspicious protocol specification: {message.protocol}',
                'severity': 8,
                'location': 'protocol'
            })

        # Check encoding security
        if message.encoding:
            dangerous_encodings = ['base64', 'hex', 'url']
            if any(enc in message.encoding.lower() for enc in dangerous_encodings):
                vulnerabilities.append({
                    'type': 'suspicious_encoding',
                    'description': f'Potentially dangerous encoding: {message.encoding}',
                    'severity': 6,
                    'location': 'encoding'
                })

        return vulnerabilities

    def _analyze_conversation_security(self, message: FIPAMessage) -> List[Dict[str, Any]]:
        """Analyze conversation-level security."""
        vulnerabilities = []

        # Check for conversation hijacking patterns
        if message.conversation_id:
            # Very short conversation IDs might be guessable
            if len(message.conversation_id) < 8:
                vulnerabilities.append({
                    'type': 'weak_conversation_id',
                    'description': 'Conversation ID too short (potential hijacking risk)',
                    'severity': 5,
                    'location': 'conversation'
                })

            # Check for suspicious conversation ID patterns
            if re.match(r'^(test|admin|debug|default)', message.conversation_id, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'default_conversation_id',
                    'description': 'Default or common conversation ID detected',
                    'severity': 6,
                    'location': 'conversation'
                })

        return vulnerabilities

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        vuln_types = {vuln['type'] for vuln in vulnerabilities}

        if any('dangerous_' in vtype for vtype in vuln_types):
            recommendations.append("Implement strict content filtering and input validation")

        if 'oversized_content' in vuln_types:
            recommendations.append("Implement content size limits and validation")

        if 'missing_sender' in vuln_types or 'missing_receiver' in vuln_types:
            recommendations.append("Enforce mandatory agent identity verification")

        if 'suspicious_agent_id' in vuln_types:
            recommendations.append("Implement agent identity whitelisting")

        if 'weak_conversation_id' in vuln_types:
            recommendations.append("Use cryptographically secure conversation identifiers")

        if 'protocol_tampering' in vuln_types:
            recommendations.append("Implement protocol integrity validation")

        return recommendations

    def validate_protocol_compliance(self, message: FIPAMessage) -> Dict[str, Any]:
        """Validate FIPA-ACL protocol compliance."""
        compliance_issues = []

        # Check required fields
        if not message.performative:
            compliance_issues.append("Missing required performative")

        if message.performative not in self.valid_performatives:
            compliance_issues.append(f"Invalid performative: {message.performative}")

        # Check semantic constraints
        if message.performative in ['agree', 'refuse'] and not message.in_reply_to:
            compliance_issues.append(f"'{message.performative}' requires 'in-reply-to' field")

        if message.performative == 'cfp' and not message.reply_by:
            compliance_issues.append("'cfp' should specify 'reply-by' deadline")

        # Check conversation flow
        if message.in_reply_to and not message.conversation_id:
            compliance_issues.append("Reply messages should maintain conversation-id")

        return {
            'is_compliant': len(compliance_issues) == 0,
            'issues': compliance_issues,
            'compliance_score': max(0, 10 - len(compliance_issues))
        }

    def extract_features(self, message: FIPAMessage) -> Dict[str, Any]:
        """Extract features for ML-based analysis."""
        content = message.content or ""

        return {
            'message_length': len(content),
            'content_entropy': self._calculate_entropy(content),
            'has_sender': bool(message.sender),
            'has_receiver': bool(message.receiver),
            'has_content': bool(message.content),
            'has_conversation_id': bool(message.conversation_id),
            'has_protocol': bool(message.protocol),
            'performative_encoded': hash(message.performative) % 1000,
            'sender_length': len(message.sender) if message.sender else 0,
            'receiver_length': len(message.receiver) if message.receiver else 0,
            'conversation_id_length': len(message.conversation_id) if message.conversation_id else 0,
            'contains_dangerous_keywords': sum(
                1 for category in self.DANGEROUS_PATTERNS.values()
                for pattern in category
                if pattern.lower() in content.lower()
            ),
            'special_char_ratio': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', content)) / max(len(content), 1),
            'uppercase_ratio': len(re.findall(r'[A-Z]', content)) / max(len(content), 1),
            'digit_ratio': len(re.findall(r'\d', content)) / max(len(content), 1)
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