"""
Agent-to-Agent (A2A) Protocol Parser
Parses and analyzes A2A communication messages for security threats.
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
class A2AMessage:
    """Parsed A2A message structure."""
    sender: str
    recipient: str
    message_type: str
    payload: Dict[str, Any]
    timestamp: datetime
    session_id: Optional[str] = None
    encryption: Optional[str] = None
    signature: Optional[str] = None


class A2AParser:
    """
    Parser for Agent-to-Agent (A2A) communication protocol.

    Analyzes A2A messages for security vulnerabilities and protocol compliance.
    """

    # Class-level constants to replace magic numbers and literals
    HIGH_RISK_THRESHOLD = 5
    MIN_SECURE_SESSION_ID_LENGTH = 16
    INSECURE_SESSION_IDS = {"test", "admin", "default", "demo"}
    MAX_MESSAGE_AGE_SECONDS = 300  # 5 minutes

    def __init__(self, config: Dict[str, Any]):
        """Initialize A2A parser with configuration."""
        self.config = config
        self.security_patterns = self._load_security_patterns()
        self.known_vulnerabilities = self._load_vulnerability_database()

        logger.info("A2A parser initialized", config_keys=list(config.keys()))

    def _load_security_patterns(self) -> Dict[str, re.Pattern]:
        """Load security patterns for threat detection."""
        patterns = {
            'sql_injection': re.compile(r'(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b)', re.IGNORECASE),
            'xss_pattern': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            'command_injection': re.compile(r'(\||;|&|\$\(|\`)', re.IGNORECASE),
            'path_traversal': re.compile(r'\.\./', re.IGNORECASE),
            'suspicious_base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
        }
        return patterns

    def _load_vulnerability_database(self) -> Dict[str, Dict[str, Any]]:
        """Load known vulnerability signatures."""
        return {
            'weak_encryption': {
                'patterns': ['md5', 'sha1', 'des', 'rc4'],
                'risk_level': 8,
                'description': 'Weak encryption algorithm detected'
            },
            'hardcoded_credentials': {
                'patterns': ['password=', 'key=', 'secret='],
                'risk_level': 9,
                'description': 'Hardcoded credentials detected'
            },
            'insecure_protocol': {
                'patterns': ['http://', 'ftp://', 'telnet://'],
                'risk_level': 6,
                'description': 'Insecure protocol usage'
            }
        }

    def parse_message(self, raw_message: str) -> A2AMessage:
        """Parse raw A2A message into structured format."""
        try:
            if raw_message.strip().startswith('{'):
                # JSON format
                data = json.loads(raw_message)
            else:
                # Custom A2A format parsing
                data = self._parse_custom_format(raw_message)

            return A2AMessage(
                sender=data.get('sender', 'unknown'),
                recipient=data.get('recipient', 'unknown'),
                message_type=data.get('type', 'unknown'),
                payload=data.get('payload', {}),
                timestamp=self._parse_timestamp(data.get('timestamp')),
                session_id=data.get('session_id'),
                encryption=data.get('encryption'),
                signature=data.get('signature')
            )

        except Exception as e:
            logger.error("Failed to parse A2A message", error=str(e), message_preview=raw_message[:100])
            raise ValueError(f"Invalid A2A message format: {e}")

    def _parse_custom_format(self, message: str) -> Dict[str, Any]:
        """Parse custom A2A message format."""
        lines = message.strip().split('\n')
        data = {}
        payload_lines = []
        in_payload = False

        for line in lines:
            if line.startswith('PAYLOAD:'):
                in_payload = True
                continue
            elif in_payload:
                payload_lines.append(line)
            elif ':' in line:
                key, value = line.split(':', 1)
                data[key.strip().lower()] = value.strip()

        if payload_lines:
            data['payload'] = {'content': '\n'.join(payload_lines)}

        return data

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse timestamp string to datetime object."""
        if not timestamp_str:
            return datetime.utcnow()

        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            try:
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except:
                return datetime.utcnow()

    def analyze_security(self, message: A2AMessage) -> Dict[str, Any]:
        """Analyze A2A message for security vulnerabilities."""
        vulnerabilities = []
        risk_score = 0

        # Check payload security
        payload_vulns = self._analyze_payload_security(message.payload)
        vulnerabilities.extend(payload_vulns)

        # Check session security
        session_vulns = self._analyze_session_security(message.session_id)
        vulnerabilities.extend(session_vulns)

        # Check encryption security
        encryption_vulns = self._analyze_encryption_security(message.encryption)
        vulnerabilities.extend(encryption_vulns)

        # Check message integrity
        integrity_vulns = self._analyze_message_integrity(message)
        vulnerabilities.extend(integrity_vulns)

        # Calculate overall risk score
        risk_score = sum(vuln.get('severity', 0) for vuln in vulnerabilities)

        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score,
            'is_secure': risk_score < self.HIGH_RISK_THRESHOLD,
            'recommendations': self._generate_recommendations(vulnerabilities)
        }

    def _analyze_payload_security(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze payload for security issues."""
        vulnerabilities = []
        payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)

        # Check for known vulnerability patterns
        for vuln_type, vuln_info in self.known_vulnerabilities.items():
            for pattern in vuln_info['patterns']:
                if pattern.lower() in payload_str.lower():
                    vulnerabilities.append({
                        'type': vuln_type,
                        'description': vuln_info['description'],
                        'severity': vuln_info['risk_level'],
                        'location': 'payload'
                    })

        # Check for security patterns
        for pattern_name, pattern in self.security_patterns.items():
            if pattern.search(payload_str):
                vulnerabilities.append({
                    'type': pattern_name,
                    'description': f'Suspicious {pattern_name} pattern detected',
                    'severity': 7,
                    'location': 'payload'
                })

        return vulnerabilities

    def _analyze_session_security(self, session_id: Optional[str]) -> List[Dict[str, Any]]:
        """Analyze session ID for security issues."""
        vulnerabilities = []

        if not session_id:
            vulnerabilities.append({
                'type': 'missing_session_id',
                'description': 'No session ID provided',
                'severity': 4,
                'location': 'session'
            })
            return vulnerabilities

        # Use class constants instead of magic numbers and literals
        if len(session_id) < self.MIN_SECURE_SESSION_ID_LENGTH:
            vulnerabilities.append({
                'type': 'weak_session_id',
                'description': f'Session ID too short (minimum {self.MIN_SECURE_SESSION_ID_LENGTH} characters)',
                'severity': 6,
                'location': 'session'
            })

        if session_id.lower() in self.INSECURE_SESSION_IDS:
            vulnerabilities.append({
                'type': 'default_session_id',
                'description': 'Default or common session ID detected',
                'severity': 8,
                'location': 'session'
            })

        return vulnerabilities

    def _analyze_encryption_security(self, encryption: Optional[str]) -> List[Dict[str, Any]]:
        """Analyze encryption settings for security issues."""
        vulnerabilities = []

        if not encryption:
            vulnerabilities.append({
                'type': 'no_encryption',
                'description': 'Message not encrypted',
                'severity': 7,
                'location': 'encryption'
            })
            return vulnerabilities

        # Check for weak encryption algorithms
        weak_algorithms = ['des', 'rc4', 'md5', 'sha1']
        if any(alg in encryption.lower() for alg in weak_algorithms):
            vulnerabilities.append({
                'type': 'weak_encryption',
                'description': f'Weak encryption algorithm: {encryption}',
                'severity': 8,
                'location': 'encryption'
            })

        return vulnerabilities

    def _analyze_message_integrity(self, message: A2AMessage) -> List[Dict[str, Any]]:
        """Analyze message integrity and authenticity."""
        vulnerabilities = []

        if not message.signature:
            vulnerabilities.append({
                'type': 'missing_signature',
                'description': 'Message not digitally signed',
                'severity': 5,
                'location': 'signature'
            })

        # Check for suspicious message patterns
        if message.message_type == 'unknown':
            vulnerabilities.append({
                'type': 'unknown_message_type',
                'description': 'Unknown or missing message type',
                'severity': 3,
                'location': 'header'
            })

        return vulnerabilities

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on vulnerabilities."""
        recommendations = []

        vuln_types = {vuln['type'] for vuln in vulnerabilities}

        if 'no_encryption' in vuln_types:
            recommendations.append("Implement end-to-end encryption for all A2A communications")

        if 'weak_encryption' in vuln_types:
            recommendations.append("Upgrade to strong encryption algorithms (AES-256, RSA-2048+)")

        if 'missing_signature' in vuln_types:
            recommendations.append("Implement digital signatures for message authenticity")

        if 'weak_session_id' in vuln_types or 'default_session_id' in vuln_types:
            recommendations.append("Use cryptographically secure random session IDs")

        if any('injection' in vtype for vtype in vuln_types):
            recommendations.append("Implement input validation and sanitization")

        return recommendations

    def validate_protocol_compliance(self, message: A2AMessage) -> Dict[str, Any]:
        """Validate A2A protocol compliance."""
        compliance_issues = []

        # Required fields check
        required_fields = ['sender', 'recipient', 'message_type']
        for field in required_fields:
            if not getattr(message, field) or getattr(message, field) == 'unknown':
                compliance_issues.append(f"Missing required field: {field}")

        # Message type validation
        valid_types = ['request', 'response', 'notification', 'heartbeat', 'error']
        if message.message_type not in valid_types:
            compliance_issues.append(f"Invalid message type: {message.message_type}")

        # Timestamp validation
        time_diff = abs((datetime.utcnow() - message.timestamp).total_seconds())
        if time_diff > self.MAX_MESSAGE_AGE_SECONDS:
            compliance_issues.append("Message timestamp is too old or in future")

        return {
            'is_compliant': len(compliance_issues) == 0,
            'issues': compliance_issues,
            'compliance_score': max(0, 10 - len(compliance_issues))
        }

    def extract_features(self, message: A2AMessage) -> Dict[str, Any]:
        """Extract features for ML-based analysis."""
        payload_str = json.dumps(message.payload) if isinstance(message.payload, dict) else str(message.payload)

        return {
            'message_length': len(payload_str),
            'payload_entropy': self._calculate_entropy(payload_str),
            'has_encryption': bool(message.encryption),
            'has_signature': bool(message.signature),
            'session_id_length': len(message.session_id) if message.session_id else 0,
            'timestamp_age': (datetime.utcnow() - message.timestamp).total_seconds(),
            'sender_hash': hashlib.md5(message.sender.encode()).hexdigest()[:8],
            'recipient_hash': hashlib.md5(message.recipient.encode()).hexdigest()[:8],
            'message_type_encoded': hash(message.message_type) % 1000,
            'contains_urls': len(re.findall(r'https?://', payload_str)),
            'contains_base64': len(self.security_patterns['suspicious_base64'].findall(payload_str)),
            'special_char_ratio': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', payload_str)) / max(len(payload_str), 1)
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