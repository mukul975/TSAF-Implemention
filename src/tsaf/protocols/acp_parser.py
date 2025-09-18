"""
ACP (Agent Communication Protocol) Parser
Parses and analyzes ACP communication messages for security threats.
"""

import re
import xml.etree.ElementTree as ET
import hashlib
import math
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class ACPMessageType(Enum):
    """ACP message types."""
    REQUEST = "request"
    RESPONSE = "response"
    INFORM = "inform"
    QUERY = "query"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    NOTIFY = "notify"
    CONFIRM = "confirm"
    REFUSE = "refuse"
    ERROR = "error"


@dataclass
class ACPMessage:
    """Parsed ACP message structure."""
    message_type: str
    sender: Optional[str] = None
    receiver: Optional[str] = None
    content: Optional[str] = None
    message_id: Optional[str] = None
    conversation_id: Optional[str] = None
    reply_to: Optional[str] = None
    timestamp: Optional[datetime] = None
    priority: Optional[str] = None
    encoding: Optional[str] = None
    security_context: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    raw_xml: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class ACPParser:
    """
    Parser for Agent Communication Protocol (ACP) messages.

    Analyzes ACP XML-based messages for security vulnerabilities and protocol compliance.
    """

    # Security thresholds
    HIGH_RISK_THRESHOLD = 7
    MAX_CONTENT_SIZE = 2 * 1024 * 1024  # 2MB
    MAX_XML_DEPTH = 10
    MAX_ATTRIBUTES = 50

    # XML security patterns
    XML_BOMB_PATTERNS = [
        '<!ENTITY',
        'SYSTEM',
        '&lol;',
        '&lol1;',
        '&lol2;'
    ]

    # Dangerous content patterns
    DANGEROUS_PATTERNS = {
        'code_execution': [
            'eval(', 'exec(', 'system(', 'shell(', 'subprocess.',
            'os.system', '__import__', 'compile(', 'execfile('
        ],
        'file_access': [
            'open(', 'file(', 'read(', 'write(', '/etc/passwd',
            '/etc/shadow', '~/.ssh/', 'private_key', '../'
        ],
        'network_access': [
            'urllib', 'requests', 'socket(', 'connect(',
            'bind(', 'listen(', 'http://', 'ftp://', 'telnet://'
        ],
        'injection_attacks': [
            'union select', 'drop table', 'insert into',
            '<script>', 'javascript:', 'data:text/html',
            'onload=', 'onerror='
        ],
        'xml_attacks': [
            '<!DOCTYPE', '<!ENTITY', 'SYSTEM', 'PUBLIC',
            '&xxe;', '&remote;', '&internal;'
        ]
    }

    def __init__(self, config: Dict[str, Any]):
        """Initialize ACP parser with configuration."""
        self.config = config
        self.security_patterns = self._load_security_patterns()
        self.valid_message_types = {t.value for t in ACPMessageType}

        logger.info("ACP parser initialized", config_keys=list(config.keys()))

    def _load_security_patterns(self) -> Dict[str, re.Pattern]:
        """Load security patterns for threat detection."""
        patterns = {
            'xxe_attack': re.compile(r'<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)', re.IGNORECASE),
            'xml_bomb': re.compile(r'<!ENTITY\s+\w+\s+"[^"]*(&\w+;)+[^"]*"', re.IGNORECASE),
            'script_injection': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            'sql_injection': re.compile(r'(\bunion\s+select\b|\bdrop\s+table\b)', re.IGNORECASE),
            'command_injection': re.compile(r'(\||;|&|`|\$\(|\${)', re.IGNORECASE),
            'path_traversal': re.compile(r'(\.\.\/|\.\.\\|%2e%2e%2f)', re.IGNORECASE),
            'external_entity': re.compile(r'SYSTEM\s+["\'][^"\']*["\']', re.IGNORECASE),
            'cdata_injection': re.compile(r'<!\[CDATA\[.*?\]\]>', re.IGNORECASE | re.DOTALL),
        }
        return patterns

    def parse_message(self, raw_message: str) -> ACPMessage:
        """Parse raw ACP message into structured format."""
        try:
            # Store raw message for analysis
            self.raw_xml = raw_message.strip()

            # Basic XML security checks before parsing
            self._validate_xml_security(self.raw_xml)

            # Parse XML structure
            if self.raw_xml.startswith('<'):
                return self._parse_xml_format(self.raw_xml)
            else:
                return self._parse_text_format(self.raw_xml)

        except ET.ParseError as e:
            logger.error("Failed to parse ACP XML", error=str(e), message_preview=raw_message[:100])
            raise ValueError(f"Invalid ACP XML format: {e}")
        except Exception as e:
            logger.error("Failed to parse ACP message", error=str(e))
            raise ValueError(f"Invalid ACP message format: {e}")

    def _validate_xml_security(self, xml_content: str) -> None:
        """Validate XML content for security issues before parsing."""
        # Check for XML bombs and XXE attacks
        for pattern in self.XML_BOMB_PATTERNS:
            if pattern in xml_content:
                raise ValueError(f"Potential XML security issue detected: {pattern}")

        # Check content size
        if len(xml_content) > self.MAX_CONTENT_SIZE:
            raise ValueError(f"XML content exceeds size limit: {len(xml_content)} bytes")

        # Check for excessive nesting (approximate)
        open_tags = xml_content.count('<')
        close_tags = xml_content.count('</')
        if open_tags - close_tags > self.MAX_XML_DEPTH:
            raise ValueError("XML nesting depth exceeds security limits")

    def _parse_xml_format(self, xml_content: str) -> ACPMessage:
        """Parse XML-based ACP message."""
        # Disable XML external entity processing for security
        root = ET.fromstring(xml_content)

        # Extract basic message information
        message_type = root.tag.split('}')[-1]  # Remove namespace if present
        if message_type == 'message':
            message_type = root.get('type', 'inform')

        # Parse message components
        message = ACPMessage(
            message_type=message_type,
            sender=self._extract_xml_value(root, ['sender', 'from']),
            receiver=self._extract_xml_value(root, ['receiver', 'to']),
            content=self._extract_xml_content(root),
            message_id=root.get('id') or self._extract_xml_value(root, ['message-id', 'messageId']),
            conversation_id=self._extract_xml_value(root, ['conversation-id', 'conversationId']),
            reply_to=self._extract_xml_value(root, ['reply-to', 'replyTo']),
            timestamp=self._parse_timestamp(self._extract_xml_value(root, ['timestamp', 'time'])),
            priority=self._extract_xml_value(root, ['priority']),
            encoding=root.get('encoding'),
            headers=self._extract_headers(root),
            raw_xml=xml_content
        )

        # Extract security context if present
        security_elem = root.find('.//security') or root.find('.//sec')
        if security_elem is not None:
            message.security_context = self._parse_security_context(security_elem)

        return message

    def _parse_text_format(self, text_content: str) -> ACPMessage:
        """Parse text-based ACP message."""
        lines = text_content.split('\n')
        message_data = {}
        content_lines = []
        in_content = False

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.upper().startswith('CONTENT:'):
                in_content = True
                continue
            elif in_content:
                content_lines.append(line)
            elif ':' in line:
                key, value = line.split(':', 1)
                message_data[key.strip().lower()] = value.strip()

        return ACPMessage(
            message_type=message_data.get('type', 'inform'),
            sender=message_data.get('sender') or message_data.get('from'),
            receiver=message_data.get('receiver') or message_data.get('to'),
            content='\\n'.join(content_lines) if content_lines else message_data.get('content'),
            message_id=message_data.get('message-id') or message_data.get('id'),
            conversation_id=message_data.get('conversation-id'),
            reply_to=message_data.get('reply-to'),
            timestamp=self._parse_timestamp(message_data.get('timestamp')),
            priority=message_data.get('priority'),
            encoding=message_data.get('encoding')
        )

    def _extract_xml_value(self, root: ET.Element, tag_names: List[str]) -> Optional[str]:
        """Extract value from XML element by tag names."""
        for tag_name in tag_names:
            elem = root.find(f'.//{tag_name}') or root.find(f'.//{tag_name.replace("-", "_")}')
            if elem is not None:
                return elem.text or elem.get('value')
        return None

    def _extract_xml_content(self, root: ET.Element) -> Optional[str]:
        """Extract message content from XML."""
        # Look for content in various possible locations
        content_elem = (root.find('.//content') or
                       root.find('.//body') or
                       root.find('.//message-content'))

        if content_elem is not None:
            # Handle CDATA and regular text
            content = content_elem.text or ''
            if content_elem.get('type') == 'cdata':
                content = f"<![CDATA[{content}]]>"
            return content

        # If no specific content element, use all text content
        return ET.tostring(root, encoding='unicode', method='text').strip()

    def _extract_headers(self, root: ET.Element) -> Dict[str, str]:
        """Extract headers from XML message."""
        headers = {}

        # Extract attributes from root element
        for key, value in root.attrib.items():
            if key not in ['id', 'type', 'encoding']:
                headers[key] = value

        # Look for explicit headers section
        headers_elem = root.find('.//headers') or root.find('.//header')
        if headers_elem is not None:
            for child in headers_elem:
                headers[child.tag] = child.text or child.get('value', '')

        return headers

    def _parse_security_context(self, security_elem: ET.Element) -> Dict[str, Any]:
        """Parse security context from XML element."""
        context = {}

        for child in security_elem:
            if child.tag == 'signature':
                context['signature'] = child.text
            elif child.tag == 'encryption':
                context['encryption'] = {
                    'algorithm': child.get('algorithm'),
                    'key_id': child.get('key-id'),
                    'data': child.text
                }
            elif child.tag == 'certificate':
                context['certificate'] = child.text
            else:
                context[child.tag] = child.text

        return context

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse timestamp string to datetime."""
        if not timestamp_str:
            return None

        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            try:
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except:
                return None

    def analyze_security(self, message: ACPMessage) -> Dict[str, Any]:
        """Analyze ACP message for security vulnerabilities."""
        vulnerabilities = []
        risk_score = 0

        # Check XML structure security
        if message.raw_xml:
            xml_vulns = self._analyze_xml_security(message.raw_xml)
            vulnerabilities.extend(xml_vulns)

        # Check content security
        if message.content:
            content_vulns = self._analyze_content_security(message.content)
            vulnerabilities.extend(content_vulns)

        # Check message structure
        structure_vulns = self._analyze_message_structure(message)
        vulnerabilities.extend(structure_vulns)

        # Check security context
        if message.security_context:
            security_vulns = self._analyze_security_context(message.security_context)
            vulnerabilities.extend(security_vulns)

        # Check headers security
        if message.headers:
            header_vulns = self._analyze_headers_security(message.headers)
            vulnerabilities.extend(header_vulns)

        # Calculate overall risk score
        risk_score = sum(vuln.get('severity', 0) for vuln in vulnerabilities)

        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score,
            'is_secure': risk_score < self.HIGH_RISK_THRESHOLD,
            'recommendations': self._generate_recommendations(vulnerabilities)
        }

    def _analyze_xml_security(self, xml_content: str) -> List[Dict[str, Any]]:
        """Analyze XML structure for security issues."""
        vulnerabilities = []

        # Check for XXE attacks
        for pattern_name, pattern in self.security_patterns.items():
            if 'xml' in pattern_name or 'xxe' in pattern_name:
                matches = pattern.findall(xml_content)
                if matches:
                    vulnerabilities.append({
                        'type': pattern_name,
                        'description': f'Potential {pattern_name} attack detected',
                        'severity': 9,
                        'location': 'xml_structure',
                        'matches': matches[:3]
                    })

        # Check for XML bombs
        entity_count = xml_content.count('<!ENTITY')
        if entity_count > 5:
            vulnerabilities.append({
                'type': 'potential_xml_bomb',
                'description': f'Excessive entity declarations ({entity_count})',
                'severity': 8,
                'location': 'xml_structure'
            })

        # Check for external references
        if 'SYSTEM' in xml_content and ('http://' in xml_content or 'file://' in xml_content):
            vulnerabilities.append({
                'type': 'external_entity_reference',
                'description': 'External entity reference detected',
                'severity': 9,
                'location': 'xml_structure'
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
            if 'xml' not in pattern_name:  # Non-XML patterns
                matches = pattern.findall(content)
                if matches:
                    vulnerabilities.append({
                        'type': pattern_name,
                        'description': f'Suspicious {pattern_name} pattern detected',
                        'severity': 7,
                        'location': 'content',
                        'matches': matches[:3]
                    })

        return vulnerabilities

    def _analyze_message_structure(self, message: ACPMessage) -> List[Dict[str, Any]]:
        """Analyze message structure for issues."""
        vulnerabilities = []

        # Check for missing critical fields
        if not message.sender:
            vulnerabilities.append({
                'type': 'missing_sender',
                'description': 'Message missing sender identification',
                'severity': 6,
                'location': 'structure'
            })

        if not message.receiver:
            vulnerabilities.append({
                'type': 'missing_receiver',
                'description': 'Message missing receiver identification',
                'severity': 4,
                'location': 'structure'
            })

        if not message.message_id:
            vulnerabilities.append({
                'type': 'missing_message_id',
                'description': 'Message missing unique identifier',
                'severity': 3,
                'location': 'structure'
            })

        # Check message type validity
        if message.message_type not in self.valid_message_types:
            vulnerabilities.append({
                'type': 'invalid_message_type',
                'description': f'Unknown message type: {message.message_type}',
                'severity': 5,
                'location': 'structure'
            })

        return vulnerabilities

    def _analyze_security_context(self, security_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security context for issues."""
        vulnerabilities = []

        # Check for missing security features
        if 'signature' not in security_context:
            vulnerabilities.append({
                'type': 'missing_signature',
                'description': 'Message lacks digital signature',
                'severity': 5,
                'location': 'security'
            })

        if 'encryption' not in security_context:
            vulnerabilities.append({
                'type': 'missing_encryption',
                'description': 'Message not encrypted',
                'severity': 6,
                'location': 'security'
            })

        # Check encryption algorithm
        encryption = security_context.get('encryption', {})
        if isinstance(encryption, dict):
            algorithm = encryption.get('algorithm', '').lower()
            weak_algorithms = ['des', 'rc4', 'md5', 'sha1']
            if any(weak_alg in algorithm for weak_alg in weak_algorithms):
                vulnerabilities.append({
                    'type': 'weak_encryption',
                    'description': f'Weak encryption algorithm: {algorithm}',
                    'severity': 8,
                    'location': 'security'
                })

        return vulnerabilities

    def _analyze_headers_security(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze headers for security issues."""
        vulnerabilities = []

        # Check for excessive headers
        if len(headers) > self.MAX_ATTRIBUTES:
            vulnerabilities.append({
                'type': 'excessive_headers',
                'description': f'Too many headers ({len(headers)})',
                'severity': 4,
                'location': 'headers'
            })

        # Check for suspicious header values
        for key, value in headers.items():
            if any(dangerous in value.lower() for dangerous_list in self.DANGEROUS_PATTERNS.values()
                   for dangerous in dangerous_list):
                vulnerabilities.append({
                    'type': 'dangerous_header_content',
                    'description': f'Dangerous content in header {key}: {value[:50]}...',
                    'severity': 7,
                    'location': 'headers'
                })

        return vulnerabilities

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        vuln_types = {vuln['type'] for vuln in vulnerabilities}

        if any('xml' in vtype for vtype in vuln_types):
            recommendations.append("Disable XML external entity processing and validate XML structure")

        if any('dangerous_' in vtype for vtype in vuln_types):
            recommendations.append("Implement comprehensive input validation and content filtering")

        if 'missing_signature' in vuln_types:
            recommendations.append("Implement digital signatures for message authenticity")

        if 'missing_encryption' in vuln_types:
            recommendations.append("Enable end-to-end encryption for sensitive communications")

        if 'weak_encryption' in vuln_types:
            recommendations.append("Upgrade to strong encryption algorithms (AES-256, RSA-2048+)")

        if 'oversized_content' in vuln_types:
            recommendations.append("Implement content size limits and streaming for large messages")

        return recommendations

    def validate_protocol_compliance(self, message: ACPMessage) -> Dict[str, Any]:
        """Validate ACP protocol compliance."""
        compliance_issues = []

        # Check required fields
        if not message.message_type:
            compliance_issues.append("Missing message type")

        if message.message_type not in self.valid_message_types:
            compliance_issues.append(f"Invalid message type: {message.message_type}")

        # Check XML structure if present
        if message.raw_xml:
            try:
                root = ET.fromstring(message.raw_xml)
                # Basic XML validation passed
            except ET.ParseError:
                compliance_issues.append("Invalid XML structure")

        # Check message flow constraints
        if message.message_type == 'response' and not message.reply_to:
            compliance_issues.append("Response message should specify reply-to")

        if message.message_type in ['request', 'query'] and not message.message_id:
            compliance_issues.append("Request/query messages should have unique message ID")

        return {
            'is_compliant': len(compliance_issues) == 0,
            'issues': compliance_issues,
            'compliance_score': max(0, 10 - len(compliance_issues))
        }

    def extract_features(self, message: ACPMessage) -> Dict[str, Any]:
        """Extract features for ML-based analysis."""
        content = message.content or ""
        raw_xml = message.raw_xml or ""

        return {
            'message_length': len(content),
            'xml_length': len(raw_xml),
            'content_entropy': self._calculate_entropy(content),
            'xml_entropy': self._calculate_entropy(raw_xml),
            'has_sender': bool(message.sender),
            'has_receiver': bool(message.receiver),
            'has_message_id': bool(message.message_id),
            'has_conversation_id': bool(message.conversation_id),
            'has_security_context': bool(message.security_context),
            'headers_count': len(message.headers) if message.headers else 0,
            'message_type_encoded': hash(message.message_type) % 1000,
            'xml_tag_count': raw_xml.count('<') if raw_xml else 0,
            'xml_attribute_count': raw_xml.count('=') if raw_xml else 0,
            'contains_cdata': '<!\\[CDATA\\[' in raw_xml,
            'contains_entities': '<!ENTITY' in raw_xml,
            'contains_dangerous_keywords': sum(
                1 for category in self.DANGEROUS_PATTERNS.values()
                for pattern in category
                if pattern.lower() in content.lower()
            ),
            'special_char_ratio': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', content)) / max(len(content), 1)
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