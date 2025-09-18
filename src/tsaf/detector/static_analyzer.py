"""
Static Code Analyzer for Security Threat Detection
Analyzes code and messages for potential security vulnerabilities.
"""

import re
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability."""
    type: str
    severity: str
    description: str
    location: str
    confidence: float
    metadata: Dict[str, Any]


class StaticAnalyzer:
    """
    Static analyzer for detecting security vulnerabilities in code and messages.

    Performs language-specific analysis to reduce false positives.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize static analyzer with configuration."""
        self.config = config
        self._load_patterns()

        logger.info("Static analyzer initialized", config_keys=list(config.keys()))

    def _load_patterns(self):
        """Load security patterns organized by language and vulnerability type."""
        self._advanced_patterns = {
            "code_injection": {
                "python": [
                    {
                        "pattern": r"exec\s*\(\s*['\"].*['\"].*\)",
                        "description": "Dangerous exec() usage",
                        "severity": "high"
                    },
                    {
                        "pattern": r"eval\s*\(\s*['\"].*['\"].*\)",
                        "description": "Dangerous eval() usage",
                        "severity": "high"
                    },
                    {
                        "pattern": r"__import__\s*\(\s*['\"].*['\"].*\)",
                        "description": "Dynamic import with user input",
                        "severity": "medium"
                    }
                ],
                "javascript": [
                    {
                        "pattern": r"eval\s*\(\s*['\"].*['\"].*\)",
                        "description": "Dangerous eval() usage",
                        "severity": "high"
                    },
                    {
                        "pattern": r"Function\s*\(\s*['\"].*['\"].*\)",
                        "description": "Dynamic function creation",
                        "severity": "high"
                    },
                    {
                        "pattern": r"setTimeout\s*\(\s*['\"].*['\"].*\)",
                        "description": "String-based setTimeout",
                        "severity": "medium"
                    }
                ],
                "sql": [
                    {
                        "pattern": r"SELECT.*FROM.*WHERE.*=.*['\"].*['\"]",
                        "description": "Potential SQL injection",
                        "severity": "high"
                    },
                    {
                        "pattern": r"INSERT.*INTO.*VALUES.*['\"].*['\"]",
                        "description": "Potential SQL injection in INSERT",
                        "severity": "high"
                    },
                    {
                        "pattern": r"UPDATE.*SET.*=.*['\"].*['\"].*WHERE",
                        "description": "Potential SQL injection in UPDATE",
                        "severity": "high"
                    }
                ],
                "php": [
                    {
                        "pattern": r"eval\s*\(\s*\$.*\)",
                        "description": "Dangerous eval() with variable",
                        "severity": "high"
                    },
                    {
                        "pattern": r"system\s*\(\s*\$.*\)",
                        "description": "System command execution",
                        "severity": "high"
                    },
                    {
                        "pattern": r"shell_exec\s*\(\s*\$.*\)",
                        "description": "Shell command execution",
                        "severity": "high"
                    }
                ]
            },
            "xss": [
                {
                    "pattern": r"<script[^>]*>.*</script>",
                    "description": "Script tag detected",
                    "severity": "high"
                },
                {
                    "pattern": r"javascript:[^'\"\s]+",
                    "description": "JavaScript URL scheme",
                    "severity": "medium"
                },
                {
                    "pattern": r"on\w+\s*=\s*['\"].*['\"]",
                    "description": "Inline event handler",
                    "severity": "medium"
                }
            ]
        }

        # Language detection patterns
        self._language_patterns = {
            "python": [
                r"def\s+\w+\s*\(",
                r"import\s+\w+",
                r"from\s+\w+\s+import",
                r"if\s+__name__\s*==\s*['\"]__main__['\"]",
                r"print\s*\("
            ],
            "javascript": [
                r"function\s+\w+\s*\(",
                r"var\s+\w+\s*=",
                r"let\s+\w+\s*=",
                r"const\s+\w+\s*=",
                r"console\.log\s*\(",
                r"=>\s*\{"
            ],
            "sql": [
                r"SELECT\s+.*\s+FROM",
                r"INSERT\s+INTO",
                r"UPDATE\s+.*\s+SET",
                r"DELETE\s+FROM",
                r"CREATE\s+TABLE",
                r"ALTER\s+TABLE"
            ],
            "php": [
                r"<\?php",
                r"\$\w+\s*=",
                r"function\s+\w+\s*\(",
                r"echo\s+",
                r"include\s+",
                r"require\s+"
            ]
        }

    def _detect_language(self, message: str) -> Optional[str]:
        """
        Detect the programming language of the given message.

        Args:
            message: The message content to analyze

        Returns:
            Detected language name or None if no language detected
        """
        if not message:
            return None

        # Count pattern matches for each language
        language_scores = {}

        for language, patterns in self._language_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE | re.MULTILINE):
                    score += 1

            if score > 0:
                language_scores[language] = score

        if not language_scores:
            return None

        # Return language with highest score
        detected_language = max(language_scores, key=language_scores.get)
        logger.debug("Language detected", language=detected_language, scores=language_scores)

        return detected_language

    def analyze_message(self, message: str, metadata: Dict[str, Any] = None) -> List[Vulnerability]:
        """
        Analyze a message for security vulnerabilities.

        Args:
            message: The message content to analyze
            metadata: Additional metadata about the message

        Returns:
            List of detected vulnerabilities
        """
        if not message:
            return []

        vulnerabilities = []
        metadata = metadata or {}

        # Detect language first to avoid cross-language false positives
        detected_language = self._detect_language(message)

        # Language-specific code injection analysis
        vulnerabilities.extend(self._analyze_code_injection(message, detected_language))

        # XSS analysis (language-agnostic)
        vulnerabilities.extend(self._analyze_xss(message))

        return vulnerabilities

    def _analyze_code_injection(self, message: str, detected_language: Optional[str]) -> List[Vulnerability]:
        """
        Analyze message for code injection vulnerabilities using language-specific patterns.

        Args:
            message: The message content to analyze
            detected_language: The detected programming language

        Returns:
            List of code injection vulnerabilities
        """
        vulnerabilities = []

        if detected_language is None:
            # No language detected - skip analysis or use conservative default
            logger.debug("No language detected, skipping code injection analysis")
            return vulnerabilities

        # Get language-specific patterns
        patterns = self._advanced_patterns["code_injection"].get(detected_language, [])

        if not patterns:
            logger.debug("No patterns available for detected language", language=detected_language)
            return vulnerabilities

        # Apply only the patterns for the detected language
        for pattern_data in patterns:
            pattern = pattern_data["pattern"]
            description = pattern_data["description"]
            severity = pattern_data["severity"]

            matches = re.finditer(pattern, message, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                vulnerability = Vulnerability(
                    type="code_injection",
                    severity=severity,
                    description=f"{description} (detected in {detected_language})",
                    location=f"Position {match.start()}-{match.end()}",
                    confidence=0.8,
                    metadata={
                        "detected_language": detected_language,
                        "pattern": pattern,
                        "matched_text": match.group(0)
                    }
                )
                vulnerabilities.append(vulnerability)

                logger.warning(
                    "Code injection vulnerability detected",
                    type=vulnerability.type,
                    severity=severity,
                    language=detected_language,
                    location=vulnerability.location
                )

        return vulnerabilities

    def _analyze_xss(self, message: str) -> List[Vulnerability]:
        """
        Analyze message for XSS vulnerabilities.

        Args:
            message: The message content to analyze

        Returns:
            List of XSS vulnerabilities
        """
        vulnerabilities = []

        for pattern_data in self._advanced_patterns["xss"]:
            pattern = pattern_data["pattern"]
            description = pattern_data["description"]
            severity = pattern_data["severity"]

            matches = re.finditer(pattern, message, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                vulnerability = Vulnerability(
                    type="xss",
                    severity=severity,
                    description=description,
                    location=f"Position {match.start()}-{match.end()}",
                    confidence=0.7,
                    metadata={
                        "pattern": pattern,
                        "matched_text": match.group(0)
                    }
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """
        Analyze a file for security vulnerabilities.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of detected vulnerabilities
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            metadata = {"file_path": file_path}
            return self.analyze_message(content, metadata)

        except Exception as e:
            logger.error("Failed to analyze file", file_path=file_path, error=str(e))
            return []

    def get_supported_languages(self) -> List[str]:
        """
        Get list of supported programming languages.

        Returns:
            List of supported language names
        """
        return list(self._language_patterns.keys())