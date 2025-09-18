"""
TSAF Detector Module
Security threat detection and analysis components.
"""

from .static_analyzer import StaticAnalyzer, Vulnerability

try:
    from .ml_detector import MLThreatDetector
    __all__ = ['StaticAnalyzer', 'Vulnerability', 'MLThreatDetector']
except ImportError:
    # ML dependencies not available
    __all__ = ['StaticAnalyzer', 'Vulnerability']