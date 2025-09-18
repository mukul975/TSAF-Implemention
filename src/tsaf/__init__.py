"""
TSAF - Translation Security Analysis Framework
Advanced security analysis framework for multi-agent communication protocols.
"""

__version__ = "1.0.0"
__author__ = "TSAF Development Team"
__description__ = "Translation Security Analysis Framework for Multi-Agent Systems"

from tsaf.core.config import TSAFConfig, load_config
from tsaf.core.exceptions import TSAFException

__all__ = [
    "TSAFConfig",
    "load_config",
    "TSAFException",
    "__version__"
]