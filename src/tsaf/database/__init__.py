"""
Database Package
Database models, connections, and repositories for TSAF framework.
"""

from tsaf.database.models import (
    Agent, Message, Vulnerability, Translation, SecurityEvent,
    VerificationResult, AuditLog, SystemMetrics, Configuration,
    ProtocolTypeDB, VulnerabilityCategoryDB, SeverityLevel
)
from tsaf.database.connection import (
    DatabaseManager, get_database_manager, initialize_database_manager, close_database_manager
)
from tsaf.database.repositories import (
    BaseRepository, AgentRepository, MessageRepository, VulnerabilityRepository,
    TranslationRepository, SecurityEventRepository, VerificationResultRepository,
    ConfigurationRepository, MetricsRepository
)

__all__ = [
    # Models
    "Agent", "Message", "Vulnerability", "Translation", "SecurityEvent",
    "VerificationResult", "AuditLog", "SystemMetrics", "Configuration",
    "ProtocolTypeDB", "VulnerabilityCategoryDB", "SeverityLevel",

    # Connection
    "DatabaseManager", "get_database_manager", "initialize_database_manager", "close_database_manager",

    # Repositories
    "BaseRepository", "AgentRepository", "MessageRepository", "VulnerabilityRepository",
    "TranslationRepository", "SecurityEventRepository", "VerificationResultRepository",
    "ConfigurationRepository", "MetricsRepository"
]