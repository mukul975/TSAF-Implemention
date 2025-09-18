"""
Configuration Management
Centralized configuration for TSAF framework.
"""

import os
from typing import Dict, Any, List, Optional
from pathlib import Path

from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings

import structlog

logger = structlog.get_logger(__name__)


class DatabaseConfig(BaseModel):
    """Database configuration."""
    database_url: str = Field(default="sqlite:///tsaf.db", description="Database URL")
    echo_sql: bool = Field(default=False, description="Echo SQL queries")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max overflow connections")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")
    create_tables: bool = Field(default=True, description="Auto-create tables")
    disable_pool: bool = Field(default=False, description="Disable connection pooling")

    @property
    def sync_url(self) -> str:
        """Get synchronous database URL."""
        if self.database_url.startswith("postgresql+asyncpg"):
            return self.database_url.replace("postgresql+asyncpg", "postgresql")
        elif self.database_url.startswith("sqlite+aiosqlite"):
            return self.database_url.replace("sqlite+aiosqlite", "sqlite")
        return self.database_url

    @property
    def async_url(self) -> str:
        """Get asynchronous database URL."""
        if self.database_url.startswith("postgresql://"):
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        elif self.database_url.startswith("sqlite:///"):
            return self.database_url.replace("sqlite:///", "sqlite+aiosqlite:///")
        return self.database_url


class ServerConfig(BaseModel):
    """Server configuration."""
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port", ge=1, le=65535)
    workers: int = Field(default=1, description="Number of workers")
    reload: bool = Field(default=False, description="Auto-reload on changes")
    debug: bool = Field(default=False, description="Debug mode")
    access_log: bool = Field(default=True, description="Enable access logging")


class SecurityConfig(BaseModel):
    """Security configuration."""
    api_keys: Dict[str, str] = Field(default_factory=dict, description="API keys")
    rate_limit: int = Field(default=1000, description="Requests per hour")
    rate_window: int = Field(default=3600, description="Rate limit window in seconds")
    max_content_length: int = Field(default=10 * 1024 * 1024, description="Max request size")
    enable_cors: bool = Field(default=True, description="Enable CORS")
    cors_origins: List[str] = Field(default=["*"], description="CORS allowed origins")
    cors_methods: List[str] = Field(default=["GET", "POST", "PUT", "DELETE"], description="CORS allowed methods")
    cors_headers: List[str] = Field(default=["*"], description="CORS allowed headers")


class AnalyzerConfig(BaseModel):
    """Analyzer configuration."""
    enable_static_analysis: bool = Field(default=True, description="Enable static analysis")
    enable_dynamic_analysis: bool = Field(default=True, description="Enable dynamic analysis")
    enable_ml_detection: bool = Field(default=True, description="Enable ML detection")
    enable_behavioral_analysis: bool = Field(default=True, description="Enable behavioral analysis")

    # ML Model configuration
    model_cache_dir: str = Field(default="./models", description="Model cache directory")
    bert_model_name: str = Field(default="bert-base-uncased", description="BERT model name")
    max_sequence_length: int = Field(default=512, description="Max token sequence length")

    # Analysis thresholds
    risk_threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Risk score threshold")
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0, description="Confidence threshold")
    semantic_threshold: float = Field(default=0.8, ge=0.0, le=1.0, description="Semantic similarity threshold")

    # Performance settings
    max_concurrent_analyses: int = Field(default=10, ge=1, description="Max concurrent analyses")
    analysis_timeout: int = Field(default=30, ge=1, description="Analysis timeout in seconds")


class DetectorConfig(BaseModel):
    """Detector configuration."""
    enable_pattern_detection: bool = Field(default=True, description="Enable pattern detection")
    enable_signature_detection: bool = Field(default=True, description="Enable signature detection")
    enable_anomaly_detection: bool = Field(default=True, description="Enable anomaly detection")
    enable_heuristic_detection: bool = Field(default=True, description="Enable heuristic detection")

    # Detection sensitivity
    detection_sensitivity: float = Field(default=0.7, ge=0.0, le=1.0, description="Detection sensitivity")
    false_positive_threshold: float = Field(default=0.1, ge=0.0, le=1.0, description="False positive threshold")

    # Pattern databases
    pattern_db_path: str = Field(default="./patterns", description="Pattern database path")
    signature_db_path: str = Field(default="./signatures", description="Signature database path")
    custom_rules_path: str = Field(default="./rules", description="Custom rules path")


class TranslatorConfig(BaseModel):
    """Translator configuration."""
    enable_semantic_validation: bool = Field(default=True, description="Enable semantic validation")
    enable_security_validation: bool = Field(default=True, description="Enable security validation")
    enable_formal_verification: bool = Field(default=True, description="Enable formal verification")

    # Translation settings
    preserve_metadata: bool = Field(default=True, description="Preserve message metadata")
    validate_schema: bool = Field(default=True, description="Validate schema compliance")

    # Performance settings
    translation_timeout: int = Field(default=60, ge=1, description="Translation timeout in seconds")
    max_translation_size: int = Field(default=1024 * 1024, description="Max translation size in bytes")


class VerifierConfig(BaseModel):
    """Formal verifier configuration."""
    enable_proverif: bool = Field(default=True, description="Enable ProVerif verification")
    enable_tamarin: bool = Field(default=True, description="Enable Tamarin verification")
    enable_tlaplus: bool = Field(default=True, description="Enable TLA+ verification")

    # Tool paths
    proverif_path: Optional[str] = Field(default=None, description="ProVerif binary path")
    tamarin_path: Optional[str] = Field(default=None, description="Tamarin binary path")
    tlc_path: Optional[str] = Field(default=None, description="TLC binary path")
    tlaplus_path: Optional[str] = Field(default=None, description="TLA+ tools path")

    # Verification settings
    verification_timeout: int = Field(default=300, ge=1, description="Verification timeout in seconds")
    parallel_verification: bool = Field(default=True, description="Enable parallel verification")
    max_verification_memory: int = Field(default=2048, description="Max memory per verification (MB)")

    # Tool-specific timeouts
    proverif_timeout: Optional[int] = Field(default=None, description="ProVerif timeout")
    tamarin_timeout: Optional[int] = Field(default=None, description="Tamarin timeout")
    tlaplus_timeout: Optional[int] = Field(default=None, description="TLA+ timeout")


class MonitoringConfig(BaseModel):
    """Monitoring and metrics configuration."""
    enable_metrics: bool = Field(default=True, description="Enable metrics collection")
    enable_tracing: bool = Field(default=True, description="Enable request tracing")
    enable_alerts: bool = Field(default=True, description="Enable alerting")

    # Metrics settings
    metrics_interval: int = Field(default=60, ge=1, description="Metrics collection interval")
    metrics_retention: int = Field(default=7 * 24 * 3600, description="Metrics retention in seconds")

    # Alert thresholds
    error_rate_threshold: float = Field(default=0.05, description="Error rate alert threshold")
    response_time_threshold: float = Field(default=5.0, description="Response time alert threshold")
    memory_threshold: float = Field(default=0.9, description="Memory usage alert threshold")


class TSAFConfig(BaseSettings):
    """Main TSAF configuration."""

    # Environment
    environment: str = Field(default="development", description="Environment name")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # Component configurations
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    analyzer: AnalyzerConfig = Field(default_factory=AnalyzerConfig)
    detector: DetectorConfig = Field(default_factory=DetectorConfig)
    translator: TranslatorConfig = Field(default_factory=TranslatorConfig)
    verifier: VerifierConfig = Field(default_factory=VerifierConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"
        case_sensitive = False

    @validator("log_level")
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of: {valid_levels}")
        return v.upper()

    @classmethod
    def from_env(cls) -> "TSAFConfig":
        """Load configuration from environment variables."""
        return cls()

    @classmethod
    def from_file(cls, config_path: str) -> "TSAFConfig":
        """Load configuration from file."""
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        import json
        import yaml

        if config_path.endswith('.json'):
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        elif config_path.endswith('.yaml') or config_path.endswith('.yml'):
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
        else:
            raise ValueError("Configuration file must be JSON or YAML")

        return cls(**config_data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.dict()

    def save_to_file(self, config_path: str) -> None:
        """Save configuration to file."""
        config_file = Path(config_path)
        config_data = self.to_dict()

        if config_path.endswith('.json'):
            import json
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        elif config_path.endswith('.yaml') or config_path.endswith('.yml'):
            import yaml
            with open(config_file, 'w') as f:
                yaml.safe_dump(config_data, f, indent=2)
        else:
            raise ValueError("Configuration file must be JSON or YAML")


def load_config() -> TSAFConfig:
    """
    Load TSAF configuration from various sources.

    Priority order:
    1. Environment variables
    2. Configuration file (if TSAF_CONFIG_FILE is set)
    3. Default values
    """
    try:
        # Check for configuration file
        config_file = os.getenv("TSAF_CONFIG_FILE")
        if config_file and os.path.exists(config_file):
            logger.info("Loading configuration from file", config_file=config_file)
            return TSAFConfig.from_file(config_file)

        # Load from environment
        logger.info("Loading configuration from environment variables")
        return TSAFConfig.from_env()

    except Exception as e:
        logger.error("Failed to load configuration", error=str(e))
        logger.info("Using default configuration")
        return TSAFConfig()


def create_default_config_file(config_path: str) -> None:
    """Create a default configuration file."""
    config = TSAFConfig()
    config.save_to_file(config_path)
    logger.info("Default configuration file created", config_path=config_path)