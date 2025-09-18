"""
Core Exceptions
Custom exception classes for TSAF framework.
"""

from typing import Optional, Dict, Any


class TSAFException(Exception):
    """Base exception for TSAF framework."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
        self.cause = cause

    def __str__(self) -> str:
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary."""
        result = {
            "error": self.__class__.__name__,
            "message": self.message
        }

        if self.code:
            result["code"] = self.code

        if self.details:
            result["details"] = self.details

        if self.cause:
            result["cause"] = str(self.cause)

        return result


class ConfigurationError(TSAFException):
    """Exception raised for configuration-related errors."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.config_key = config_key
        self.config_value = config_value

        if config_key:
            self.details["config_key"] = config_key
        if config_value is not None:
            self.details["config_value"] = str(config_value)


class DatabaseError(TSAFException):
    """Exception raised for database-related errors."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        table: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.operation = operation
        self.table = table

        if operation:
            self.details["operation"] = operation
        if table:
            self.details["table"] = table


class AnalysisError(TSAFException):
    """Exception raised for analysis-related errors."""

    def __init__(
        self,
        message: str,
        analyzer_type: Optional[str] = None,
        protocol: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.analyzer_type = analyzer_type
        self.protocol = protocol

        if analyzer_type:
            self.details["analyzer_type"] = analyzer_type
        if protocol:
            self.details["protocol"] = protocol


class TranslationError(TSAFException):
    """Exception raised for translation-related errors."""

    def __init__(
        self,
        message: str,
        source_protocol: Optional[str] = None,
        target_protocol: Optional[str] = None,
        translation_step: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.source_protocol = source_protocol
        self.target_protocol = target_protocol
        self.translation_step = translation_step

        if source_protocol:
            self.details["source_protocol"] = source_protocol
        if target_protocol:
            self.details["target_protocol"] = target_protocol
        if translation_step:
            self.details["translation_step"] = translation_step


class VerificationError(TSAFException):
    """Exception raised for formal verification errors."""

    def __init__(
        self,
        message: str,
        verification_tool: Optional[str] = None,
        property_name: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.verification_tool = verification_tool
        self.property_name = property_name

        if verification_tool:
            self.details["verification_tool"] = verification_tool
        if property_name:
            self.details["property_name"] = property_name


class SecurityError(TSAFException):
    """Exception raised for security-related errors."""

    def __init__(
        self,
        message: str,
        security_level: Optional[str] = None,
        threat_type: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.security_level = security_level
        self.threat_type = threat_type

        if security_level:
            self.details["security_level"] = security_level
        if threat_type:
            self.details["threat_type"] = threat_type


class ValidationError(TSAFException):
    """Exception raised for validation errors."""

    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        field_value: Optional[Any] = None,
        validation_rule: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.field_name = field_name
        self.field_value = field_value
        self.validation_rule = validation_rule

        if field_name:
            self.details["field_name"] = field_name
        if field_value is not None:
            self.details["field_value"] = str(field_value)
        if validation_rule:
            self.details["validation_rule"] = validation_rule


class ProtocolError(TSAFException):
    """Exception raised for protocol-related errors."""

    def __init__(
        self,
        message: str,
        protocol_type: Optional[str] = None,
        protocol_version: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.protocol_type = protocol_type
        self.protocol_version = protocol_version

        if protocol_type:
            self.details["protocol_type"] = protocol_type
        if protocol_version:
            self.details["protocol_version"] = protocol_version


class TimeoutError(TSAFException):
    """Exception raised for timeout errors."""

    def __init__(
        self,
        message: str,
        timeout_duration: Optional[float] = None,
        operation: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.timeout_duration = timeout_duration
        self.operation = operation

        if timeout_duration is not None:
            self.details["timeout_duration"] = timeout_duration
        if operation:
            self.details["operation"] = operation


class ResourceError(TSAFException):
    """Exception raised for resource-related errors."""

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_name: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.resource_name = resource_name

        if resource_type:
            self.details["resource_type"] = resource_type
        if resource_name:
            self.details["resource_name"] = resource_name


class AuthenticationError(TSAFException):
    """Exception raised for authentication errors."""

    def __init__(
        self,
        message: str,
        auth_method: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.auth_method = auth_method

        if auth_method:
            self.details["auth_method"] = auth_method


class AuthorizationError(TSAFException):
    """Exception raised for authorization errors."""

    def __init__(
        self,
        message: str,
        required_permission: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.required_permission = required_permission

        if required_permission:
            self.details["required_permission"] = required_permission