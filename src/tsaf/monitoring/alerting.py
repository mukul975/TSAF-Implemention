"""
Alerting and Notification System
Intelligent alerting for TSAF framework monitoring.
"""

import asyncio
import json
import smtplib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import structlog

logger = structlog.get_logger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertStatus(str, Enum):
    """Alert status."""
    ACTIVE = "active"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"


@dataclass
class Alert:
    """Alert definition."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.ACTIVE
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = "tsaf"
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    resolved_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None


@dataclass
class AlertRule:
    """Alert rule definition."""
    name: str
    description: str
    severity: AlertSeverity
    condition: Callable[[Dict[str, Any]], bool]
    threshold: Optional[float] = None
    duration: timedelta = timedelta(minutes=1)
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class NotificationChannel:
    """Notification channel configuration."""
    name: str
    type: str  # email, slack, webhook, sms
    config: Dict[str, Any]
    enabled: bool = True
    severity_filter: List[AlertSeverity] = field(default_factory=lambda: list(AlertSeverity))


class AlertManager:
    """
    Comprehensive alerting and notification system.

    Features:
    - Rule-based alerting
    - Multiple notification channels
    - Alert grouping and suppression
    - Escalation policies
    - Alert history and analytics
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules: Dict[str, AlertRule] = {}
        self.channels: Dict[str, NotificationChannel] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.monitoring_task: Optional[asyncio.Task] = None
        self.running = False

        # Setup default rules and channels
        self._setup_default_rules()
        self._setup_default_channels()

        logger.info("Alert manager initialized")

    def _setup_default_rules(self):
        """Setup default alert rules."""

        # High CPU usage
        self.add_rule(AlertRule(
            name="high_cpu_usage",
            description="CPU usage is above threshold",
            severity=AlertSeverity.WARNING,
            condition=lambda metrics: metrics.get('cpu_percent', 0) > 80,
            threshold=80.0,
            duration=timedelta(minutes=2),
            annotations={
                "summary": "High CPU usage detected",
                "description": "CPU usage is above 80% for more than 2 minutes"
            }
        ))

        # High memory usage
        self.add_rule(AlertRule(
            name="high_memory_usage",
            description="Memory usage is above threshold",
            severity=AlertSeverity.WARNING,
            condition=lambda metrics: metrics.get('memory_percent', 0) > 85,
            threshold=85.0,
            duration=timedelta(minutes=2),
            annotations={
                "summary": "High memory usage detected",
                "description": "Memory usage is above 85% for more than 2 minutes"
            }
        ))

        # Database connection issues
        self.add_rule(AlertRule(
            name="database_unhealthy",
            description="Database health check failed",
            severity=AlertSeverity.CRITICAL,
            condition=lambda health: health.get('database', {}).get('status') != 'healthy',
            duration=timedelta(seconds=30),
            annotations={
                "summary": "Database connectivity issues",
                "description": "Database health check is failing"
            }
        ))

        # High error rate
        self.add_rule(AlertRule(
            name="high_error_rate",
            description="Error rate is above threshold",
            severity=AlertSeverity.WARNING,
            condition=lambda metrics: metrics.get('error_rate', 0) > 0.05,
            threshold=0.05,
            duration=timedelta(minutes=5),
            annotations={
                "summary": "High error rate detected",
                "description": "Error rate is above 5% for more than 5 minutes"
            }
        ))

        # Security threats
        self.add_rule(AlertRule(
            name="security_threat_detected",
            description="High-risk security threat detected",
            severity=AlertSeverity.CRITICAL,
            condition=lambda analysis: analysis.get('risk_score', 0) > 0.8 and analysis.get('is_malicious', False),
            duration=timedelta(seconds=0),  # Immediate
            annotations={
                "summary": "Security threat detected",
                "description": "High-risk malicious content detected"
            }
        ))

        # Verification failures
        self.add_rule(AlertRule(
            name="verification_failures",
            description="Multiple verification failures",
            severity=AlertSeverity.WARNING,
            condition=lambda metrics: metrics.get('verification_failure_rate', 0) > 0.2,
            threshold=0.2,
            duration=timedelta(minutes=10),
            annotations={
                "summary": "High verification failure rate",
                "description": "Verification failure rate is above 20%"
            }
        ))

    def _setup_default_channels(self):
        """Setup default notification channels."""

        # Email channel
        if self.config.get('email_enabled', False):
            self.add_channel(NotificationChannel(
                name="email",
                type="email",
                config={
                    "smtp_server": self.config.get('smtp_server', 'localhost'),
                    "smtp_port": self.config.get('smtp_port', 587),
                    "username": self.config.get('smtp_username'),
                    "password": self.config.get('smtp_password'),
                    "from_email": self.config.get('from_email', 'tsaf@example.com'),
                    "to_emails": self.config.get('alert_emails', [])
                },
                severity_filter=[AlertSeverity.WARNING, AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]
            ))

        # Webhook channel
        if self.config.get('webhook_enabled', False):
            self.add_channel(NotificationChannel(
                name="webhook",
                type="webhook",
                config={
                    "url": self.config.get('webhook_url'),
                    "headers": self.config.get('webhook_headers', {}),
                    "timeout": self.config.get('webhook_timeout', 10)
                }
            ))

        # Slack channel
        if self.config.get('slack_enabled', False):
            self.add_channel(NotificationChannel(
                name="slack",
                type="slack",
                config={
                    "webhook_url": self.config.get('slack_webhook_url'),
                    "channel": self.config.get('slack_channel', '#alerts'),
                    "username": self.config.get('slack_username', 'TSAF Bot')
                },
                severity_filter=[AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]
            ))

    def add_rule(self, rule: AlertRule):
        """Add an alert rule."""
        self.rules[rule.name] = rule
        logger.debug("Alert rule added", rule_name=rule.name)

    def remove_rule(self, name: str):
        """Remove an alert rule."""
        if name in self.rules:
            del self.rules[name]
            logger.debug("Alert rule removed", rule_name=name)

    def add_channel(self, channel: NotificationChannel):
        """Add a notification channel."""
        self.channels[channel.name] = channel
        logger.debug("Notification channel added", channel_name=channel.name)

    def remove_channel(self, name: str):
        """Remove a notification channel."""
        if name in self.channels:
            del self.channels[name]
            logger.debug("Notification channel removed", channel_name=name)

    async def evaluate_rules(self, data: Dict[str, Any]) -> List[Alert]:
        """Evaluate all alert rules against provided data."""
        alerts = []

        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue

            try:
                # Evaluate condition
                triggered = rule.condition(data)

                if triggered:
                    # Check if alert already exists
                    alert_id = f"{rule_name}_{hash(str(rule.labels))}"

                    if alert_id not in self.active_alerts:
                        # Create new alert
                        alert = Alert(
                            id=alert_id,
                            name=rule_name,
                            description=rule.description,
                            severity=rule.severity,
                            labels=rule.labels.copy(),
                            annotations=rule.annotations.copy()
                        )

                        # Add context from data
                        alert.annotations.update({
                            "triggered_at": datetime.utcnow().isoformat(),
                            "data_snapshot": json.dumps(data, default=str)[:1000]
                        })

                        self.active_alerts[alert_id] = alert
                        alerts.append(alert)

                        logger.warning(
                            "Alert triggered",
                            alert_id=alert_id,
                            rule_name=rule_name,
                            severity=rule.severity.value
                        )

                else:
                    # Check if we should resolve existing alert
                    alert_id = f"{rule_name}_{hash(str(rule.labels))}"
                    if alert_id in self.active_alerts:
                        alert = self.active_alerts[alert_id]
                        alert.status = AlertStatus.RESOLVED
                        alert.resolved_at = datetime.utcnow()

                        # Move to history
                        self.alert_history.append(alert)
                        del self.active_alerts[alert_id]

                        logger.info(
                            "Alert resolved",
                            alert_id=alert_id,
                            rule_name=rule_name
                        )

            except Exception as e:
                logger.error(
                    "Alert rule evaluation failed",
                    rule_name=rule_name,
                    error=str(e)
                )

        return alerts

    async def send_notifications(self, alerts: List[Alert]):
        """Send notifications for alerts."""
        if not alerts:
            return

        for channel_name, channel in self.channels.items():
            if not channel.enabled:
                continue

            # Filter alerts by severity
            filtered_alerts = [
                alert for alert in alerts
                if alert.severity in channel.severity_filter
            ]

            if not filtered_alerts:
                continue

            try:
                if channel.type == "email":
                    await self._send_email_notifications(channel, filtered_alerts)
                elif channel.type == "webhook":
                    await self._send_webhook_notifications(channel, filtered_alerts)
                elif channel.type == "slack":
                    await self._send_slack_notifications(channel, filtered_alerts)

                logger.info(
                    "Notifications sent",
                    channel=channel_name,
                    alert_count=len(filtered_alerts)
                )

            except Exception as e:
                logger.error(
                    "Failed to send notifications",
                    channel=channel_name,
                    error=str(e)
                )

    async def _send_email_notifications(self, channel: NotificationChannel, alerts: List[Alert]):
        """Send email notifications."""
        config = channel.config

        if not config.get('to_emails'):
            return

        # Group alerts by severity
        alert_groups = {}
        for alert in alerts:
            severity = alert.severity.value
            if severity not in alert_groups:
                alert_groups[severity] = []
            alert_groups[severity].append(alert)

        # Create email content
        subject = f"TSAF Alerts - {len(alerts)} alert(s)"
        if len(alert_groups) == 1:
            severity = list(alert_groups.keys())[0]
            subject = f"TSAF {severity.upper()} Alert - {alerts[0].name}"

        body = self._format_email_body(alert_groups)

        # Send email
        msg = MIMEMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'html'))

        # Send via SMTP
        def send_email():
            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                if config.get('username') and config.get('password'):
                    server.starttls()
                    server.login(config['username'], config['password'])
                server.send_message(msg)

        await asyncio.get_event_loop().run_in_executor(None, send_email)

    async def _send_webhook_notifications(self, channel: NotificationChannel, alerts: List[Alert]):
        """Send webhook notifications."""
        import httpx

        config = channel.config
        url = config['url']

        payload = {
            "alerts": [
                {
                    "id": alert.id,
                    "name": alert.name,
                    "description": alert.description,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "timestamp": alert.timestamp.isoformat(),
                    "labels": alert.labels,
                    "annotations": alert.annotations
                }
                for alert in alerts
            ],
            "timestamp": datetime.utcnow().isoformat(),
            "source": "tsaf"
        }

        headers = config.get('headers', {})
        headers['Content-Type'] = 'application/json'

        timeout = config.get('timeout', 10)

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()

    async def _send_slack_notifications(self, channel: NotificationChannel, alerts: List[Alert]):
        """Send Slack notifications."""
        import httpx

        config = channel.config
        webhook_url = config['webhook_url']

        # Format Slack message
        color_map = {
            AlertSeverity.INFO: "good",
            AlertSeverity.WARNING: "warning",
            AlertSeverity.CRITICAL: "danger",
            AlertSeverity.EMERGENCY: "danger"
        }

        attachments = []
        for alert in alerts:
            attachment = {
                "color": color_map.get(alert.severity, "warning"),
                "title": f"{alert.severity.value.upper()}: {alert.name}",
                "text": alert.description,
                "fields": [
                    {
                        "title": "Timestamp",
                        "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True
                    },
                    {
                        "title": "Status",
                        "value": alert.status.value,
                        "short": True
                    }
                ],
                "footer": "TSAF Alert Manager",
                "ts": int(alert.timestamp.timestamp())
            }

            # Add custom fields from annotations
            for key, value in alert.annotations.items():
                if key not in ["data_snapshot"]:  # Skip large fields
                    attachment["fields"].append({
                        "title": key.replace("_", " ").title(),
                        "value": str(value)[:100],  # Limit length
                        "short": True
                    })

            attachments.append(attachment)

        payload = {
            "channel": config.get('channel', '#alerts'),
            "username": config.get('username', 'TSAF Bot'),
            "text": f"🚨 {len(alerts)} TSAF alert(s) triggered",
            "attachments": attachments
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()

    def _format_email_body(self, alert_groups: Dict[str, List[Alert]]) -> str:
        """Format email body for alerts."""
        html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .alert { margin: 10px 0; padding: 10px; border-left: 4px solid; }
                .critical { border-color: #dc3545; background-color: #f8d7da; }
                .warning { border-color: #ffc107; background-color: #fff3cd; }
                .info { border-color: #17a2b8; background-color: #d1ecf1; }
                .emergency { border-color: #6f42c1; background-color: #e2d9f3; }
                .timestamp { color: #666; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <h2>TSAF Alert Notification</h2>
        """

        for severity, alerts in alert_groups.items():
            html += f"<h3>{severity.upper()} Alerts ({len(alerts)})</h3>"

            for alert in alerts:
                css_class = severity.lower()
                html += f"""
                <div class="alert {css_class}">
                    <h4>{alert.name}</h4>
                    <p>{alert.description}</p>
                    <div class="timestamp">
                        Triggered: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </div>
                </div>
                """

        html += """
            <hr>
            <p><small>This alert was generated by TSAF Alert Manager</small></p>
        </body>
        </html>
        """

        return html

    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str):
        """Acknowledge an active alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = acknowledged_by

            logger.info(
                "Alert acknowledged",
                alert_id=alert_id,
                acknowledged_by=acknowledged_by
            )

    async def resolve_alert(self, alert_id: str):
        """Manually resolve an alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()

            # Move to history
            self.alert_history.append(alert)
            del self.active_alerts[alert_id]

            logger.info("Alert manually resolved", alert_id=alert_id)

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        active_alerts = list(self.active_alerts.values())

        severity_counts = {severity.value: 0 for severity in AlertSeverity}
        for alert in active_alerts:
            severity_counts[alert.severity.value] += 1

        return {
            "active_alerts": len(active_alerts),
            "severity_breakdown": severity_counts,
            "rules_configured": len(self.rules),
            "channels_configured": len(self.channels),
            "total_alerts_history": len(self.alert_history)
        }