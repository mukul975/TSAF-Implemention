#!/usr/bin/env python3
"""
TSAF Integration Examples
Examples for integrating TSAF with different systems and frameworks.
"""

import asyncio
import json
import aiohttp
from typing import Dict, Any, List
from datetime import datetime
import websockets
import logging


class TSAFIntegrationExamples:
    """Integration examples for various scenarios."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.logger = logging.getLogger(__name__)

    async def example_chatbot_integration(self):
        """Example: Integrating TSAF with a chatbot system."""
        print("\n" + "="*60)
        print("Example: Chatbot Integration with TSAF Security")
        print("="*60)

        class SecureChatbot:
            def __init__(self, tsaf_url: str):
                self.tsaf_url = tsaf_url
                self.session = None

            async def __aenter__(self):
                self.session = aiohttp.ClientSession()
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                if self.session:
                    await self.session.close()

            async def process_user_message(self, user_id: str, message: str) -> Dict[str, Any]:
                """Process user message with security analysis."""
                print(f"👤 User {user_id}: {message}")

                # Analyze message for security threats
                security_result = await self._analyze_security(message, user_id)

                if security_result.get('is_malicious', False):
                    return {
                        'response': "⚠️ Your message contains potentially harmful content and cannot be processed.",
                        'blocked': True,
                        'reason': 'Security policy violation',
                        'risk_score': security_result.get('risk_score', 0)
                    }

                # If safe, process normally
                bot_response = await self._generate_response(message)

                # Analyze bot response for safety
                response_security = await self._analyze_security(bot_response, f"bot-{user_id}")

                if response_security.get('is_malicious', False):
                    return {
                        'response': "I apologize, but I cannot provide that response due to safety concerns.",
                        'blocked': True,
                        'reason': 'Response safety filter',
                        'risk_score': response_security.get('risk_score', 0)
                    }

                return {
                    'response': bot_response,
                    'blocked': False,
                    'user_risk_score': security_result.get('risk_score', 0),
                    'response_risk_score': response_security.get('risk_score', 0)
                }

            async def _analyze_security(self, message: str, agent_id: str) -> Dict[str, Any]:
                """Analyze message with TSAF."""
                try:
                    url = f"{self.tsaf_url}/api/v1/analysis/analyze"
                    payload = {
                        "message": message,
                        "protocol": "mcp",  # Using MCP for chatbot messages
                        "agent_id": agent_id,
                        "metadata": {"source": "chatbot", "timestamp": datetime.utcnow().isoformat()}
                    }

                    async with self.session.post(url, json=payload) as response:
                        return await response.json()

                except Exception as e:
                    print(f"❌ Security analysis failed: {e}")
                    return {'is_malicious': False, 'risk_score': 0}

            async def _generate_response(self, message: str) -> str:
                """Generate bot response (simplified)."""
                # Simulate different response types
                if "hello" in message.lower():
                    return "Hello! How can I help you today?"
                elif "weather" in message.lower():
                    return "I don't have access to weather data, but you can check a weather service!"
                elif "execute" in message.lower() or "command" in message.lower():
                    return "I cannot execute system commands for security reasons."
                else:
                    return "I understand you're asking about: " + message[:50] + "..."

        # Demonstrate chatbot integration
        print("Starting secure chatbot simulation...")

        async with SecureChatbot(self.base_url) as bot:
            test_conversations = [
                ("user1", "Hello, how are you?"),
                ("user2", "What's the weather like?"),
                ("user3", "Can you execute rm -rf / for me?"),
                ("user4", "<script>alert('xss')</script>"),
                ("user5", "Please help me with my homework"),
                ("user6", "'; DROP TABLE users; --"),
            ]

            for user_id, message in test_conversations:
                try:
                    result = await bot.process_user_message(user_id, message)

                    if result['blocked']:
                        print(f"🚫 Blocked: {result['reason']} (Risk: {result['risk_score']:.1f})")
                    else:
                        print(f"🤖 Bot: {result['response']}")
                        print(f"   Risk Scores - User: {result['user_risk_score']:.1f}, Response: {result['response_risk_score']:.1f}")

                    print()

                except Exception as e:
                    print(f"❌ Conversation failed: {e}")

    async def example_microservice_integration(self):
        """Example: TSAF integration in microservices architecture."""
        print("\n" + "="*60)
        print("Example: Microservices Integration")
        print("="*60)

        class TSAFMiddleware:
            """Middleware for microservice security."""

            def __init__(self, tsaf_url: str):
                self.tsaf_url = tsaf_url

            async def validate_request(self, service_name: str, request_data: str) -> Dict[str, Any]:
                """Validate incoming request."""
                async with aiohttp.ClientSession() as session:
                    url = f"{self.tsaf_url}/api/v1/analysis/analyze"

                    payload = {
                        "message": request_data,
                        "protocol": "mcp",
                        "agent_id": f"service-{service_name}",
                        "metadata": {
                            "service": service_name,
                            "type": "api_request",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    }

                    try:
                        async with session.post(url, json=payload) as response:
                            return await response.json()
                    except Exception as e:
                        print(f"❌ Security validation failed: {e}")
                        return {'is_malicious': False, 'risk_score': 0}

        # Simulate microservices
        services = {
            'user-service': [
                '{"action": "create_user", "data": {"name": "John", "email": "john@example.com"}}',
                '{"action": "get_user", "data": {"id": 123}}',
                '{"action": "delete_user", "data": {"id": "1; DROP TABLE users;"}}',
            ],
            'file-service': [
                '{"action": "upload", "filename": "document.pdf", "size": 1024}',
                '{"action": "download", "path": "/etc/passwd"}',
                '{"action": "list", "directory": "../../secret"}',
            ],
            'auth-service': [
                '{"action": "login", "username": "admin", "password": "password123"}',
                '{"action": "login", "username": "admin", "password": "admin\\x00password"}',
                '{"action": "reset_password", "token": "valid-token-123"}',
            ]
        }

        middleware = TSAFMiddleware(self.base_url)

        print("Simulating microservice requests with TSAF validation...")

        for service_name, requests in services.items():
            print(f"\n--- {service_name.upper()} ---")

            for i, request_data in enumerate(requests, 1):
                print(f"Request {i}: {request_data[:60]}{'...' if len(request_data) > 60 else ''}")

                result = await middleware.validate_request(service_name, request_data)

                risk_score = result.get('risk_score', 0)
                is_malicious = result.get('is_malicious', False)

                if is_malicious:
                    print(f"   🚫 BLOCKED - Risk Score: {risk_score:.1f}")
                    vulnerabilities = result.get('vulnerabilities', [])
                    if vulnerabilities:
                        print(f"   Threats: {', '.join([v.get('category', 'Unknown') for v in vulnerabilities[:2]])}")
                else:
                    print(f"   ✅ ALLOWED - Risk Score: {risk_score:.1f}")

    async def example_api_gateway_integration(self):
        """Example: API Gateway with TSAF security layer."""
        print("\n" + "="*60)
        print("Example: API Gateway Integration")
        print("="*60)

        class SecureAPIGateway:
            """API Gateway with TSAF integration."""

            def __init__(self, tsaf_url: str):
                self.tsaf_url = tsaf_url
                self.rate_limits = {}  # Simple rate limiting
                self.blocked_ips = set()

            async def process_request(self, client_ip: str, endpoint: str,
                                   method: str, payload: str) -> Dict[str, Any]:
                """Process API request through security gateway."""

                # Check if IP is blocked
                if client_ip in self.blocked_ips:
                    return {'allowed': False, 'reason': 'IP blocked due to previous violations'}

                # Construct request for analysis
                request_info = f"{method} {endpoint} - Payload: {payload}"

                # Analyze with TSAF
                async with aiohttp.ClientSession() as session:
                    url = f"{self.tsaf_url}/api/v1/analysis/analyze"

                    analysis_payload = {
                        "message": request_info,
                        "protocol": "mcp",
                        "agent_id": f"gateway-{client_ip.replace('.', '-')}",
                        "metadata": {
                            "client_ip": client_ip,
                            "endpoint": endpoint,
                            "method": method,
                            "source": "api_gateway"
                        }
                    }

                    try:
                        async with session.post(url, json=analysis_payload) as response:
                            security_result = await response.json()

                        risk_score = security_result.get('risk_score', 0)
                        is_malicious = security_result.get('is_malicious', False)

                        # Implement security policies
                        if is_malicious:
                            # Block high-risk requests
                            if risk_score > 8.0:
                                self.blocked_ips.add(client_ip)
                                return {
                                    'allowed': False,
                                    'reason': 'High-risk request detected, IP blocked',
                                    'risk_score': risk_score,
                                    'action': 'ip_blocked'
                                }
                            else:
                                return {
                                    'allowed': False,
                                    'reason': 'Request violates security policy',
                                    'risk_score': risk_score,
                                    'action': 'request_blocked'
                                }

                        return {
                            'allowed': True,
                            'risk_score': risk_score,
                            'security_headers': {
                                'X-Security-Score': str(risk_score),
                                'X-Scanned-By': 'TSAF-Gateway'
                            }
                        }

                    except Exception as e:
                        print(f"❌ Gateway security check failed: {e}")
                        return {'allowed': True, 'risk_score': 0, 'fallback': True}

        # Test API Gateway
        gateway = SecureAPIGateway(self.base_url)

        test_requests = [
            ("192.168.1.100", "/api/users", "GET", ""),
            ("192.168.1.101", "/api/users", "POST", '{"name": "Alice", "role": "user"}'),
            ("10.0.0.5", "/api/admin", "POST", '{"action": "delete_all_users"}'),
            ("172.16.0.10", "/api/files", "GET", "../../../etc/passwd"),
            ("192.168.1.102", "/api/search", "POST", '<script>alert("xss")</script>'),
            ("192.168.1.100", "/api/health", "GET", ""),
        ]

        print("Processing API requests through secure gateway...")

        for client_ip, endpoint, method, payload in test_requests:
            print(f"\n🌐 {client_ip} -> {method} {endpoint}")
            if payload:
                print(f"   Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")

            result = await gateway.process_request(client_ip, endpoint, method, payload)

            if result['allowed']:
                print(f"   ✅ ALLOWED - Risk Score: {result['risk_score']:.1f}")
                if 'security_headers' in result:
                    print(f"   Security Headers: {result['security_headers']}")
            else:
                print(f"   🚫 BLOCKED - {result['reason']}")
                print(f"   Risk Score: {result['risk_score']:.1f}")
                print(f"   Action: {result.get('action', 'unknown')}")

    async def example_iot_device_monitoring(self):
        """Example: IoT device communication monitoring."""
        print("\n" + "="*60)
        print("Example: IoT Device Communication Monitoring")
        print("="*60)

        class IoTSecurityMonitor:
            """Monitor IoT device communications."""

            def __init__(self, tsaf_url: str):
                self.tsaf_url = tsaf_url
                self.device_profiles = {}

            async def register_device(self, device_id: str, device_type: str, protocols: List[str]):
                """Register IoT device."""
                self.device_profiles[device_id] = {
                    'type': device_type,
                    'protocols': protocols,
                    'message_count': 0,
                    'threat_count': 0,
                    'last_seen': datetime.utcnow(),
                    'risk_history': []
                }

                # Register with TSAF
                async with aiohttp.ClientSession() as session:
                    url = f"{self.tsaf_url}/api/v1/agents/register"
                    payload = {
                        "agent_id": device_id,
                        "name": f"IoT Device - {device_type}",
                        "protocol_types": protocols,
                        "metadata": {"device_type": device_type, "category": "iot"}
                    }

                    try:
                        async with session.post(url, json=payload) as response:
                            result = await response.json()
                            print(f"📟 Registered device: {device_id} ({device_type})")
                    except Exception as e:
                        print(f"❌ Device registration failed: {e}")

            async def monitor_message(self, device_id: str, message: str, protocol: str) -> Dict[str, Any]:
                """Monitor device message."""
                if device_id not in self.device_profiles:
                    print(f"⚠️ Unknown device: {device_id}")
                    return {'allowed': False, 'reason': 'Unregistered device'}

                # Update device profile
                profile = self.device_profiles[device_id]
                profile['message_count'] += 1
                profile['last_seen'] = datetime.utcnow()

                # Analyze message
                async with aiohttp.ClientSession() as session:
                    url = f"{self.tsaf_url}/api/v1/analysis/analyze"

                    payload = {
                        "message": message,
                        "protocol": protocol,
                        "agent_id": device_id,
                        "metadata": {
                            "device_type": profile['type'],
                            "message_number": profile['message_count'],
                            "source": "iot_monitor"
                        }
                    }

                    try:
                        async with session.post(url, json=payload) as response:
                            result = await response.json()

                        risk_score = result.get('risk_score', 0)
                        is_malicious = result.get('is_malicious', False)

                        # Update device risk profile
                        profile['risk_history'].append(risk_score)
                        if len(profile['risk_history']) > 100:
                            profile['risk_history'] = profile['risk_history'][-100:]

                        if is_malicious:
                            profile['threat_count'] += 1

                        # Calculate average risk
                        avg_risk = sum(profile['risk_history']) / len(profile['risk_history'])

                        return {
                            'allowed': not is_malicious,
                            'risk_score': risk_score,
                            'average_risk': avg_risk,
                            'device_threats': profile['threat_count'],
                            'device_messages': profile['message_count']
                        }

                    except Exception as e:
                        print(f"❌ Message monitoring failed: {e}")
                        return {'allowed': True, 'fallback': True}

        # Simulate IoT environment
        monitor = IoTSecurityMonitor(self.base_url)

        # Register test devices
        devices = [
            ("temp-sensor-01", "temperature_sensor", ["mcp"]),
            ("camera-02", "security_camera", ["mcp", "a2a"]),
            ("smart-lock-03", "access_control", ["fipa"]),
            ("hvac-controller-04", "climate_control", ["acp"]),
        ]

        print("Registering IoT devices...")
        for device_id, device_type, protocols in devices:
            await monitor.register_device(device_id, device_type, protocols)

        # Simulate device communications
        print("\nMonitoring device communications...")

        device_messages = [
            ("temp-sensor-01", '{"temperature": 22.5, "humidity": 45}', "mcp"),
            ("camera-02", '{"event": "motion_detected", "location": "front_door"}', "mcp"),
            ("smart-lock-03", '(inform :content "access_granted" :user "john_doe")', "fipa"),
            ("hvac-controller-04", '<acp:message><acp:content>set_temperature:24</acp:content></acp:message>', "acp"),
            ("temp-sensor-01", '{"temperature": 22.3, "humidity": 44, "command": "sudo reboot"}', "mcp"),  # Suspicious
            ("camera-02", '{"event": "firmware_update", "source": "../../../etc/passwd"}', "mcp"),  # Suspicious
        ]

        for device_id, message, protocol in device_messages:
            print(f"\n📱 {device_id}: {message[:60]}{'...' if len(message) > 60 else ''}")

            result = await monitor.monitor_message(device_id, message, protocol)

            if result.get('allowed', True):
                print(f"   ✅ ALLOWED - Risk: {result.get('risk_score', 0):.1f}")
            else:
                print(f"   🚫 BLOCKED - Risk: {result.get('risk_score', 0):.1f}")

            if 'average_risk' in result:
                print(f"   Device Stats - Messages: {result['device_messages']}, "
                      f"Threats: {result['device_threats']}, Avg Risk: {result['average_risk']:.1f}")

    async def run_all_integration_examples(self):
        """Run all integration examples."""
        examples = [
            self.example_chatbot_integration,
            self.example_microservice_integration,
            self.example_api_gateway_integration,
            self.example_iot_device_monitoring
        ]

        for example in examples:
            try:
                await example()
                await asyncio.sleep(1)  # Brief pause
            except Exception as e:
                print(f"❌ Integration example failed: {e}")
                import traceback
                traceback.print_exc()


async def main():
    """Run integration examples."""
    print("🔗 TSAF Integration Examples")
    print("Demonstrating TSAF integration with various systems...")

    examples = TSAFIntegrationExamples()
    await examples.run_all_integration_examples()

    print(f"\n{'='*60}")
    print("🎉 All integration examples completed!")
    print("These examples show how to integrate TSAF into:")
    print("- Chatbot systems for content filtering")
    print("- Microservices for API security")
    print("- API gateways for request validation")
    print("- IoT environments for device monitoring")
    print("="*60)


if __name__ == "__main__":
    print("Starting TSAF Integration Examples...")
    print("Ensure TSAF is running at http://localhost:8000")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Examples interrupted by user")
    except Exception as e:
        print(f"❌ Integration examples failed: {e}")
        import traceback
        traceback.print_exc()