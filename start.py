#!/usr/bin/env python3
"""
TSAF Startup Script
Convenient script to start the TSAF application with various options.
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path


def main():
    """Main startup function."""
    parser = argparse.ArgumentParser(description="Start TSAF Application")

    parser.add_argument("--mode", choices=["dev", "prod", "docker"], default="dev",
                       help="Deployment mode (default: dev)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    parser.add_argument("--config", help="Configuration file path")

    args = parser.parse_args()

    # Set up environment
    if args.config:
        os.environ["TSAF_CONFIG_FILE"] = args.config

    # Ensure we're in the right directory
    os.chdir(Path(__file__).parent)

    if args.mode == "docker":
        start_docker()
    elif args.mode == "prod":
        start_production(args)
    else:
        start_development(args)


def start_development(args):
    """Start in development mode."""
    print("🚀 Starting TSAF in development mode...")

    # Set development environment
    os.environ["TSAF_ENV"] = "development"

    cmd = [
        sys.executable, "-m", "uvicorn",
        "tsaf.main:app",
        "--host", args.host,
        "--port", str(args.port),
        "--log-level", "info"
    ]

    if args.reload:
        cmd.append("--reload")

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n👋 TSAF application stopped")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start TSAF: {e}")
        sys.exit(1)


def start_production(args):
    """Start in production mode."""
    print("🚀 Starting TSAF in production mode...")

    # Set production environment
    os.environ["TSAF_ENV"] = "production"

    cmd = [
        sys.executable, "-m", "gunicorn",
        "tsaf.main:app",
        "-w", str(args.workers),
        "-k", "uvicorn.workers.UvicornWorker",
        "-b", f"{args.host}:{args.port}",
        "--log-level", "info",
        "--access-logfile", "-",
        "--error-logfile", "-"
    ]

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n👋 TSAF application stopped")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start TSAF: {e}")
        sys.exit(1)


def start_docker():
    """Start using Docker Compose."""
    print("🐳 Starting TSAF with Docker Compose...")

    # Check if Docker Compose is available
    try:
        subprocess.run(["docker-compose", "--version"],
                      check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker Compose not found. Please install Docker Compose.")
        sys.exit(1)

    # Start services
    try:
        subprocess.run(["docker-compose", "up", "-d"], check=True)
        print("✅ TSAF services started successfully")
        print("📖 API Documentation: http://localhost:8000/docs")
        print("📊 Monitoring: http://localhost:3000 (Grafana)")
        print("📈 Metrics: http://localhost:9090 (Prometheus)")
        print("\n🔍 To view logs: docker-compose logs -f")
        print("🛑 To stop: docker-compose down")

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start TSAF with Docker: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()