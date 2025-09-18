#!/bin/bash
set -e

# TSAF Docker Entrypoint Script
echo "🚀 Starting TSAF Application"

# Wait for database to be ready
if [ "$DATABASE__DATABASE_URL" ]; then
    echo "⏳ Waiting for database to be ready..."

    # Extract database connection details
    DB_HOST=$(echo $DATABASE__DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
    DB_PORT=$(echo $DATABASE__DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')

    if [ "$DB_HOST" ] && [ "$DB_PORT" ]; then
        echo "🔍 Checking database connectivity: $DB_HOST:$DB_PORT"

        # Wait for database to be available
        timeout 60 bash -c "
            until nc -z $DB_HOST $DB_PORT; do
                echo 'Database not ready, waiting...'
                sleep 2
            done
        " || {
            echo "❌ Database connection timeout"
            exit 1
        }

        echo "✅ Database is ready"
    fi
fi

# Run database migrations if enabled
if [ "${TSAF_RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "🔄 Running database migrations..."
    python -c "
import asyncio
from tsaf.database.connection import initialize_database_manager
from tsaf.core.config import load_config

async def run_migrations():
    config = load_config()
    db_manager = initialize_database_manager(config.database)
    await db_manager.initialize()
    print('✅ Database migrations completed')

asyncio.run(run_migrations())
" || {
        echo "❌ Database migration failed"
        exit 1
    }
fi

# Initialize application data directories
echo "📁 Initializing application directories..."
mkdir -p /app/data/{patterns,signatures,rules,models,cache}
mkdir -p /app/logs

# Set proper permissions
chmod 755 /app/data /app/logs
chmod -R 644 /app/data/* 2>/dev/null || true
chmod -R 644 /app/logs/* 2>/dev/null || true

# Download ML models if needed
if [ "${TSAF_DOWNLOAD_MODELS:-false}" = "true" ]; then
    echo "📦 Downloading ML models..."
    python -c "
try:
    from transformers import AutoTokenizer, AutoModel
    model_name = 'bert-base-uncased'
    print(f'Downloading {model_name}...')
    tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir='/app/models')
    model = AutoModel.from_pretrained(model_name, cache_dir='/app/models')
    print('✅ Models downloaded successfully')
except Exception as e:
    print(f'⚠️ Model download failed: {e}')
    print('Application will continue without ML models')
"
fi

# Validate configuration
echo "🔧 Validating configuration..."
python -c "
from tsaf.core.config import load_config
try:
    config = load_config()
    print(f'✅ Configuration loaded successfully')
    print(f'   Environment: {config.environment}')
    print(f'   Database: {config.database.database_url.split(\"@\")[-1] if \"@\" in config.database.database_url else \"SQLite\"}')
    print(f'   Server: {config.server.host}:{config.server.port}')
except Exception as e:
    print(f'❌ Configuration validation failed: {e}')
    exit(1)
"

# Pre-flight checks
echo "🔍 Running pre-flight checks..."
python -c "
import sys
import importlib

# Check required modules
required_modules = ['fastapi', 'uvicorn', 'sqlalchemy', 'structlog', 'pydantic']
missing_modules = []

for module in required_modules:
    try:
        importlib.import_module(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print(f'❌ Missing required modules: {missing_modules}')
    sys.exit(1)

print('✅ All required modules available')
"

# Display startup information
echo "📊 TSAF Application Info:"
echo "   Version: $(python -c "import tsaf; print(tsaf.__version__)" 2>/dev/null || echo "1.0.0")"
echo "   Python: $(python --version)"
echo "   Environment: ${TSAF_ENV:-development}"
echo "   Workers: ${TSAF_WORKERS:-1}"
echo "   Debug: ${TSAF_DEBUG:-false}"

# Set default values for production
export TSAF_ENV=${TSAF_ENV:-production}
export TSAF_WORKERS=${TSAF_WORKERS:-1}

# Start the application
echo "🚀 Starting TSAF application..."
echo "================================================"

# Execute the command passed to docker run
exec "$@"