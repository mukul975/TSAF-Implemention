#!/bin/bash

# TSAF Quick Run Script
# Activates virtual environment and runs TSAF

echo "🚀 Starting TSAF - Translation Security Analysis Framework"
echo ""

# Check if virtual environment exists
if [ ! -d "tsaf-venv" ]; then
    echo "❌ Virtual environment not found. Please run setup.sh first:"
    echo "   ./setup.sh"
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source tsaf-venv/bin/activate

# Set Python path
export PYTHONPATH=src

# Run TSAF
echo "🚀 Starting TSAF server..."
echo "📍 Server will be available at: http://localhost:8000"
echo "📖 API documentation at: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python start.py