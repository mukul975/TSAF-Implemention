#!/bin/bash

# TSAF Setup Script
# Sets up virtual environment and installs all dependencies

echo "🚀 TSAF - Translation Security Analysis Framework"
echo "=" * 50
echo "Setting up virtual environment and dependencies..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}❌ Error: requirements.txt not found. Please run this script from the TSAF project directory.${NC}"
    exit 1
fi

echo -e "${BLUE}📁 Current directory: $(pwd)${NC}"
echo ""

# Step 1: Create virtual environment
echo -e "${YELLOW}🔧 Step 1: Creating virtual environment...${NC}"
if [ -d "tsaf-venv" ]; then
    echo -e "${GREEN}✅ Virtual environment already exists${NC}"
else
    python3 -m venv tsaf-venv
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Virtual environment created successfully${NC}"
    else
        echo -e "${RED}❌ Failed to create virtual environment${NC}"
        exit 1
    fi
fi
echo ""

# Step 2: Activate virtual environment
echo -e "${YELLOW}🔧 Step 2: Activating virtual environment...${NC}"
source tsaf-venv/bin/activate
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Virtual environment activated${NC}"
    echo -e "${BLUE}📍 Using Python: $(which python)${NC}"
    echo -e "${BLUE}📍 Python version: $(python --version)${NC}"
else
    echo -e "${RED}❌ Failed to activate virtual environment${NC}"
    exit 1
fi
echo ""

# Step 3: Upgrade pip
echo -e "${YELLOW}🔧 Step 3: Upgrading pip...${NC}"
python -m pip install --upgrade pip
echo -e "${GREEN}✅ pip upgraded${NC}"
echo ""

# Step 4: Install core dependencies
echo -e "${YELLOW}🔧 Step 4: Installing core dependencies...${NC}"
python -m pip install fastapi uvicorn[standard] sqlalchemy structlog pydantic
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Core dependencies installed${NC}"
else
    echo -e "${RED}❌ Failed to install core dependencies${NC}"
    exit 1
fi
echo ""

# Step 5: Install ML dependencies (optional)
echo -e "${YELLOW}🔧 Step 5: Installing ML dependencies (this may take a few minutes)...${NC}"
python -m pip install torch transformers scikit-learn numpy
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ ML dependencies installed${NC}"
else
    echo -e "${YELLOW}⚠️ ML dependencies failed - TSAF will run without ML features${NC}"
fi
echo ""

# Step 6: Install remaining requirements
echo -e "${YELLOW}🔧 Step 6: Installing remaining requirements...${NC}"
python -m pip install -r requirements.txt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ All requirements installed${NC}"
else
    echo -e "${YELLOW}⚠️ Some requirements may have failed - check output above${NC}"
fi
echo ""

# Step 7: Create models directory
echo -e "${YELLOW}🔧 Step 7: Creating models directory...${NC}"
mkdir -p models
echo -e "${GREEN}✅ Models directory created${NC}"
echo ""

# Step 8: Test TSAF installation
echo -e "${YELLOW}🔧 Step 8: Testing TSAF installation...${NC}"
export PYTHONPATH=src
python -c "
try:
    from tsaf.main import app
    print('✅ TSAF imported successfully!')
    print('🎉 Installation completed successfully!')
    print('')
    print('📋 Next steps:')
    print('   1. Activate virtual environment: source tsaf-venv/bin/activate')
    print('   2. Run TSAF: PYTHONPATH=src python start.py')
    print('   3. Visit: http://localhost:8000')
    print('   4. API docs: http://localhost:8000/docs')
except ImportError as e:
    print(f'❌ Import failed: {e}')
    print('⚠️ Installation may be incomplete')
"
echo ""

# Final instructions
echo -e "${BLUE}🎯 TSAF Setup Complete!${NC}"
echo ""
echo -e "${GREEN}To run TSAF:${NC}"
echo -e "${BLUE}  1. Activate virtual environment:${NC}"
echo -e "     source tsaf-venv/bin/activate"
echo ""
echo -e "${BLUE}  2. Start TSAF server:${NC}"
echo -e "     PYTHONPATH=src python start.py"
echo ""
echo -e "${BLUE}  3. Access TSAF:${NC}"
echo -e "     • Main API: http://localhost:8000"
echo -e "     • Documentation: http://localhost:8000/docs"
echo -e "     • Health Check: http://localhost:8000/health"
echo ""
echo -e "${GREEN}🛡️ TSAF is ready for security analysis!${NC}"