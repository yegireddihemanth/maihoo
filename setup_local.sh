#!/bin/bash

# ============================================
# Local Development Setup Script
# ============================================

set -e

echo "🚀 Setting up BGV Application for local development..."

# ============================================
# Step 1: Check Python version
# ============================================
echo "🐍 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.9 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python $PYTHON_VERSION found"

# ============================================
# Step 2: Create virtual environment
# ============================================
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
else
    echo "✅ Virtual environment already exists"
fi

# ============================================
# Step 3: Activate virtual environment
# ============================================
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# ============================================
# Step 4: Upgrade pip
# ============================================
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# ============================================
# Step 5: Install dependencies
# ============================================
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# ============================================
# Step 6: Install python-dotenv for .env support
# ============================================
echo "📝 Installing python-dotenv..."
pip install python-dotenv

# ============================================
# Step 7: Create .env file if it doesn't exist
# ============================================
if [ ! -f ".env" ]; then
    echo "📄 Creating .env file from template..."
    cp .env.example .env
    echo ""
    echo "⚠️ IMPORTANT: Edit .env file and add your actual API keys!"
    echo "   nano .env"
    echo ""
else
    echo "✅ .env file already exists"
fi

# ============================================
# Step 8: Check if Ollama is installed (for AI features)
# ============================================
if command -v ollama &> /dev/null; then
    echo "✅ Ollama is installed"
    echo "📥 Pulling required models..."
    ollama pull llama3.2 || echo "⚠️ Could not pull llama3.2"
    ollama pull nomic-embed-text || echo "⚠️ Could not pull nomic-embed-text"
else
    echo "⚠️ Ollama not found. Install from: https://ollama.com"
    echo "   AI features will not work without Ollama"
fi

# ============================================
# Step 9: Test configuration
# ============================================
echo ""
echo "🧪 Testing configuration..."
python3 -c "
from secrets_manager import secrets_manager
print('✅ Secrets manager loaded successfully')
is_valid, missing = secrets_manager.validate()
if not is_valid:
    print(f'⚠️ Missing secrets: {missing}')
    print('Please update your .env file')
" || echo "⚠️ Configuration test failed"

# ============================================
# Done!
# ============================================
echo ""
echo "============================================"
echo "✅ Setup Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Edit .env file with your API keys:"
echo "     nano .env"
echo ""
echo "  2. Activate virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  3. Run the application:"
echo "     python main.py"
echo ""
echo "  4. Access the API:"
echo "     http://localhost:8000"
echo ""
