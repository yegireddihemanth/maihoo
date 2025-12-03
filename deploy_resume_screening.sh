#!/bin/bash

# ============================================
# BGV System with Resume Screening - AWS Deployment Script
# ============================================

set -e  # Exit on error

echo "============================================"
echo "BGV Resume Screening Deployment Script"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if running on Ubuntu
if [ ! -f /etc/lsb-release ]; then
    print_error "This script is designed for Ubuntu. Exiting."
    exit 1
fi

print_success "Running on Ubuntu"

# Update system packages
echo ""
print_info "Updating system packages..."
sudo apt update -y
sudo apt upgrade -y
print_success "System packages updated"

# Install Python 3.10+
echo ""
print_info "Installing Python 3.10+..."
sudo apt install python3.10 python3.10-venv python3-pip -y
print_success "Python installed: $(python3 --version)"

# Install system dependencies
echo ""
print_info "Installing system dependencies..."
sudo apt install tesseract-ocr poppler-utils libjpeg-dev zlib1g-dev -y
print_success "System dependencies installed"

# Create project directory if not exists
PROJECT_DIR="/home/ubuntu/bgv-system"
if [ ! -d "$PROJECT_DIR" ]; then
    print_warning "Project directory not found. Please upload your project files first."
    exit 1
fi

cd $PROJECT_DIR
print_success "Changed to project directory: $PROJECT_DIR"

# Create virtual environment
echo ""
print_info "Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
echo ""
print_info "Upgrading pip..."
pip install --upgrade pip
print_success "Pip upgraded"

# Install Python dependencies
echo ""
print_info "Installing Python dependencies from requirements.txt..."
pip install -r requirements.txt
print_success "Python dependencies installed"

# Verify critical packages
echo ""
print_info "Verifying critical packages..."
python -c "import openai; print('OpenAI version:', openai.__version__)" && print_success "OpenAI installed"
python -c "import numpy; print('NumPy version:', numpy.__version__)" && print_success "NumPy installed"
python -c "import fastapi; print('FastAPI version:', fastapi.__version__)" && print_success "FastAPI installed"

# Check .env file
echo ""
if [ ! -f ".env" ]; then
    print_error ".env file not found!"
    print_info "Please create .env file with required configuration"
    print_info "See AWS_DEPLOYMENT_RESUME_SCREENING.md for details"
    exit 1
else
    print_success ".env file found"
    
    # Check for OpenAI API key
    if grep -q "OPENAI_API_KEY=sk-" .env; then
        print_success "OpenAI API key configured"
    else
        print_error "OpenAI API key not found in .env!"
        print_info "Resume screening requires OPENAI_API_KEY"
        exit 1
    fi
fi

# Secure .env file
chmod 600 .env
print_success ".env file secured (chmod 600)"

# Create systemd service
echo ""
print_info "Creating systemd service..."
sudo tee /etc/systemd/system/bgv-app.service > /dev/null <<EOF
[Unit]
Description=BGV Application with Resume Screening
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin"
ExecStart=$PROJECT_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port 5001 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
print_success "Systemd service created"

# Reload systemd
sudo systemctl daemon-reload
print_success "Systemd reloaded"

# Enable and start service
sudo systemctl enable bgv-app
sudo systemctl start bgv-app
print_success "BGV application service enabled and started"

# Check service status
sleep 3
if sudo systemctl is-active --quiet bgv-app; then
    print_success "BGV application is running"
else
    print_error "BGV application failed to start"
    print_info "Check logs with: sudo journalctl -u bgv-app -n 50"
    exit 1
fi

# Install Nginx
echo ""
print_info "Installing Nginx..."
sudo apt install nginx -y
print_success "Nginx installed"

# Create Nginx configuration
echo ""
print_info "Configuring Nginx..."
read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME

sudo tee /etc/nginx/sites-available/bgv-app > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    # Increase upload size for resume files
    client_max_body_size 100M;

    location / {
        proxy_pass http://localhost:5001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Increase timeout for resume processing
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
}
EOF
print_success "Nginx configuration created"

# Enable site
sudo ln -sf /etc/nginx/sites-available/bgv-app /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
print_success "Nginx site enabled"

# Test Nginx configuration
if sudo nginx -t; then
    print_success "Nginx configuration is valid"
else
    print_error "Nginx configuration has errors"
    exit 1
fi

# Restart Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
print_success "Nginx restarted and enabled"

# Install Certbot for SSL
echo ""
read -p "Do you want to setup SSL with Let's Encrypt? (y/n): " SETUP_SSL

if [ "$SETUP_SSL" = "y" ] || [ "$SETUP_SSL" = "Y" ]; then
    print_info "Installing Certbot..."
    sudo apt install certbot python3-certbot-nginx -y
    print_success "Certbot installed"
    
    print_info "Obtaining SSL certificate..."
    print_warning "Make sure your domain DNS is pointing to this server!"
    read -p "Press Enter to continue..."
    
    sudo certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME
    
    if [ $? -eq 0 ]; then
        print_success "SSL certificate obtained successfully"
    else
        print_error "Failed to obtain SSL certificate"
        print_info "You can run 'sudo certbot --nginx' manually later"
    fi
else
    print_warning "Skipping SSL setup. You can run 'sudo certbot --nginx' later"
fi

# Final status check
echo ""
echo "============================================"
echo "Deployment Summary"
echo "============================================"
echo ""

# Check application status
if sudo systemctl is-active --quiet bgv-app; then
    print_success "BGV Application: Running"
else
    print_error "BGV Application: Not Running"
fi

# Check Nginx status
if sudo systemctl is-active --quiet nginx; then
    print_success "Nginx: Running"
else
    print_error "Nginx: Not Running"
fi

# Display access information
echo ""
echo "============================================"
echo "Access Information"
echo "============================================"
if [ "$SETUP_SSL" = "y" ] || [ "$SETUP_SSL" = "Y" ]; then
    echo "Application URL: https://$DOMAIN_NAME"
    echo "API Documentation: https://$DOMAIN_NAME/docs"
else
    echo "Application URL: http://$DOMAIN_NAME"
    echo "API Documentation: http://$DOMAIN_NAME/docs"
fi
echo ""
echo "Resume Screening Endpoints:"
echo "  - Basic: POST /secure/ai_resume_screening"
echo "  - Enhanced: POST /secure/ai_resume_screening_enhanced"
echo ""

# Display useful commands
echo "============================================"
echo "Useful Commands"
echo "============================================"
echo "View logs:           sudo journalctl -u bgv-app -f"
echo "Restart app:         sudo systemctl restart bgv-app"
echo "Check status:        sudo systemctl status bgv-app"
echo "Restart Nginx:       sudo systemctl restart nginx"
echo "Test Nginx config:   sudo nginx -t"
echo ""

print_success "Deployment completed successfully!"
echo ""
print_info "Next steps:"
echo "  1. Test the application endpoints"
echo "  2. Upload sample resumes for testing"
echo "  3. Monitor logs for any errors"
echo "  4. Setup OpenAI usage monitoring"
echo ""
print_warning "Remember to monitor OpenAI API costs!"
echo ""
