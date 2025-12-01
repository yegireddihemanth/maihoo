#!/bin/bash

# ============================================
# BGV Application Deployment Script for AWS EC2
# ============================================

set -e  # Exit on error

echo "🚀 Starting BGV Application Deployment..."

# ============================================
# Configuration
# ============================================
APP_DIR="/home/ubuntu/bgv-app"
SERVICE_NAME="bgv-app"
PYTHON_BIN="/usr/bin/python3"
PIP_BIN="/usr/bin/pip3"

# ============================================
# Step 1: Update system packages
# ============================================
echo "📦 Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# ============================================
# Step 2: Install Python and dependencies
# ============================================
echo "🐍 Installing Python and pip..."
sudo apt-get install -y python3 python3-pip python3-venv

# ============================================
# Step 3: Install AWS CLI (if not installed)
# ============================================
if ! command -v aws &> /dev/null; then
    echo "📥 Installing AWS CLI..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
else
    echo "✅ AWS CLI already installed"
fi

# ============================================
# Step 4: Create application directory
# ============================================
echo "📁 Setting up application directory..."
sudo mkdir -p $APP_DIR
sudo chown ubuntu:ubuntu $APP_DIR
cd $APP_DIR

# ============================================
# Step 5: Clone or update repository
# ============================================
echo "📥 Fetching application code..."
if [ -d ".git" ]; then
    echo "Updating existing repository..."
    git pull origin main
else
    echo "Cloning repository..."
    # Replace with your actual repository URL
    git clone https://github.com/your-username/bgv-app.git .
fi

# ============================================
# Step 6: Install Python dependencies
# ============================================
echo "📦 Installing Python dependencies..."
$PIP_BIN install --upgrade pip
$PIP_BIN install -r requirements.txt

# ============================================
# Step 7: Install boto3 for AWS Secrets Manager
# ============================================
echo "🔐 Installing AWS SDK..."
$PIP_BIN install boto3

# ============================================
# Step 8: Test AWS Secrets Manager access
# ============================================
echo "🧪 Testing AWS Secrets Manager access..."
if aws secretsmanager get-secret-value --secret-id bgv-app/production --region us-east-1 > /dev/null 2>&1; then
    echo "✅ AWS Secrets Manager access confirmed"
else
    echo "⚠️ WARNING: Cannot access AWS Secrets Manager"
    echo "Make sure IAM role is attached to EC2 instance"
fi

# ============================================
# Step 9: Create systemd service file
# ============================================
echo "⚙️ Creating systemd service..."
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null <<EOF
[Unit]
Description=BGV Application
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=$APP_DIR
Environment="AWS_REGION=us-east-1"
Environment="SECRET_NAME=bgv-app/production"
Environment="USE_AWS_SECRETS=true"
Environment="PYTHONUNBUFFERED=1"
Environment="ENVIRONMENT=production"
ExecStart=$PYTHON_BIN $APP_DIR/main.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/$SERVICE_NAME.log
StandardError=append:/var/log/$SERVICE_NAME-error.log

[Install]
WantedBy=multi-user.target
EOF

# ============================================
# Step 10: Create log files
# ============================================
echo "📝 Setting up logging..."
sudo touch /var/log/$SERVICE_NAME.log
sudo touch /var/log/$SERVICE_NAME-error.log
sudo chown ubuntu:ubuntu /var/log/$SERVICE_NAME.log
sudo chown ubuntu:ubuntu /var/log/$SERVICE_NAME-error.log

# ============================================
# Step 11: Reload systemd and start service
# ============================================
echo "🔄 Reloading systemd..."
sudo systemctl daemon-reload

echo "🚀 Starting application..."
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

# ============================================
# Step 12: Check service status
# ============================================
echo ""
echo "============================================"
echo "📊 Service Status:"
echo "============================================"
sudo systemctl status $SERVICE_NAME --no-pager

echo ""
echo "============================================"
echo "📝 Recent Logs:"
echo "============================================"
sudo tail -n 20 /var/log/$SERVICE_NAME.log

echo ""
echo "============================================"
echo "✅ Deployment Complete!"
echo "============================================"
echo ""
echo "Useful commands:"
echo "  View logs:        sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart service:  sudo systemctl restart $SERVICE_NAME"
echo "  Stop service:     sudo systemctl stop $SERVICE_NAME"
echo "  Service status:   sudo systemctl status $SERVICE_NAME"
echo ""
