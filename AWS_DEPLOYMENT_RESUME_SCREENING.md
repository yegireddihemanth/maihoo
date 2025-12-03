# AWS Deployment Guide - Resume Screening System

## 🚀 Deploying Resume Screening to AWS EC2

This guide covers deploying the enhanced BGV system with resume screening capabilities to AWS EC2.

---

## 📋 Prerequisites

### 1. AWS Account Setup
- AWS account with EC2 access
- EC2 instance running (Ubuntu 20.04 or later recommended)
- Security group configured (ports 80, 443, 5001 open)
- SSH key pair for instance access

### 2. Required API Keys
- ✅ OpenAI API key (REQUIRED for resume screening)
- ✅ AWS credentials (for S3 resume storage)
- ✅ Other API keys (Surepass, Google, etc.)

---

## 🔧 Step 1: Connect to EC2 Instance

```bash
# SSH into your EC2 instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Update system packages
sudo apt update
sudo apt upgrade -y
```

---

## 📦 Step 2: Install System Dependencies

```bash
# Install Python 3.10+
sudo apt install python3.10 python3.10-venv python3-pip -y

# Install Tesseract OCR (for education validation)
sudo apt install tesseract-ocr -y

# Install Poppler (for PDF processing)
sudo apt install poppler-utils -y

# Install system libraries for image processing
sudo apt install libjpeg-dev zlib1g-dev -y

# Verify installations
python3 --version
tesseract --version
pdftotext -v
```

---

## 📁 Step 3: Upload Project Files

### Option A: Using Git (Recommended)
```bash
# Clone your repository
cd /home/ubuntu
git clone https://github.com/your-repo/bgv-system.git
cd bgv-system
```

### Option B: Using SCP
```bash
# From your local machine
scp -i your-key.pem -r /path/to/project ubuntu@your-ec2-ip:/home/ubuntu/bgv-system
```

---

## 🐍 Step 4: Setup Python Environment

```bash
# Navigate to project directory
cd /home/ubuntu/bgv-system

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt

# Verify critical packages
python -c "import openai; print('OpenAI:', openai.__version__)"
python -c "import numpy; print('NumPy:', numpy.__version__)"
python -c "import fastapi; print('FastAPI:', fastapi.__version__)"
```

---

## 🔐 Step 5: Configure Environment Variables

```bash
# Create .env file
nano .env
```

Add the following (replace with your actual values):

```bash
# ============================================
# MongoDB Configuration
# ============================================
MONGO_URI=mongodb://your-mongo-uri
DB_NAME=bgv_database

# ============================================
# JWT Secret
# ============================================
JWT_SECRET=your-super-secret-jwt-key-change-this

# ============================================
# OpenAI API (REQUIRED for Resume Screening)
# ============================================
OPENAI_API_KEY=sk-your-openai-api-key-here

# ============================================
# AWS Configuration (for S3 Resume Storage)
# ============================================
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name

# ============================================
# Surepass API (for Verification)
# ============================================
SUREPASS_API_KEY=your-surepass-api-key
SUREPASS_BASE_URL=https://kyc-api.surepass.io

# ============================================
# Google OAuth (Optional)
# ============================================
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# ============================================
# Cloudinary (Optional)
# ============================================
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# ============================================
# Email Configuration (Optional)
# ============================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# ============================================
# Application Settings
# ============================================
ENVIRONMENT=production
DEBUG=False
ALLOWED_ORIGINS=https://your-domain.com,https://www.your-domain.com
```

Save and exit (Ctrl+X, Y, Enter)

```bash
# Secure the .env file
chmod 600 .env
```

---

## ✅ Step 6: Test the Application

```bash
# Activate virtual environment (if not already)
source venv/bin/activate

# Test run the application
python main.py

# Or with uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 5001
```

Open another terminal and test:
```bash
# Test basic health check
curl http://localhost:5001/

# Test resume screening endpoint (should return 401 without auth)
curl -X POST http://localhost:5001/secure/ai_resume_screening
```

If you see responses, the app is working! Press Ctrl+C to stop.

---

## 🔄 Step 7: Setup Systemd Service (Production)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/bgv-app.service
```

Add the following:

```ini
[Unit]
Description=BGV Application with Resume Screening
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/bgv-system
Environment="PATH=/home/ubuntu/bgv-system/venv/bin"
ExecStart=/home/ubuntu/bgv-system/venv/bin/uvicorn main:app --host 0.0.0.0 --port 5001 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Save and exit.

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable bgv-app

# Start the service
sudo systemctl start bgv-app

# Check status
sudo systemctl status bgv-app

# View logs
sudo journalctl -u bgv-app -f
```

---

## 🌐 Step 8: Setup Nginx Reverse Proxy

```bash
# Install Nginx
sudo apt install nginx -y

# Create Nginx configuration
sudo nano /etc/nginx/sites-available/bgv-app
```

Add the following:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # Increase upload size for resume files
    client_max_body_size 100M;

    location / {
        proxy_pass http://localhost:5001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeout for resume processing
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
}
```

Save and exit.

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/bgv-app /etc/nginx/sites-enabled/

# Remove default site
sudo rm /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx

# Enable Nginx to start on boot
sudo systemctl enable nginx
```

---

## 🔒 Step 9: Setup SSL with Let's Encrypt (HTTPS)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Follow the prompts:
# - Enter email address
# - Agree to terms
# - Choose to redirect HTTP to HTTPS (option 2)

# Test auto-renewal
sudo certbot renew --dry-run
```

---

## 🧪 Step 10: Test Resume Screening Endpoints

### Test Basic Screening
```bash
# Get JWT token first (login)
TOKEN=$(curl -X POST https://your-domain.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your-email@example.com","password":"your-password"}' \
  | jq -r '.token')

# Test basic resume screening
curl -X POST https://your-domain.com/secure/ai_resume_screening \
  -H "Authorization: Bearer $TOKEN" \
  -F "jd_file=@job_description.pdf" \
  -F "resume_files=@resume1.pdf" \
  -F "resume_files=@resume2.pdf" \
  -F "top_n=5"
```

### Test Enhanced Screening
```bash
curl -X POST https://your-domain.com/secure/ai_resume_screening_enhanced \
  -H "Authorization: Bearer $TOKEN" \
  -F "jd_file=@job_description.pdf" \
  -F "resume_files=@resume1.pdf" \
  -F "resume_files=@resume2.pdf" \
  -F "top_n=5" \
  -F "must_have_requirements=5+ years Python,AWS certification" \
  -F "nice_to_have=Docker,Kubernetes" \
  -F "min_embedding_score=0.5" \
  -F "embedding_weight=0.3" \
  -F "llm_weight=0.7"
```

---

## 📊 Step 11: Monitor Application

### View Application Logs
```bash
# Real-time logs
sudo journalctl -u bgv-app -f

# Last 100 lines
sudo journalctl -u bgv-app -n 100

# Logs from today
sudo journalctl -u bgv-app --since today
```

### View Nginx Logs
```bash
# Access logs
sudo tail -f /var/log/nginx/access.log

# Error logs
sudo tail -f /var/log/nginx/error.log
```

### Monitor System Resources
```bash
# CPU and Memory usage
htop

# Disk usage
df -h

# Check service status
sudo systemctl status bgv-app
sudo systemctl status nginx
```

---

## 🔧 Step 12: Performance Optimization

### Increase Uvicorn Workers
Edit the systemd service:
```bash
sudo nano /etc/systemd/system/bgv-app.service
```

Change workers based on CPU cores:
```ini
ExecStart=/home/ubuntu/bgv-system/venv/bin/uvicorn main:app --host 0.0.0.0 --port 5001 --workers 4
```

For 4 CPU cores, use 4 workers. For 8 cores, use 8 workers.

```bash
# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart bgv-app
```

### Configure Nginx Caching (Optional)
```bash
sudo nano /etc/nginx/nginx.conf
```

Add inside `http` block:
```nginx
# Cache configuration
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=1g inactive=60m;
```

---

## 💰 Step 13: Monitor OpenAI API Costs

### Setup Cost Alerts
1. Go to OpenAI Dashboard: https://platform.openai.com/usage
2. Set up usage alerts
3. Monitor daily/monthly spending

### Expected Costs
- **Basic Screening:** $0.007 per 100 resumes
- **Enhanced Screening:** $0.010 per 100 resumes
- **Monthly (1000 resumes):** ~$0.10
- **Annual (10,000 resumes):** ~$1.00

### Cost Optimization
```bash
# Monitor API usage in logs
sudo journalctl -u bgv-app | grep "OpenAI"

# Track number of screening requests
sudo journalctl -u bgv-app | grep "Resume Screening" | wc -l
```

---

## 🔄 Step 14: Update Application

When you need to update the code:

```bash
# SSH into EC2
ssh -i your-key.pem ubuntu@your-ec2-ip

# Navigate to project
cd /home/ubuntu/bgv-system

# Pull latest changes
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Update dependencies (if requirements.txt changed)
pip install -r requirements.txt --upgrade

# Restart application
sudo systemctl restart bgv-app

# Check status
sudo systemctl status bgv-app

# Monitor logs for errors
sudo journalctl -u bgv-app -f
```

---

## 🐛 Troubleshooting

### Issue: Application won't start
```bash
# Check logs
sudo journalctl -u bgv-app -n 50

# Common causes:
# 1. Missing .env file
# 2. Wrong Python path
# 3. Port already in use
# 4. Missing dependencies

# Test manually
cd /home/ubuntu/bgv-system
source venv/bin/activate
python main.py
```

### Issue: OpenAI API errors
```bash
# Verify API key
cat .env | grep OPENAI_API_KEY

# Test OpenAI connection
python -c "
import openai
import os
from dotenv import load_dotenv
load_dotenv()
client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
print('OpenAI connection successful!')
"
```

### Issue: Resume upload fails
```bash
# Check Nginx upload size
sudo nano /etc/nginx/sites-available/bgv-app

# Ensure this line exists:
client_max_body_size 100M;

# Restart Nginx
sudo systemctl restart nginx
```

### Issue: Slow resume processing
```bash
# Check CPU usage
htop

# Increase workers if CPU is underutilized
sudo nano /etc/systemd/system/bgv-app.service
# Change --workers 4 to --workers 8

sudo systemctl daemon-reload
sudo systemctl restart bgv-app
```

---

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] EC2 instance running (Ubuntu 20.04+)
- [ ] Security groups configured (ports 80, 443, 5001)
- [ ] Domain name pointed to EC2 IP
- [ ] OpenAI API key obtained
- [ ] AWS credentials configured
- [ ] All API keys ready

### Installation
- [ ] System packages installed
- [ ] Python 3.10+ installed
- [ ] Virtual environment created
- [ ] Dependencies installed from requirements.txt
- [ ] .env file configured with all keys

### Configuration
- [ ] Systemd service created and enabled
- [ ] Nginx installed and configured
- [ ] SSL certificate obtained (Let's Encrypt)
- [ ] Upload size limits increased
- [ ] Timeouts configured

### Testing
- [ ] Application starts successfully
- [ ] Basic endpoints respond
- [ ] Resume screening endpoints work
- [ ] File uploads work (up to 100 resumes)
- [ ] Authentication works
- [ ] HTTPS works

### Monitoring
- [ ] Application logs accessible
- [ ] Nginx logs accessible
- [ ] OpenAI usage monitoring setup
- [ ] Cost alerts configured
- [ ] System resource monitoring

---

## 🎯 Quick Commands Reference

```bash
# Start application
sudo systemctl start bgv-app

# Stop application
sudo systemctl stop bgv-app

# Restart application
sudo systemctl restart bgv-app

# View logs
sudo journalctl -u bgv-app -f

# Check status
sudo systemctl status bgv-app

# Restart Nginx
sudo systemctl restart nginx

# Test Nginx config
sudo nginx -t

# Renew SSL certificate
sudo certbot renew

# Update application
cd /home/ubuntu/bgv-system && git pull && sudo systemctl restart bgv-app
```

---

## ✅ Post-Deployment Verification

### 1. Test Basic Endpoints
```bash
# Health check
curl https://your-domain.com/

# Login
curl -X POST https://your-domain.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'
```

### 2. Test Resume Screening
- Upload 5 sample resumes via Postman
- Verify processing completes in 10-20 seconds
- Check results are accurate
- Verify OpenAI API calls in dashboard

### 3. Monitor Performance
- Check CPU usage (should be < 50% idle)
- Check memory usage (should have 20%+ free)
- Check disk space (should have 20%+ free)
- Monitor response times (should be < 5s for screening)

---

## 🎉 Deployment Complete!

Your BGV system with resume screening is now live on AWS!

### Access URLs:
- **Application:** https://your-domain.com
- **API Docs:** https://your-domain.com/docs
- **Resume Screening (Basic):** POST /secure/ai_resume_screening
- **Resume Screening (Enhanced):** POST /secure/ai_resume_screening_enhanced

### Next Steps:
1. Share API documentation with team
2. Train HR staff on using resume screening
3. Monitor costs and usage
4. Collect feedback and iterate
5. Scale up as needed

**Your resume screening system is production-ready!** 🚀
