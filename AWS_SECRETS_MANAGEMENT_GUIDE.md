# AWS Secrets Management Guide - Secure Your API Keys

## 🔐 Current Problem

You're exposing sensitive keys in your code:

```python
# ❌ BAD - Exposed in config.py
SUREPASS_TOKEN = "eyJhbGc..."
MONGO_URI = "mongodb+srv://username:password@..."
```

**Risks:**
- Keys visible in Git history
- Anyone with code access has your keys
- Hard to rotate keys
- Compliance issues

---

## ✅ Best Solution for AWS EC2: AWS Secrets Manager + Environment Variables

### Why This Approach?
- ✅ Keys never in code
- ✅ Automatic rotation
- ✅ Audit logging
- ✅ IAM-based access control
- ✅ Encrypted at rest
- ✅ Easy to update without code changes

---

## 🚀 Step-by-Step Implementation

### Step 1: Store Secrets in AWS Secrets Manager

**1.1 Go to AWS Secrets Manager Console**
```
https://console.aws.amazon.com/secretsmanager/
```

**1.2 Create New Secret**

Click "Store a new secret" → "Other type of secret"

**Add your secrets as key-value pairs:**
```json
{
  "SUREPASS_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "MONGO_URI": "mongodb+srv://maihoo:password@cluster.mongodb.net/",
  "SESSION_SECRET": "super-secret-key-for-sessions",
  "CLOUDINARY_CLOUD_NAME": "dz0nugtfe",
  "CLOUDINARY_API_KEY": "823959276223763",
  "CLOUDINARY_API_SECRET": "3WL9jN__Me9PG0tn6xQej9R37cE"
}
```

**1.3 Name Your Secret**
```
Secret name: bgv-app/production
Description: BGV Application Production Secrets
```

**1.4 Configure Rotation (Optional)**
- Skip for now, can enable later

**1.5 Review and Store**
- Click "Store"
- Note the ARN: `arn:aws:secretsmanager:region:account:secret:bgv-app/production-xxxxx`

---

### Step 2: Grant EC2 Instance Access to Secrets

**2.1 Create IAM Role for EC2**

Go to IAM Console → Roles → Create Role

**Select trusted entity:**
- AWS service
- EC2

**Attach policies:**
Create custom policy named `BGVSecretsAccess`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:bgv-app/production-*"
    }
  ]
}
```

**Name the role:** `BGV-EC2-SecretsAccess`

**2.2 Attach Role to EC2 Instance**

```bash
# Via AWS Console:
EC2 → Instances → Select your instance → Actions → Security → Modify IAM role
→ Select "BGV-EC2-SecretsAccess"

# Via AWS CLI:
aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=BGV-EC2-SecretsAccess
```

---

### Step 3: Install AWS SDK in Your Application

**SSH into your EC2 instance:**

```bash
ssh -i your-key.pem ubuntu@your-ec2-ip
```

**Install boto3 (AWS SDK for Python):**

```bash
pip install boto3
```

**Add to requirements.txt:**
```txt
boto3==1.34.0
```

---

### Step 4: Create Secrets Manager Helper

Create `secrets_manager.py`:

```python
import boto3
import json
import os
from functools import lru_cache

class SecretsManager:
    def __init__(self):
        self.region_name = os.getenv('AWS_REGION', 'us-east-1')
        self.secret_name = os.getenv('SECRET_NAME', 'bgv-app/production')
        self.client = boto3.client('secretsmanager', region_name=self.region_name)
        self._secrets = None
    
    @lru_cache(maxsize=1)
    def get_secrets(self):
        """
        Fetch secrets from AWS Secrets Manager
        Cached to avoid repeated API calls
        """
        if self._secrets is not None:
            return self._secrets
        
        try:
            print(f"🔐 Fetching secrets from AWS Secrets Manager: {self.secret_name}")
            response = self.client.get_secret_value(SecretId=self.secret_name)
            
            if 'SecretString' in response:
                self._secrets = json.loads(response['SecretString'])
                print("✅ Secrets loaded successfully")
                return self._secrets
            else:
                raise Exception("Secret not found in response")
                
        except Exception as e:
            print(f"❌ Error fetching secrets: {str(e)}")
            print("⚠️ Falling back to environment variables")
            # Fallback to environment variables for local development
            return self._get_env_fallback()
    
    def _get_env_fallback(self):
        """Fallback to environment variables for local development"""
        return {
            'SUREPASS_TOKEN': os.getenv('SUREPASS_TOKEN', ''),
            'MONGO_URI': os.getenv('MONGO_URI', ''),
            # AI configuration removed
            'SESSION_SECRET': os.getenv('SESSION_SECRET', 'dev-secret-key'),
            'CLOUDINARY_CLOUD_NAME': os.getenv('CLOUDINARY_CLOUD_NAME', ''),
            'CLOUDINARY_API_KEY': os.getenv('CLOUDINARY_API_KEY', ''),
            'CLOUDINARY_API_SECRET': os.getenv('CLOUDINARY_API_SECRET', '')
        }
    
    def get(self, key, default=None):
        """Get a specific secret value"""
        secrets = self.get_secrets()
        return secrets.get(key, default)

# Singleton instance
secrets_manager = SecretsManager()
```

---

### Step 5: Update Your Config Files

**Update `config.py`:**

```python
from secrets_manager import secrets_manager
import cloudinary
import cloudinary.uploader
import cloudinary.api

# Fetch secrets from AWS Secrets Manager
SUREPASS_BASE_URL = "https://kyc-api.surepass.io/api/v1"
SUREPASS_TOKEN = secrets_manager.get('SUREPASS_TOKEN')

# MongoDB
MONGO_URI = secrets_manager.get('MONGO_URI')
MONGO_DB_NAME = "bgv_core"

# AI configuration removed

# Session Secret
SESSION_SECRET = secrets_manager.get('SESSION_SECRET').encode()

# Cloudinary Configuration
cloudinary.config(
    cloud_name=secrets_manager.get('CLOUDINARY_CLOUD_NAME'),
    api_key=secrets_manager.get('CLOUDINARY_API_KEY'),
    api_secret=secrets_manager.get('CLOUDINARY_API_SECRET'),
    secure=True
)

print("✅ Configuration loaded from AWS Secrets Manager")
```

**Update `main.py`:**

```python
from config import SESSION_SECRET, MONGO_URI, MONGO_DB_NAME

# Use the secrets
mongoUri = MONGO_URI
mongoDbName = MONGO_DB_NAME
sessionSecret = SESSION_SECRET

# Rest of your code...
```

**Update `apis.py`:**

```python
from config import SUREPASS_TOKEN

# Use the token
SUREPASS_TOKEN = SUREPASS_TOKEN  # Already loaded from Secrets Manager

# Rest of your code...
```

---

### Step 6: Update .gitignore

**Add to `.gitignore`:**

```
# Environment files
.env
.env.local
.env.production

# Config files with secrets (if any)
config_local.py
secrets.json

# AWS credentials
.aws/

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python

# IDE
.vscode/
.idea/
*.swp
*.swo
```

---

### Step 7: Set Environment Variables on EC2

**Create systemd service file:**

```bash
sudo nano /etc/systemd/system/bgv-app.service
```

**Add:**

```ini
[Unit]
Description=BGV Application
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/bgv-app
Environment="AWS_REGION=us-east-1"
Environment="SECRET_NAME=bgv-app/production"
Environment="PYTHONUNBUFFERED=1"
ExecStart=/usr/bin/python3 /home/ubuntu/bgv-app/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable bgv-app
sudo systemctl start bgv-app
sudo systemctl status bgv-app
```

---

## 🔄 Alternative: Environment Variables Only (Simpler)

If you don't want to use AWS Secrets Manager yet:

### Step 1: Create `.env` file on EC2

```bash
cd /home/ubuntu/bgv-app
nano .env
```

**Add:**

```bash
SUREPASS_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
MONGO_URI=mongodb+srv://maihoo:password@cluster.mongodb.net/
# AI configuration removed
SESSION_SECRET=super-secret-key-for-sessions
CLOUDINARY_CLOUD_NAME=dz0nugtfe
CLOUDINARY_API_KEY=823959276223763
CLOUDINARY_API_SECRET=3WL9jN__Me9PG0tn6xQej9R37cE
```

**Secure the file:**

```bash
chmod 600 .env
chown ubuntu:ubuntu .env
```

### Step 2: Install python-dotenv

```bash
pip install python-dotenv
```

### Step 3: Update config.py

```python
from dotenv import load_dotenv
import os
import cloudinary

# Load environment variables from .env file
load_dotenv()

# Fetch from environment
SUREPASS_TOKEN = os.getenv('SUREPASS_TOKEN')
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'bgv_core')
# AI configuration removed
SESSION_SECRET = os.getenv('SESSION_SECRET', 'default-secret').encode()

# Cloudinary
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)

print("✅ Configuration loaded from environment variables")
```

---

## 📊 Comparison: Secrets Manager vs Environment Variables

| Feature | AWS Secrets Manager | Environment Variables |
|---------|-------------------|----------------------|
| **Security** | ⭐⭐⭐⭐⭐ Encrypted, IAM-controlled | ⭐⭐⭐ File permissions only |
| **Rotation** | ⭐⭐⭐⭐⭐ Automatic | ⭐ Manual |
| **Audit** | ⭐⭐⭐⭐⭐ Full CloudTrail logs | ⭐ None |
| **Cost** | $0.40/secret/month + $0.05/10k API calls | Free |
| **Complexity** | ⭐⭐⭐ Medium | ⭐ Simple |
| **Best For** | Production | Development/Testing |

---

## 🎯 Recommended Approach

### For Production (AWS EC2):
✅ **Use AWS Secrets Manager**
- More secure
- Better for compliance
- Easier to rotate keys
- Audit logging

### For Development (Local):
✅ **Use .env file**
- Simpler setup
- Faster development
- No AWS costs

---

## 🔒 Additional Security Best Practices

### 1. Never Commit Secrets to Git

**Check git history:**
```bash
git log --all --full-history --source -- config.py
```

**If secrets were committed, remove from history:**
```bash
# Use BFG Repo-Cleaner
brew install bfg  # or download from https://rtyley.github.io/bfg-repo-cleaner/
bfg --replace-text passwords.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### 2. Use Different Secrets for Each Environment

```
bgv-app/development
bgv-app/staging
bgv-app/production
```

### 3. Rotate Secrets Regularly

**Set up automatic rotation in AWS Secrets Manager:**
- Go to your secret
- Edit rotation
- Enable automatic rotation
- Set rotation schedule (e.g., every 30 days)

### 4. Monitor Secret Access

**Enable CloudTrail logging:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=bgv-app/production
```

### 5. Use IAM Roles, Not Access Keys

**Never do this on EC2:**
```bash
# ❌ BAD
aws configure
AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Instead, attach IAM role to EC2 instance** ✅

---

## 🧪 Testing Your Setup

### Test 1: Verify Secrets Manager Access

```bash
# SSH into EC2
ssh -i your-key.pem ubuntu@your-ec2-ip

# Test AWS CLI access
aws secretsmanager get-secret-value \
  --secret-id bgv-app/production \
  --region us-east-1
```

**Expected output:**
```json
{
  "ARN": "arn:aws:secretsmanager:...",
  "Name": "bgv-app/production",
  "SecretString": "{\"SUREPASS_TOKEN\":\"...\",\"MONGO_URI\":\"...\"}"
}
```

### Test 2: Verify Python Can Load Secrets

```python
# test_secrets.py
from secrets_manager import secrets_manager

print("Testing secrets loading...")
secrets = secrets_manager.get_secrets()
print(f"✅ Loaded {len(secrets)} secrets")
print(f"✅ SUREPASS_TOKEN: {secrets.get('SUREPASS_TOKEN')[:20]}...")
print(f"✅ MONGO_URI: {secrets.get('MONGO_URI')[:30]}...")
```

Run:
```bash
python test_secrets.py
```

---

## 📝 Migration Checklist

- [ ] Create AWS Secrets Manager secret
- [ ] Add all API keys to secret
- [ ] Create IAM role with Secrets Manager access
- [ ] Attach IAM role to EC2 instance
- [ ] Install boto3 on EC2
- [ ] Create `secrets_manager.py`
- [ ] Update `config.py` to use Secrets Manager
- [ ] Test application startup
- [ ] Remove hardcoded secrets from code
- [ ] Update `.gitignore`
- [ ] Commit changes (without secrets!)
- [ ] Deploy to EC2
- [ ] Verify application works
- [ ] Delete old config files with secrets

---

## 🆘 Troubleshooting

### Error: "Unable to locate credentials"

**Solution:**
```bash
# Check if IAM role is attached
aws sts get-caller-identity

# If not, attach role to EC2 instance
```

### Error: "Access Denied"

**Solution:**
```bash
# Check IAM policy
aws iam get-role-policy \
  --role-name BGV-EC2-SecretsAccess \
  --policy-name BGVSecretsAccess
```

### Error: "Secret not found"

**Solution:**
```bash
# List all secrets
aws secretsmanager list-secrets

# Check secret name matches
```

---

That's your complete guide to securing API keys on AWS EC2! 🔐
