# Migration Guide: Secure Your API Keys

## 🎯 Goal

Move from hardcoded secrets in `config.py` to secure AWS Secrets Manager.

---

## 📋 What You Have Now

```python
# config.py - ❌ INSECURE
SUREPASS_TOKEN = "eyJhbGc..."  # Exposed in code
MONGO_URI = "mongodb+srv://username:password@..."  # Exposed in code
cloudinary.config(
    cloud_name = "dz0nugtfe",  # Exposed in code
    api_key = "823959276223763",  # Exposed in code
    api_secret = "3WL9jN__Me9PG0tn6xQej9R37cE"  # Exposed in code
)
```

---

## ✅ What You'll Have

```python
# config_secure.py - ✅ SECURE
from secrets_manager import secrets_manager

SUREPASS_TOKEN = secrets_manager.get('SUREPASS_TOKEN')  # From AWS
MONGO_URI = secrets_manager.get('MONGO_URI')  # From AWS
cloudinary.config(
    cloud_name = secrets_manager.get('CLOUDINARY_CLOUD_NAME'),  # From AWS
    api_key = secrets_manager.get('CLOUDINARY_API_KEY'),  # From AWS
    api_secret = secrets_manager.get('CLOUDINARY_API_SECRET')  # From AWS
)
```

---

## 🚀 Migration Steps

### Step 1: Backup Current Config

```bash
# Backup your current config
cp config.py config.py.backup
```

### Step 2: Install Required Packages

```bash
# Add to requirements.txt
echo "boto3==1.34.0" >> requirements.txt
echo "python-dotenv==1.0.0" >> requirements.txt

# Install
pip install boto3 python-dotenv
```

### Step 3: Create .env File for Local Development

```bash
# Copy template
cp .env.example .env

# Edit with your actual values
nano .env
```

**Add your secrets:**
```bash
SUREPASS_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
MONGO_URI=mongodb+srv://maihoo:password@cluster.mongodb.net/
# AI configuration removed
SESSION_SECRET=your-super-secret-key
CLOUDINARY_CLOUD_NAME=dz0nugtfe
CLOUDINARY_API_KEY=823959276223763
CLOUDINARY_API_SECRET=3WL9jN__Me9PG0tn6xQej9R37cE
USE_AWS_SECRETS=false
```

**Secure the file:**
```bash
chmod 600 .env
```

### Step 4: Test Locally

```bash
# Test secrets loading
python3 -c "
from secrets_manager import secrets_manager
secrets = secrets_manager.get_secrets()
print('✅ Loaded secrets:', list(secrets.keys()))
"

# Test application
python main.py
```

### Step 5: Update Imports in Your Code

**Find all files that import from config:**
```bash
grep -r "from config import" .
grep -r "import config" .
```

**Update imports:**
```python
# Old
from config import SUREPASS_TOKEN, MONGO_URI

# New
from config_secure import SUREPASS_TOKEN, MONGO_URI
```

**Or rename file:**
```bash
mv config.py config_old.py
mv config_secure.py config.py
```

### Step 6: Update .gitignore

```bash
# Add to .gitignore
cat >> .gitignore << EOF

# Environment files
.env
.env.local
.env.production

# Config backups
config.py.backup
config_old.py

# AWS credentials
.aws/

# Secrets
secrets.json
token.json
EOF
```

### Step 7: Remove Secrets from Git History

**Check if secrets were committed:**
```bash
git log --all --full-history --source -- config.py | grep -i "token\|password\|secret"
```

**If found, clean history:**
```bash
# Install BFG Repo-Cleaner
brew install bfg  # macOS
# or download from https://rtyley.github.io/bfg-repo-cleaner/

# Create file with secrets to remove
cat > secrets.txt << EOF
SUREPASS_TOKEN
MONGO_URI
CLOUDINARY_API_SECRET
EOF

# Clean repository
bfg --replace-text secrets.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (WARNING: This rewrites history!)
git push origin --force --all
```

### Step 8: Setup AWS Secrets Manager (Production)

**8.1 Create Secret in AWS Console:**

1. Go to: https://console.aws.amazon.com/secretsmanager/
2. Click "Store a new secret"
3. Select "Other type of secret"
4. Add key-value pairs:

```json
{
  "SUREPASS_TOKEN": "eyJhbGc...",
  "MONGO_URI": "mongodb+srv://...",
  // AI configuration removed
  "SESSION_SECRET": "your-secret-key",
  "CLOUDINARY_CLOUD_NAME": "dz0nugtfe",
  "CLOUDINARY_API_KEY": "823959276223763",
  "CLOUDINARY_API_SECRET": "3WL9jN__Me9PG0tn6xQej9R37cE"
}
```

5. Name: `bgv-app/production`
6. Click "Store"

**8.2 Create IAM Role:**

```bash
# Create policy file
cat > bgv-secrets-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:bgv-app/production-*"
    }
  ]
}
EOF

# Create policy
aws iam create-policy \
  --policy-name BGVSecretsAccess \
  --policy-document file://bgv-secrets-policy.json

# Create role
aws iam create-role \
  --role-name BGV-EC2-SecretsAccess \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach policy to role
aws iam attach-role-policy \
  --role-name BGV-EC2-SecretsAccess \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/BGVSecretsAccess

# Create instance profile
aws iam create-instance-profile \
  --instance-profile-name BGV-EC2-SecretsAccess

# Add role to instance profile
aws iam add-role-to-instance-profile \
  --instance-profile-name BGV-EC2-SecretsAccess \
  --role-name BGV-EC2-SecretsAccess
```

**8.3 Attach Role to EC2:**

```bash
# Attach to existing instance
aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=BGV-EC2-SecretsAccess

# Or via AWS Console:
# EC2 → Instances → Select instance → Actions → Security → Modify IAM role
```

### Step 9: Deploy to EC2

**9.1 Copy files to EC2:**

```bash
# Copy new files
scp -i your-key.pem secrets_manager.py ubuntu@your-ec2-ip:/home/ubuntu/bgv-app/
scp -i your-key.pem config_secure.py ubuntu@your-ec2-ip:/home/ubuntu/bgv-app/
scp -i your-key.pem deploy_to_ec2.sh ubuntu@your-ec2-ip:/home/ubuntu/bgv-app/
```

**9.2 SSH and deploy:**

```bash
# SSH into EC2
ssh -i your-key.pem ubuntu@your-ec2-ip

# Run deployment script
cd /home/ubuntu/bgv-app
chmod +x deploy_to_ec2.sh
./deploy_to_ec2.sh
```

**9.3 Verify deployment:**

```bash
# Check service status
sudo systemctl status bgv-app

# Check logs
sudo journalctl -u bgv-app -f

# Test secrets loading
python3 -c "
import os
os.environ['USE_AWS_SECRETS'] = 'true'
from secrets_manager import secrets_manager
secrets = secrets_manager.get_secrets()
print('✅ Loaded from AWS:', list(secrets.keys()))
"
```

### Step 10: Verify Everything Works

**10.1 Test API endpoints:**

```bash
# Health check
curl http://your-ec2-ip:8000/

# Login
curl -X POST http://your-ec2-ip:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'
```

**10.2 Check logs for errors:**

```bash
sudo tail -f /var/log/bgv-app.log
```

**10.3 Monitor secrets access:**

```bash
# Check CloudTrail for Secrets Manager access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=bgv-app/production \
  --max-results 10
```

---

## 🔄 Rollback Plan

If something goes wrong:

```bash
# On EC2
cd /home/ubuntu/bgv-app

# Restore old config
cp config.py.backup config.py

# Restart service
sudo systemctl restart bgv-app

# Check status
sudo systemctl status bgv-app
```

---

## ✅ Post-Migration Checklist

- [ ] Secrets loaded from AWS Secrets Manager on EC2
- [ ] Secrets loaded from .env locally
- [ ] Application starts without errors
- [ ] API endpoints work correctly
- [ ] No secrets in git repository
- [ ] .env file in .gitignore
- [ ] IAM role attached to EC2
- [ ] CloudTrail logging enabled
- [ ] Old config.py backed up
- [ ] Team notified of changes

---

## 🆘 Troubleshooting

### Issue: "Unable to locate credentials"

**Solution:**
```bash
# Check IAM role
aws sts get-caller-identity

# If empty, attach role to EC2
```

### Issue: "Secret not found"

**Solution:**
```bash
# List secrets
aws secretsmanager list-secrets

# Check secret name matches
echo $SECRET_NAME
```

### Issue: "Access Denied"

**Solution:**
```bash
# Check IAM policy
aws iam get-role-policy \
  --role-name BGV-EC2-SecretsAccess \
  --policy-name BGVSecretsAccess
```

### Issue: Application not starting

**Solution:**
```bash
# Check logs
sudo journalctl -u bgv-app -n 50

# Check environment variables
sudo systemctl show bgv-app | grep Environment

# Test manually
cd /home/ubuntu/bgv-app
python3 main.py
```

---

## 📊 Before vs After

### Before (Insecure):
```
config.py (in git)
├── SUREPASS_TOKEN = "eyJhbGc..."  ❌
├── MONGO_URI = "mongodb+srv://..."  ❌
└── CLOUDINARY_API_SECRET = "..."  ❌
```

### After (Secure):
```
AWS Secrets Manager
├── bgv-app/production
│   ├── SUREPASS_TOKEN  ✅
│   ├── MONGO_URI  ✅
│   └── CLOUDINARY_API_SECRET  ✅
│
config.py (in git)
├── from secrets_manager import secrets_manager  ✅
└── SUREPASS_TOKEN = secrets_manager.get('SUREPASS_TOKEN')  ✅
```

---

That's your complete migration guide! 🔐
