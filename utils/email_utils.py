# utils.py
import os
import jwt
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple

# SECRET for self-verification tokens (keep different from auth token)
SELF_VERIF_SECRET = os.environ.get("SELF_VERIF_SECRET", "change_this_secret")
SELF_VERIF_ALGO = "HS256"
SELF_VERIF_EXPIRE_MINUTES = int(os.environ.get("SELF_VERIF_EXPIRE_MINUTES", "1440"))  # default: 24h

# Simple mailer config — replace with your SMTP or transactional provider
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.example.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "username")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "password")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@example.com")
FRONTEND_SELF_VERIFY_URL = os.environ.get("FRONTEND_SELF_VERIFY_URL", "http://localhost:3000/self-verify")

def create_self_token(candidateId: str, organizationId: str, expires_minutes: int = None) -> Tuple[str, int]:
    exp_minutes = expires_minutes or SELF_VERIF_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    payload = {
        "candidateId": str(candidateId),
        "organizationId": str(organizationId),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=exp_minutes)).timestamp())
    }
    token = jwt.encode(payload, SELF_VERIF_SECRET, algorithm=SELF_VERIF_ALGO)
    return token, payload["exp"]

def decode_self_token(token: str) -> dict:
    """Raises jwt.ExpiredSignatureError, jwt.DecodeError if invalid."""
    return jwt.decode(token, SELF_VERIF_SECRET, algorithms=[SELF_VERIF_ALGO])

def send_self_verification_email(to_email: str, candidateName: str, token: str, organizationName: str):
    verify_link = f"{FRONTEND_SELF_VERIFY_URL}?token={token}"
    subject = f"Start your verification for {organizationName}"
    body = f"""
Hi {candidateName},

Please click the link below to start your verification process for {organizationName}:

{verify_link}

This link will expire in {int(SELF_VERIF_EXPIRE_MINUTES/60)} hours.

If you did not request this, ignore this email.

Thanks,
{organizationName}
"""
    # Build message
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    # Send
    try:
        s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        s.starttls()
        s.login(SMTP_USERNAME, SMTP_PASSWORD)
        s.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        s.quit()
    except Exception as e:
        # If you prefer, raise so the caller logs/handles it
        print(f"[utils.send_self_verification_email] failed: {e}")
        raise
