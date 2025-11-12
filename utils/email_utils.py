import jwt
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple

# ============================================================
# 🔐 Self-verification token configuration
# ============================================================
SELF_VERIF_SECRET = "my_secret_key_123"  # change to something unique
SELF_VERIF_ALGO = "HS256"
SELF_VERIF_EXPIRE_MINUTES = 1440  # 24 hours

# ============================================================
# 📧 Gmail SMTP configuration (using App Password)
# ============================================================
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "hemanthdevapple@gmail.com"          # your Gmail ID
SMTP_PASSWORD = "wqjd ctur lkwf zhwl"          # your generated App Password (16 chars, spaces optional)
FROM_EMAIL = "hemanthdevapple@gmail.com"             # sender address
FRONTEND_SELF_VERIFY_URL = "http://localhost:3000/self-verify"  # your frontend link

# ============================================================
# 🔑 Token creation and decoding helpers
# ============================================================
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
    """Raises jwt.ExpiredSignatureError or jwt.DecodeError if invalid."""
    return jwt.decode(token, SELF_VERIF_SECRET, algorithms=[SELF_VERIF_ALGO])


# ============================================================
# ✉️ Email sender (simple Gmail SMTP)
# ============================================================
def send_self_verification_email(to_email: str, candidateName: str, token: str, organizationName: str):
    """
    Sends self-verification link to the candidate via Gmail SMTP.
    Uses your Gmail account (App Password).
    """
    verify_link = f"{FRONTEND_SELF_VERIFY_URL}?token={token}"
    subject = f"Start your verification for {organizationName}"

    body = f"""
Hi {candidateName},

Please click the link below to start your verification process for {organizationName}:

{verify_link}

This link will expire in {int(SELF_VERIF_EXPIRE_MINUTES/60)} hours.

If you did not request this, ignore this email.

Thanks,
{organizationName} Verification Team
"""

    # Build the MIME email
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.starttls()  # enable TLS
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        print(f"[Email Sent ✅] Verification mail sent to {to_email}")
    except Exception as e:
        print(f"[Email Error ❌] Failed to send to {to_email}: {e}")
        raise
