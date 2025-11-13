# utils/email_utils.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "hemanthdevapple@gmail.com"
SMTP_PASSWORD = "wqjd ctur lkwf zhwl"   # App password
FROM_EMAIL = "hemanthdevapple@gmail.com"

FRONTEND_SELF_VERIFY_URL = "http://localhost:3000/self-verify"

def send_self_verification_email(to_email, candidateName, organizationName,
                                 candidateId, organizationId, aadhaarLast4):

    link = FRONTEND_SELF_VERIFY_URL

    body = f"""
Hi {candidateName},

You have been selected for self-verification for {organizationName}.

Use the details below to log in:

Candidate ID: {candidateId}
Organization ID: {organizationId}
Email: {to_email}
Aadhaar Last 4 Digits: {aadhaarLast4}

Verification Link:
{link}

Thanks,
{organizationName} Verification Team
"""

    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = f"Self Verification - {organizationName}"
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USERNAME, SMTP_PASSWORD)
        s.sendmail(FROM_EMAIL, [to_email], msg.as_string())
