# utils/email_utils.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "hemanthdevapple@gmail.com"
SMTP_PASSWORD = "wqjd ctur lkwf zhwl"   # App password
FROM_EMAIL = "hemanthdevapple@gmail.com"

FRONTEND_SELF_VERIFY_URL = "https://maihoo.onrender.com/self-verify"

def send_self_verification_email(to_email, candidateName, organizationName,
                                 stage, token, expiresAt):

    link = f"{FRONTEND_SELF_VERIFY_URL}?token={token}"

    body = f"""
Hi {candidateName},

You have been requested to complete the {stage.upper()} stage verification 
for {organizationName}.

Stage: {stage}
Verification Link: {link}
This link will expire at: {expiresAt}

If you did not request this, please contact your HR/Verification team.

Thanks,
{organizationName} Verification Team
"""

    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = f"{stage.capitalize()} Stage Verification - {organizationName}"
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USERNAME, SMTP_PASSWORD)
        s.sendmail(FROM_EMAIL, [to_email], msg.as_string())
