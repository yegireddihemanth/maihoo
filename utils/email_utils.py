import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

# -------------------------------------------------------------------------
# 🔧 Config — You can later move these to environment variables
# -------------------------------------------------------------------------
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "no-reply@bgvapp.in"   # Replace with your verified sender
SMTP_PASSWORD = "your-app-password"  # Use app password, not your main email password


# -------------------------------------------------------------------------
# 📩 Email Helper — Self Verification Mail
# -------------------------------------------------------------------------
async def send_self_verification_link(candidate, org, verification_link):
    """
    Send self-verification email to the candidate.
    candidate: dict -> candidate details
    org: dict -> organization details
    verification_link: str -> secure link
    """
    try:
        candidate_name = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip() or "Candidate"
        org_name = org.get("organizationName", "Your Organization")

        subject = f"Complete Your Background Verification - {org_name}"
        body = f"""
                Hello {candidate_name},

                Your background verification for {org_name} has been initiated.

                Please complete your verification by clicking the link below:
                🔗 {verification_link}

                This link will expire in 48 hours.

                Best regards,  
                BGV Verification Team
                        """

        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = candidate.get("email")
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [candidate.get("email")], msg.as_string())

        print(f"[EMAIL SENT] Self-verification link sent to {candidate.get('email')}")
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send self-verification email: {e}")
        return False
