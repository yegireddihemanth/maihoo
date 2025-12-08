
import base64
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

FRONTEND_SELF_VERIFY_URL = "https://bgv-zfdw.onrender.com/candidate/self-verification"

# Email configuration
GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")

def send_email_smtp(to_email, subject, body):
    """
    Send email using Gmail SMTP with App Password (RECOMMENDED for production)
    
    Setup:
    1. Go to Google Account → Security
    2. Enable 2-Step Verification
    3. Generate App Password
    4. Add to .env: GMAIL_USER and GMAIL_APP_PASSWORD
    """
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise Exception("Gmail credentials not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD in environment variables.")
    
    msg = MIMEMultipart()
    msg['From'] = GMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Use SMTP_SSL for port 465 (more reliable)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ SMTP Error: {e}")
        raise Exception(f"Failed to send email: {str(e)}")


def send_self_verification_email(to_email, candidateName, organizationName,
                                 stage, token, expiresAt):
    """Send self-verification email using SMTP"""
    
    # Build verification link
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

    try:
        send_email_smtp(
            to_email=to_email,
            subject=f"{stage.capitalize()} Stage Verification - {organizationName}",
            body=body
        )
        print("Email sent successfully to:", to_email)
    except Exception as e:
        print("Error sending email:", str(e))
        raise Exception(f"Email sending failed: {str(e)}")


def send_password_reset_email(toEmail, userName, userId, newPassword):
    """
    Sends an email notification to the user after password reset.
    Includes username and new password.
    """

    body = f"""
Hi {userName},

Your password has been successfully reset.

Here are your updated login credentials:

User ID (Email): {toEmail}
User Unique ID: {userId}
New Password: {newPassword}

For security reasons, please do not share this password with anyone.

If you did not request this reset, please contact the support team immediately.

Thanks,
Maihoo Verification Team
"""

    try:
        send_email_smtp(
            to_email=toEmail,
            subject="Password Reset Confirmation - Maihoo",
            body=body
        )
        print("Password reset email sent to:", toEmail)
    except Exception as e:
        print("Error sending password reset email:", str(e))
        raise Exception(f"Email sending failed: {str(e)}")

def send_organization_welcome_email(
    toEmail,
    organizationName,
    spocName,
    loginEmail,
    defaultPassword,
    mainDomain,
    subDomain,
    services,
    credentials,
    logoUrl=None
):
    """
    Sends a welcome email when a new organization is registered.
    Includes login details for the SPOC.
    """

    # Convert services list to readable text (e.g., "- Employment Verification: 120.0")
    servicesText = ""
    if services:
        for s in services:
            servicesText += f"- {s.get('serviceName')}: {s.get('price')}\n"
    else:
        servicesText = "No services added yet.\n"

    credentialsText = f"""
Total Allowed Users: {credentials.get('totalAllowed')}
Users Used: {credentials.get('used')}
""".strip()

    body = f"""
Hello {spocName},

Welcome to the BGVApp Platform!

Your organization **{organizationName}** has been successfully registered.

-------------------------
LOGIN CREDENTIALS
-------------------------
Login Email: {loginEmail}
Default Password: {defaultPassword}

Please log in and change your password immediately.

-------------------------
ORGANIZATION DETAILS
-------------------------
Organization Name: {organizationName}
Main Domain: {mainDomain or 'Not Provided'}
Subdomain: {subDomain}

-------------------------
PLAN/USAGE CREDENTIALS
-------------------------
{credentialsText}

-------------------------
SERVICES ENABLED
-------------------------
{servicesText}

-------------------------
LOGO
-------------------------
{logoUrl or 'No logo provided'}

If you have any questions or need help setting up your workspace,
please reach out to your support team.

Thanks,
BGVApp Team
"""

    try:
        send_email_smtp(
            to_email=toEmail,
            subject=f"Welcome to BGVApp - {organizationName} Registration Successful",
            body=body
        )
        print(f"✅ Welcome email sent to {toEmail}")
    except Exception as e:
        print("Error sending organization welcome email:", str(e))
        raise Exception(f"Email sending failed: {str(e)}")
    

def send_ticket_email(toEmail, subject, body):
    """
    Sends ticket-related emails using SMTP
    """
    try:
        send_email_smtp(
            to_email=toEmail,
            subject=subject,
            body=body
        )
        print(f"✅ Ticket email sent to {toEmail}")
    except Exception as e:
        print("Email sending failed:", str(e))
        raise Exception(f"Email sending failed: {str(e)}")


def send_verification_consent_email(to_email, candidate_name, organization_name, 
                                  verification_checks, consent_token, expires_at, 
                                  consent_url=None):
    """
    Sends consent email to candidate before starting backend verification using SMTP.
    
    Args:
        to_email: Candidate's email
        candidate_name: Candidate's name
        organization_name: Organization requesting verification
        verification_checks: List of checks to be performed
        consent_token: Unique token for consent validation
        expires_at: Token expiration time
        consent_url: Frontend consent page URL (optional)
    """
    
    # Default consent URL if not provided
    if not consent_url:
        consent_url = "https://bgv-zfdw.onrender.com/candidate/consent"
    
    # Build consent link with token
    consent_link = f"{consent_url}?token={consent_token}"
    
    # Format verification checks list
    checks_list = ""
    for i, check in enumerate(verification_checks, 1):
        checks_list += f"{i}. {check.get('name', 'Unknown Check')}\n"
        if check.get('description'):
            checks_list += f"   - {check['description']}\n"
    
    body = f"""
Dear {candidate_name},

{organization_name} has requested to perform background verification checks on your profile.

Before we begin the verification process, we need your explicit consent to proceed with the following checks:

VERIFICATION CHECKS TO BE PERFORMED:
{checks_list}

IMPORTANT INFORMATION:
- These checks will be conducted by our verification team
- Your personal information will be handled securely and confidentially
- You have the right to know what checks are being performed
- This consent is required before any verification can begin

WHAT YOU NEED TO DO:
1. Click the consent link below
2. Review the detailed list of verification checks
3. Provide your consent by checking the agreement box
4. Submit your response

CONSENT LINK: {consent_link}

This consent link will expire on: {expires_at}

If you have any questions about these verification checks or need clarification, please contact:
- Organization: {organization_name}
- Support: support@bgvapp.in

If you did not expect this verification request, please contact us immediately.

Thank you for your cooperation.

Best regards,
BGVApp Verification Team
"""

    try:
        send_email_smtp(
            to_email=to_email,
            subject=f"Verification Consent Required - {organization_name}",
            body=body
        )
        print(f"✅ Verification consent email sent to {to_email}")
    except Exception as e:
        print(f"Error sending verification consent email: {str(e)}")
        raise Exception(f"Email sending failed: {str(e)}")
