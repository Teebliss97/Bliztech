import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


BREVO_SMTP_SERVER = "smtp-relay.brevo.com"
BREVO_SMTP_PORT   = 587
BREVO_LOGIN       = "a6df42001@smtp-brevo.com"


def _get_brevo_config():
    password  = os.getenv("BREVO_SMTP_KEY")
    from_email = os.getenv("MAIL_FROM") or os.getenv("SENDGRID_FROM_EMAIL")
    return password, from_email


def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """
    Generic Brevo SMTP email sender.
    Returns True if sent, False otherwise.
    """
    password, from_email = _get_brevo_config()

    if not password or not from_email:
        print("❌ Brevo not configured: missing BREVO_SMTP_KEY or MAIL_FROM")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_email
    msg["To"]      = to_email
    msg.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP(BREVO_SMTP_SERVER, BREVO_SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(BREVO_LOGIN, password)
            server.sendmail(from_email, to_email, msg.as_string())
        print(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Brevo error: {e}")
        return False


def send_course_completion_email(to_email: str) -> bool:
    """
    Sends course completion email via Brevo SMTP.
    Returns True if sent successfully, False otherwise.
    """
    subject = "🎉 Congratulations! You completed the BlizTech Cyber Awareness Course"

    html_content = """
    <html>
      <body style="font-family: Arial, sans-serif; background:#0b1220; color:#ffffff; padding:20px;">
        <h2>🏆 Course Completed!</h2>
        <p>Congratulations!</p>
        <p>
          You have successfully completed all <strong>10 topics</strong> in the
          <strong>BlizTech Cybersecurity Awareness Course</strong>.
        </p>
        <p>
          You've taken an important step toward staying safer online.
        </p>
        <hr style="border:1px solid #2c3e50">
        <p style="font-size:14px; color:#b0c4de;">
          BlizTech • Cyber Awareness Program<br>
          Learn. Protect. Stay Safe.
        </p>
      </body>
    </html>
    """

    return send_email(to_email=to_email, subject=subject, html_content=html_content)