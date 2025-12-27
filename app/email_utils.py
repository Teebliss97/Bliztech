import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


def _get_sendgrid_config():
    """
    Supports either env naming:
      - SENDGRID_API_KEY
      - MAIL_FROM  (recommended)
      - or SENDGRID_FROM_EMAIL (your current naming)
    """
    api_key = os.getenv("SENDGRID_API_KEY")
    from_email = os.getenv("MAIL_FROM") or os.getenv("SENDGRID_FROM_EMAIL")
    return api_key, from_email


def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """
    Generic SendGrid email sender.
    Returns True if sent, False otherwise.
    """
    api_key, from_email = _get_sendgrid_config()

    if not api_key or not from_email:
        print("❌ SendGrid not configured: missing SENDGRID_API_KEY or MAIL_FROM/SENDGRID_FROM_EMAIL")
        return False

    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        html_content=html_content,
    )

    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        print("✅ Email sent:", response.status_code)
        return True
    except Exception as e:
        print("❌ SendGrid error:", e)
        return False


def send_course_completion_email(to_email: str) -> bool:
    """
    Sends course completion email using SendGrid.
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
          You’ve taken an important step toward staying safer online.
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
