import os
import resend


def _get_resend_config():
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("MAIL_FROM") or os.getenv("SENDGRID_FROM_EMAIL")
    return api_key, from_email


def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """
    Generic Resend email sender.
    Returns True if sent, False otherwise.
    """
    api_key, from_email = _get_resend_config()

    if not api_key or not from_email:
        print("❌ Resend not configured: missing RESEND_API_KEY or MAIL_FROM")
        return False

    resend.api_key = api_key

    try:
        response = resend.Emails.send({
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        })
        print("✅ Email sent:", response.get("id"))
        return True
    except Exception as e:
        print("❌ Resend error:", e)
        return False


def send_course_completion_email(to_email: str) -> bool:
    """
    Sends course completion email using Resend.
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