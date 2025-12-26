from flask import Blueprint, abort
from flask_login import login_required, current_user
import os
from app.email_utils import send_course_completion_email

test_bp = Blueprint("test", __name__)

@test_bp.route("/test-email")
@login_required
def test_email():
    if os.getenv("ENABLE_EMAIL_TEST_ROUTE") != "1":
        abort(404)

    ok = send_course_completion_email(current_user.email)
    return "✅ Test email sent" if ok else "❌ Test email failed"
