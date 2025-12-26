from flask import Blueprint, render_template, session, redirect, url_for
from flask_login import current_user

from app.models import Progress
from app.blueprints.topics.routes import TOPICS

cert_bp = Blueprint("cert", __name__, url_prefix="")

def _progress_key():
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return session.get("anon_id")

def _progress_dict(user_id: str) -> dict:
    if not user_id:
        return {}
    rows = Progress.query.filter_by(user_id=user_id).all()
    return {r.slug: r.to_dict() for r in rows}

@cert_bp.route("/certificate")
def certificate():
    user_id = _progress_key()
    progress = _progress_dict(user_id)

    total = len(TOPICS)
    completed = sum(1 for t in TOPICS if bool(progress.get(t["slug"], {}).get("passed")))
    course_done = (completed == total and total > 0)

    if not course_done:
        return redirect(url_for("topics.list_topics"))

    return render_template(
        "certificate.html",
        completed=completed,
        total=total
    )
