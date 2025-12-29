from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from flask_login import current_user

from app.models import Progress
from app.blueprints.topics.routes import TOPICS
from app.utils.ratelimit import rate_limit

main_bp = Blueprint("main", __name__)


def _progress_key() -> str:
    # logged in users: user:<id>
    if current_user.is_authenticated:
        return f"user:{current_user.id}"

    # anonymous users: anon:<uuid> stored in session
    # Your app/__init__.py already guarantees this exists before each request.
    return session["anon_id"]


def _progress_map(progress_user_id: str) -> dict:
    rows = Progress.query.filter_by(user_id=progress_user_id).all()
    return {r.slug: r.to_dict() for r in rows}


def _is_unlocked(slug: str, pmap: dict) -> bool:
    if slug == "topic1":
        return True

    idx = next((i for i, t in enumerate(TOPICS) if t["slug"] == slug), None)
    if idx is None or idx == 0:
        return False

    prev_slug = TOPICS[idx - 1]["slug"]
    return bool(pmap.get(prev_slug, {}).get("passed"))


def _next_topic(pmap: dict):
    for i, t in enumerate(TOPICS, start=1):
        slug = t["slug"]
        passed = bool(pmap.get(slug, {}).get("passed"))
        if (not passed) and _is_unlocked(slug, pmap):
            return {"slug": slug, "label": f"Topic {i}"}
    return None


def _last_completed_title(pmap: dict):
    last = None
    for t in TOPICS:
        if bool(pmap.get(t["slug"], {}).get("passed")):
            last = t["title"]
    return last


@main_bp.route("/")
def home():
    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)

    total = len(TOPICS)
    completed = sum(1 for t in TOPICS if bool(pmap.get(t["slug"], {}).get("passed")))
    percent = int(round((completed / total) * 100)) if total else 0

    next_t = _next_topic(pmap)
    course_done = (total > 0 and completed == total)

    progress = None
    if completed > 0 and next_t:
        progress = {
            "completed": completed,
            "total": total,
            "percent": percent,
            "next_slug": next_t["slug"],
            "next_label": next_t["label"],
            "last_title": _last_completed_title(pmap),
        }

    return render_template(
        "home.html",
        progress=progress,
        total_topics=total,
        course_done=course_done,
    )


@main_bp.route("/progress")
def my_progress():
    """User/anon-facing progress dashboard."""
    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)

    rows = []
    completed = 0
    for i, t in enumerate(TOPICS, start=1):
        slug = t["slug"]
        r = pmap.get(slug, {})
        passed = bool(r.get("passed"))
        if passed:
            completed += 1
        rows.append(
            {
                "i": i,
                "slug": slug,
                "title": t["title"],
                "passed": passed,
                "score": r.get("score"),
                "attempts": r.get("attempts", 0),
                "updated_at": r.get("updated_at"),
                "unlocked": _is_unlocked(slug, pmap),
            }
        )

    total = len(TOPICS)
    percent = int(round((completed / total) * 100)) if total else 0
    course_done = (total > 0 and completed == total)

    return render_template(
        "progress.html",
        rows=rows,
        completed=completed,
        total=total,
        percent=percent,
        course_done=course_done,
        is_logged_in=bool(current_user.is_authenticated),
    )


@main_bp.route("/progress/reset", methods=["POST"])
@rate_limit(limit=3, window_seconds=60, key_prefix="reset")
def reset_progress():
    """Allow users (and anonymous sessions) to reset their own progress."""
    progress_user_id = _progress_key()

    confirm = (request.form.get("confirm") or "").strip().lower()
    if confirm != "reset":
        flash("Type RESET to confirm.", "error")
        return redirect(url_for("main.my_progress"))

    from app.extensions import db
    Progress.query.filter_by(user_id=progress_user_id).delete(synchronize_session=False)
    db.session.commit()
    session.pop("last_result", None)
    flash("Your course progress has been reset.", "success")
    return redirect(url_for("topics.list_topics"))


@main_bp.route("/complete")
def completion_page():
    """Celebration / completion flow page."""
    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)

    total = len(TOPICS)
    completed = sum(1 for t in TOPICS if bool(pmap.get(t["slug"], {}).get("passed")))
    course_done = (total > 0 and completed == total)

    if not course_done:
        flash("Finish all topics to unlock the completion page.", "error")
        return redirect(url_for("topics.list_topics"))

    return render_template(
        "complete.html",
        is_logged_in=bool(current_user.is_authenticated),
    )
