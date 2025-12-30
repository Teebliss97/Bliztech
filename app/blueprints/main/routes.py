from datetime import datetime

from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from flask_login import current_user

from app.models import Progress
from app.blueprints.topics.routes import TOPICS
from app.utils.ratelimit import rate_limit

main_bp = Blueprint("main", __name__)


# -------------------------
# Phase 6 / 6.1.1: Account-based progress only
# -------------------------
def _login_required_redirect(message: str):
    flash(message, "error")
    return redirect(url_for("auth.login", next=request.path))


def _require_login(message: str = "Please log in to view your dashboard and track progress."):
    if not current_user.is_authenticated:
        return _login_required_redirect(message)
    return None


def _progress_key() -> str:
    """Logged-in users only."""
    return f"user:{current_user.id}"


def _progress_rows(progress_user_id: str):
    """Only topic rows (topic1..topic10)."""
    return (
        Progress.query.filter_by(user_id=progress_user_id)
        .filter(Progress.slug.like("topic%"))
        .all()
    )


def _progress_map(progress_user_id: str) -> dict:
    rows = _progress_rows(progress_user_id)
    return {r.slug: r for r in rows}


def _is_unlocked(slug: str, pmap: dict) -> bool:
    if slug == "topic1":
        return True

    idx = next((i for i, t in enumerate(TOPICS) if t["slug"] == slug), None)
    if idx is None or idx == 0:
        return False

    prev_slug = TOPICS[idx - 1]["slug"]
    prev_row = pmap.get(prev_slug)
    return bool(prev_row and prev_row.passed)


def _course_stats(pmap: dict):
    total = len(TOPICS)
    completed = 0
    attempts_total = 0
    last_activity = None  # datetime

    for t in TOPICS:
        row = pmap.get(t["slug"])
        if row:
            attempts_total += int(row.attempts or 0)
            if row.updated_at and (last_activity is None or row.updated_at > last_activity):
                last_activity = row.updated_at
            if row.passed:
                completed += 1

    percent = int(round((completed / total) * 100)) if total else 0
    course_done = (total > 0 and completed == total)

    return {
        "total": total,
        "completed": completed,
        "percent": percent,
        "course_done": course_done,
        "attempts_total": attempts_total,
        "last_activity": last_activity,
    }


def _next_unlocked_incomplete(pmap: dict):
    """
    Next step for the user:
    - first topic that is unlocked AND not passed
    """
    for i, t in enumerate(TOPICS, start=1):
        slug = t["slug"]
        row = pmap.get(slug)
        passed = bool(row and row.passed)
        if (not passed) and _is_unlocked(slug, pmap):
            return {
                "slug": slug,
                "title": t["title"],
                "label": f"Topic {i}",
            }
    return None


def _resume_topic(pmap: dict):
    """
    Continue where you stopped:
    - choose the most recently updated topic row that is NOT passed.
    - if none, fall back to next_unlocked_incomplete.
    """
    candidate = None
    for t in TOPICS:
        slug = t["slug"]
        row = pmap.get(slug)
        if not row:
            continue
        if row.passed:
            continue
        if row.updated_at and (candidate is None or row.updated_at > candidate.updated_at):
            candidate = row

    if candidate:
        t = next((x for x in TOPICS if x["slug"] == candidate.slug), None)
        return {
            "slug": candidate.slug,
            "title": t["title"] if t else candidate.slug,
            "updated_at": candidate.updated_at,
        }

    # fallback
    nxt = _next_unlocked_incomplete(pmap)
    if nxt:
        return {"slug": nxt["slug"], "title": nxt["title"], "updated_at": None}
    return None


# -------------------------
# HOME (keep it simple)
# -------------------------
@main_bp.route("/")
def home():
    """
    Home remains public.
    If logged in, show lightweight progress teaser (optional).
    If anon, just show normal homepage.
    """
    if not current_user.is_authenticated:
        return render_template("home.html", progress=None, total_topics=len(TOPICS), course_done=False)

    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)
    stats = _course_stats(pmap)
    nxt = _next_unlocked_incomplete(pmap)

    progress = None
    if stats["completed"] > 0 and nxt:
        progress = {
            "completed": stats["completed"],
            "total": stats["total"],
            "percent": stats["percent"],
            "next_slug": nxt["slug"],
            "next_label": nxt["label"],
        }

    return render_template(
        "home.html",
        progress=progress,
        total_topics=stats["total"],
        course_done=stats["course_done"],
    )


# -------------------------
# Phase 6.1.1: DASHBOARD
# -------------------------
@main_bp.route("/dashboard")
def dashboard():
    gate = _require_login("Please log in to view your dashboard and continue your course.")
    if gate:
        return gate

    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)

    stats = _course_stats(pmap)
    resume = _resume_topic(pmap)
    nxt = _next_unlocked_incomplete(pmap)

    # Build topic table rows (for quick glance)
    rows = []
    for i, t in enumerate(TOPICS, start=1):
        slug = t["slug"]
        row = pmap.get(slug)
        passed = bool(row and row.passed)
        rows.append(
            {
                "i": i,
                "slug": slug,
                "title": t["title"],
                "passed": passed,
                "score": (row.score if row else None),
                "attempts": (row.attempts if row else 0),
                "updated_at": (row.updated_at if row else None),
                "unlocked": _is_unlocked(slug, pmap),
            }
        )

    return render_template(
        "dashboard.html",
        stats=stats,
        resume=resume,
        next_topic=nxt,
        rows=rows,
    )


# -------------------------
# Backward compatible: /progress -> /dashboard
# -------------------------
@main_bp.route("/progress")
def my_progress():
    gate = _require_login("Please log in to view your progress.")
    if gate:
        return gate
    return redirect(url_for("main.dashboard"))


@main_bp.route("/progress/reset", methods=["POST"])
@rate_limit(limit=3, window_seconds=60, key_prefix="reset")
def reset_progress():
    """
    Logged-in users only: reset THEIR own progress.
    (Aligns with Phase 6: no anon progress.)
    """
    gate = _require_login("Please log in to reset your progress.")
    if gate:
        return gate

    confirm = (request.form.get("confirm") or "").strip().lower()
    if confirm != "reset":
        flash("Type RESET to confirm.", "error")
        return redirect(url_for("main.dashboard"))

    from app.extensions import db
    progress_user_id = _progress_key()

    Progress.query.filter_by(user_id=progress_user_id).delete(synchronize_session=False)
    db.session.commit()

    session.pop("last_result", None)
    flash("Your course progress has been reset.", "success")
    return redirect(url_for("topics.list_topics"))


@main_bp.route("/complete")
def completion_page():
    """
    Completion page should be logged-in only (certificate + trust).
    """
    gate = _require_login("Please log in to view the completion page.")
    if gate:
        return gate

    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)

    total = len(TOPICS)
    completed = sum(1 for t in TOPICS if bool(pmap.get(t["slug"]) and pmap[t["slug"]].passed))
    course_done = (total > 0 and completed == total)

    if not course_done:
        flash("Finish all topics to unlock the completion page.", "error")
        return redirect(url_for("topics.list_topics"))

    return render_template("complete.html", is_logged_in=True)
