from flask import Blueprint, render_template, session
from flask_login import current_user

from app.models import Progress
from app.blueprints.topics.routes import TOPICS

main_bp = Blueprint("main", __name__)


def _progress_key() -> str:
    # logged in users: user:<id>
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    # anonymous users: anon:<uuid> stored in session
    return session.get("anon_id")


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
            # user said topic title not necessary -> show "Topic 2" style label
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
