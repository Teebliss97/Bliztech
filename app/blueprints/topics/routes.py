from flask import Blueprint, render_template, session
from flask_login import current_user

from app.models import Progress

topics_bp = Blueprint("topics", __name__, url_prefix="/topics")

TOPICS = [
    {"slug": "topic1", "title": "Topic 1: Introduction to Cybersecurity", "content": "topic1_intro.html", "time": "3–5 mins"},
    {"slug": "topic2", "title": "Topic 2: Phishing & Scam Awareness", "content": "topic2_phishing.html", "time": "3–5 mins"},
    {"slug": "topic3", "title": "Topic 3: Passwords & Passphrases", "content": "topic3_passwords.html", "time": "3–5 mins"},
    {"slug": "topic4", "title": "Topic 4: Two-Factor Authentication (2FA)", "content": "topic4_2fa.html", "time": "3–5 mins"},
    {"slug": "topic5", "title": "Topic 5: Malware & Ransomware Basics", "content": "topic5_malware.html", "time": "4–6 mins"},
    {"slug": "topic6", "title": "Topic 6: Safe Browsing & Downloads", "content": "topic6_safe_browsing.html", "time": "3–5 mins"},
    {"slug": "topic7", "title": "Topic 7: Social Media Safety & Privacy", "content": "topic7_social_media.html", "time": "3–5 mins"},
    {"slug": "topic8", "title": "Topic 8: Public Wi-Fi & Mobile Safety", "content": "topic8_public_wifi.html", "time": "3–5 mins"},
    {"slug": "topic9", "title": "Topic 9: Online Shopping & Payment Safety", "content": "topic9_payments.html", "time": "3–5 mins"},
    {"slug": "topic10", "title": "Topic 10: Backups & Device Updates", "content": "topic10_backups_updates.html", "time": "3–5 mins"},
]

TOPIC_MAP = {t["slug"]: t for t in TOPICS}


# -------------------------
# IMPORTANT: Progress key
# -------------------------
def _progress_key():
    """
    Use a stable key for progress:
    - logged in users:  user:<id>
    - anonymous users:  anon:<uuid>  (stored in session)
    """
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    
    if "anon_id" not in session:
        import uuid
        session["anon_id"] = f"anon:{uuid.uuid4().hex}"
        
    return session.get("anon_id")


def _progress_dict(user_id: str) -> dict:
    if not user_id:
        return {}
    rows = Progress.query.filter_by(user_id=user_id).all()
    return {r.slug: r.to_dict() for r in rows}


def _is_unlocked(slug: str, progress: dict) -> bool:
    if slug == "topic1":
        return True

    idx = next((i for i, t in enumerate(TOPICS) if t["slug"] == slug), None)
    if idx is None:
        return False

    prev_slug = TOPICS[idx - 1]["slug"]
    return bool(progress.get(prev_slug, {}).get("passed"))


def _course_completed(progress: dict) -> bool:
    """
    True if all topics are passed in progress dict.
    (Ignores any special slugs like __course_completion_emailed__)
    """
    return all(bool(progress.get(t["slug"], {}).get("passed")) for t in TOPICS)


@topics_bp.route("/")
def list_topics():
    user_id = _progress_key()
    progress = _progress_dict(user_id)

    view = []
    completed_count = 0

    for t in TOPICS:
        slug = t["slug"]
        unlocked = _is_unlocked(slug, progress)
        p = progress.get(slug, {})
        completed = bool(p.get("passed"))

        if completed:
            completed_count += 1

        view.append({
            **t,
            "unlocked": unlocked,
            "completed": completed,
            "score": p.get("score"),
            "attempts": p.get("attempts", 0),
        })

    total = len(TOPICS)
    progress_pct = int(round((completed_count / total) * 100)) if total else 0

    # ✅ Certificate button only for logged-in users who completed all topics
    can_get_certificate = bool(current_user.is_authenticated and _course_completed(progress))

    return render_template(
        "topics/list.html",
        topics=view,
        completed_count=completed_count,
        total_topics=total,
        progress_pct=progress_pct,
        can_get_certificate=can_get_certificate,
    )


@topics_bp.route("/<slug>")
def topic_detail(slug):
    topic = TOPIC_MAP.get(slug)
    if not topic:
        return "Topic not found", 404

    user_id = _progress_key()
    progress = _progress_dict(user_id)

    if not _is_unlocked(slug, progress):
        return render_template("topics/locked.html", topic=topic), 403

    return render_template(
        "topics/detail.html",
        topic=topic,
        content_template=topic["content"]
    )
