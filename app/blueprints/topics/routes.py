from flask import Blueprint, render_template, session, url_for
from flask_login import current_user

from app.models import Progress

topics_bp = Blueprint("topics", __name__, url_prefix="/topics")

TOPICS = [
    {
        "slug": "topic1",
        "title": "Topic 1: Introduction to Cybersecurity",
        "description": "Understand what cybersecurity is, why it matters, and how everyday users are affected by cyber threats.",
        "content": "topic1_intro.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic2",
        "title": "Topic 2: Phishing & Scam Awareness",
        "description": "Learn how phishing scams work, common warning signs, and how attackers trick users into giving away information.",
        "content": "topic2_phishing.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic3",
        "title": "Topic 3: Passwords & Passphrases",
        "description": "Learn how to create strong passwords and passphrases, and why weak passwords are one of the biggest security risks.",
        "content": "topic3_passwords.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic4",
        "title": "Topic 4: Two-Factor Authentication (2FA)",
        "description": "Understand how two-factor authentication works and why it adds an extra layer of protection to your accounts.",
        "content": "topic4_2fa.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic5",
        "title": "Topic 5: Malware & Ransomware Basics",
        "description": "Learn what malware and ransomware are, how they infect devices, and the impact they can have on data and systems.",
        "content": "topic5_malware.html",
        "time": "4–6 mins",
    },
    {
        "slug": "topic6",
        "title": "Topic 6: Safe Browsing & Downloads",
        "description": "Learn how to browse the web safely, avoid malicious downloads, and recognise unsafe websites.",
        "content": "topic6_safe_browsing.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic7",
        "title": "Topic 7: Social Media Safety & Privacy",
        "description": "Understand how social media platforms collect data and how to protect your privacy and personal information online.",
        "content": "topic7_social_media.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic8",
        "title": "Topic 8: Public Wi-Fi & Mobile Safety",
        "description": "Learn the risks of public Wi-Fi and how to keep your phone and data secure when on the move.",
        "content": "topic8_public_wifi.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic9",
        "title": "Topic 9: Online Shopping & Payment Safety",
        "description": "Learn how to shop online safely, recognise secure payment methods, and avoid common online shopping scams.",
        "content": "topic9_payments.html",
        "time": "3–5 mins",
    },
    {
        "slug": "topic10",
        "title": "Topic 10: Backups & Device Updates",
        "description": "Understand why regular backups and software updates are critical for protecting your devices and data.",
        "content": "topic10_backups_updates.html",
        "time": "3–5 mins",
    },
]

TOPIC_MAP = {t["slug"]: t for t in TOPICS}


# -------------------------
# Phase 6: Soft gating rules
# -------------------------
def _user_progress_key() -> str | None:
    """
    Phase 6 decision:
    - Only logged-in users have stored progress.
    - Anonymous users can READ topics but do NOT track progress / unlock.
    """
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return None


def _progress_dict(user_id: str | None) -> dict:
    if not user_id:
        return {}
    rows = Progress.query.filter_by(user_id=user_id).all()
    return {r.slug: r.to_dict() for r in rows}


def _is_unlocked_for_logged_in(slug: str, progress: dict) -> bool:
    """
    Unlock logic applies only to logged-in users (progress-based).
    """
    if slug == "topic1":
        return True

    idx = next((i for i, t in enumerate(TOPICS) if t["slug"] == slug), None)
    if idx is None:
        return False

    prev_slug = TOPICS[idx - 1]["slug"]
    return bool(progress.get(prev_slug, {}).get("passed"))


def _course_completed(progress: dict) -> bool:
    return all(bool(progress.get(t["slug"], {}).get("passed")) for t in TOPICS)


@topics_bp.route("/")
def list_topics():
    user_id = _user_progress_key()
    progress = _progress_dict(user_id)

    view = []
    completed_count = 0

    for t in TOPICS:
        slug = t["slug"]

        if current_user.is_authenticated:
            unlocked = _is_unlocked_for_logged_in(slug, progress)
        else:
            unlocked = True  # allow reading lessons freely for anon

        p = progress.get(slug, {}) if current_user.is_authenticated else {}
        completed = bool(p.get("passed")) if current_user.is_authenticated else False

        if completed:
            completed_count += 1

        view.append({
            **t,
            "unlocked": unlocked,
            "completed": completed,
            "score": p.get("score"),
            "attempts": p.get("attempts", 0) if current_user.is_authenticated else 0,
        })

    total = len(TOPICS)
    progress_pct = int(round((completed_count / total) * 100)) if total else 0

    # Certificate only for logged-in users who completed all topics
    can_get_certificate = bool(current_user.is_authenticated and _course_completed(progress))

    # For template UI (nice CTA)
    login_url = url_for("auth.login", next=url_for("topics.list_topics"))

    return render_template(
        "topics/list.html",
        topics=view,
        completed_count=completed_count,
        total_topics=total,
        progress_pct=progress_pct,
        can_get_certificate=can_get_certificate,
        is_anon=not current_user.is_authenticated,
        login_url=login_url,
    )


@topics_bp.route("/<slug>")
def topic_detail(slug):
    topic = TOPIC_MAP.get(slug)
    if not topic:
        return "Topic not found", 404

    # Phase 6:
    # - anon users can read topic content (no 403 locked page)
    # - unlocking rules apply only to logged-in users
    if current_user.is_authenticated:
        user_id = _user_progress_key()
        progress = _progress_dict(user_id)

        if not _is_unlocked_for_logged_in(slug, progress):
            # Keep your existing locked experience for logged-in users
            return render_template("topics/locked.html", topic=topic), 403

    login_url = url_for("auth.login", next=url_for("topics.topic_detail", slug=slug))

    return render_template(
        "topics/detail.html",
        topic=topic,
        content_template=topic["content"],
        is_anon=not current_user.is_authenticated,
        login_url=login_url,
    )
