"""
BlizTech Academy — Central Access Control Helpers
app/utils/access.py

Single source of truth for course access logic.

After the free-pivot (May 2026):
    - The "Get Into Cybersecurity" advanced course is FREE.
    - Access is unlocked by completing the Free Awareness Course
      (all 10 topics passed in the `Progress` table).
    - Legacy paid-access flags (User.has_course_access, CourseAccess table)
      are no longer honoured — every user follows the same rule.
    - Admins always have access.

Import from here EVERYWHERE you need to check advanced-course access.
Do NOT duplicate this logic in individual blueprints.
"""

from flask_login import current_user

from app.models import Progress, User
from app.blueprints.topics.routes import TOPICS


# ─────────────────────────────────────────────────────────────────────────────
#  Progress key — matches the format used in topics/quizzes blueprints
# ─────────────────────────────────────────────────────────────────────────────

def _progress_key_for(user) -> str:
    """
    Build the Progress.user_id key used across the free course.
    Matches the format used in app/blueprints/topics/routes.py and
    app/blueprints/quizzes/routes.py — DO NOT change without migrating data.
    """
    return f"user:{user.id}"


# ─────────────────────────────────────────────────────────────────────────────
#  Awareness course completion check
# ─────────────────────────────────────────────────────────────────────────────

def has_completed_awareness(user) -> bool:
    """
    True if the given user has passed the quizzes for ALL 10 free-course topics.

    A topic is considered "completed" when its Progress row exists AND
    Progress.passed is True (i.e. user scored >= 70% on that topic's quiz).
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False

    progress_user_id = _progress_key_for(user)

    rows = Progress.query.filter_by(user_id=progress_user_id).all()
    pmap = {r.slug: r for r in rows}

    return all(
        (pmap.get(t["slug"]) is not None and pmap[t["slug"]].passed)
        for t in TOPICS
    )


def awareness_progress(user) -> dict:
    """
    Return progress stats for the awareness course.

    Returns:
        {
            "completed": int,    # number of topics passed
            "total": int,        # total topics
            "percent": int,      # 0-100
            "is_complete": bool, # all topics passed
            "next_slug": str|None,  # next incomplete topic slug (None if done)
        }
    """
    total = len(TOPICS)
    if user is None or not getattr(user, "is_authenticated", False):
        return {
            "completed": 0,
            "total": total,
            "percent": 0,
            "is_complete": False,
            "next_slug": TOPICS[0]["slug"] if TOPICS else None,
        }

    progress_user_id = _progress_key_for(user)
    rows = Progress.query.filter_by(user_id=progress_user_id).all()
    pmap = {r.slug: r for r in rows}

    completed = 0
    next_slug = None
    for t in TOPICS:
        row = pmap.get(t["slug"])
        if row and row.passed:
            completed += 1
        elif next_slug is None:
            next_slug = t["slug"]

    percent = int(round((completed / total) * 100)) if total else 0
    return {
        "completed": completed,
        "total": total,
        "percent": percent,
        "is_complete": completed == total,
        "next_slug": next_slug,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Advanced course access — the single check used everywhere
# ─────────────────────────────────────────────────────────────────────────────

def has_advanced_course_access(user) -> bool:
    """
    True if the user can access the "Get Into Cybersecurity" advanced course.

    Rules (May 2026 free pivot):
        - Admins always have access.
        - Otherwise, the user must have completed the awareness course.
        - Legacy paid flags (User.has_course_access, CourseAccess) are
          NOT honoured. Everyone follows the same rule.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False

    # Always re-fetch from DB to avoid stale current_user proxy data
    fresh = User.query.get(user.id)
    if fresh is None:
        return False

    if fresh.is_admin:
        return True

    return has_completed_awareness(fresh)


def current_user_has_advanced_access() -> bool:
    """Convenience wrapper for the current Flask-Login user."""
    return has_advanced_course_access(current_user)