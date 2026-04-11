from datetime import datetime
import re

from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
from flask_login import current_user
from app.models import Progress
from app.blueprints.topics.routes import TOPICS
from app.utils.ratelimit import rate_limit
from flask import make_response
from app.link_analyzer import analyze_url
from flask_login import login_required
from flask import jsonify
from flask_login import login_required, current_user
from app.models import LessonRead, CourseAccess, CourseTopic
from app.extensions import db, limiter
from markupsafe import escape

main_bp = Blueprint("main", __name__)

YOUTUBE_CHANNEL_URL = "https://www.youtube.com/@Bliz_Tech"
_REF_RE = re.compile(r"^[A-Za-z0-9]{4,64}$")

BOOKING_RECIPIENT = "Toheebatinuke@gmail.com"


@main_bp.app_context_processor
def inject_globals():
    has_cert = False
    if current_user.is_authenticated:
        from app.models import Certificate
        has_cert = current_user.is_admin or bool(
            Certificate.query.filter_by(
                user_id=current_user.id, revoked=False
            ).first()
        )
    return {
        "current_year": datetime.utcnow().year,
        "has_certificate": has_cert,
    }


def _login_required_redirect(message: str):
    flash(message, "error")
    return redirect(url_for("auth.login", next=request.path))


def _require_login(message: str = "Please log in to view your dashboard and track progress."):
    if not current_user.is_authenticated:
        return _login_required_redirect(message)
    return None


def _progress_key() -> str:
    return f"user:{current_user.id}"


def _progress_rows(progress_user_id: str):
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
    last_activity = None

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
    for i, t in enumerate(TOPICS, start=1):
        slug = t["slug"]
        row = pmap.get(slug)
        passed = bool(row and row.passed)
        if (not passed) and _is_unlocked(slug, pmap):
            return {"slug": slug, "title": t["title"], "label": f"Topic {i}"}
    return None


def _resume_topic(pmap: dict):
    candidate = None
    for t in TOPICS:
        slug = t["slug"]
        row = pmap.get(slug)
        if not row or row.passed:
            continue
        if row.updated_at and (candidate is None or row.updated_at > candidate.updated_at):
            candidate = row

    if candidate:
        t = next((x for x in TOPICS if x["slug"] == candidate.slug), None)
        return {"slug": candidate.slug, "title": t["title"] if t else candidate.slug, "updated_at": candidate.updated_at}

    return _next_unlocked_incomplete(pmap)


# -------------------------
# HOME
# -------------------------
@main_bp.route("/")
def home():
    ref = (request.args.get("ref") or "").strip()
    if ref and _REF_RE.match(ref):
        session["ref_code"] = ref

    if not current_user.is_authenticated:
        return render_template("home.html", youtube_url=YOUTUBE_CHANNEL_URL, progress=None, total_topics=len(TOPICS), course_done=False)

    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)
    stats = _course_stats(pmap)
    resume = _resume_topic(pmap)
    nxt = _next_unlocked_incomplete(pmap)

    progress = {
        "completed": stats["completed"],
        "total": stats["total"],
        "percent": stats["percent"],
        "course_done": stats["course_done"],
        "resume": resume,
        "next_topic": nxt,
    }

    return render_template("home.html", youtube_url=YOUTUBE_CHANNEL_URL, progress=progress, total_topics=stats["total"], course_done=stats["course_done"])


# -------------------------
# BOOK A SESSION
# -------------------------
@main_bp.route("/book-session", methods=["POST"])
@limiter.limit("5 per hour")
def book_session():
    # Escape all user input before using in HTML to prevent XSS
    name    = escape((request.form.get("name") or "").strip())
    email   = escape((request.form.get("email") or "").strip())
    topic   = escape((request.form.get("topic") or "").strip())
    message = escape((request.form.get("message") or "").strip())

    if not name or not email or not topic:
        return jsonify({"ok": False, "error": "Please fill in all required fields."}), 400

    from app.email_utils import send_email

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <h2 style="color:#00D97E;">New Mentorship Booking Request</h2>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px 0;color:#666;width:120px;">Name</td><td style="padding:8px 0;font-weight:bold;">{name}</td></tr>
        <tr><td style="padding:8px 0;color:#666;">Email</td><td style="padding:8px 0;font-weight:bold;">{email}</td></tr>
        <tr><td style="padding:8px 0;color:#666;">Topic</td><td style="padding:8px 0;">{topic}</td></tr>
        <tr><td style="padding:8px 0;color:#666;">Message</td><td style="padding:8px 0;">{message or '—'}</td></tr>
      </table>
      <hr style="border:1px solid #eee;margin:16px 0;">
      <p style="color:#666;font-size:13px;">Reply directly to <strong>{email}</strong> to confirm the session time and payment details.</p>
      <p style="color:#666;font-size:13px;">Price: ₦20,000 (Africa) · £20 (International) · 30 minutes</p>
    </div>
    """

    ok = send_email(
        to=BOOKING_RECIPIENT,
        subject=f"Mentorship Booking: {name} — {topic}",
        html=html,
    )

    if ok:
        return jsonify({"ok": True})
    else:
        return jsonify({"ok": False, "error": "Failed to send email. Please try again."}), 500


# -------------------------
# DASHBOARD
# -------------------------
@main_bp.route("/dashboard")
def dashboard():
    gate = _require_login("Please log in to view your dashboard.")
    if gate:
        return gate

    progress_user_id = _progress_key()
    pmap = _progress_map(progress_user_id)
    stats = _course_stats(pmap)
    resume = _resume_topic(pmap)
    nxt = _next_unlocked_incomplete(pmap)

    rows = []
    for i, t in enumerate(TOPICS, start=1):
        slug = t["slug"]
        row = pmap.get(slug)
        rows.append({
            "i": i, "slug": slug, "title": t["title"],
            "passed": bool(row and row.passed),
            "score": (row.score if row else None),
            "attempts": (row.attempts if row else 0),
            "updated_at": (row.updated_at if row else None),
            "unlocked": _is_unlocked(slug, pmap),
        })

    return render_template("dashboard.html", stats=stats, resume=resume, next_topic=nxt, rows=rows)


@main_bp.route("/progress")
def my_progress():
    gate = _require_login("Please log in to view your progress.")
    if gate:
        return gate
    return redirect(url_for("main.dashboard"))


@main_bp.route("/progress/reset", methods=["POST"])
@rate_limit("3 per minute")
def reset_progress():
    gate = _require_login("Please log in to reset your progress.")
    if gate:
        return gate

    confirm = (request.form.get("confirm") or "").strip().lower()
    if confirm != "reset":
        flash("Type RESET to confirm.", "error")
        return redirect(url_for("main.dashboard"))

    from app.extensions import db
    Progress.query.filter_by(user_id=_progress_key()).delete(synchronize_session=False)
    db.session.commit()
    session.pop("last_result", None)
    flash("Your course progress has been reset.", "success")
    return redirect(url_for("topics.list_topics"))


@main_bp.route("/complete")
def completion_page():
    gate = _require_login("Please log in to view the completion page.")
    if gate:
        return gate

    pmap = _progress_map(_progress_key())
    completed = sum(1 for t in TOPICS if pmap.get(t["slug"]) and pmap[t["slug"]].passed)

    if completed != len(TOPICS):
        flash("Finish all topics to unlock the completion page.", "error")
        return redirect(url_for("topics.list_topics"))

    return render_template("complete.html", is_logged_in=True)


# -------------------------
# SUPPORT / ABOUT / LEGAL
# -------------------------
@main_bp.route("/support")
def support():
    return render_template(
        "support.html",
        gumroad_url="https://atinuke2.gumroad.com/l/business-security?_gl=1*jf0s6y*_ga*MTc3OTIzMDQ0Mi4xNzY3OTE0ODcx*_ga_6LJN6D94N6*czE3NjgwMDg3NDYkbzQkZzEkdDE3NjgwMDg3NDYkajYwJGwwJGgw",
        paypal_email="atinukeadebayo97@gmail.com",
    )


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/privacy")
def privacy():
    return render_template("privacy.html")


@main_bp.route("/terms")
def terms():
    return render_template("terms.html")


@main_bp.route("/cookies")
def cookies():
    return render_template("cookies.html")


@main_bp.route("/disclaimer")
def disclaimer():
    return render_template("disclaimer.html")


# -------------------------
# SITEMAP
# -------------------------
@main_bp.route("/sitemap.xml", methods=["GET"])
def sitemap():
    pages = []
    lastmod = datetime.utcnow().date().isoformat()

    static_routes = [
        ("main.home", {}), ("topics.list_topics", {}), ("main.about", {}),
        ("main.support", {}), ("main.privacy", {}), ("main.terms", {}),
        ("main.cookies", {}), ("main.disclaimer", {}),
    ]

    for endpoint, params in static_routes:
        pages.append({"loc": url_for(endpoint, _external=True, **params), "lastmod": lastmod, "changefreq": "weekly", "priority": "0.8"})

    for topic in TOPICS:
        pages.append({"loc": url_for("topics.topic_detail", slug=topic["slug"], _external=True), "lastmod": lastmod, "changefreq": "monthly", "priority": "0.7"})

    xml = render_template("sitemap.xml", pages=pages)
    response = make_response(xml)
    response.headers["Content-Type"] = "application/xml"
    return response


# -------------------------
# LINK ANALYZER
# -------------------------
@main_bp.route('/link-analyzer', methods=['GET', 'POST'])
def link_analyzer():
    result = None
    url = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            result = analyze_url(url)
    return render_template('link_analyzer.html', result=result, url=url)


# -------------------------
# PAID COURSE — landing page
# -------------------------
@main_bp.route('/course')
def course():
    from app.models import CourseAccess
    has_access = False
    if current_user.is_authenticated:
        has_access = current_user.is_admin or bool(
            CourseAccess.query.filter_by(user_id=current_user.id).first()
        )
    return render_template('course.html', has_access=has_access)


# -------------------------
# PAID COURSE — lesson list
# -------------------------
@main_bp.route('/course/lessons')
@login_required
def course_lessons():
    from app.models import CourseTopic, CourseAccess, User
    fresh_user = User.query.get(current_user.id)
    has_access = (
        fresh_user.is_admin
        or bool(fresh_user.has_course_access)
        or bool(CourseAccess.query.filter_by(user_id=current_user.id).first())
    )
    if not has_access:
        flash("You need to purchase the course to access lessons.", "error")
        return redirect(url_for("main.course"))

    topics = CourseTopic.query.order_by(CourseTopic.order).all()

    section_names = {
        "A": "Foundation",
        "B": "Technical Core",
        "C": "Defence & Response",
        "D": "Career Launchpad",
    }

    sections = {"A": [], "B": [], "C": [], "D": []}
    for t in topics:
        key = t.section.strip().upper() if t.section else ""
        if key in sections:
            sections[key].append(t)

    return render_template("course_lessons.html", sections=sections, section_names=section_names, total=len(topics))


# -------------------------
# PAID COURSE — single lesson
# -------------------------
@main_bp.route('/course/lessons/<slug>')
@login_required
def course_lesson(slug):
    from app.models import CourseTopic, CourseAccess, User
    fresh_user = User.query.get(current_user.id)
    has_access = (
        fresh_user.is_admin
        or bool(fresh_user.has_course_access)
        or bool(CourseAccess.query.filter_by(user_id=current_user.id).first())
    )
    if not has_access:
        flash("You need to purchase the course to access lessons.", "error")
        return redirect(url_for("main.course"))

    topic = CourseTopic.query.filter_by(slug=slug).first_or_404()

    all_topics = CourseTopic.query.order_by(CourseTopic.order).all()
    idx = next((i for i, t in enumerate(all_topics) if t.slug == slug), None)
    prev_topic = all_topics[idx - 1] if idx and idx > 0 else None
    next_topic = all_topics[idx + 1] if idx is not None and idx < len(all_topics) - 1 else None

    return render_template("course_lesson.html", topic=topic, prev_topic=prev_topic, next_topic=next_topic)


# -------------------------
# PAID COURSE — thank you page
# -------------------------
@main_bp.route('/course/thankyou')
def course_thankyou():
    return render_template('course_thankyou.html')


# -------------------------
# PAID COURSE — check access (AJAX polling from thank you page)
# -------------------------
@main_bp.route('/course/check-access')
@login_required
def course_check_access():
    from app.models import CourseAccess
    has_access = current_user.is_admin or bool(
        CourseAccess.query.filter_by(user_id=current_user.id).first()
    )
    return jsonify({"has_access": has_access})


@main_bp.route("/course/lessons/<slug>/mark-read", methods=["POST"])
@login_required
def mark_lesson_read(slug):
    topic = CourseTopic.query.filter_by(slug=slug).first()
    if not topic:
        return jsonify({"ok": False, "error": "lesson not found"}), 404

    has_access = current_user.is_admin or CourseAccess.query.filter_by(user_id=current_user.id).first()
    if not has_access:
        return jsonify({"ok": False, "error": "no access"}), 403

    existing = LessonRead.query.filter_by(user_id=current_user.id, slug=slug).first()
    if not existing:
        read = LessonRead(user_id=current_user.id, slug=slug)
        db.session.add(read)
        db.session.commit()

    count = LessonRead.query.filter_by(user_id=current_user.id).count()
    return jsonify({"ok": True, "read_count": count, "all_done": count >= 20})