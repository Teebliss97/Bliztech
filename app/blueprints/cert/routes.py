import io
import os
import math
from datetime import datetime

from flask import (
    render_template, request, redirect, url_for,
    flash, send_file, abort, current_app,
)
from flask_login import login_required, current_user

from reportlab.lib.pagesizes import landscape, A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from app.blueprints.cert import cert_bp
from app.extensions import db, limiter
from app.models import Certificate, Progress


def _passed_topic_count():
    key = f"user:{current_user.id}"
    return (
        Progress.query.filter_by(user_id=key, passed=True)
        .filter(Progress.slug.like("topic%"))
        .with_entities(Progress.slug)
        .distinct()
        .count()
    )


def _required_topics():
    v = current_app.config.get("CERT_REQUIRED_TOPICS") or os.getenv("CERT_REQUIRED_TOPICS", "10")
    try:
        return max(1, int(v))
    except Exception:
        return 10


def user_completed_free_course():
    return _passed_topic_count() >= _required_topics()


def get_or_create_paid_certificate(recipient_name):
    existing = Certificate.query.filter_by(user_id=current_user.id).filter(
        Certificate.cert_id.like('P%')
    ).first()
    if existing:
        if recipient_name and recipient_name != existing.recipient_name:
            existing.recipient_name = recipient_name
            db.session.commit()
        return existing
    import uuid
    cert = Certificate(
        user_id=current_user.id,
        user_email=current_user.email,
        recipient_name=recipient_name,
        issued_at=datetime.utcnow(),
    )
    cert.cert_id = 'P' + uuid.uuid4().hex[:11].upper()
    db.session.add(cert)
    db.session.commit()
    return cert


def _has_paid_access():
    from app.models import CourseAccess
    return current_user.is_admin or bool(CourseAccess.query.filter_by(user_id=current_user.id).first())


# ─────────────────────────────────────────────
# FREE COURSE — disabled
# ─────────────────────────────────────────────

@cert_bp.route("/", methods=["GET"])
@login_required
@limiter.limit("30 per minute")
def certificate_home():
    flash("The free course certificate has been retired. Complete the paid course to earn a certificate.", "info")
    return redirect(url_for("main.course"))


@cert_bp.route("/pdf", methods=["POST"])
@login_required
@limiter.limit("10 per minute; 30 per hour")
def certificate_pdf():
    flash("The free course certificate has been retired.", "info")
    return redirect(url_for("main.course"))


# ─────────────────────────────────────────────
# PAID COURSE CERTIFICATE
# ─────────────────────────────────────────────

@cert_bp.route("/paid", methods=["GET"])
@login_required
@limiter.limit("30 per minute")
def paid_certificate_home():
    if not _has_paid_access():
        flash("You need to purchase the course to access a certificate.", "error")
        return redirect(url_for("main.course"))

    default_name = (current_user.email.split("@")[0] or "Student").replace(".", " ").title()
    existing = Certificate.query.filter_by(user_id=current_user.id).filter(
        Certificate.cert_id.like('P%')
    ).first()

    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    verify_url = f"{base_url}/certificate/verify/{existing.cert_id}" if existing and base_url else None

    # Check if user has completed all 20 lessons
    # Admins can always download; regular users must complete all lessons
    from app.models import CourseTopic
    total_lessons = CourseTopic.query.count()
    course_complete = current_user.is_admin  # admins always get access
    # For non-admins, we pass the flag to the template — actual enforcement is in the PDF route

    return render_template(
        "cert/paid_certificate.html",
        default_name=default_name,
        cert=existing,
        verify_url=verify_url,
        is_admin=current_user.is_admin,
        total_lessons=total_lessons,
    )


@cert_bp.route("/paid/pdf", methods=["POST"])
@login_required
@limiter.limit("10 per minute; 30 per hour")
def paid_certificate_pdf():
    if not _has_paid_access():
        abort(403)

    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Please enter your name for the certificate.", "error")
        return redirect(url_for("cert.paid_certificate_home"))

    # Completion check — admins bypass, regular users must complete all lessons
    # We check via a hidden field sent from the form (JS sets it based on localStorage)
    if not current_user.is_admin:
        completed_count = int(request.form.get("completed_count", "0") or "0")
        from app.models import CourseTopic
        total = CourseTopic.query.count()
        if completed_count < total:
            flash(f"You need to complete all {total} lessons before downloading your certificate. You have completed {completed_count}.", "error")
            return redirect(url_for("cert.paid_certificate_home"))

    cert = get_or_create_paid_certificate(name)
    buf = _generate_certificate_pdf(cert)

    filename = f"BlizTech-GIC-Certificate-{cert.cert_id}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")


def _generate_certificate_pdf(cert):
    """
    Generate a premium dark certificate PDF entirely in code.
    No background image — clean dark theme matching BlizTech brand.
    Landscape A4: 841.9 × 595.3 pts
    """
    pagesize = landscape(A4)
    W, H = pagesize
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=pagesize)
    c.setTitle("BlizTech — Certificate of Completion")

    # ── Background ──────────────────────────────────────────────
    # Deep dark background
    c.setFillColorRGB(0.04, 0.04, 0.05)
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # Subtle green radial glow top-right
    # Approximate with layered transparent rectangles
    for i in range(8):
        alpha = 0.018 - i * 0.002
        r = 180 - i * 20
        if alpha > 0 and r > 0:
            c.setFillColorRGB(0, 0.85, 0.49)
            c.saveState()
            # Can't do true radial, so use concentric circles via ellipse
            c.setFillAlpha(alpha)
            cx_glow = W - 80
            cy_glow = H - 60
            c.ellipse(cx_glow - r, cy_glow - r, cx_glow + r, cy_glow + r, fill=1, stroke=0)
            c.restoreState()

    # ── Border ───────────────────────────────────────────────────
    # Outer border
    c.setStrokeColorRGB(0.12, 0.12, 0.14)
    c.setLineWidth(1)
    c.rect(16, 16, W - 32, H - 32, fill=0, stroke=1)

    # Inner accent border — green
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(0.4)
    c.rect(22, 22, W - 44, H - 44, fill=0, stroke=1)

    # Green top bar
    c.setFillColorRGB(0, 0.85, 0.49)
    c.rect(22, H - 22, W - 44, 3, fill=1, stroke=0)

    # Green bottom bar
    c.rect(22, 22, W - 44, 3, fill=1, stroke=0)

    cx = W / 2

    # ── Header ───────────────────────────────────────────────────
    # BlizTech wordmark
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(cx, H - 60, "BLIZTECH ACADEMY")

    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica", 8)
    c.drawCentredString(cx, H - 74, "bliztechacademy.com")

    # Divider
    c.setStrokeColorRGB(0.15, 0.15, 0.18)
    c.setLineWidth(0.5)
    c.line(cx - 200, H - 84, cx + 200, H - 84)

    # "CERTIFICATE OF COMPLETION"
    c.setFillColorRGB(0.75, 0.75, 0.80)
    c.setFont("Helvetica", 9)
    # Letter-spaced via drawString with manual spacing
    title_text = "CERTIFICATE  OF  COMPLETION"
    c.drawCentredString(cx, H - 104, title_text)

    # Green underline
    tw = c.stringWidth(title_text, "Helvetica", 9)
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(0.8)
    c.line(cx - tw/2, H - 109, cx + tw/2, H - 109)

    # ── Body ─────────────────────────────────────────────────────
    # "This is to certify that"
    c.setFillColorRGB(0.55, 0.55, 0.60)
    c.setFont("Helvetica-Oblique", 11)
    c.drawCentredString(cx, H - 148, "This is to certify that")

    # Recipient name — large white bold
    name_size = 38
    # Scale down if name is long
    nw = c.stringWidth(cert.recipient_name, "Helvetica-Bold", name_size)
    while nw > W - 160 and name_size > 22:
        name_size -= 2
        nw = c.stringWidth(cert.recipient_name, "Helvetica-Bold", name_size)

    c.setFillColorRGB(0.96, 0.96, 0.98)
    c.setFont("Helvetica-Bold", name_size)
    c.drawCentredString(cx, H - 196, cert.recipient_name)

    # Gold underline
    c.setStrokeColorRGB(0.85, 0.70, 0.25)
    c.setLineWidth(1)
    c.line(cx - nw/2, H - 204, cx + nw/2, H - 204)

    # "has successfully completed"
    c.setFillColorRGB(0.55, 0.55, 0.60)
    c.setFont("Helvetica-Oblique", 11)
    c.drawCentredString(cx, H - 228, "has successfully completed")

    # Course name — green
    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(cx, H - 260, "Get Into Cybersecurity")

    # Detail line
    c.setFillColorRGB(0.40, 0.40, 0.45)
    c.setFont("Helvetica", 9)
    c.drawCentredString(cx, H - 280,
        "20 structured lessons  \u00b7  4 sections  \u00b7  4 practical labs  \u00b7  Lifetime access")

    # ── Footer divider ────────────────────────────────────────────
    c.setStrokeColorRGB(0.12, 0.12, 0.15)
    c.setLineWidth(0.5)
    footer_line_y = 120
    c.line(40, footer_line_y, W - 40, footer_line_y)

    # ── Footer columns ────────────────────────────────────────────
    col_l = W * 0.20
    col_c = cx
    col_r = W * 0.80

    label_y = footer_line_y - 16
    value_y = footer_line_y - 32

    c.setFillColorRGB(0.35, 0.35, 0.40)
    c.setFont("Helvetica", 7.5)
    c.drawCentredString(col_l, label_y, "ISSUED BY")
    c.drawCentredString(col_c, label_y, "CERTIFICATE ID")
    c.drawCentredString(col_r, label_y, "DATE ISSUED")

    c.setFillColorRGB(0.80, 0.80, 0.85)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(col_l, value_y, "BlizTech Academy")

    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(col_c, value_y, cert.cert_id)

    c.setFillColorRGB(0.80, 0.80, 0.85)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(col_r, value_y, cert.issued_at.strftime("%d %B %Y"))

    # Verify URL
    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    if base_url:
        verify_url = f"{base_url}/certificate/verify/{cert.cert_id}"
        c.setFillColorRGB(0.28, 0.28, 0.32)
        c.setFont("Helvetica", 7)
        c.drawCentredString(cx, footer_line_y - 48, f"Verify at: {verify_url}")

    # ── Corner accents ────────────────────────────────────────────
    accent = 18
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(1.5)
    # Top-left
    c.line(28, H - 28, 28 + accent, H - 28)
    c.line(28, H - 28, 28, H - 28 - accent)
    # Top-right
    c.line(W - 28, H - 28, W - 28 - accent, H - 28)
    c.line(W - 28, H - 28, W - 28, H - 28 - accent)
    # Bottom-left
    c.line(28, 28, 28 + accent, 28)
    c.line(28, 28, 28, 28 + accent)
    # Bottom-right
    c.line(W - 28, 28, W - 28 - accent, 28)
    c.line(W - 28, 28, W - 28, 28 + accent)

    # ── Shield icon (simple geometric, bottom-left area) ──────────
    sx, sy = 100, 82
    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFillAlpha(0.12)
    # Shield outline
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(0.8)
    c.setFillAlpha(0.08)
    shield_pts = [
        (sx, sy + 28), (sx + 20, sy + 28),
        (sx + 20, sy + 8), (sx + 10, sy),
        (sx, sy + 8), (sx, sy + 28)
    ]
    path = c.beginPath()
    path.moveTo(*shield_pts[0])
    for pt in shield_pts[1:]:
        path.lineTo(*pt)
    path.close()
    c.drawPath(path, fill=1, stroke=1)
    c.setFillAlpha(1)

    c.showPage()
    c.save()
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────
# VERIFICATION
# ─────────────────────────────────────────────

@cert_bp.route("/verify/<cert_id>", methods=["GET"])
@limiter.limit("30 per minute; 200 per day")
def verify_certificate(cert_id):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    if not cert:
        return render_template("cert/verify.html", found=False, cert_id=cert_id)
    return render_template("cert/verify.html", found=True, cert=cert)