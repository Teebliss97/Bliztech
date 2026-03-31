import io
import os
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


# ── FREE COURSE — disabled ───────────────────────────────────

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


# ── PAID COURSE CERTIFICATE ──────────────────────────────────

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

    from app.models import CourseTopic
    total_lessons = CourseTopic.query.count()

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

    if not current_user.is_admin:
        completed_count = int(request.form.get("completed_count", "0") or "0")
        from app.models import CourseTopic
        total = CourseTopic.query.count()
        if completed_count < total:
            flash(f"Complete all {total} lessons to download your certificate. You have completed {completed_count}.", "error")
            return redirect(url_for("cert.paid_certificate_home"))

    cert = get_or_create_paid_certificate(name)
    buf = _generate_certificate_pdf(cert)
    filename = f"BlizTech-GIC-Certificate-{cert.cert_id}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")


def _generate_certificate_pdf(cert):
    """
    Premium dark certificate — landscape A4 (841.9 x 595.3 pts)
    Content is spread across the full height with generous spacing.
    """
    pagesize = landscape(A4)
    W, H = pagesize  # 841.9 x 595.3
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=pagesize)
    c.setTitle("BlizTech — Certificate of Completion")

    # ── Background ──────────────────────────────────────────
    c.setFillColorRGB(0.04, 0.04, 0.05)
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # Subtle green glow — top right
    for i in range(6):
        r = 220 - i * 30
        alpha = 0.015 - i * 0.002
        if r > 0 and alpha > 0:
            c.saveState()
            c.setFillColorRGB(0, 0.85, 0.49)
            c.setFillAlpha(alpha)
            c.ellipse(W - 60 - r, H - 60 - r, W - 60 + r, H - 60 + r, fill=1, stroke=0)
            c.restoreState()

    # ── Borders ─────────────────────────────────────────────
    c.setStrokeColorRGB(0.12, 0.12, 0.15)
    c.setLineWidth(1)
    c.rect(14, 14, W - 28, H - 28, fill=0, stroke=1)

    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(0.5)
    c.rect(20, 20, W - 40, H - 40, fill=0, stroke=1)

    # Top green bar
    c.setFillColorRGB(0, 0.85, 0.49)
    c.rect(20, H - 20, W - 40, 4, fill=1, stroke=0)
    # Bottom green bar
    c.rect(20, 20, W - 40, 4, fill=1, stroke=0)

    # Corner accents
    a = 22
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(1.5)
    for px, py, dx, dy in [(26, H-26, 1, -1), (W-26, H-26, -1, -1), (26, 26, 1, 1), (W-26, 26, -1, 1)]:
        c.line(px, py, px + dx*a, py)
        c.line(px, py, px, py + dy*a)

    cx = W / 2

    # ── Header — y positions from top ───────────────────────
    # H = 595. Work top-down leaving good margins.

    # Brand name
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(cx, H - 68, "BLIZTECH ACADEMY")

    # URL
    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica", 10)
    c.drawCentredString(cx, H - 88, "bliztechacademy.com")

    # Thin divider
    c.setStrokeColorRGB(0.18, 0.18, 0.22)
    c.setLineWidth(0.5)
    c.line(cx - 220, H - 102, cx + 220, H - 102)

    # "CERTIFICATE OF COMPLETION"
    c.setFillColorRGB(0.78, 0.78, 0.82)
    c.setFont("Helvetica-Bold", 13)
    title = "CERTIFICATE  OF  COMPLETION"
    c.drawCentredString(cx, H - 124, title)

    # Green underline
    tw = c.stringWidth(title, "Helvetica-Bold", 13)
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(1)
    c.line(cx - tw/2, H - 131, cx + tw/2, H - 131)

    # ── Body — spread across middle of page ─────────────────
    # Available vertical space: from H-150 down to ~160 (footer area)
    # That's about 390pts — use it generously

    # "This is to certify that"
    c.setFillColorRGB(0.55, 0.55, 0.62)
    c.setFont("Helvetica-Oblique", 13)
    c.drawCentredString(cx, H - 175, "This is to certify that")

    # Recipient name
    name_size = 46
    nw = c.stringWidth(cert.recipient_name, "Helvetica-Bold", name_size)
    while nw > W - 140 and name_size > 28:
        name_size -= 2
        nw = c.stringWidth(cert.recipient_name, "Helvetica-Bold", name_size)

    c.setFillColorRGB(0.97, 0.97, 1.0)
    c.setFont("Helvetica-Bold", name_size)
    c.drawCentredString(cx, H - 232, cert.recipient_name)

    # Gold underline
    c.setStrokeColorRGB(0.85, 0.70, 0.25)
    c.setLineWidth(1.2)
    c.line(cx - nw/2, H - 242, cx + nw/2, H - 242)

    # "has successfully completed"
    c.setFillColorRGB(0.55, 0.55, 0.62)
    c.setFont("Helvetica-Oblique", 13)
    c.drawCentredString(cx, H - 278, "has successfully completed")

    # Course name
    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(cx, H - 322, "Get Into Cybersecurity")

    # Detail line
    c.setFillColorRGB(0.48, 0.48, 0.54)
    c.setFont("Helvetica", 12)
    c.drawCentredString(cx, H - 356,
        "20 structured lessons  \u00b7  4 sections  \u00b7  4 practical labs  \u00b7  Lifetime access")

    # ── Footer ──────────────────────────────────────────────
    # Footer divider sits at y=148 — well above the bottom border
    footer_y = 155
    c.setStrokeColorRGB(0.16, 0.16, 0.20)
    c.setLineWidth(0.5)
    c.line(40, footer_y, W - 40, footer_y)

    col_l = W * 0.22
    col_c = cx
    col_r = W * 0.78

    # Labels
    c.setFillColorRGB(0.38, 0.38, 0.44)
    c.setFont("Helvetica", 9)
    c.drawCentredString(col_l, footer_y - 20, "ISSUED BY")
    c.drawCentredString(col_c, footer_y - 20, "CERTIFICATE ID")
    c.drawCentredString(col_r, footer_y - 20, "DATE ISSUED")

    # Values
    c.setFillColorRGB(0.82, 0.82, 0.88)
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(col_l, footer_y - 40, "BlizTech Academy")

    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(col_c, footer_y - 40, cert.cert_id)

    c.setFillColorRGB(0.82, 0.82, 0.88)
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(col_r, footer_y - 40, cert.issued_at.strftime("%d %B %Y"))

    # Verify URL
    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    if base_url:
        verify_url = f"{base_url}/certificate/verify/{cert.cert_id}"
        c.setFillColorRGB(0.30, 0.30, 0.36)
        c.setFont("Helvetica", 8)
        c.drawCentredString(cx, footer_y - 60, f"Verify: {verify_url}")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf


# ── VERIFICATION ─────────────────────────────────────────────

@cert_bp.route("/verify/<cert_id>", methods=["GET"])
@limiter.limit("30 per minute; 200 per day")
def verify_certificate(cert_id):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    if not cert:
        return render_template("cert/verify.html", found=False, cert_id=cert_id)
    return render_template("cert/verify.html", found=True, cert=cert)