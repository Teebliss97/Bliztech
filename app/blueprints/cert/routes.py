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


def _user_progress_key():
    return f"user:{current_user.id}"


def _required_topics():
    v = current_app.config.get("CERT_REQUIRED_TOPICS") or os.getenv("CERT_REQUIRED_TOPICS", "10")
    try:
        return max(1, int(v))
    except Exception:
        return 10


def _passed_topic_count():
    return (
        Progress.query.filter_by(user_id=_user_progress_key(), passed=True)
        .filter(Progress.slug.like("topic%"))
        .with_entities(Progress.slug)
        .distinct()
        .count()
    )


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


# ─────────────────────────────────────────────
# FREE COURSE CERTIFICATE — disabled
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
    from app.models import CourseAccess
    has_access = current_user.is_admin or CourseAccess.query.filter_by(user_id=current_user.id).first()
    if not has_access:
        flash("You need to purchase the course to access a certificate.", "error")
        return redirect(url_for("main.course"))

    default_name = (current_user.email.split("@")[0] or "Student").replace(".", " ").title()
    existing = Certificate.query.filter_by(user_id=current_user.id).filter(
        Certificate.cert_id.like('P%')
    ).first()

    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    verify_url = f"{base_url}/certificate/verify/{existing.cert_id}" if existing and base_url else None

    return render_template(
        "cert/paid_certificate.html",
        default_name=default_name,
        cert=existing,
        verify_url=verify_url,
    )


@cert_bp.route("/paid/pdf", methods=["POST"])
@login_required
@limiter.limit("10 per minute; 30 per hour")
def paid_certificate_pdf():
    from app.models import CourseAccess
    has_access = current_user.is_admin or CourseAccess.query.filter_by(user_id=current_user.id).first()
    if not has_access:
        abort(403)

    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Please enter your name for the certificate.", "error")
        return redirect(url_for("cert.paid_certificate_home"))

    cert = get_or_create_paid_certificate(name)

    # ── PDF ─────────────────────────────────────────────────────
    # Background image is 800×533 portrait-ish, used landscape A4
    # A4 landscape = 841.9 × 595.3 pts
    pagesize = landscape(A4)
    W, H = pagesize
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=pagesize)
    c.setTitle("BlizTech Certificate of Completion")

    # 1. Draw background full page
    bg_path = os.path.join(current_app.root_path, "static", "img", "certificate-bg.png")
    if os.path.exists(bg_path):
        try:
            c.drawImage(ImageReader(bg_path), 0, 0, width=W, height=H, preserveAspectRatio=False)
        except Exception:
            pass

    # The background already has:
    #   - BlizTech logo + branding (top left)
    #   - "CERTIFICATE OF COMPLETION" heading (upper centre)
    #   - Gold seal (bottom left)
    #   - Signature / Director of Training (bottom right)
    #   - Tagline (bottom centre)
    #   - Watermark
    #
    # We ONLY add the dynamic recipient block in the centre white space.
    # Working from top of page downward:
    #   ~y=430  heading sits here (approx)
    #   ~y=370  our content starts

    cx = W / 2

    # "This is to certify that"
    c.setFillColorRGB(0.30, 0.30, 0.40)
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(cx, H - 200, "This is to certify that")

    # Recipient name — large dark navy
    c.setFillColorRGB(0.08, 0.10, 0.22)
    c.setFont("Helvetica-Bold", 36)
    c.drawCentredString(cx, H - 246, cert.recipient_name)

    # Gold underline beneath name
    nw = c.stringWidth(cert.recipient_name, "Helvetica-Bold", 36)
    c.setStrokeColorRGB(0.72, 0.58, 0.18)
    c.setLineWidth(0.8)
    c.line(cx - nw/2, H - 254, cx + nw/2, H - 254)

    # "has successfully completed"
    c.setFillColorRGB(0.35, 0.35, 0.45)
    c.setFont("Helvetica-Oblique", 11)
    c.drawCentredString(cx, H - 278, "has successfully completed")

    # Course name — brand green
    c.setFillColorRGB(0.0, 0.55, 0.33)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(cx, H - 308, "Get Into Cybersecurity")

    # Detail line
    c.setFillColorRGB(0.45, 0.45, 0.55)
    c.setFont("Helvetica", 9)
    c.drawCentredString(cx, H - 328,
        "20 structured lessons  \u00b7  4 sections  \u00b7  4 practical labs  \u00b7  Lifetime access")

    # Footer data — slot into the existing footer area of the background
    # bg footer labels sit around y=88, values around y=72
    # columns: issued by ~x=220, cert id ~cx, date ~x=W-200
    col_l = 220
    col_c = cx
    col_r = W - 200

    c.setFillColorRGB(0.40, 0.40, 0.50)
    c.setFont("Helvetica", 7.5)
    c.drawCentredString(col_l, 92, "ISSUED BY")
    c.drawCentredString(col_c, 92, "CERTIFICATE ID")
    c.drawCentredString(col_r, 92, "DATE ISSUED")

    c.setFillColorRGB(0.10, 0.12, 0.24)
    c.setFont("Helvetica-Bold", 9.5)
    c.drawCentredString(col_l, 76, "BlizTech Academy")

    c.setFillColorRGB(0.0, 0.50, 0.30)
    c.setFont("Helvetica-Bold", 9.5)
    c.drawCentredString(col_c, 76, cert.cert_id)

    c.setFillColorRGB(0.10, 0.12, 0.24)
    c.setFont("Helvetica-Bold", 9.5)
    c.drawCentredString(col_r, 76, cert.issued_at.strftime("%d %B %Y"))

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f"BlizTech-GIC-Certificate-{cert.cert_id}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")


# ─────────────────────────────────────────────
# CERTIFICATE VERIFICATION
# ─────────────────────────────────────────────

@cert_bp.route("/verify/<cert_id>", methods=["GET"])
@limiter.limit("30 per minute; 200 per day")
def verify_certificate(cert_id):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    if not cert:
        return render_template("cert/verify.html", found=False, cert_id=cert_id)
    return render_template("cert/verify.html", found=True, cert=cert)