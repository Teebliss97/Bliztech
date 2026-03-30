import io
import os
from datetime import datetime

from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    abort,
    current_app,
)
from flask_login import login_required, current_user

from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors

from app.blueprints.cert import cert_bp
from app.extensions import db, limiter
from app.models import Certificate, Progress


def _user_progress_key() -> str:
    return f"user:{current_user.id}"


def _required_topics() -> int:
    v = current_app.config.get("CERT_REQUIRED_TOPICS") or os.getenv("CERT_REQUIRED_TOPICS", "10")
    try:
        return max(1, int(v))
    except Exception:
        return 10


def _passed_topic_count() -> int:
    return (
        Progress.query.filter_by(user_id=_user_progress_key(), passed=True)
        .filter(Progress.slug.like("topic%"))
        .with_entities(Progress.slug)
        .distinct()
        .count()
    )


def user_completed_free_course() -> bool:
    return _passed_topic_count() >= _required_topics()


def user_completed_paid_course() -> bool:
    from app.models import CourseTopic, CourseAccess
    has_access = current_user.is_admin or CourseAccess.query.filter_by(user_id=current_user.id).first()
    if not has_access:
        return False
    # Check all 20 paid course lessons exist — we just verify access for now
    # In future this can check a PaidProgress model
    return True


def get_or_create_certificate(recipient_name: str, course_type: str = "free"):
    """Get or create a certificate. course_type: 'free' or 'paid'"""
    # Use cert_id prefix to distinguish: free certs = standard, paid = 'P' prefix
    # For simplicity, paid course gets a separate certificate record using user_id + type
    # We store them in the same table but with different cert_ids
    if course_type == "paid":
        # Look for existing paid cert (cert_id starts with 'P')
        existing = Certificate.query.filter_by(user_id=current_user.id).filter(
            Certificate.cert_id.like('P%')
        ).first()
    else:
        existing = Certificate.query.filter_by(user_id=current_user.id).filter(
            ~Certificate.cert_id.like('P%')
        ).first()

    if existing:
        if recipient_name and recipient_name != existing.recipient_name:
            existing.recipient_name = recipient_name
            db.session.commit()
        return existing

    import uuid
    cert_id_val = ('P' + uuid.uuid4().hex[:11].upper()) if course_type == "paid" else None

    cert = Certificate(
        user_id=current_user.id,
        user_email=current_user.email,
        recipient_name=recipient_name,
        issued_at=datetime.utcnow(),
    )
    if cert_id_val:
        cert.cert_id = cert_id_val

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

    # Check paid course access
    has_access = current_user.is_admin or CourseAccess.query.filter_by(user_id=current_user.id).first()
    if not has_access:
        flash("You need to purchase the course to access a certificate.", "error")
        return redirect(url_for("main.course"))

    default_name = (current_user.email.split("@")[0] or "Student").replace(".", " ").title()

    # Look for existing paid cert
    existing = Certificate.query.filter_by(user_id=current_user.id).filter(
        Certificate.cert_id.like('P%')
    ).first()

    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    verify_url = None
    if existing and base_url:
        verify_url = f"{base_url}/certificate/verify/{existing.cert_id}"

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

    cert = get_or_create_certificate(name, course_type="paid")

    # ── PDF generation ──────────────────────────────────────────
    pagesize = landscape(A4)
    width, height = pagesize
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=pagesize)
    c.setTitle("BlizTech Certificate of Completion")

    # Background image
    bg_path = os.path.join(current_app.root_path, "static", "img", "certificate-bg.png")
    try:
        if os.path.exists(bg_path):
            bg = ImageReader(bg_path)
            c.drawImage(bg, 0, 0, width=width, height=height, mask="auto")
    except Exception:
        # Fallback: draw a clean dark background
        c.setFillColorRGB(0.05, 0.05, 0.05)
        c.rect(0, 0, width, height, fill=1, stroke=0)

    center_x = width / 2

    # Green top border
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(4)
    c.line(40, height - 10, width - 40, height - 10)

    # Green bottom border
    c.line(40, 10, width - 40, 10)

    # ── Header ──
    # BlizTech logo text
    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(center_x, height - 55, "BLIZTECH ACADEMY")

    c.setFillColorRGB(0.6, 0.6, 0.6)
    c.setFont("Helvetica", 9)
    c.drawCentredString(center_x, height - 72, "bliztechacademy.com")

    # Divider line
    c.setStrokeColorRGB(0.15, 0.15, 0.15)
    c.setLineWidth(0.5)
    c.line(60, height - 85, width - 60, height - 85)

    # Certificate title
    c.setFillColorRGB(0.9, 0.9, 0.9)
    c.setFont("Helvetica", 11)
    c.drawCentredString(center_x, height - 115, "CERTIFICATE OF COMPLETION")

    # Decorative line under title
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(1)
    line_w = 180
    c.line(center_x - line_w/2, height - 122, center_x + line_w/2, height - 122)

    # ── Body ──
    c.setFillColorRGB(0.65, 0.65, 0.65)
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(center_x, height - 160, "This is to certify that")

    # Recipient name
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 36)
    c.drawCentredString(center_x, height - 210, cert.recipient_name)

    # Name underline
    name_width = c.stringWidth(cert.recipient_name, "Helvetica-Bold", 36)
    c.setStrokeColorRGB(0, 0.85, 0.49)
    c.setLineWidth(1)
    c.line(center_x - name_width/2, height - 218, center_x + name_width/2, height - 218)

    c.setFillColorRGB(0.65, 0.65, 0.65)
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(center_x, height - 248, "has successfully completed the paid course")

    # Course name
    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(center_x, height - 285, "Get Into Cybersecurity")

    # Course detail
    c.setFillColorRGB(0.55, 0.55, 0.55)
    c.setFont("Helvetica", 10)
    c.drawCentredString(center_x, height - 308,
        "20 structured lessons  ·  4 sections  ·  4 practical labs  ·  Lifetime access")

    # ── Footer ──
    # Three footer columns
    footer_y = 80
    col1_x = width * 0.22
    col2_x = width * 0.5
    col3_x = width * 0.78

    # Divider line above footer
    c.setStrokeColorRGB(0.15, 0.15, 0.15)
    c.setLineWidth(0.5)
    c.line(60, footer_y + 36, width - 60, footer_y + 36)

    c.setFillColorRGB(0.45, 0.45, 0.45)
    c.setFont("Helvetica", 8)
    c.drawCentredString(col1_x, footer_y + 22, "ISSUED BY")
    c.drawCentredString(col2_x, footer_y + 22, "CERTIFICATE ID")
    c.drawCentredString(col3_x, footer_y + 22, "DATE ISSUED")

    c.setFillColorRGB(0.85, 0.85, 0.85)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(col1_x, footer_y + 6, "BlizTech Academy")

    c.setFillColorRGB(0, 0.85, 0.49)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(col2_x, footer_y + 6, cert.cert_id)

    c.setFillColorRGB(0.85, 0.85, 0.85)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(col3_x, footer_y + 6, cert.issued_at.strftime("%d %B %Y"))

    # Verification URL
    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    if base_url:
        verify_url = f"{base_url}/certificate/verify/{cert.cert_id}"
        c.setFillColorRGB(0.4, 0.4, 0.4)
        c.setFont("Helvetica", 8)
        c.drawCentredString(center_x, footer_y - 14, f"Verify at: {verify_url}")

    c.showPage()
    c.save()
    buffer.seek(0)

    filename = f"BlizTech-GIC-Certificate-{cert.cert_id}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


# ─────────────────────────────────────────────
# CERTIFICATE VERIFICATION (shared)
# ─────────────────────────────────────────────

@cert_bp.route("/verify/<cert_id>", methods=["GET"])
@limiter.limit("30 per minute; 200 per day")
def verify_certificate(cert_id: str):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    if not cert:
        return render_template("cert/verify.html", found=False, cert_id=cert_id)
    return render_template("cert/verify.html", found=True, cert=cert)