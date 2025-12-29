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

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from app.blueprints.cert import cert_bp
from app.extensions import db
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


def user_completed_course() -> bool:
    return _passed_topic_count() >= _required_topics()


def get_or_create_certificate(recipient_name: str) -> Certificate:
    existing = Certificate.query.filter_by(user_id=current_user.id).first()
    if existing:
        if recipient_name and recipient_name != existing.recipient_name:
            existing.recipient_name = recipient_name
            db.session.commit()
        return existing

    cert = Certificate(
        user_id=current_user.id,
        user_email=current_user.email,
        recipient_name=recipient_name,
        issued_at=datetime.utcnow(),
    )
    db.session.add(cert)
    db.session.commit()
    return cert


@cert_bp.route("/", methods=["GET"])
@login_required
def certificate_home():
    required = _required_topics()
    passed_count = _passed_topic_count()

    if passed_count < required:
        remaining = required - passed_count
        flash(f"Complete {remaining} more topic(s) to unlock your certificate.", "info")
        return redirect(url_for("topics.list_topics"))

    default_name = (current_user.email.split("@")[0] or "Student").replace(".", " ").title()

    existing = Certificate.query.filter_by(user_id=current_user.id).first()
    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    verify_url = None
    if existing and base_url:
        verify_url = f"{base_url}/certificate/verify/{existing.cert_id}"

    return render_template(
        "cert/certificate.html",
        default_name=default_name,
        cert=existing,
        verify_url=verify_url,
    )


@cert_bp.route("/pdf", methods=["POST"])
@login_required
def certificate_pdf():
    if not user_completed_course():
        abort(403)

    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Please enter your name for the certificate.", "error")
        return redirect(url_for("cert.certificate_home"))

    cert = get_or_create_certificate(name)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setTitle("BlizTech Certificate of Completion")

    # =========================================================
    # BACKGROUND (fills the entire page)
    # =========================================================
    bg_path = os.path.join(current_app.root_path, "static", "img", "certificate-bg.png")
    try:
        if os.path.exists(bg_path):
            bg = ImageReader(bg_path)
            c.drawImage(bg, 0, 0, width=width, height=height, mask="auto")
    except Exception:
        pass

    # =========================================================
    # TEXT (keep clean, no duplicate Director of Training text)
    # - Use italic for body text (not watermark)
    # =========================================================

    # Title (keep, but small enough to not fight watermark)
    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width / 2, height - 110, "CERTIFICATE OF COMPLETION")

    # Intro (italic)
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(width / 2, height - 150, "This is to certify that")

    # Name (bold, clean area)
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(width / 2, height - 210, cert.recipient_name)

    # Body (italic)
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(width / 2, height - 250, "has successfully completed the")

    # Course name (bold)
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width / 2, height - 280, "BlizTech Cyber Awareness Course")

    # Extra line (italic)
    c.setFont("Helvetica-Oblique", 11)
    c.drawCentredString(
        width / 2,
        height - 305,
        "demonstrating practical knowledge of cybersecurity best practices.",
    )

    # =========================================================
    # Footer details (keep near bottom, no extra signature text)
    # =========================================================
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(width / 2, 120, f"Issued: {cert.issued_at.strftime('%d %b %Y')}")
    c.drawCentredString(width / 2, 105, f"Certificate ID: {cert.cert_id}")

    base_url = current_app.config.get("RENDER_EXTERNAL_URL") or ""
    if base_url:
        verify_url = f"{base_url}/certificate/verify/{cert.cert_id}"
        c.setFont("Helvetica-Oblique", 9)
        c.drawCentredString(width / 2, 90, f"Verify: {verify_url}")

    # Tagline (italic) - optional and subtle
    c.setFont("Helvetica-Oblique", 9)
    c.drawCentredString(width / 2, 70, "BlizTech • Learn. Protect. Stay Safe.")

    # =========================================================
    # IMPORTANT: Only ONE PAGE
    # Do NOT call showPage() twice.
    # =========================================================
    c.showPage()
    c.save()

    buffer.seek(0)
    filename = f"BlizTech-Certificate-{cert.cert_id}.pdf"

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@cert_bp.route("/verify/<cert_id>", methods=["GET"])
def verify_certificate(cert_id: str):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first()
    if not cert:
        return render_template("cert/verify.html", found=False, cert_id=cert_id)

    return render_template("cert/verify.html", found=True, cert=cert)
