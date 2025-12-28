import io
import os
from datetime import datetime

from flask import render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import login_required, current_user

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from app.blueprints.cert import cert_bp
from app.extensions import db
from app.models import Certificate, Progress

# Import your TOPICS list so we only count real topic slugs
from app.blueprints.topics.routes import TOPICS


def _user_progress_key() -> str:
    return f"user:{current_user.id}"


def _required_topics_count() -> int:
    """
    By default: required = len(TOPICS) (your full course)
    But you can temporarily test with 1 topic by setting:
      CERT_REQUIRED_TOPICS=1   (in Render env vars)
    """
    raw = os.getenv("CERT_REQUIRED_TOPICS", "").strip()
    if raw.isdigit():
        return max(1, int(raw))
    return len(TOPICS)


def user_completed_course() -> bool:
    """
    Only count PASSED rows for real topic slugs (topic1..topic10).
    """
    topic_slugs = [t["slug"] for t in TOPICS]

    passed_count = (
        Progress.query.filter(
            Progress.user_id == _user_progress_key(),
            Progress.passed.is_(True),
            Progress.slug.in_(topic_slugs),
        )
        .with_entities(Progress.slug)
        .distinct()
        .count()
    )

    return passed_count >= _required_topics_count()


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
    if not user_completed_course():
        flash("Complete all topics to unlock your certificate ✅", "error")
        return redirect(url_for("topics.list_topics"))

    default_name = (current_user.email.split("@")[0] or "Student").replace(".", " ").title()
    return render_template("cert/certificate.html", default_name=default_name)


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

    # Create PDF in memory
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setTitle("BlizTech Certificate")

    # Header
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(width / 2, height - 120, "CERTIFICATE OF COMPLETION")

    c.setFont("Helvetica", 12)
    c.drawCentredString(width / 2, height - 150, "This certifies that")

    # Name
    c.setFont("Helvetica-Bold", 26)
    c.drawCentredString(width / 2, height - 200, cert.recipient_name)

    c.setFont("Helvetica", 12)
    c.drawCentredString(width / 2, height - 230, "has successfully completed the")

    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width / 2, height - 260, "BlizTech Cyber Awareness Course")

    # Details
    c.setFont("Helvetica", 11)
    c.drawCentredString(width / 2, height - 310, f"Issued: {cert.issued_at.strftime('%d %b %Y')}")
    c.drawCentredString(width / 2, height - 330, f"Certificate ID: {cert.cert_id}")

    # Verification URL (Render env var)
    base_url = (os.getenv("RENDER_EXTERNAL_URL") or "").strip().rstrip("/")
    if base_url:
        verify_url = f"{base_url}/certificate/verify/{cert.cert_id}"
        c.setFont("Helvetica", 10)
        c.drawCentredString(width / 2, 110, f"Verify: {verify_url}")

    # Footer
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(width / 2, 80, "BlizTech • Learn. Protect. Stay Safe.")

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
