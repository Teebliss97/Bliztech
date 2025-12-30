import os
from functools import wraps
from datetime import datetime, timedelta

from flask import Blueprint, abort, render_template, request, redirect, url_for, flash
from flask_login import current_user

from app.extensions import db, limiter
from app.models import User, Progress, Certificate, AdminAuditLog, SecurityEvent, LoginSecurityState

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _audit(action: str, target_type: str = None, target_id: str = None, detail: str = None):
    """
    Durable admin audit log.
    """
    try:
        log = AdminAuditLog(
            actor_user_id=getattr(current_user, "id", None) if current_user.is_authenticated else None,
            actor_email=getattr(current_user, "email", None) if current_user.is_authenticated else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip=_client_ip(),
            user_agent=(request.headers.get("User-Agent") or "")[:300],
            detail=detail,
            created_at=datetime.utcnow(),
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/")
@admin_required
@limiter.limit("60 per minute")
def dashboard():
    total_users = User.query.count()
    total_progress = Progress.query.count()
    passed_count = Progress.query.filter_by(passed=True).count()

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_progress=total_progress,
        passed_count=passed_count,
    )


@admin_bp.route("/monitoring")
@admin_required
@limiter.limit("30 per minute")
def monitoring():
    now = datetime.utcnow()
    since_24h = now - timedelta(hours=24)

    def _count(name: str) -> int:
        return (
            SecurityEvent.query
            .filter(SecurityEvent.event == name)
            .filter(SecurityEvent.created_at >= since_24h)
            .count()
        )

    counts = {
        "rate_limited_24h": _count("rate_limited"),
        "auth_failed_24h": _count("auth_login_failed"),
        "auth_locked_24h": _count("auth_login_locked"),
        "http_error_24h": _count("http_error"),
        "slow_request_24h": _count("slow_request"),
    }

    events = (
        SecurityEvent.query
        .order_by(SecurityEvent.created_at.desc())
        .limit(200)
        .all()
    )

    locked_now = (
        LoginSecurityState.query
        .filter(LoginSecurityState.locked_until != None)  # noqa
        .filter(LoginSecurityState.locked_until > now)
        .order_by(LoginSecurityState.locked_until.desc())
        .limit(200)
        .all()
    )

    return render_template(
        "admin/monitoring.html",
        counts=counts,
        events=events,
        locked_now=locked_now,
        now=now,
    )


@admin_bp.route("/users")
@admin_required
@limiter.limit("60 per minute")
def users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/progress")
@admin_required
@limiter.limit("60 per minute")
def progress():
    rows = Progress.query.order_by(Progress.updated_at.desc()).limit(200).all()
    return render_template("admin/progress.html", rows=rows)


@admin_bp.route("/certificates")
@admin_required
@limiter.limit("30 per minute")
def certificates():
    q = (request.args.get("q") or "").strip()
    query = Certificate.query.order_by(Certificate.issued_at.desc())

    if q:
        q_up = q.upper()
        query = query.filter(
            (Certificate.cert_id.ilike(f"%{q_up}%"))
            | (Certificate.user_email.ilike(f"%{q}%"))
            | (Certificate.recipient_name.ilike(f"%{q}%"))
        )

    certs = query.limit(200).all()
    return render_template("admin/certificates.html", certs=certs, q=q)


@admin_bp.route("/certificates/<cert_id>")
@admin_required
@limiter.limit("60 per minute")
def certificate_detail(cert_id: str):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first_or_404()

    progress_key = f"user:{cert.user_id}"
    passed_topics = (
        Progress.query.filter_by(user_id=progress_key, passed=True)
        .filter(Progress.slug.like("topic%"))
    )
    passed_count = passed_topics.count()

    return render_template(
        "admin/certificate_detail.html",
        cert=cert,
        passed_count=passed_count,
    )


@admin_bp.route("/certificates/<cert_id>/reissue", methods=["POST"])
@admin_required
@limiter.limit("10 per minute; 30 per hour")
def certificate_reissue(cert_id: str):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first_or_404()

    import uuid
    old_id = cert.cert_id
    cert.cert_id = uuid.uuid4().hex[:12].upper()
    cert.issued_at = datetime.utcnow()
    cert.revoked = False
    cert.revoked_at = None
    cert.revoked_reason = None

    db.session.commit()

    _audit(
        action="CERT_REISSUE",
        target_type="certificate",
        target_id=old_id,
        detail=f"new_cert_id={cert.cert_id}",
    )

    flash("Certificate re-issued with a new ID ✅", "success")
    return redirect(url_for("admin.certificate_detail", cert_id=cert.cert_id))


@admin_bp.route("/certificates/<cert_id>/revoke", methods=["POST"])
@admin_required
@limiter.limit("10 per minute; 30 per hour")
def certificate_revoke(cert_id: str):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first_or_404()

    reason = (request.form.get("reason") or "").strip() or None
    cert.revoked = True
    cert.revoked_at = datetime.utcnow()
    cert.revoked_reason = reason
    db.session.commit()

    _audit(
        action="CERT_REVOKE",
        target_type="certificate",
        target_id=cert.cert_id,
        detail=f"reason={reason or ''}",
    )

    flash("Certificate revoked.", "success")
    return redirect(url_for("admin.certificate_detail", cert_id=cert.cert_id))


@admin_bp.route("/certificates/<cert_id>/unrevoke", methods=["POST"])
@admin_required
@limiter.limit("10 per minute; 30 per hour")
def certificate_unrevoke(cert_id: str):
    cert_id = (cert_id or "").strip().upper()
    cert = Certificate.query.filter_by(cert_id=cert_id).first_or_404()

    cert.revoked = False
    cert.revoked_at = None
    cert.revoked_reason = None
    db.session.commit()

    _audit(
        action="CERT_UNREVOKE",
        target_type="certificate",
        target_id=cert.cert_id,
        detail="",
    )

    flash("Certificate un-revoked ✅", "success")
    return redirect(url_for("admin.certificate_detail", cert_id=cert.cert_id))


@admin_bp.route("/audit")
@admin_required
@limiter.limit("30 per minute")
def audit_logs():
    q = (request.args.get("q") or "").strip()

    query = AdminAuditLog.query.order_by(AdminAuditLog.created_at.desc())

    if q:
        query = query.filter(
            (AdminAuditLog.actor_email.ilike(f"%{q}%"))
            | (AdminAuditLog.action.ilike(f"%{q}%"))
            | (AdminAuditLog.target_id.ilike(f"%{q}%"))
            | (AdminAuditLog.target_type.ilike(f"%{q}%"))
        )

    logs = query.limit(200).all()
    return render_template("admin/audit.html", logs=logs, q=q)


@admin_bp.route("/bootstrap", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def bootstrap_admin():
    token_env = os.getenv("ADMIN_BOOTSTRAP_TOKEN")
    if not token_env:
        abort(404)

    existing_admin = User.query.filter_by(is_admin=True).first()
    if existing_admin:
        abort(403)

    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        email = (request.form.get("email") or "").strip().lower()

        if token != token_env:
            _audit(action="ADMIN_BOOTSTRAP_FAIL", target_type="user", target_id=email, detail="bad_token")
            flash("Invalid token.", "error")
            return redirect(url_for("admin.bootstrap_admin"))

        user = User.query.filter_by(email=email).first()
        if not user:
            _audit(action="ADMIN_BOOTSTRAP_FAIL", target_type="user", target_id=email, detail="user_not_found")
            flash("User not found. Register first, then try again.", "error")
            return redirect(url_for("admin.bootstrap_admin"))

        user.is_admin = True
        db.session.commit()

        _audit(action="ADMIN_BOOTSTRAP_SUCCESS", target_type="user", target_id=email, detail="")
        flash(f"{email} is now an admin ✅", "success")
        return redirect(url_for("auth.login"))

    return render_template("admin/bootstrap.html")
