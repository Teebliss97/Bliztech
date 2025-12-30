import os
from functools import wraps
from datetime import datetime, timedelta

from flask import Blueprint, abort, render_template, request, redirect, url_for, flash
from flask_login import current_user

from app.extensions import db, limiter
from app.models import (
    User,
    Progress,
    Certificate,
    AdminAuditLog,
    SecurityEvent,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# -------------------------
# Helpers
# -------------------------

def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _audit(action: str, target_type: str = None, target_id: str = None, detail: str = None):
    """
    Durable admin audit log (tamper-evident).
    """
    try:
        log = AdminAuditLog(
            actor_user_id=current_user.id if current_user.is_authenticated else None,
            actor_email=current_user.email if current_user.is_authenticated else None,
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


def _parse_int(name: str, default: int, min_v: int, max_v: int) -> int:
    raw = (request.form.get(name) or request.args.get(name) or "").strip()
    try:
        v = int(raw)
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


# -------------------------
# Dashboard
# -------------------------

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


# -------------------------
# Users
# -------------------------

@admin_bp.route("/users")
@admin_required
@limiter.limit("60 per minute")
def users():
    order_col = getattr(User, "created_at", None) or User.id
    users = User.query.order_by(order_col.desc()).all()
    return render_template("admin/users.html", users=users)


# -------------------------
# Progress
# -------------------------

@admin_bp.route("/progress")
@admin_required
@limiter.limit("60 per minute")
def progress():
    rows = Progress.query.order_by(Progress.updated_at.desc()).limit(200).all()
    return render_template("admin/progress.html", rows=rows)


# -------------------------
# Certificates
# -------------------------

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
    passed_count = (
        Progress.query.filter_by(user_id=progress_key, passed=True)
        .filter(Progress.slug.like("topic%"))
        .count()
    )

    return render_template(
        "admin/certificate_detail.html",
        cert=cert,
        passed_count=passed_count,
    )


@admin_bp.route("/certificates/<cert_id>/reissue", methods=["POST"])
@admin_required
@limiter.limit("10 per minute; 30 per hour")
def certificate_reissue(cert_id: str):
    cert = Certificate.query.filter_by(cert_id=cert_id.upper()).first_or_404()

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
    cert = Certificate.query.filter_by(cert_id=cert_id.upper()).first_or_404()
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
    cert = Certificate.query.filter_by(cert_id=cert_id.upper()).first_or_404()

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


# -------------------------
# Audit Logs (read-only)
# -------------------------

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


# -------------------------
# Monitoring (Phase 5.2)
# -------------------------

@admin_bp.route("/monitoring")
@admin_required
@limiter.limit("30 per minute")
def monitoring():
    page = _parse_int("page", 1, 1, 10_000)
    per_page = 50

    q = (request.args.get("q") or "").strip()
    event = (request.args.get("event") or "").strip()
    ip = (request.args.get("ip") or "").strip()
    path = (request.args.get("path") or "").strip()
    status = (request.args.get("status") or "").strip()

    query = SecurityEvent.query.order_by(SecurityEvent.created_at.desc())

    if event:
        query = query.filter(SecurityEvent.event.ilike(f"%{event}%"))
    if ip:
        query = query.filter(SecurityEvent.ip.ilike(f"%{ip}%"))
    if path:
        query = query.filter(SecurityEvent.path.ilike(f"%{path}%"))
    if status:
        try:
            query = query.filter(SecurityEvent.status == int(status))
        except ValueError:
            pass
    if q:
        query = query.filter(SecurityEvent.detail.ilike(f"%{q}%"))

    total = query.count()
    pages = max(1, (total + per_page - 1) // per_page)

    events = query.offset((page - 1) * per_page).limit(per_page).all()

    return render_template(
        "admin/monitoring.html",
        events=events,
        total=total,
        page=page,
        pages=pages,
        has_prev=page > 1,
        has_next=page < pages,
        prev_num=page - 1,
        next_num=page + 1,
        q=q,
        event=event,
        ip=ip,
        path=path,
        status=status,
    )


# -------------------------
# Phase 5.3 — Retention Cleanup
# -------------------------

@admin_bp.route("/monitoring/cleanup", methods=["POST"])
@admin_required
@limiter.limit("5 per minute")
def monitoring_cleanup():
    keep_security_days = _parse_int("keep_security_days", 30, 1, 365)
    keep_audit_days = _parse_int("keep_audit_days", 180, 1, 3650)

    cutoff_security = datetime.utcnow() - timedelta(days=keep_security_days)
    cutoff_audit = datetime.utcnow() - timedelta(days=keep_audit_days)

    deleted_security = (
        SecurityEvent.query.filter(SecurityEvent.created_at < cutoff_security)
        .delete(synchronize_session=False)
    )
    deleted_audit = (
        AdminAuditLog.query.filter(AdminAuditLog.created_at < cutoff_audit)
        .delete(synchronize_session=False)
    )

    db.session.commit()

    _audit(
        action="MONITORING_CLEANUP",
        target_type="retention",
        target_id="security+audit",
        detail=f"security_days={keep_security_days},audit_days={keep_audit_days},"
               f"deleted_security={deleted_security},deleted_audit={deleted_audit}",
    )

    flash(
        f"Cleanup complete ✅ Deleted {deleted_security} security events "
        f"and {deleted_audit} audit logs.",
        "success",
    )
    return redirect(url_for("admin.monitoring"))


# -------------------------
# Admin bootstrap (one-time)
# -------------------------

@admin_bp.route("/bootstrap", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def bootstrap_admin():
    token_env = os.getenv("ADMIN_BOOTSTRAP_TOKEN")
    if not token_env:
        abort(404)

    if User.query.filter_by(is_admin=True).first():
        abort(403)

    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        email = (request.form.get("email") or "").strip().lower()

        if token != token_env:
            _audit("ADMIN_BOOTSTRAP_FAIL", "user", email, "bad_token")
            flash("Invalid token.", "error")
            return redirect(url_for("admin.bootstrap_admin"))

        user = User.query.filter_by(email=email).first()
        if not user:
            _audit("ADMIN_BOOTSTRAP_FAIL", "user", email, "user_not_found")
            flash("User not found. Register first.", "error")
            return redirect(url_for("admin.bootstrap_admin"))

        user.is_admin = True
        db.session.commit()

        _audit("ADMIN_BOOTSTRAP_SUCCESS", "user", email, "")
        flash(f"{email} is now an admin ✅", "success")
        return redirect(url_for("auth.login"))

    return render_template("admin/bootstrap.html")
