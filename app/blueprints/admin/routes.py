import os
from functools import wraps
from datetime import datetime, timedelta

from flask import Blueprint, abort, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user

from app.extensions import db, limiter
from app.models import (
    User,
    Progress,
    Certificate,
    AdminAuditLog,
    SecurityEvent,
    Referral,
    CourseAccess,
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


def _grant_course_access(email: str, sale_id: str = None, granted_by: str = "webhook") -> tuple[bool, str]:
    """
    Core logic to grant paid course access to a user by email.
    Returns (success: bool, message: str)
    """
    email = email.strip().lower()
    user = User.query.filter_by(email=email).first()

    if not user:
        return False, f"No account found for {email}. They need to register first."

    existing = CourseAccess.query.filter_by(user_id=user.id).first()
    if existing:
        return True, f"{email} already has access."

    access = CourseAccess(
        user_id=user.id,
        granted_at=datetime.utcnow(),
        granted_by=granted_by,
        gumroad_sale_id=sale_id,
    )
    user.has_course_access = True
    db.session.add(access)
    db.session.commit()

    return True, f"Access granted to {email}."


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
# Grant Course Access (manual)
# -------------------------

@admin_bp.route("/course/grant", methods=["GET", "POST"])
@admin_required
@limiter.limit("30 per minute")
def grant_course_access():
    message = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        sale_id = (request.form.get("sale_id") or "").strip() or None

        if not email:
            message = {"type": "error", "text": "Email is required."}
        else:
            success, msg = _grant_course_access(
                email=email,
                sale_id=sale_id,
                granted_by=current_user.email,
            )
            message = {"type": "success" if success else "error", "text": msg}
            _audit(
                action="COURSE_ACCESS_GRANT",
                target_type="user",
                target_id=email,
                detail=f"sale_id={sale_id or ''}, result={msg}",
            )

    access_list = (
        db.session.query(CourseAccess, User.email)
        .join(User, User.id == CourseAccess.user_id)
        .order_by(CourseAccess.granted_at.desc())
        .all()
    )

    rows = []
    for ca, email in access_list:
        rows.append({
            "email": email,
            "granted_at": ca.granted_at,
            "granted_by": ca.granted_by,
            "gumroad_sale_id": ca.gumroad_sale_id,
        })

    return render_template(
        "admin/grant_course_access.html",
        message=message,
        access_list=rows,
    )


# -------------------------
# Gumroad Webhook (automatic access)
# -------------------------

@admin_bp.route("/gumroad/webhook", methods=["POST"])
@limiter.limit("60 per minute")
def gumroad_webhook():
    """
    Gumroad pings this URL after every sale.
    Automatically grants paid course access to the buyer.

    Setup in Gumroad:
    Settings → Advanced → Ping URL → https://bliztechacademy.com/admin/gumroad/webhook

    Optional: set GUMROAD_WEBHOOK_SECRET in Render env vars and add it
    as a query param in the Gumroad ping URL for basic verification:
    https://bliztechacademy.com/admin/gumroad/webhook?secret=YOUR_SECRET
    """
    # Optional secret verification
    webhook_secret = os.getenv("GUMROAD_WEBHOOK_SECRET", "")
    if webhook_secret:
        provided = request.args.get("secret", "") or request.form.get("secret", "")
        if provided != webhook_secret:
            _audit("GUMROAD_WEBHOOK_REJECTED", "webhook", "gumroad", "bad_secret")
            return jsonify({"error": "Unauthorized"}), 401

    # Gumroad sends form data
    email = (request.form.get("email") or "").strip().lower()
    sale_id = (request.form.get("sale_id") or "").strip() or None
    product_id = (request.form.get("product_id") or "").strip()
    refunded = request.form.get("refunded", "false").lower() == "true"

    if not email:
        return jsonify({"error": "No email in payload"}), 400

    # Handle refunds — revoke access
    if refunded:
        user = User.query.filter_by(email=email).first()
        if user:
            access = CourseAccess.query.filter_by(user_id=user.id).first()
            if access:
                db.session.delete(access)
                user.has_course_access = False
                db.session.commit()
                _audit("GUMROAD_REFUND_REVOKE", "user", email, f"sale_id={sale_id}")
        return jsonify({"status": "access_revoked"}), 200

    # Grant access
    success, msg = _grant_course_access(
        email=email,
        sale_id=sale_id,
        granted_by="gumroad_webhook",
    )

    _audit(
        action="GUMROAD_WEBHOOK_GRANT" if success else "GUMROAD_WEBHOOK_FAIL",
        target_type="user",
        target_id=email,
        detail=f"sale_id={sale_id}, product_id={product_id}, result={msg}",
    )

    return jsonify({"status": "ok", "message": msg}), 200


# -------------------------
# Referrals
# -------------------------

@admin_bp.route("/referrals")
@admin_required
@limiter.limit("60 per minute")
def referrals():
    days = _parse_int("days", 30, 1, 3650)
    cutoff = datetime.utcnow() - timedelta(days=days)
    q = (request.args.get("q") or "").strip()

    latest_q = (
        db.session.query(
            Referral,
            User.email.label("referrer_email"),
            User.referral_code.label("referrer_code"),
        )
        .join(User, User.id == Referral.referrer_id)
        .filter(Referral.created_at >= cutoff)
        .order_by(Referral.created_at.desc())
    )
    if q:
        q_low = q.lower()
        latest_q = latest_q.filter(
            (User.email.ilike(f"%{q_low}%"))
            | (User.referral_code.ilike(f"%{q}%"))
            | (Referral.referral_code_used.ilike(f"%{q}%"))
        )
    latest = latest_q.limit(200).all()

    agg_q = (
        db.session.query(
            User.id,
            User.email,
            User.referral_code,
            db.func.count(Referral.id).label("referrals_count"),
            db.func.max(Referral.created_at).label("last_referral_at"),
        )
        .outerjoin(Referral, Referral.referrer_id == User.id)
        .group_by(User.id, User.email, User.referral_code)
        .order_by(db.desc("referrals_count"), db.desc("last_referral_at"))
    )
    if q:
        agg_q = agg_q.filter(
            (User.email.ilike(f"%{q}%"))
            | (User.referral_code.ilike(f"%{q}%"))
        )
    top_referrers = agg_q.limit(200).all()

    total_referrals_in_window = (
        Referral.query.filter(Referral.created_at >= cutoff).count()
    )

    return render_template(
        "admin/referrals.html",
        top_referrers=top_referrers,
        latest=latest,
        total_referrals_in_window=total_referrals_in_window,
        days=days,
        q=q,
    )


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
    _audit("CERT_REISSUE", "certificate", old_id, f"new_cert_id={cert.cert_id}")
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
    _audit("CERT_REVOKE", "certificate", cert.cert_id, f"reason={reason or ''}")
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
    _audit("CERT_UNREVOKE", "certificate", cert.cert_id, "")
    flash("Certificate un-revoked ✅", "success")
    return redirect(url_for("admin.certificate_detail", cert_id=cert.cert_id))


# -------------------------
# Audit Logs
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
# Monitoring
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
# Admin bootstrap
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