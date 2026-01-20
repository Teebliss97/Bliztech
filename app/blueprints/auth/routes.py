import os
import uuid
import json
import re
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

from flask import render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, current_user

from app.blueprints.auth import auth_bp
from app.email_utils import send_email
from app.extensions import db, limiter
from app.models import (
    User,
    Progress,
    LoginSecurityState,
    SecurityEvent,
    Referral,
)


def _anon_key():
    return session.get("anon_id")


def _user_key(user_id: int):
    return f"user:{user_id}"


def _mask_email(email: str) -> str:
    """
    Mask email for logs: to***@domain.com
    """
    email = (email or "").strip().lower()
    if "@" not in email:
        return "unknown"
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        masked = "*" * len(name)
    else:
        masked = name[:2] + "*" * (len(name) - 2)
    return f"{masked}@{domain}"


def _log_auth_event(event: str, **fields):
    """
    Phase 5.2:
    - JSON logs to Render
    - Persist to DB (SecurityEvent) if DB_MONITORING_ENABLED=1
    """
    payload = {"event": event, **fields}
    current_app.logger.info(json.dumps(payload, default=str, separators=(",", ":")))

    if os.getenv("DB_MONITORING_ENABLED", "1") != "1":
        return

    try:
        ev = SecurityEvent(
            event=event,
            ip=fields.get("ip"),
            email_masked=fields.get("email"),
            endpoint=request.endpoint,
            path=request.path,
            method=request.method,
            status=None,
            duration_ms=None,
            detail=str(fields)[:2000],
            created_at=datetime.utcnow(),
        )
        db.session.add(ev)
        db.session.commit()
    except Exception:
        db.session.rollback()


def _merge_progress(anon_id: str, user_id: str):
    anon_rows = Progress.query.filter_by(user_id=anon_id).all()
    if not anon_rows:
        return

    for r in anon_rows:
        existing = Progress.query.filter_by(user_id=user_id, slug=r.slug).first()

        if existing is None:
            r.user_id = user_id
            db.session.add(r)
            continue

        existing.attempts = (existing.attempts or 0) + (r.attempts or 0)
        existing.passed = bool(existing.passed or r.passed)
        existing.score = max(existing.score or 0, r.score or 0)

        if r.updated_at and (not existing.updated_at or r.updated_at > existing.updated_at):
            existing.updated_at = r.updated_at

        db.session.delete(r)
        db.session.add(existing)

    db.session.commit()


def _admin_emails_set() -> set[str]:
    raw = os.getenv("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def _ensure_admin_if_allowed(user: User) -> bool:
    allowed = _admin_emails_set()
    if not allowed:
        return False

    if user.email.lower() in allowed and not getattr(user, "is_admin", False):
        user.is_admin = True
        db.session.add(user)
        db.session.commit()
        return True

    return False


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _lockout_config():
    max_attempts = int(os.getenv("AUTH_LOCKOUT_MAX_ATTEMPTS", "5"))
    window_minutes = int(os.getenv("AUTH_LOCKOUT_WINDOW_MINUTES", "10"))
    ban_minutes = int(os.getenv("AUTH_LOCKOUT_BAN_MINUTES", "15"))
    return max_attempts, window_minutes, ban_minutes


def _get_state(email: str, ip: str) -> LoginSecurityState:
    email = (email or "").strip().lower()
    ip = (ip or "").strip()
    state = LoginSecurityState.query.filter_by(email=email, ip=ip).first()
    if not state:
        state = LoginSecurityState(email=email, ip=ip, attempts=0, first_attempt_at=datetime.utcnow())
        db.session.add(state)
        db.session.commit()
    return state


def _is_locked(state: LoginSecurityState) -> bool:
    return bool(state.locked_until and state.locked_until > datetime.utcnow())


def _register_failed_login(email: str, ip: str) -> tuple[bool, int, int]:
    """
    Returns (is_now_locked, seconds_remaining_if_locked, attempts_now)
    """
    max_attempts, window_minutes, ban_minutes = _lockout_config()
    now = datetime.utcnow()

    state = _get_state(email, ip)

    state.last_attempt_at = now
    if _is_locked(state):
        db.session.add(state)
        db.session.commit()
        seconds = int((state.locked_until - now).total_seconds())
        return True, max(0, seconds), state.attempts or 0

    window = timedelta(minutes=window_minutes)
    if state.first_attempt_at and (now - state.first_attempt_at) > window:
        state.attempts = 0
        state.first_attempt_at = now

    state.attempts = (state.attempts or 0) + 1
    state.last_attempt_at = now

    if state.attempts >= max_attempts:
        state.locked_until = now + timedelta(minutes=ban_minutes)
        db.session.add(state)
        db.session.commit()
        seconds = int((state.locked_until - now).total_seconds())
        return True, max(0, seconds), state.attempts or 0

    db.session.add(state)
    db.session.commit()
    return False, 0, state.attempts or 0


def _clear_login_state(email: str, ip: str) -> None:
    email = (email or "").strip().lower()
    ip = (ip or "").strip()
    state = LoginSecurityState.query.filter_by(email=email, ip=ip).first()
    if state:
        db.session.delete(state)
        db.session.commit()


def _safe_next_url(default_endpoint: str = "main.home") -> str:
    """
    Prevent open redirects:
    - only allow relative paths on this site (e.g. /quiz/topic1)
    - allow empty => go home
    """
    nxt = request.args.get("next") or request.form.get("next") or ""
    nxt = (nxt or "").strip()

    if not nxt:
        return url_for(default_endpoint)

    parts = urlsplit(nxt)

    # If user tries to pass an absolute URL (netloc set), ignore it.
    if parts.scheme or parts.netloc:
        return url_for(default_endpoint)

    # Ensure it starts with /
    if not parts.path.startswith("/"):
        return url_for(default_endpoint)

    # Rebuild safe relative URL (path + query only)
    safe_rel = urlunsplit(("", "", parts.path, parts.query, ""))
    return safe_rel


# -------------------------
# Password policy (Option B)
# -------------------------
_PASSWORD_POLICY = {
    "min_len": 8,
    "upper": re.compile(r"[A-Z]"),
    "lower": re.compile(r"[a-z]"),
    "digit": re.compile(r"\d"),
    "special": re.compile(r"[^A-Za-z0-9]"),
}


def _password_ok(pw: str) -> bool:
    pw = pw or ""
    if len(pw) < _PASSWORD_POLICY["min_len"]:
        return False
    if not _PASSWORD_POLICY["upper"].search(pw):
        return False
    if not _PASSWORD_POLICY["lower"].search(pw):
        return False
    if not _PASSWORD_POLICY["digit"].search(pw):
        return False
    if not _PASSWORD_POLICY["special"].search(pw):
        return False
    return True


def _password_help() -> str:
    return "Password must be 8+ characters and include uppercase, lowercase, a number, and a special character."


# -------------------------
# Email verification helpers
# -------------------------
def _external_base_url() -> str:
    """
    Use canonical host if available, otherwise fallback to RENDER_EXTERNAL_URL if set.
    """
    canonical = os.getenv("CANONICAL_HOST", "").strip()
    if canonical:
        return f"https://{canonical}"
    return (os.getenv("RENDER_EXTERNAL_URL", "") or "").rstrip("/")


def _send_verification_email(user: User) -> bool:
    token = user.generate_email_verify_token()

    base_url = _external_base_url()
    verify_path = url_for("auth.verify_email", token=token)
    verify_link = f"{base_url}{verify_path}" if base_url else verify_path

    html = render_template(
        "emails/verify_email.html",
        verify_link=verify_link,
        user_email=user.email,
    )
    return send_email(user.email, "Verify your BlizTech email", html)


# -------------------------
# Referral helpers (signup-based)
# -------------------------
_REF_RE = re.compile(r"^[A-Za-z0-9]{4,64}$")


def _get_referrer_from_session() -> tuple[User | None, str | None]:
    """
    Returns (referrer_user, code_used) or (None, None).
    """
    code = (session.get("ref_code") or "").strip()
    if not code:
        return None, None

    if not _REF_RE.match(code):
        # bad code: clear it so it doesn't keep trying
        session.pop("ref_code", None)
        return None, None

    referrer = User.query.filter_by(referral_code=code).first()
    if not referrer:
        # code not found: clear it
        session.pop("ref_code", None)
        return None, None

    return referrer, code


def _apply_referral_on_signup(new_user: User) -> None:
    """
    If a valid referrer exists in session, record:
    - new_user.referred_by_id
    - a row in Referral table
    """
    referrer, code_used = _get_referrer_from_session()
    if not referrer:
        return

    # Prevent self-referral (defensive)
    if referrer.id == new_user.id:
        session.pop("ref_code", None)
        return

    # If already referred (shouldn't happen due to unique constraint), exit safely
    existing = Referral.query.filter_by(referred_user_id=new_user.id).first()
    if existing:
        session.pop("ref_code", None)
        return

    try:
        new_user.referred_by_id = referrer.id
        db.session.add(new_user)

        row = Referral(
            referrer_id=referrer.id,
            referred_user_id=new_user.id,
            referral_code_used=code_used,
            source="url_param",
            status="signup",
            created_at=datetime.utcnow(),
        )
        db.session.add(row)

        db.session.commit()
        session.pop("ref_code", None)  # ✅ clear once successfully used
    except Exception:
        db.session.rollback()


@auth_bp.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per minute; 10 per hour")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("auth/signup.html", next=request.form.get("next", ""))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/signup.html", next=request.form.get("next", ""))

        if not _password_ok(password):
            flash(_password_help(), "error")
            return render_template("auth/signup.html", next=request.form.get("next", ""))

        exists = User.query.filter_by(email=email).first()
        if exists:
            flash("That email is already registered. Please log in.", "error")
            return redirect(url_for("auth.login", next=request.form.get("next", "")))

        user = User(email=email)
        user.set_password(password)

        if email in _admin_emails_set():
            user.is_admin = True

        # New accounts start unverified
        user.email_verified = False
        user.email_verified_at = None

        # Ensure this user has a referral code (auto-generated)
        if not getattr(user, "referral_code", None):
            user.referral_code = User.generate_unique_referral_code()

        db.session.add(user)
        db.session.commit()

        # Apply referral (signup-based)
        _apply_referral_on_signup(user)

        # Send verification email
        ok = _send_verification_email(user)
        if not ok:
            current_app.logger.error("SendGrid verify email failed for %s", user.email)

        flash("Account created ✅ Please check your email to verify your account before logging in.", "success")
        return redirect(url_for("auth.login", next=request.form.get("next", "")))

    return render_template("auth/signup.html", next=request.args.get("next", ""))


@auth_bp.route("/verify-email/<token>")
@limiter.limit("10 per minute")
def verify_email(token):
    user = User.verify_email_verify_token(token, max_age_seconds=60 * 60 * 24)  # 24h
    if not user:
        flash("That verification link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))

    if not user.email_verified:
        user.email_verified = True
        user.email_verified_at = datetime.utcnow()
        db.session.commit()

    flash("Email verified ✅ You can now log in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["POST"])
@limiter.limit("3 per minute; 10 per hour")
def resend_verification():
    email = (request.form.get("email") or "").strip().lower()
    ip = _client_ip()

    # Generic response to avoid email enumeration
    generic_msg = "If that email exists and is not verified, we’ve sent a new verification link."

    if not email:
        flash(generic_msg, "success")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        _log_auth_event("auth_resend_verify_unknown_email", email=_mask_email(email), ip=ip)
        flash(generic_msg, "success")
        return redirect(url_for("auth.login"))

    if user.email_verified:
        _log_auth_event("auth_resend_verify_already_verified", email=_mask_email(email), ip=ip, user_id=user.id)
        flash("That email is already verified. Please log in.", "success")
        return redirect(url_for("auth.login"))

    ok = _send_verification_email(user)
    _log_auth_event("auth_resend_verify_sent", email=_mask_email(email), ip=ip, user_id=user.id, ok=bool(ok))
    flash(generic_msg, "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        ip = _client_ip()
        masked = _mask_email(email)

        # Early block if locked
        state = LoginSecurityState.query.filter_by(email=email, ip=ip).first()
        if state and state.locked_until and state.locked_until > datetime.utcnow():
            seconds = int((state.locked_until - datetime.utcnow()).total_seconds())
            minutes = max(1, int(round(seconds / 60)))
            _log_auth_event("auth_login_blocked_locked", email=masked, ip=ip, minutes_remaining=minutes)
            flash(f"Too many failed attempts. Try again in about {minutes} minute(s).", "error")
            return render_template("auth/login.html", next=request.form.get("next", request.args.get("next", "")))

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            locked, seconds, attempts = _register_failed_login(email=email, ip=ip)
            if locked:
                minutes = max(1, int(round(seconds / 60)))
                _log_auth_event(
                    "auth_login_locked",
                    email=masked,
                    ip=ip,
                    attempts=attempts,
                    ban_minutes=minutes,
                )
                flash(f"Too many failed attempts. Try again in about {minutes} minute(s).", "error")
            else:
                _log_auth_event(
                    "auth_login_failed",
                    email=masked,
                    ip=ip,
                    attempts=attempts,
                )
                flash("Invalid email or password.", "error")
            return render_template("auth/login.html", next=request.form.get("next", request.args.get("next", "")))

        # Block login if not verified
        if not getattr(user, "email_verified", False):
            _log_auth_event("auth_login_blocked_unverified", email=masked, ip=ip, user_id=user.id)
            flash("Please verify your email before logging in. Use 'Resend verification' below.", "error")
            return render_template("auth/login.html", next=request.form.get("next", request.args.get("next", "")), email_prefill=email)

        # Success: clear lockout state
        _clear_login_state(email=email, ip=ip)

        _ensure_admin_if_allowed(user)
        login_user(user)

        anon_id = _anon_key()
        if anon_id:
            _merge_progress(anon_id, _user_key(user.id))
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

        _log_auth_event("auth_login_success", email=masked, ip=ip, user_id=user.id)
        flash("Welcome back ✅", "success")
        return redirect(_safe_next_url(default_endpoint="main.home"))

    return render_template("auth/login.html", next=request.args.get("next", ""), email_prefill="")


@auth_bp.route("/logout")
def logout():
    if current_user.is_authenticated:
        _log_auth_event("auth_logout", user_id=current_user.id, email=_mask_email(current_user.email), ip=_client_ip())
        logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("main.home"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute; 10 per hour")
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        flash("If that email exists, a reset link has been sent.", "success")
        _log_auth_event("auth_forgot_password_requested", email=_mask_email(email), ip=_client_ip())

        user = User.query.filter_by(email=email).first()
        if user:
            token = user.generate_reset_token()

            base_url = _external_base_url()
            reset_path = url_for("auth.reset_password", token=token)
            reset_link = f"{base_url}{reset_path}" if base_url else reset_path

            html = render_template("emails/reset_password.html", reset_link=reset_link)

            ok = send_email(user.email, "Reset your BlizTech password", html)
            if not ok:
                current_app.logger.error("SendGrid email failed for %s", user.email)

        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def reset_password(token):
    user = User.verify_reset_token(token, max_age_seconds=3600)
    if not user:
        flash("That reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = (request.form.get("password") or "").strip()
        confirm = (request.form.get("confirm") or "").strip()

        if not _password_ok(password):
            flash(_password_help(), "error")
            return render_template("auth/reset_password.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/reset_password.html")

        user.set_password(password)
        db.session.commit()

        _log_auth_event("auth_password_reset_success", email=_mask_email(user.email), user_id=user.id, ip=_client_ip())

        flash("Password updated successfully ✅ Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html")
