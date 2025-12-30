import os
import uuid
from datetime import datetime, timedelta

from flask import render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, current_user

from app.blueprints.auth import auth_bp
from app.email_utils import send_email
from app.extensions import db, limiter
from app.models import User, Progress, LoginSecurityState


def _anon_key():
    return session.get("anon_id")  # "anon:<uuid>"


def _user_key(user_id: int):
    return f"user:{user_id}"


def _merge_progress(anon_id: str, user_id: str):
    """
    Move anon progress rows to logged-in user.
    If both exist for same slug: keep best (passed wins, else higher score).
    """
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


# ---------------------------
# Phase 4.4: Login lockout (IP + email)
# ---------------------------

def _client_ip() -> str:
    # Works well behind Render + ProxyFix
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
    if state.locked_until and state.locked_until > datetime.utcnow():
        return True
    return False


def _register_failed_login(email: str, ip: str) -> tuple[bool, int]:
    """
    Returns (is_now_locked, seconds_remaining_if_locked)
    """
    max_attempts, window_minutes, ban_minutes = _lockout_config()
    now = datetime.utcnow()

    state = _get_state(email, ip)

    # If currently locked, just update last_attempt_at and return
    state.last_attempt_at = now
    if _is_locked(state):
        db.session.add(state)
        db.session.commit()
        seconds = int((state.locked_until - now).total_seconds())
        return True, max(0, seconds)

    # Reset window if expired
    window = timedelta(minutes=window_minutes)
    if state.first_attempt_at and (now - state.first_attempt_at) > window:
        state.attempts = 0
        state.first_attempt_at = now

    # Increment attempts
    state.attempts = (state.attempts or 0) + 1
    state.last_attempt_at = now

    # Lock if exceeded
    if state.attempts >= max_attempts:
        state.locked_until = now + timedelta(minutes=ban_minutes)
        db.session.add(state)
        db.session.commit()
        seconds = int((state.locked_until - now).total_seconds())
        return True, max(0, seconds)

    db.session.add(state)
    db.session.commit()
    return False, 0


def _clear_login_state(email: str, ip: str) -> None:
    email = (email or "").strip().lower()
    ip = (ip or "").strip()
    state = LoginSecurityState.query.filter_by(email=email, ip=ip).first()
    if state:
        db.session.delete(state)
        db.session.commit()


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
            return render_template("auth/signup.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/signup.html")

        if len(password) < 8:
            flash("Password should be at least 8 characters.", "error")
            return render_template("auth/signup.html")

        exists = User.query.filter_by(email=email).first()
        if exists:
            flash("That email is already registered. Please log in.", "error")
            return redirect(url_for("auth.login"))

        user = User(email=email)
        user.set_password(password)

        if email in _admin_emails_set():
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        login_user(user)

        anon_id = _anon_key()
        if anon_id:
            _merge_progress(anon_id, _user_key(user.id))
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

        flash("Account created successfully ✅", "success")
        return redirect(url_for("main.home"))

    return render_template("auth/signup.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        ip = _client_ip()

        # Phase 4.4: block early if locked
        state = LoginSecurityState.query.filter_by(email=email, ip=ip).first()
        if state and state.locked_until and state.locked_until > datetime.utcnow():
            seconds = int((state.locked_until - datetime.utcnow()).total_seconds())
            minutes = max(1, int(round(seconds / 60)))
            flash(f"Too many failed attempts. Try again in about {minutes} minute(s).", "error")
            return render_template("auth/login.html")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            locked, seconds = _register_failed_login(email=email, ip=ip)
            if locked:
                minutes = max(1, int(round(seconds / 60)))
                flash(f"Too many failed attempts. Try again in about {minutes} minute(s).", "error")
            else:
                flash("Invalid email or password.", "error")
            return render_template("auth/login.html")

        # success: clear lockout state
        _clear_login_state(email=email, ip=ip)

        _ensure_admin_if_allowed(user)
        login_user(user)

        anon_id = _anon_key()
        if anon_id:
            _merge_progress(anon_id, _user_key(user.id))
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

        flash("Welcome back ✅", "success")
        return redirect(url_for("main.home"))

    return render_template("auth/login.html")


@auth_bp.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("main.home"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute; 10 per hour")
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        flash("If that email exists, a reset link has been sent.", "success")

        user = User.query.filter_by(email=email).first()
        if user:
            token = user.generate_reset_token()

            base_url = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
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
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if len(password) < 8:
            flash("Password should be at least 8 characters.", "error")
            return render_template("auth/reset_password.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/reset_password.html")

        user.set_password(password)
        db.session.commit()

        flash("Password updated successfully ✅ Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html")
