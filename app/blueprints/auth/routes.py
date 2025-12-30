import os
import uuid

from flask import render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, current_user

from app.blueprints.auth import auth_bp
from app.email_utils import send_email
from app.extensions import db, limiter
from app.models import User, Progress


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
    """
    Comma-separated list in Render env var ADMIN_EMAILS
    Example: "toheebatinuke@gmail.com, another@email.com"
    """
    raw = os.getenv("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def _ensure_admin_if_allowed(user: User) -> bool:
    """
    If user's email is in ADMIN_EMAILS, make them admin.
    Returns True if we changed anything.
    """
    allowed = _admin_emails_set()
    if not allowed:
        return False

    if user.email.lower() in allowed and not getattr(user, "is_admin", False):
        user.is_admin = True
        db.session.add(user)
        db.session.commit()
        return True

    return False


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

        # ✅ auto-admin for allowed emails
        if email in _admin_emails_set():
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        login_user(user)

        # merge anon progress into new account
        anon_id = _anon_key()
        if anon_id:
            _merge_progress(anon_id, _user_key(user.id))
            # reset anon session id so it doesn't conflict
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

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "error")
            return render_template("auth/login.html")

        # ✅ if this email should be admin, ensure it
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


# ---------------------------
# Password reset routes
# ---------------------------

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute; 10 per hour")
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        # Always respond the same (avoid account enumeration)
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
