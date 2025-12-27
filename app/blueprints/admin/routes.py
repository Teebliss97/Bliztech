import os
from functools import wraps
from flask import Blueprint, abort, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.extensions import db
from app.models import User, Progress
from app.blueprints.admin import admin_bp

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


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


@admin_bp.route("/users")
@admin_required
def users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/progress")
@admin_required
def progress():
    rows = Progress.query.order_by(Progress.updated_at.desc()).limit(200).all()
    return render_template("admin/progress.html", rows=rows)


# ✅ One-time bootstrap (needed because Render Free has no shell)
@admin_bp.route("/bootstrap", methods=["GET", "POST"])
def bootstrap_admin():
    token_env = os.getenv("ADMIN_BOOTSTRAP_TOKEN")
    if not token_env:
        abort(404)

    # Only allow bootstrap if no admin exists yet
    existing_admin = User.query.filter_by(is_admin=True).first()
    if existing_admin:
        abort(403)

    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        email = (request.form.get("email") or "").strip().lower()

        if token != token_env:
            flash("Invalid token.", "error")
            return redirect(url_for("admin.bootstrap_admin"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User not found. Register first, then try again.", "error")
            return redirect(url_for("admin.bootstrap_admin"))

        user.is_admin = True
        db.session.commit()

        flash(f"{email} is now an admin ✅", "success")
        return redirect(url_for("auth.login"))

    return render_template("admin/bootstrap.html")
