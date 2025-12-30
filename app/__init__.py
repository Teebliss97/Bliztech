import os
import uuid

from flask import Flask, session, request, redirect
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import db, login_manager, migrate


def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # DB URL (Render Postgres sometimes uses postgres://)
    db_url = os.getenv("DATABASE_URL", "sqlite:///bliztech.db")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ---- Production detection ----
    is_production = (os.getenv("FLASK_ENV") == "production") or (os.getenv("RENDER") == "true")

    # ---- Proxy / HTTPS correctness on Render ----
    # Render sits behind a reverse proxy. This makes Flask respect:
    # X-Forwarded-Proto, X-Forwarded-For, etc.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # ---- Cookie hardening ----
    # (Important for auth/session security)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # safe default; use "Strict" if you want even tighter
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"

    if is_production:
        app.config["SESSION_COOKIE_SECURE"] = True
        app.config["REMEMBER_COOKIE_SECURE"] = True

    # Optional: allow you to force https redirects in production
    # Set env FORCE_HTTPS=1 on Render
    force_https = os.getenv("FORCE_HTTPS", "0") == "1"

    db.init_app(app)
    login_manager.init_app(app)

    # ✅ Flask-Migrate init
    migrate.init_app(app, db)

    @app.before_request
    def ensure_anon_id():
        if "anon_id" not in session:
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

    # ---- Force HTTPS redirect (production, optional) ----
    @app.before_request
    def redirect_to_https():
        if not is_production or not force_https:
            return
        # After ProxyFix, request.is_secure will work properly on Render
        if request.is_secure:
            return
        # Avoid redirect loops on healthchecks or local
        if request.headers.get("X-Forwarded-Proto", "").lower() == "https":
            return
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

    # ---- Security headers ----
    @app.after_request
    def add_security_headers(resp):
        # Basic hardening
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # HSTS only when you're on HTTPS in production
        if is_production:
            # 1 year + include subdomains
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # CSP (conservative, should not break your current templates)
        # If you later add external CDNs, we can extend this safely.
        csp = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        resp.headers["Content-Security-Policy"] = csp

        return resp

    # Core blueprints
    from app.blueprints.main.routes import main_bp
    from app.blueprints.topics.routes import topics_bp
    from app.blueprints.quizzes.routes import quizzes_bp
    from app.blueprints.auth import auth_bp
    from app.blueprints.cert import cert_bp
    from app.blueprints.admin.routes import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(topics_bp)
    app.register_blueprint(quizzes_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(cert_bp)
    app.register_blueprint(admin_bp)

    # Test-only blueprint (disabled on production by default)
    if os.getenv("ENABLE_EMAIL_TEST_ROUTE") == "1":
        from app.blueprints.main.test_email import test_bp
        app.register_blueprint(test_bp)

    # ---- Error pages (use your Phase 2 templates) ----
    @app.errorhandler(404)
    def not_found(e):
        return (app.jinja_env.get_or_select_template("errors/404.html").render(), 404)

    @app.errorhandler(500)
    def server_error(e):
        return (app.jinja_env.get_or_select_template("errors/500.html").render(), 500)

    return app
