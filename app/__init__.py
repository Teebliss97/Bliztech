import os
import uuid
import logging
from logging.config import dictConfig
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, session, jsonify, g, has_request_context, request, redirect, Response
from dotenv import load_dotenv

from app.extensions import db, login_manager, migrate


class RequestIdFilter(logging.Filter):
    """
    Safe logging filter: only reads g.request_id when a request context exists.
    Prevents: 'Working outside of application context'
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            record.request_id = getattr(g, "request_id", "-")
            record.remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
            record.path = request.path
            record.method = request.method
        else:
            record.request_id = "-"
            record.remote_addr = "-"
            record.path = "-"
            record.method = "-"
        return True


def _configure_logging():
    """
    Works on Render + locally. Adds request_id if available.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "request_id": {
                "()": RequestIdFilter
            }
        },
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s request_id=%(request_id)s %(remote_addr)s %(method)s %(path)s - %(message)s"
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["request_id"]
            }
        },
        "root": {
            "level": log_level,
            "handlers": ["wsgi"]
        }
    })


def create_app():
    load_dotenv()

    _configure_logging()

    app = Flask(__name__)

    # -------------------------
    # Core config
    # -------------------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    db_url = os.getenv("DATABASE_URL", "sqlite:///bliztech.db")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # -------------------------
    # Proxy / HTTPS settings (Render is behind a proxy)
    # -------------------------
    # If you already use ProxyFix somewhere else, keep only ONE place.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Cookies more secure in production
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    # Only mark secure cookies in production (https)
    if os.getenv("FLASK_ENV") == "production":
        app.config["SESSION_COOKIE_SECURE"] = True

    # -------------------------
    # Canonical domain enforcement (Phase 4.1)
    # -------------------------
    # Recommended canonical: https://bliztechacademy.com (non-www)
    CANONICAL_HOST = os.getenv("CANONICAL_HOST", "bliztechacademy.com")

    @app.before_request
    def enforce_canonical_domain():
        # Avoid breaking local development
        if request.host.startswith("localhost") or request.host.startswith("127.0.0.1"):
            return

        # Determine scheme (ProxyFix usually makes request.scheme correct)
        proto = request.headers.get("X-Forwarded-Proto", request.scheme)

        # Split current URL
        parts = urlsplit(request.url)
        host = request.host

        # Enforce HTTPS + canonical host
        needs_https = (proto != "https") or (parts.scheme != "https")
        needs_host = (host != CANONICAL_HOST)

        if needs_https or needs_host:
            new_scheme = "https"
            new_netloc = CANONICAL_HOST
            # Keep path + query exactly as-is
            new_url = urlunsplit((new_scheme, new_netloc, parts.path, parts.query, parts.fragment))
            return redirect(new_url, code=301)

    # -------------------------
    # Security headers (Phase 4.2)
    # -------------------------
    SECURITY_HEADERS_ENABLED = os.getenv("SECURITY_HEADERS_ENABLED", "1") == "1"
    HSTS_ENABLED = os.getenv("HSTS_ENABLED", "1") == "1"
    HSTS_PRELOAD = os.getenv("HSTS_PRELOAD", "0") == "1"  # enable later only when ready
    CSP_REPORT_ONLY = os.getenv("CSP_REPORT_ONLY", "1") == "1"  # start report-only to avoid breaking pages

    def _build_csp() -> str:
        # Start reasonably strict, but safe for most Flask apps.
        # If you use external CDNs (fonts, analytics), we’ll add domains later.
        directives = {
            "default-src": ["'self'"],
            "base-uri": ["'self'"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'none'"],  # prevents clickjacking (better than X-Frame-Options)
            "form-action": ["'self'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'", "data:"],
            "style-src": ["'self'", "'unsafe-inline'"],  # many templates need inline styles; tighten later
            "script-src": ["'self'"],  # if you rely on inline JS, we’ll switch to nonce later
            "connect-src": ["'self'"],
            "upgrade-insecure-requests": [],  # harmless since you already force https
        }

        parts = []
        for k, v in directives.items():
            if v:
                parts.append(f"{k} {' '.join(v)}")
            else:
                parts.append(f"{k}")
        return "; ".join(parts)

    CSP_VALUE = _build_csp()

    @app.after_request
    def set_security_headers(resp: Response):
        if not SECURITY_HEADERS_ENABLED:
            return resp

        # Basic hardening
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        # These help isolate browsing contexts (generally safe)
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        # Legacy clickjacking protection (kept as extra, CSP frame-ancestors is primary)
        resp.headers.setdefault("X-Frame-Options", "DENY")

        # HSTS (only meaningful on HTTPS responses)
        if HSTS_ENABLED:
            # 1 year is standard. Include subdomains when you're sure all subdomains are HTTPS.
            hsts = "max-age=31536000; includeSubDomains"
            if HSTS_PRELOAD:
                hsts += "; preload"
            resp.headers.setdefault("Strict-Transport-Security", hsts)

        # CSP (start Report-Only, then enforce when confirmed)
        if CSP_REPORT_ONLY:
            resp.headers.setdefault("Content-Security-Policy-Report-Only", CSP_VALUE)
        else:
            resp.headers.setdefault("Content-Security-Policy", CSP_VALUE)

        return resp

    # -------------------------
    # Init extensions
    # -------------------------
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # -------------------------
    # Request IDs + anon session ID
    # -------------------------
    @app.before_request
    def ensure_ids():
        # anonymous id (for anonymous progress)
        if "anon_id" not in session:
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

        # request id (for logs + tracing)
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex

    # -------------------------
    # Health check (Phase 4)
    # -------------------------
    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    # -------------------------
    # Blueprints
    # -------------------------
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

    app.logger.info("Application started successfully")
    return app
