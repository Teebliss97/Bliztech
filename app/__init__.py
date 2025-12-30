import os
import uuid
import json
import time
import logging
from datetime import datetime
from logging.config import dictConfig
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, session, jsonify, g, has_request_context, request, redirect, Response
from dotenv import load_dotenv

from app.extensions import db, login_manager, migrate, limiter


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
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Cookies more secure in production
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    if os.getenv("FLASK_ENV") == "production":
        app.config["SESSION_COOKIE_SECURE"] = True

    # -------------------------
    # Canonical domain enforcement (Phase 4.1)
    # -------------------------
    CANONICAL_HOST = os.getenv("CANONICAL_HOST", "bliztechacademy.com")

    @app.before_request
    def enforce_canonical_domain():
        if request.host.startswith("localhost") or request.host.startswith("127.0.0.1"):
            return

        proto = request.headers.get("X-Forwarded-Proto", request.scheme)
        parts = urlsplit(request.url)
        host = request.host

        needs_https = (proto != "https") or (parts.scheme != "https")
        needs_host = (host != CANONICAL_HOST)

        if needs_https or needs_host:
            new_url = urlunsplit(("https", CANONICAL_HOST, parts.path, parts.query, parts.fragment))
            return redirect(new_url, code=301)

    # -------------------------
    # Security headers (Phase 4.2)
    # -------------------------
    SECURITY_HEADERS_ENABLED = os.getenv("SECURITY_HEADERS_ENABLED", "1") == "1"
    HSTS_ENABLED = os.getenv("HSTS_ENABLED", "1") == "1"
    HSTS_PRELOAD = os.getenv("HSTS_PRELOAD", "0") == "1"
    CSP_REPORT_ONLY = os.getenv("CSP_REPORT_ONLY", "1") == "1"

    def _build_csp() -> str:
        directives = {
            "default-src": ["'self'"],
            "base-uri": ["'self'"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'self'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'", "data:"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "script-src": ["'self'"],
            "connect-src": ["'self'"],
            "upgrade-insecure-requests": [],
        }
        parts = []
        for k, v in directives.items():
            parts.append(f"{k} {' '.join(v)}" if v else f"{k}")
        return "; ".join(parts)

    CSP_VALUE = _build_csp()

    @app.after_request
    def set_security_headers(resp: Response):
        if not SECURITY_HEADERS_ENABLED:
            return resp

        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")

        if HSTS_ENABLED:
            hsts = "max-age=31536000; includeSubDomains"
            if HSTS_PRELOAD:
                hsts += "; preload"
            resp.headers.setdefault("Strict-Transport-Security", hsts)

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
    # Rate limiting (Phase 4.3)
    # -------------------------
    limiter_storage = os.getenv("RATELIMIT_STORAGE_URI")
    if limiter_storage:
        app.config["RATELIMIT_STORAGE_URI"] = limiter_storage

    app.config["RATELIMIT_HEADERS_ENABLED"] = True
    limiter.init_app(app)

    # -------------------------
    # Monitoring helpers (Phase 5.1 + 5.2)
    # -------------------------
    LOG_SECURITY_EVENTS = os.getenv("LOG_SECURITY_EVENTS", "1") == "1"
    SLOW_REQUEST_MS = int(os.getenv("SLOW_REQUEST_MS", "1200"))
    DB_MONITORING_ENABLED = os.getenv("DB_MONITORING_ENABLED", "1") == "1"

    def _client_ip() -> str:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _log_event(event: str, level: str = "info", **fields):
        """
        Phase 5.2:
        - Always logs JSON to Render logs (if LOG_SECURITY_EVENTS=1)
        - Optionally persists to DB (if DB_MONITORING_ENABLED=1)
        """
        payload = {
            "event": event,
            "path": request.path if has_request_context() else None,
            "method": request.method if has_request_context() else None,
            "ip": _client_ip() if has_request_context() else None,
            **fields,
        }

        if LOG_SECURITY_EVENTS:
            msg = json.dumps(payload, default=str, separators=(",", ":"))
            getattr(app.logger, level, app.logger.info)(msg)

        if not DB_MONITORING_ENABLED:
            return

        # Import here to avoid import cycles
        try:
            from app.models import SecurityEvent
            ev = SecurityEvent(
                event=event,
                ip=payload.get("ip"),
                endpoint=payload.get("endpoint"),
                path=payload.get("path"),
                method=payload.get("method"),
                status=payload.get("status"),
                duration_ms=payload.get("duration_ms"),
                detail=str(payload.get("detail") or payload.get("limit") or "")[:2000],
                created_at=datetime.utcnow(),
            )
            db.session.add(ev)
            db.session.commit()
        except Exception:
            db.session.rollback()

    # -------------------------
    # Request IDs + timing + anon session ID
    # -------------------------
    @app.before_request
    def ensure_ids_and_timer():
        g._t0 = time.time()

        if "anon_id" not in session:
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex

    @app.after_request
    def attach_request_id_and_log(resp: Response):
        # Always return X-Request-ID to client (useful for debugging)
        try:
            resp.headers.setdefault("X-Request-ID", getattr(g, "request_id", ""))
        except Exception:
            pass

        # Request timing
        try:
            dt_ms = int(round((time.time() - getattr(g, "_t0", time.time())) * 1000))
        except Exception:
            dt_ms = None

        # Log slow requests
        if dt_ms is not None and dt_ms >= SLOW_REQUEST_MS:
            _log_event(
                "slow_request",
                level="warning",
                endpoint=request.endpoint,
                status=resp.status_code,
                duration_ms=dt_ms,
            )

        # Log 4xx/5xx (excluding common static assets noise)
        if resp.status_code >= 400 and not request.path.startswith("/static/"):
            _log_event(
                "http_error",
                level="warning",
                endpoint=request.endpoint,
                status=resp.status_code,
                duration_ms=dt_ms,
            )

        return resp

    # Log rate limiting (429) nicely
    try:
        from flask_limiter.errors import RateLimitExceeded

        @app.errorhandler(RateLimitExceeded)
        def handle_rate_limit(e):
            _log_event(
                "rate_limited",
                level="warning",
                endpoint=request.endpoint,
                status=429,
                limit=str(getattr(e, "description", ""))[:200],
            )
            return jsonify({
                "error": "rate_limited",
                "message": "Too many requests. Please slow down and try again shortly."
            }), 429
    except Exception:
        pass

    # -------------------------
    # Health check
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

    if os.getenv("ENABLE_EMAIL_TEST_ROUTE") == "1":
        from app.blueprints.main.test_email import test_bp
        app.register_blueprint(test_bp)

    app.logger.info("Application started successfully")
    return app
