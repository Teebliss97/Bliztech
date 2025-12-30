import os
import uuid
import logging
from logging.config import dictConfig

from flask import Flask, session, request, g
from dotenv import load_dotenv

from app.extensions import db, login_manager, migrate


def _configure_logging(app: Flask) -> None:
    """
    Render/Gunicorn friendly logging:
    - logs to stdout
    - includes request id
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s %(name)s rid=%(request_id)s - %(message)s"
            }
        },
        "filters": {
            "request_id": {
                "()": "app.__init__.RequestIdFilter",
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
                "filters": ["request_id"],
            }
        },
        "root": {
            "level": log_level,
            "handlers": ["wsgi"]
        }
    })

    # Flask's default logger uses app.logger; ensure it inherits root config
    app.logger.setLevel(log_level)


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = getattr(g, "request_id", "-")
        return True


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # -------------------
    # Core config
    # -------------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # DB URL (Render Postgres sometimes uses postgres://)
    db_url = os.getenv("DATABASE_URL", "sqlite:///bliztech.db")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Cookie safety (works well for production)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    # Render is HTTPS; keep secure cookies on production
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "1") == "1"

    # Optional: certificate required topics from env
    if os.getenv("CERT_REQUIRED_TOPICS"):
        try:
            app.config["CERT_REQUIRED_TOPICS"] = int(os.getenv("CERT_REQUIRED_TOPICS"))
        except Exception:
            pass

    # Used by certificate verify URL (your code reads this)
    if os.getenv("RENDER_EXTERNAL_URL"):
        app.config["RENDER_EXTERNAL_URL"] = os.getenv("RENDER_EXTERNAL_URL")

    # -------------------
    # Logging
    # -------------------
    _configure_logging(app)

    # -------------------
    # Extensions
    # -------------------
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # -------------------
    # Request hooks
    # -------------------
    @app.before_request
    def ensure_anon_and_request_id():
        # Request id for tracing issues in Render logs
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]

        # Stable anon id (your topics logic depends on this)
        if "anon_id" not in session:
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

    @app.after_request
    def attach_request_id(resp):
        resp.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return resp

    # -------------------
    # Error logging (no sensitive dumps)
    # -------------------
    @app.errorhandler(500)
    def internal_error(err):
        app.logger.exception("500 Internal Server Error: %s %s", request.method, request.path)
        return err, 500

    @app.errorhandler(404)
    def not_found(err):
        # Keep 404 logs light (optional)
        app.logger.info("404 Not Found: %s %s", request.method, request.path)
        return err, 404

    # -------------------
    # Health check (Render-friendly)
    # -------------------
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    # -------------------
    # Blueprints
    # -------------------
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

    app.logger.info("App started. env=%s", os.getenv("FLASK_ENV", "production"))

    return app
