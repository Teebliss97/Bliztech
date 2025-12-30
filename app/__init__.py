import os
import uuid
import logging
from logging.config import dictConfig

from flask import Flask, session, request, g
from dotenv import load_dotenv

from app.extensions import db, login_manager, migrate


def configure_logging():
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s %(name)s - %(message)s"
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
            }
        },
        "root": {
            "level": log_level,
            "handlers": ["wsgi"]
        }
    })


class RequestLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        rid = getattr(g, "request_id", "-")
        return f"rid={rid} {msg}", kwargs


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # --------------------
    # Core config
    # --------------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    db_url = os.getenv("DATABASE_URL", "sqlite:///bliztech.db")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True

    if os.getenv("RENDER_EXTERNAL_URL"):
        app.config["RENDER_EXTERNAL_URL"] = os.getenv("RENDER_EXTERNAL_URL")

    # --------------------
    # Logging
    # --------------------
    configure_logging()
    app.logger = RequestLoggerAdapter(app.logger, {})

    # --------------------
    # Extensions
    # --------------------
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # --------------------
    # Request hooks
    # --------------------
    @app.before_request
    def attach_request_id():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
        if "anon_id" not in session:
            session["anon_id"] = f"anon:{uuid.uuid4().hex}"

    @app.after_request
    def add_request_id_header(resp):
        resp.headers["X-Request-ID"] = g.request_id
        return resp

    # --------------------
    # Errors
    # --------------------
    @app.errorhandler(500)
    def server_error(err):
        app.logger.exception("500 error on %s %s", request.method, request.path)
        return err, 500

    @app.errorhandler(404)
    def not_found(err):
        app.logger.info("404 %s %s", request.method, request.path)
        return err, 404

    # --------------------
    # Health check
    # --------------------
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    # --------------------
    # Blueprints
    # --------------------
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
