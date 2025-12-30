import os

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"

migrate = Migrate()

# Phase 4.3 - Rate limiter
# Put default limits here (safe across Flask-Limiter versions).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[
        os.getenv("RATELIMIT_DEFAULT", "200 per day"),
        os.getenv("RATELIMIT_DEFAULT_MINUTE", "60 per minute"),
    ],
)
