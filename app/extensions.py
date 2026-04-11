import os

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"

migrate = Migrate()

# Rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[
        os.getenv("RATELIMIT_DEFAULT", "200 per day"),
        os.getenv("RATELIMIT_DEFAULT_MINUTE", "60 per minute"),
    ],
)

# CSRF protection
csrf = CSRFProtect()