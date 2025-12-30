from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"

migrate = Migrate()

# Rate limiter (Phase 4.3)
# Uses client IP address as key (works correctly with ProxyFix)
limiter = Limiter(
    key_func=get_remote_address
)
