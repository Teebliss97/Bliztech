import os
from datetime import datetime

from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db, login_manager


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    # ---------------------------
    # Password reset token helpers
    # ---------------------------
    def generate_reset_token(self) -> str:
        """
        Generates a signed token that encodes the user_id.
        Token expires when verified using verify_reset_token(max_age_seconds).
        """
        secret = os.getenv("SECRET_KEY", "dev-secret")
        s = URLSafeTimedSerializer(secret)
        return s.dumps({"user_id": self.id}, salt="password-reset")

    @staticmethod
    def verify_reset_token(token: str, max_age_seconds: int = 3600):
        """
        Verifies a token and returns the user if valid, else None.
        """
        secret = os.getenv("SECRET_KEY", "dev-secret")
        s = URLSafeTimedSerializer(secret)
        try:
            data = s.loads(token, salt="password-reset", max_age=max_age_seconds)
            user_id = int(data.get("user_id"))
            return User.query.get(user_id)
        except Exception:
            return None


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # store either "anon:<uuid>" or "user:<id>"
    user_id = db.Column(db.String(80), nullable=False, index=True)
    slug = db.Column(db.String(50), nullable=False, index=True)

    attempts = db.Column(db.Integer, default=0)
    score = db.Column(db.Integer, default=0)
    passed = db.Column(db.Boolean, default=False)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "slug", name="uq_progress_user_slug"),
    )

    def to_dict(self):
        return {
            "slug": self.slug,
            "score": self.score,
            "passed": bool(self.passed),
            "attempts": self.attempts or 0,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
