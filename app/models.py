from datetime import datetime
import uuid

from flask_login import UserMixin
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


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # public-facing id (safe to show on certificate)
    cert_id = db.Column(db.String(32), unique=True, nullable=False, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user_email = db.Column(db.String(255), nullable=False)

    recipient_name = db.Column(db.String(120), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Admin controls
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not getattr(self, "cert_id", None):
            self.cert_id = uuid.uuid4().hex[:12].upper()
