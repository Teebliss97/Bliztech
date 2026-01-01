import os
import uuid
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.extensions import db, login_manager


def _ts(salt: str) -> URLSafeTimedSerializer:
    """
    Timed serializer for email verify + password reset tokens.
    """
    secret = os.getenv("SECRET_KEY", "dev-secret-change-me")
    return URLSafeTimedSerializer(secret, salt=salt)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    # ✅ Email verification fields (NEW)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    # -------------------------
    # Password reset tokens (USED by your auth routes)
    # -------------------------
    def generate_reset_token(self) -> str:
        s = _ts("bliztech-reset-password")
        return s.dumps({"user_id": self.id, "email": self.email})

    @staticmethod
    def verify_reset_token(token: str, max_age_seconds: int = 3600):
        s = _ts("bliztech-reset-password")
        try:
            data = s.loads(token, max_age=max_age_seconds)
            user_id = data.get("user_id")
            if not user_id:
                return None
            return User.query.get(int(user_id))
        except (SignatureExpired, BadSignature):
            return None

    # -------------------------
    # Email verification tokens (NEW)
    # -------------------------
    def generate_email_verify_token(self) -> str:
        s = _ts("bliztech-email-verify")
        return s.dumps({"user_id": self.id, "email": self.email})

    @staticmethod
    def verify_email_verify_token(token: str, max_age_seconds: int = 60 * 60 * 24):
        """
        Default expiry: 24 hours.
        Returns user or None.
        """
        s = _ts("bliztech-email-verify")
        try:
            data = s.loads(token, max_age=max_age_seconds)
            user_id = data.get("user_id")
            if not user_id:
                return None
            return User.query.get(int(user_id))
        except (SignatureExpired, BadSignature):
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


class LoginSecurityState(db.Model):
    """
    Tracks failed login attempts by (ip + email).
    Used for lockout / temporary bans.
    """
    __tablename__ = "login_security_state"

    id = db.Column(db.Integer, primary_key=True)

    # Normalize email to lower-case when saving
    email = db.Column(db.String(255), nullable=False, index=True)
    ip = db.Column(db.String(64), nullable=False, index=True)

    attempts = db.Column(db.Integer, nullable=False, default=0)
    first_attempt_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    locked_until = db.Column(db.DateTime, nullable=True)

    last_attempt_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("email", "ip", name="uq_login_security_email_ip"),
    )


class AdminAuditLog(db.Model):
    """
    Durable audit log for admin actions (reissue/revoke/unrevoke/bootstrap).
    """
    __tablename__ = "admin_audit_log"

    id = db.Column(db.Integer, primary_key=True)

    actor_user_id = db.Column(db.Integer, nullable=True, index=True)
    actor_email = db.Column(db.String(255), nullable=True, index=True)

    action = db.Column(db.String(100), nullable=False, index=True)  # e.g. "CERT_REISSUE"
    target_type = db.Column(db.String(50), nullable=True)          # e.g. "certificate"
    target_id = db.Column(db.String(100), nullable=True, index=True)  # e.g. cert_id

    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)

    # Small JSON-ish text or summary string (kept simple)
    detail = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


class SecurityEvent(db.Model):
    __tablename__ = "security_event"

    id = db.Column(db.Integer, primary_key=True)

    # event name like: auth_login_failed, rate_limited, slow_request, http_error
    event = db.Column(db.String(80), nullable=False, index=True)

    # request context
    ip = db.Column(db.String(64), nullable=True, index=True)
    endpoint = db.Column(db.String(200), nullable=True, index=True)
    path = db.Column(db.String(500), nullable=True, index=True)
    method = db.Column(db.String(12), nullable=True)
    status = db.Column(db.Integer, nullable=True, index=True)
    duration_ms = db.Column(db.Integer, nullable=True)

    # free-form details (limit, reason, etc.)
    detail = db.Column(db.Text, nullable=True)

    # Optional: masked email for auth-related events
    email_masked = db.Column(db.String(255), nullable=True, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<SecurityEvent {self.event} {self.status} {self.ip}>"
