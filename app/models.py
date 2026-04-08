import os
import uuid
import secrets
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.extensions import db, login_manager


def _ts(salt: str) -> URLSafeTimedSerializer:
    secret = os.getenv("SECRET_KEY", "dev-secret-change-me")
    return URLSafeTimedSerializer(secret, salt=salt)


class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    referral_code = db.Column(db.String(32), unique=True, index=True, nullable=True)
    referred_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)

    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)

    has_course_access = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    @staticmethod
    def generate_unique_referral_code() -> str:
        code = secrets.token_urlsafe(8).replace("-", "").replace("_", "")
        while User.query.filter_by(referral_code=code).first():
            code = secrets.token_urlsafe(8).replace("-", "").replace("_", "")
        return code

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

    def generate_email_verify_token(self) -> str:
        s = _ts("bliztech-email-verify")
        return s.dumps({"user_id": self.id, "email": self.email})

    @staticmethod
    def verify_email_verify_token(token: str, max_age_seconds: int = 60 * 60 * 24):
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


class Referral(db.Model):
    __tablename__ = "referrals"

    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    referred_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True, index=True)
    referral_code_used = db.Column(db.String(32), nullable=True, index=True)
    source = db.Column(db.String(50), default="url_param", nullable=False)
    status = db.Column(db.String(20), default="signup", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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
    cert_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user_email = db.Column(db.String(255), nullable=False)
    recipient_name = db.Column(db.String(120), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not getattr(self, "cert_id", None):
            self.cert_id = uuid.uuid4().hex[:12].upper()


class LoginSecurityState(db.Model):
    __tablename__ = "login_security_state"

    id = db.Column(db.Integer, primary_key=True)
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
    __tablename__ = "admin_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, nullable=True, index=True)
    actor_email = db.Column(db.String(255), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.String(100), nullable=True, index=True)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


class SecurityEvent(db.Model):
    __tablename__ = "security_event"

    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(80), nullable=False, index=True)
    ip = db.Column(db.String(64), nullable=True, index=True)
    endpoint = db.Column(db.String(200), nullable=True, index=True)
    path = db.Column(db.String(500), nullable=True, index=True)
    method = db.Column(db.String(12), nullable=True)
    status = db.Column(db.Integer, nullable=True, index=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.Text, nullable=True)
    email_masked = db.Column(db.String(255), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<SecurityEvent {self.event} {self.status} {self.ip}>"


# ─────────────────────────────────────────────
#  PAID COURSE MODELS
# ─────────────────────────────────────────────

class CourseAccess(db.Model):
    __tablename__ = "course_access"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True, index=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    granted_by = db.Column(db.String(255), nullable=True)
    gumroad_sale_id = db.Column(db.String(100), nullable=True)

    user = db.relationship("User", backref=db.backref("course_access", uselist=False))


class CourseTopic(db.Model):
    __tablename__ = "course_topic"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)
    section = db.Column(db.String(2), nullable=False)
    lesson_number = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    lab = db.Column(db.Text, nullable=True)
    order = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<CourseTopic {self.lesson_number}: {self.title}>"


class LessonRead(db.Model):
    __tablename__ = "lesson_read"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    slug = db.Column(db.String(80), nullable=False, index=True)
    read_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "slug", name="uq_lesson_read_user_slug"),
    )

    user = db.relationship("User", backref=db.backref("lessons_read", lazy="dynamic"))


class QuizAttempt(db.Model):
    __tablename__ = "quiz_attempt"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    passed = db.Column(db.Boolean, nullable=False)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = db.relationship("User", backref=db.backref("quiz_attempts", lazy="dynamic"))

    @property
    def percentage(self):
        if self.total == 0:
            return 0
        return round(self.score / self.total * 100)


# ─────────────────────────────────────────────
#  JOB BOARD
# ─────────────────────────────────────────────

class Job(db.Model):
    __tablename__ = "job"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    company = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=True)
    region = db.Column(db.String(20), nullable=False, default="international")
    level = db.Column(db.String(20), nullable=False, default="entry")
    job_type = db.Column(db.String(20), nullable=False, default="remote")
    url = db.Column(db.String(500), nullable=False)
    source = db.Column(db.String(20), nullable=False, default="manual")
    external_id = db.Column(db.String(100), nullable=True, unique=True, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    posted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<Job {self.title} @ {self.company}>"


# ─────────────────────────────────────────────
#  COMPTIA PRACTICE EXAM
# ─────────────────────────────────────────────

class ExamAttempt(db.Model):
    __tablename__ = "exam_attempt"

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    exam_set     = db.Column(db.String(64), nullable=False, default="security_plus_set1")
    score_pct    = db.Column(db.Integer, nullable=False)
    correct      = db.Column(db.Integer, nullable=False)
    total        = db.Column(db.Integer, nullable=False)
    passed       = db.Column(db.Boolean, nullable=False)
    elapsed_secs = db.Column(db.Integer, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("exam_attempts", lazy="dynamic"))

    @property
    def percentage(self):
        return self.score_pct

    def __repr__(self):
        return f"<ExamAttempt user={self.user_id} score={self.score_pct}% passed={self.passed}>"