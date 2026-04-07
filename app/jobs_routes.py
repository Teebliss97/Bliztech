import requests
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request
from app.extensions import db
from app.models import Job

jobs_bp = Blueprint("jobs", __name__)

REMOTIVE_URL = "https://remotive.com/api/remote-jobs?category=cyber-security&limit=50"
FETCH_INTERVAL_HOURS = 12
_last_fetch = None


def _guess_level(title: str) -> str:
    title = title.lower()
    if any(w in title for w in ["senior", "lead", "principal", "head", "director", "manager", "staff"]):
        return "senior"
    if any(w in title for w in ["junior", "entry", "graduate", "intern", "associate", "apprentice"]):
        return "entry"
    return "mid"


def _fetch_remotive_jobs():
    """Fetch jobs from Remotive API and upsert into database."""
    global _last_fetch
    now = datetime.utcnow()

    if _last_fetch and (now - _last_fetch) < timedelta(hours=FETCH_INTERVAL_HOURS):
        return

    try:
        resp = requests.get(REMOTIVE_URL, timeout=10)
        if resp.status_code != 200:
            return
        data = resp.json()
        jobs = data.get("jobs", [])

        for j in jobs:
            ext_id = f"remotive_{j.get('id')}"
            existing = Job.query.filter_by(external_id=ext_id).first()
            if existing:
                continue

            # Parse posted date
            try:
                posted = datetime.strptime(j.get("publication_date", "")[:10], "%Y-%m-%d")
            except Exception:
                posted = now

            # Skip jobs older than 60 days
            if (now - posted).days > 60:
                continue

            job = Job(
                title=j.get("title", "")[:200],
                company=j.get("company_name", "")[:200],
                location=j.get("candidate_required_location") or "Remote",
                region="international",
                level=_guess_level(j.get("title", "")),
                job_type="remote",
                url=j.get("url", ""),
                source="remotive",
                external_id=ext_id,
                is_active=True,
                posted_at=posted,
            )
            db.session.add(job)

        # Deactivate remotive jobs older than 60 days
        cutoff = now - timedelta(days=60)
        Job.query.filter(
            Job.source == "remotive",
            Job.posted_at < cutoff
        ).update({"is_active": False})

        db.session.commit()
        _last_fetch = now

    except Exception:
        db.session.rollback()


@jobs_bp.route("/jobs")
def job_board():
    # Try to fetch fresh jobs from Remotive
    try:
        _fetch_remotive_jobs()
    except Exception:
        pass

    region = request.args.get("region", "").strip().lower()
    level = request.args.get("level", "").strip().lower()
    job_type = request.args.get("type", "").strip().lower()
    q = request.args.get("q", "").strip()

    query = Job.query.filter_by(is_active=True)

    if region in ("africa", "international"):
        query = query.filter_by(region=region)
    if level in ("entry", "mid", "senior"):
        query = query.filter_by(level=level)
    if job_type in ("remote", "hybrid", "onsite"):
        query = query.filter_by(job_type=job_type)
    if q:
        query = query.filter(
            (Job.title.ilike(f"%{q}%")) |
            (Job.company.ilike(f"%{q}%")) |
            (Job.location.ilike(f"%{q}%"))
        )

    jobs = query.order_by(Job.posted_at.desc()).limit(100).all()

    total = Job.query.filter_by(is_active=True).count()
    africa_count = Job.query.filter_by(is_active=True, region="africa").count()
    international_count = Job.query.filter_by(is_active=True, region="international").count()

    return render_template(
        "jobs.html",
        jobs=jobs,
        total=total,
        africa_count=africa_count,
        international_count=international_count,
        region=region,
        level=level,
        job_type=job_type,
        q=q,
    )