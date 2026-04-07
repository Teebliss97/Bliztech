import requests
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request
from app.extensions import db
from app.models import Job

jobs_bp = Blueprint("jobs", __name__)

FETCH_INTERVAL_HOURS = 12
_last_fetch = None


def _guess_level(title: str) -> str:
    title = title.lower()
    if any(w in title for w in ["senior", "lead", "principal", "head", "director", "manager", "staff", "vp", "chief"]):
        return "senior"
    if any(w in title for w in ["junior", "entry", "graduate", "intern", "associate", "apprentice", "jr"]):
        return "entry"
    return "mid"


def _is_cyber_relevant(title: str, tags: list = None) -> bool:
    """Check if job is cybersecurity relevant."""
    keywords = [
        "cyber", "security", "soc", "penetration", "pentest", "infosec",
        "vulnerability", "threat", "incident", "forensic", "malware",
        "firewall", "siem", "devsecops", "compliance", "risk", "audit",
        "cloud security", "network security", "zero trust", "identity",
    ]
    text = title.lower()
    if tags:
        text += " " + " ".join(str(t).lower() for t in tags)
    return any(k in text for k in keywords)


def _fetch_remotive():
    """Remotive — free public API, no key needed."""
    searches = [
        "https://remotive.com/api/remote-jobs?search=cybersecurity&limit=50",
        "https://remotive.com/api/remote-jobs?search=security+analyst&limit=30",
        "https://remotive.com/api/remote-jobs?search=SOC+analyst&limit=20",
        "https://remotive.com/api/remote-jobs?search=penetration+testing&limit=20",
    ]
    now = datetime.utcnow()
    count = 0

    for url in searches:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            for j in resp.json().get("jobs", []):
                ext_id = f"remotive_{j.get('id')}"
                if Job.query.filter_by(external_id=ext_id).first():
                    continue
                try:
                    posted = datetime.strptime(j.get("publication_date", "")[:10], "%Y-%m-%d")
                except Exception:
                    posted = now
                if (now - posted).days > 60:
                    continue
                job = Job(
                    title=j.get("title", "")[:200],
                    company=j.get("company_name", "")[:200],
                    location=j.get("candidate_required_location") or "Remote (Worldwide)",
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
                count += 1
        except Exception:
            continue

    return count


def _fetch_remoteok():
    """RemoteOK — free public API, no key needed. Large volume of remote jobs."""
    now = datetime.utcnow()
    count = 0
    try:
        resp = requests.get(
            "https://remoteok.com/api",
            timeout=15,
            headers={"User-Agent": "BlizTechJobBoard/1.0 (bliztechacademy.com)"}
        )
        if resp.status_code != 200:
            return 0
        jobs = resp.json()
        # First item is a legal notice, skip it
        for j in jobs[1:]:
            if not isinstance(j, dict):
                continue
            title = j.get("position", "") or j.get("title", "")
            tags = j.get("tags", [])
            if not _is_cyber_relevant(title, tags):
                continue

            ext_id = f"remoteok_{j.get('id')}"
            if Job.query.filter_by(external_id=ext_id).first():
                continue

            try:
                posted = datetime.utcfromtimestamp(int(j.get("epoch", 0)))
            except Exception:
                posted = now

            if (now - posted).days > 60:
                continue

            job = Job(
                title=title[:200],
                company=(j.get("company") or "")[:200],
                location=j.get("location") or "Remote (Worldwide)",
                region="international",
                level=_guess_level(title),
                job_type="remote",
                url=j.get("url") or j.get("apply_url") or "",
                source="remoteok",
                external_id=ext_id,
                is_active=True,
                posted_at=posted,
            )
            db.session.add(job)
            count += 1
    except Exception:
        pass
    return count


def _fetch_arbeitnow():
    """Arbeitnow — free API, includes European/UK jobs, no key needed."""
    now = datetime.utcnow()
    count = 0
    try:
        # Page through results looking for security jobs
        for page in range(1, 4):
            resp = requests.get(
                f"https://www.arbeitnow.com/api/job-board-api?page={page}",
                timeout=10,
            )
            if resp.status_code != 200:
                break
            data = resp.json().get("data", [])
            if not data:
                break

            for j in data:
                title = j.get("title", "")
                tags = j.get("tags", [])
                if not _is_cyber_relevant(title, tags):
                    continue

                ext_id = f"arbeitnow_{j.get('slug', '')}"
                if not ext_id or Job.query.filter_by(external_id=ext_id).first():
                    continue

                try:
                    posted = datetime.strptime(j.get("created_at", "")[:10], "%Y-%m-%d")
                except Exception:
                    posted = now

                if (now - posted).days > 60:
                    continue

                location = j.get("location") or "Europe"
                remote = j.get("remote", False)

                job = Job(
                    title=title[:200],
                    company=(j.get("company_name") or "")[:200],
                    location=location[:200],
                    region="international",
                    level=_guess_level(title),
                    job_type="remote" if remote else "onsite",
                    url=j.get("url", "")[:500],
                    source="arbeitnow",
                    external_id=ext_id,
                    is_active=True,
                    posted_at=posted,
                )
                db.session.add(job)
                count += 1

    except Exception:
        pass
    return count


def _fetch_all_sources():
    """Run all fetchers and commit."""
    global _last_fetch
    now = datetime.utcnow()

    if _last_fetch and (now - _last_fetch) < timedelta(hours=FETCH_INTERVAL_HOURS):
        return

    try:
        _fetch_remotive()
        _fetch_remoteok()
        _fetch_arbeitnow()

        # Deactivate jobs older than 60 days from auto sources
        cutoff = now - timedelta(days=60)
        Job.query.filter(
            Job.source.in_(["remotive", "remoteok", "arbeitnow"]),
            Job.posted_at < cutoff
        ).update({"is_active": False}, synchronize_session=False)

        db.session.commit()
        _last_fetch = now

    except Exception:
        db.session.rollback()


@jobs_bp.route("/jobs")
def job_board():
    try:
        _fetch_all_sources()
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