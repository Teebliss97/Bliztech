import requests
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request
from app.extensions import db
from app.models import Job

jobs_bp = Blueprint("jobs", __name__)

FETCH_INTERVAL_HOURS = 12
_last_fetch = None

CYBER_KEYWORDS = [
    "cyber", "security", "soc", "penetration", "pentest", "infosec",
    "vulnerability", "threat", "incident", "forensic", "malware",
    "firewall", "siem", "devsecops", "compliance", "risk", "audit",
    "cloud security", "network security", "zero trust", "identity",
    "blue team", "red team", "grc", "cissp", "ceh", "comptia",
    "ethical hacking", "ctf", "appsec", "application security",
    "data protection", "privacy", "gdpr", "nist", "iso 27001",
]

STRONG_CYBER_KEYWORDS = [
    "cybersecurity", "cyber security", "soc analyst", "security analyst",
    "penetration tester", "pentester", "information security", "infosec",
    "security engineer", "security architect", "threat analyst",
    "incident response", "malware analyst", "vulnerability analyst",
    "devsecops", "cloud security", "application security",
]


def _is_cyber_relevant(title: str, tags: list = None, description: str = "") -> bool:
    text = title.lower() + " " + " ".join(str(t).lower() for t in (tags or [])) + " " + (description or "").lower()[:500]
    return any(k in text for k in CYBER_KEYWORDS)


def _cyber_priority(title: str) -> int:
    """Higher = more cybersecurity relevant. Used for sorting."""
    title_lower = title.lower()
    if any(k in title_lower for k in STRONG_CYBER_KEYWORDS):
        return 2
    if any(k in title_lower for k in CYBER_KEYWORDS):
        return 1
    return 0


def _guess_level(title: str) -> str:
    title = title.lower()
    if any(w in title for w in ["senior", "lead", "principal", "head", "director", "manager", "staff", "vp", "chief"]):
        return "senior"
    if any(w in title for w in ["junior", "entry", "graduate", "intern", "associate", "apprentice", "jr"]):
        return "entry"
    return "mid"


def _fetch_remotive():
    searches = [
        "https://remotive.com/api/remote-jobs?search=cybersecurity&limit=100",
        "https://remotive.com/api/remote-jobs?search=security+analyst&limit=100",
        "https://remotive.com/api/remote-jobs?search=SOC+analyst&limit=100",
        "https://remotive.com/api/remote-jobs?search=penetration+testing&limit=100",
        "https://remotive.com/api/remote-jobs?search=information+security&limit=100",
        "https://remotive.com/api/remote-jobs?search=devsecops&limit=50",
        "https://remotive.com/api/remote-jobs?search=cloud+security&limit=50",
    ]
    now = datetime.utcnow()

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
                if (now - posted).days > 30:
                    continue
                db.session.add(Job(
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
                ))
        except Exception:
            continue


def _fetch_remoteok():
    now = datetime.utcnow()
    try:
        resp = requests.get(
            "https://remoteok.com/api",
            timeout=15,
            headers={"User-Agent": "BlizTechJobBoard/1.0 (bliztechacademy.com)"}
        )
        if resp.status_code != 200:
            return
        for j in resp.json()[1:]:
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
            if (now - posted).days > 30:
                continue
            db.session.add(Job(
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
            ))
    except Exception:
        pass


def _fetch_himalayas():
    """Himalayas — free API, no key, excellent cybersecurity coverage."""
    now = datetime.utcnow()
    searches = [
        "https://himalayas.app/jobs/api/search?q=cybersecurity&limit=100",
        "https://himalayas.app/jobs/api/search?q=security+analyst&limit=100",
        "https://himalayas.app/jobs/api/search?q=information+security&limit=100",
        "https://himalayas.app/jobs/api/search?q=penetration+testing&limit=50",
        "https://himalayas.app/jobs/api/search?q=SOC+analyst&limit=50",
        "https://himalayas.app/jobs/api/search?q=cloud+security&limit=50",
        "https://himalayas.app/jobs/api/search?q=devsecops&limit=50",
    ]

    for url in searches:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            data = resp.json()
            jobs = data.get("jobs", [])
            for j in jobs:
                ext_id = f"himalayas_{j.get('slug', '') or j.get('id', '')}"
                if not ext_id or ext_id == "himalayas_" or Job.query.filter_by(external_id=ext_id).first():
                    continue
                try:
                    posted = datetime.strptime(j.get("createdAt", "")[:10], "%Y-%m-%d")
                except Exception:
                    posted = now
                if (now - posted).days > 30:
                    continue
                db.session.add(Job(
                    title=(j.get("title") or "")[:200],
                    company=(j.get("companyName") or "")[:200],
                    location=j.get("locationRestrictions") or j.get("location") or "Remote (Worldwide)",
                    region="international",
                    level=_guess_level(j.get("title", "")),
                    job_type="remote",
                    url=j.get("applicationLink") or j.get("url") or f"https://himalayas.app/jobs/{j.get('slug', '')}",
                    source="himalayas",
                    external_id=ext_id,
                    is_active=True,
                    posted_at=posted,
                ))
        except Exception:
            continue


def _fetch_arbeitnow():
    """Arbeitnow — free API, includes European/UK jobs."""
    now = datetime.utcnow()
    try:
        for page in range(1, 6):
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
                if (now - posted).days > 30:
                    continue
                db.session.add(Job(
                    title=title[:200],
                    company=(j.get("company_name") or "")[:200],
                    location=(j.get("location") or "Europe")[:200],
                    region="international",
                    level=_guess_level(title),
                    job_type="remote" if j.get("remote") else "onsite",
                    url=j.get("url", "")[:500],
                    source="arbeitnow",
                    external_id=ext_id,
                    is_active=True,
                    posted_at=posted,
                ))
    except Exception:
        pass


def _fetch_all_sources():
    global _last_fetch
    now = datetime.utcnow()

    if _last_fetch and (now - _last_fetch) < timedelta(hours=FETCH_INTERVAL_HOURS):
        return

    try:
        _fetch_remotive()
        _fetch_remoteok()
        _fetch_himalayas()
        _fetch_arbeitnow()

        # Deactivate auto-fetched jobs older than 30 days
        cutoff = now - timedelta(days=30)
        Job.query.filter(
            Job.source.in_(["remotive", "remoteok", "himalayas", "arbeitnow"]),
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

    # No limit — show all jobs, cybersecurity-relevant titles first
    all_jobs = query.order_by(Job.posted_at.desc()).all()

    # Sort: strong cyber titles first, then mid, then others
    all_jobs.sort(key=lambda j: _cyber_priority(j.title), reverse=True)

    total = Job.query.filter_by(is_active=True).count()
    africa_count = Job.query.filter_by(is_active=True, region="africa").count()
    international_count = Job.query.filter_by(is_active=True, region="international").count()

    return render_template(
        "jobs.html",
        jobs=all_jobs,
        total=total,
        africa_count=africa_count,
        international_count=international_count,
        region=region,
        level=level,
        job_type=job_type,
        q=q,
    )