from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_login import current_user

from app.extensions import db
from app.models import Progress
from app.blueprints.topics.routes import TOPICS
from app.email_utils import send_course_completion_email

quizzes_bp = Blueprint("quizzes", __name__, url_prefix="/quiz")

PASS_MARK = 70

# A special Progress slug to prevent duplicate completion emails (stored in DB)
COURSE_EMAIL_FLAG_SLUG = "__course_completion_emailed__"


# -------------------------
# IMPORTANT: Progress key
# -------------------------
def _progress_key() -> str:
    """
    Use a stable key for progress:
    - logged in users:  user:<id>
    - anonymous users:  anon:<uuid>  (stored in session)
    """
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    # create_app() should already ensure anon_id exists, but keep it safe:
    return session.get("anon_id") or "anon:missing"


def _progress_map(progress_user_id: str) -> dict:
    rows = Progress.query.filter_by(user_id=progress_user_id).all()
    return {r.slug: r for r in rows}


def _is_unlocked(slug: str, progress_user_id: str) -> bool:
    """
    Topic1 is always unlocked.
    TopicN is unlocked only if Topic(N-1) is passed.
    """
    if slug == "topic1":
        return True

    idx = next((i for i, t in enumerate(TOPICS) if t["slug"] == slug), None)
    if idx is None or idx == 0:
        return False

    prev_slug = TOPICS[idx - 1]["slug"]
    m = _progress_map(progress_user_id)
    prev_row = m.get(prev_slug)
    return bool(prev_row and prev_row.passed)


def _all_topics_completed(progress_user_id: str) -> bool:
    """
    True if ALL topics in TOPICS are passed for this progress_user_id.
    """
    m = _progress_map(progress_user_id)
    return all(bool(m.get(t["slug"]) and m[t["slug"]].passed) for t in TOPICS)


def _completion_email_already_sent(progress_user_id: str) -> bool:
    """
    Uses a special Progress row as a durable "email sent" flag.
    """
    flag = Progress.query.filter_by(user_id=progress_user_id, slug=COURSE_EMAIL_FLAG_SLUG).first()
    return bool(flag and flag.passed)


def _mark_completion_email_sent(progress_user_id: str) -> None:
    """
    Writes the flag row so we never send duplicates again.
    """
    flag = Progress.query.filter_by(user_id=progress_user_id, slug=COURSE_EMAIL_FLAG_SLUG).first()
    if flag is None:
        flag = Progress(user_id=progress_user_id, slug=COURSE_EMAIL_FLAG_SLUG, attempts=0)

    flag.passed = True
    flag.score = 100
    flag.updated_at = datetime.utcnow()

    db.session.add(flag)
    db.session.commit()


# -------------------------
# QUIZZES DATA
# -------------------------

QUIZZES = {
    "topic1": {
        "title": "Topic 1 Quiz: Introduction to Cybersecurity",
        "questions": [
            {
                "q": "What is cybersecurity mainly about?",
                "choices": [
                    "Making computers faster",
                    "Protecting systems and data from digital attacks",
                    "Browsing anonymously",
                    "Installing apps",
                ],
                "answer": 1,
                "explain": "Cybersecurity focuses on protecting systems, networks, and data from attacks.",
            },
            {
                "q": "Who does cybersecurity affect?",
                "choices": [
                    "Only hackers",
                    "Only companies",
                    "Only IT professionals",
                    "Everyone who uses the internet",
                ],
                "answer": 3,
                "explain": "Anyone online can be targeted.",
            },
            {
                "q": "Which activity can expose you to online risks?",
                "choices": [
                    "Online shopping",
                    "Using social media",
                    "Connecting to public Wi-Fi",
                    "All of the above",
                ],
                "answer": 3,
                "explain": "All online activities have some risk.",
            },
            {
                "q": "What is phishing?",
                "choices": [
                    "A way to improve email speed",
                    "A type of antivirus software",
                    "Fake messages designed to trick users",
                    "A secure login method",
                ],
                "answer": 2,
                "explain": "Phishing uses deception to steal info or money.",
            },
            {
                "q": "What is malware?",
                "choices": [
                    "Helpful software",
                    "A computer update",
                    "Harmful software designed to cause damage or steal data",
                    "A password manager",
                ],
                "answer": 2,
                "explain": "Malware includes viruses, spyware, ransomware, etc.",
            },
        ],
    },

    "topic2": {
        "title": "Topic 2 Quiz: Phishing & Scam Awareness",
        "questions": [
            {
                "q": "What is phishing?",
                "choices": [
                    "A technique to speed up the internet",
                    "Pretending to be trusted to steal info or money",
                    "A type of firewall",
                    "A safe way to verify identity",
                ],
                "answer": 1,
                "explain": "Phishing uses deception to get you to click, pay, or reveal info.",
            },
            {
                "q": "“Smishing” means phishing via:",
                "choices": ["Social media", "SMS/text messages", "Phone calls", "Email attachments only"],
                "answer": 1,
                "explain": "Smishing = SMS phishing.",
            },
            {
                "q": "Which is the BIGGEST red flag?",
                "choices": [
                    "A message asking for your OTP/verification code",
                    "A message with your name",
                    "A message from a known company",
                    "A message with a logo",
                ],
                "answer": 0,
                "explain": "Never share OTPs—attackers use them to take over accounts.",
            },
            {
                "q": "What should you do if you get a “bank” email asking you to log in?",
                "choices": [
                    "Click the link and log in",
                    "Reply asking if it’s real",
                    "Go to your bank app/website directly",
                    "Forward it to friends",
                ],
                "answer": 2,
                "explain": "Always verify through official channels you open yourself.",
            },
            {
                "q": "A friend says “new number, send money urgently.” What should you do?",
                "choices": [
                    "Send the money",
                    "Verify via a different channel (call/voice)",
                    "Ask for bank details",
                    "Share your OTP",
                ],
                "answer": 1,
                "explain": "Account takeover scams rely on pressure—verify first.",
            },
        ],
    },

    "topic3": {
        "title": "Topic 3 Quiz: Passwords & Passphrases",
        "questions": [
            {
                "q": "Which password is strongest?",
                "choices": ["password123", "Liverpool2025", "P@ssw0rd", "Blue-taxi!River^Moon7"],
                "answer": 3,
                "explain": "Long, random, and mixed characters is strongest.",
            },
            {
                "q": "What is a passphrase?",
                "choices": ["A short PIN", "A long phrase used as a password", "A type of virus", "A browser cookie"],
                "answer": 1,
                "explain": "Passphrases are longer and easier to remember, but harder to guess.",
            },
            {
                "q": "Why is reusing passwords risky?",
                "choices": [
                    "It makes Wi-Fi slower",
                    "One leak can unlock many of your accounts",
                    "It breaks your phone",
                    "It helps hackers track your location",
                ],
                "answer": 1,
                "explain": "If one site is breached, attackers try the same password elsewhere.",
            },
            {
                "q": "Best way to manage many strong passwords?",
                "choices": ["Write them in Notes", "Use a password manager", "Use one password everywhere", "Share with a friend"],
                "answer": 1,
                "explain": "Password managers store and generate strong unique passwords safely.",
            },
            {
                "q": "What should you do after a password leak?",
                "choices": ["Ignore it", "Change the password everywhere you used it", "Turn off Wi-Fi", "Delete the app only"],
                "answer": 1,
                "explain": "Change leaked/reused passwords immediately and enable 2FA.",
            },
        ],
    },

    "topic4": {
        "title": "Topic 4 Quiz: Two-Factor Authentication (2FA)",
        "questions": [
            {
                "q": "2FA means:",
                "choices": ["Two Facebook Accounts", "Two steps to prove it’s you", "Two passwords for one account", "Two browsers at once"],
                "answer": 1,
                "explain": "2FA adds a second step beyond your password.",
            },
            {
                "q": "Which 2FA method is usually strongest?",
                "choices": ["SMS code", "Email code", "Authenticator app code", "Posting your password"],
                "answer": 2,
                "explain": "Authenticator apps are generally more secure than SMS/email codes.",
            },
            {
                "q": "If someone asks for your OTP code, you should:",
                "choices": ["Share it quickly", "Share only with bank staff", "Never share it", "Post it in a group chat"],
                "answer": 2,
                "explain": "OTPs are like keys—sharing them gives attackers access.",
            },
            {
                "q": "2FA protects you most when:",
                "choices": [
                    "Your battery is full",
                    "Someone steals/guesses your password",
                    "You install new apps",
                    "You use a new phone case",
                ],
                "answer": 1,
                "explain": "Even if password is compromised, 2FA can stop login.",
            },
            {
                "q": "Best practice when setting up 2FA:",
                "choices": [
                    "Save backup codes safely",
                    "Use the same OTP everywhere",
                    "Disable updates",
                    "Share codes with family",
                ],
                "answer": 0,
                "explain": "Backup codes help if you lose your phone.",
            },
        ],
    },

    "topic5": {
        "title": "Topic 5 Quiz: Malware & Ransomware Basics",
        "questions": [
            {
                "q": "Malware is:",
                "choices": ["A browser feature", "Harmful software", "A password type", "A Wi-Fi standard"],
                "answer": 1,
                "explain": "Malware is software designed to harm or steal.",
            },
            {
                "q": "Ransomware usually does what?",
                "choices": ["Speeds up PC", "Encrypts your files and demands payment", "Improves Wi-Fi", "Fixes bugs"],
                "answer": 1,
                "explain": "Ransomware locks files and demands money for recovery.",
            },
            {
                "q": "Common way malware gets in?",
                "choices": ["Sketchy downloads/attachments", "Charging your phone", "Turning on airplane mode", "Changing wallpaper"],
                "answer": 0,
                "explain": "Downloads, attachments and links are common infection paths.",
            },
            {
                "q": "Best protection combo?",
                "choices": ["Ignore updates", "Antivirus + updates + safe habits", "Use public Wi-Fi always", "Turn off passwords"],
                "answer": 1,
                "explain": "Layered security reduces risk.",
            },
            {
                "q": "If infected, first step is:",
                "choices": ["Pay immediately", "Disconnect from internet and get help", "Share files online", "Reinstall random apps"],
                "answer": 1,
                "explain": "Contain first, then recover with expert guidance/clean backups.",
            },
        ],
    },

    "topic6": {
        "title": "Topic 6 Quiz: Safe Browsing & Downloads",
        "questions": [
            {
                "q": "A safe download should come from:",
                "choices": ["Random pop-ups", "Official websites/app stores", "Unknown links", "Forwarded .exe files"],
                "answer": 1,
                "explain": "Use official sources to reduce risk of malware.",
            },
            {
                "q": "HTTPS mainly means:",
                "choices": ["A site is always legit", "Your connection is encrypted", "No scams exist", "It’s government owned"],
                "answer": 1,
                "explain": "HTTPS encrypts traffic; it doesn’t guarantee trustworthiness.",
            },
            {
                "q": "If a website looks slightly weird, you should:",
                "choices": ["Enter card details", "Double-check the URL carefully", "Disable antivirus", "Send your password"],
                "answer": 1,
                "explain": "Typos and strange domains are common scam signs.",
            },
            {
                "q": "Browser extensions are risky when:",
                "choices": ["From trusted store with good reviews", "They request too many permissions", "They auto update", "They have icons"],
                "answer": 1,
                "explain": "Over-permissioned extensions can steal data.",
            },
            {
                "q": "Best habit for links:",
                "choices": ["Click fast", "Hover/long-press to preview URL", "Trust every shortened link", "Disable security warnings"],
                "answer": 1,
                "explain": "Preview links before opening them.",
            },
        ],
    },

    "topic7": {
        "title": "Topic 7 Quiz: Social Media Safety & Privacy",
        "questions": [
            {
                "q": "Best profile setting for most people:",
                "choices": ["Public always", "Private / friends only", "Share everything", "No password"],
                "answer": 1,
                "explain": "Private reduces exposure to scammers and stalkers.",
            },
            {
                "q": "A common social media scam is:",
                "choices": ["Free music", "Fake giveaways/impersonation", "Verified badge", "New emojis"],
                "answer": 1,
                "explain": "Scammers impersonate brands or friends for money/data.",
            },
            {
                "q": "If someone DMs you a “job offer” link, you should:",
                "choices": ["Click immediately", "Verify the company independently", "Send your BVN/NI number", "Share OTP"],
                "answer": 1,
                "explain": "Always verify via official website and trusted channels.",
            },
            {
                "q": "Oversharing can lead to:",
                "choices": ["Better Wi-Fi", "Identity theft and targeted scams", "Faster phone", "No effect"],
                "answer": 1,
                "explain": "Attackers use personal info to craft believable scams.",
            },
            {
                "q": "Strong security for social accounts includes:",
                "choices": ["2FA + unique password", "Same password everywhere", "Sharing logins", "Turning off updates"],
                "answer": 0,
                "explain": "Unique passwords and 2FA prevent account takeover.",
            },
        ],
    },

    "topic8": {
        "title": "Topic 8 Quiz: Public Wi-Fi & Mobile Safety",
        "questions": [
            {
                "q": "Public Wi-Fi is risky because:",
                "choices": ["It is always slow", "Attackers can intercept traffic", "It breaks phones", "It deletes photos"],
                "answer": 1,
                "explain": "Some networks allow eavesdropping or fake hotspots.",
            },
            {
                "q": "Best action on public Wi-Fi:",
                "choices": ["Do banking freely", "Use a VPN / avoid sensitive logins", "Turn off firewall", "Share hotspot password"],
                "answer": 1,
                "explain": "Avoid sensitive actions; VPN helps encrypt traffic.",
            },
            {
                "q": "A fake hotspot is:",
                "choices": ["A phone charger", "A Wi-Fi name set up by attackers", "A router update", "A secure network"],
                "answer": 1,
                "explain": "Attackers mimic cafe/airport Wi-Fi names.",
            },
            {
                "q": "If your phone is lost, you should:",
                "choices": ["Wait a week", "Use Find My/remote lock and change passwords", "Post PIN online", "Ignore it"],
                "answer": 1,
                "explain": "Lock/wipe quickly and secure accounts.",
            },
            {
                "q": "Safe phone habit:",
                "choices": ["Install any APK", "Keep OS updated", "Disable screen lock", "Turn off backups"],
                "answer": 1,
                "explain": "Updates patch known vulnerabilities.",
            },
        ],
    },

    "topic9": {
        "title": "Topic 9 Quiz: Online Shopping & Payment Safety",
        "questions": [
            {
                "q": "A safe online shop usually has:",
                "choices": ["No contact details", "Clear returns + secure payment", "Only WhatsApp contact", "Huge discounts always"],
                "answer": 1,
                "explain": "Legit stores show policies and trusted payment methods.",
            },
            {
                "q": "A big scam sign is:",
                "choices": ["Price slightly lower", "Pressure to pay by bank transfer/crypto", "Secure checkout", "Reviews on multiple sites"],
                "answer": 1,
                "explain": "Scammers prefer irreversible payments.",
            },
            {
                "q": "Before entering card details, you should:",
                "choices": ["Check URL and HTTPS", "Disable browser security", "Use public Wi-Fi", "Share OTP"],
                "answer": 0,
                "explain": "Verify the correct domain and encrypted connection.",
            },
            {
                "q": "If a “delivery fee” message comes unexpectedly:",
                "choices": ["Pay immediately", "Verify on the official courier site/app", "Forward to friends", "Send card PIN"],
                "answer": 1,
                "explain": "Scammers mimic couriers with fake payment links.",
            },
            {
                "q": "A safer payment method is often:",
                "choices": ["Direct bank transfer", "Card/PayPal with buyer protection", "Gift cards", "Crypto only"],
                "answer": 1,
                "explain": "Buyer protection helps if something goes wrong.",
            },
        ],
    },

    "topic10": {
        "title": "Topic 10 Quiz: Backups & Device Updates",
        "questions": [
            {
                "q": "Backups are important because:",
                "choices": ["They make Wi-Fi faster", "They help recover after loss/ransomware", "They stop phishing", "They delete viruses"],
                "answer": 1,
                "explain": "Backups let you restore files if something goes wrong.",
            },
            {
                "q": "The “3-2-1” backup rule means:",
                "choices": ["3 phones, 2 chargers, 1 cable", "3 copies, 2 media types, 1 offsite", "3 passwords, 2 emails, 1 bank", "3 files, 2 folders, 1 app"],
                "answer": 1,
                "explain": "Multiple copies across different storage, with one offsite/cloud.",
            },
            {
                "q": "Updates help because they:",
                "choices": ["Change wallpaper", "Patch security vulnerabilities", "Slow devices always", "Remove passwords"],
                "answer": 1,
                "explain": "Updates fix known security holes attackers exploit.",
            },
            {
                "q": "Best update habit:",
                "choices": ["Delay forever", "Enable automatic updates where possible", "Only update once a year", "Update from random sites"],
                "answer": 1,
                "explain": "Auto updates keep you protected with minimal effort.",
            },
            {
                "q": "If you get ransomware, the best recovery is:",
                "choices": ["Pay immediately", "Restore from clean backups", "Ignore it", "Send OTP to support"],
                "answer": 1,
                "explain": "Clean backups are the safest recovery path.",
            },
        ],
    },
}


@quizzes_bp.route("/<slug>")
def quiz(slug):
    quiz_data = QUIZZES.get(slug)
    if not quiz_data:
        return "Quiz not found", 404

    progress_user_id = _progress_key()
    if not _is_unlocked(slug, progress_user_id):
        flash("That quiz is locked. Complete the previous topic first.", "error")
        return redirect(url_for("topics.list_topics"))

    return render_template("quizzes/quiz.html", slug=slug, quiz=quiz_data, pass_mark=PASS_MARK)


@quizzes_bp.route("/<slug>/submit", methods=["POST"])
def submit(slug):
    quiz_data = QUIZZES.get(slug)
    if not quiz_data:
        return "Quiz not found", 404

    progress_user_id = _progress_key()
    if not _is_unlocked(slug, progress_user_id):
        flash("That quiz is locked. Complete the previous topic first.", "error")
        return redirect(url_for("topics.list_topics"))

    questions = quiz_data["questions"]
    correct = 0
    answers = []

    for i, q in enumerate(questions):
        raw = request.form.get(f"q{i}")
        ans = int(raw) if raw is not None and raw.isdigit() else None
        answers.append(ans)
        if ans is not None and ans == q["answer"]:
            correct += 1

    total = len(questions)
    score_pct = int(round((correct / total) * 100)) if total else 0
    passed = score_pct >= PASS_MARK

    row = Progress.query.filter_by(user_id=progress_user_id, slug=slug).first()
    if row is None:
        row = Progress(user_id=progress_user_id, slug=slug, attempts=0)

    row.attempts = (row.attempts or 0) + 1
    row.score = score_pct
    row.passed = passed
    row.updated_at = datetime.utcnow()

    db.session.add(row)
    db.session.commit()

    # ✅ Send completion email ONLY when Topic 10 is passed AND course is fully completed (logged-in only)
    if current_user.is_authenticated and passed and slug == "topic10":
        if not _completion_email_already_sent(progress_user_id):
            if _all_topics_completed(progress_user_id):
                ok = send_course_completion_email(current_user.email)
                if ok:
                    _mark_completion_email_sent(progress_user_id)

    session["last_result"] = {
        "slug": slug,
        "score_pct": score_pct,
        "correct": correct,
        "total": total,
        "answers": answers,
    }

    return redirect(url_for("quizzes.result", slug=slug))


@quizzes_bp.route("/<slug>/result")
def result(slug):
    quiz_data = QUIZZES.get(slug)
    if not quiz_data:
        return "Quiz not found", 404

    res = session.get("last_result")
    if not res or res.get("slug") != slug:
        return redirect(url_for("quizzes.quiz", slug=slug))

    passed = res["score_pct"] >= PASS_MARK

    # ✅ Next topic slug (only if passed)
    next_slug = None
    try:
        idx = next(i for i, t in enumerate(TOPICS) if t["slug"] == slug)
        if passed and idx < len(TOPICS) - 1:
            next_slug = TOPICS[idx + 1]["slug"]
    except StopIteration:
        next_slug = None

    # ✅ Show certificate button only when:
    # - logged in
    # - Topic 10 result
    # - passed
    # - all topics completed
    show_certificate_btn = False
    if current_user.is_authenticated and slug == "topic10" and passed:
        progress_user_id = _progress_key()
        show_certificate_btn = _all_topics_completed(progress_user_id)

    return render_template(
        "quizzes/result.html",
        quiz=quiz_data,
        result=res,
        passed=passed,
        pass_mark=PASS_MARK,
        next_slug=next_slug,
        show_certificate_btn=show_certificate_btn,
    )
