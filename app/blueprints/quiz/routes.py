from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from datetime import datetime

from app.extensions import db
from app.models import CourseAccess, LessonRead, QuizAttempt

quiz_bp = Blueprint("quiz", __name__, url_prefix="/course/quiz")

TOTAL_LESSONS = 20
PASS_THRESHOLD = 0.70  # 70%

# ─────────────────────────────────────────────
#  All 90 quiz questions
#  Format: { "q": question, "options": [A,B,C,D], "answer": 0-based index }
# ─────────────────────────────────────────────
QUESTIONS = [
    # ── Section A: Foundation (Questions 1-23) ──
    {
        "q": "What is cybersecurity?",
        "options": ["Making systems faster", "Protecting systems, networks and data from attack or damage", "Writing software code", "Designing computer hardware"],
        "answer": 1
    },
    {
        "q": "Which of the following best describes the CIA Triad?",
        "options": ["Confidentiality, Integrity, Availability", "Cybersecurity, Intelligence, Anonymity", "Control, Identify, Analyse", "Contain, Investigate, Alert"],
        "answer": 0
    },
    {
        "q": "What does 'Confidentiality' mean in the CIA Triad?",
        "options": ["Data is always available", "Only authorised people can access data", "Data cannot be modified", "Systems recover quickly from failure"],
        "answer": 1
    },
    {
        "q": "What does 'Integrity' mean in the CIA Triad?",
        "options": ["Data is encrypted at rest", "Systems are always online", "Data is accurate and has not been tampered with", "Users are who they say they are"],
        "answer": 2
    },
    {
        "q": "What does 'Availability' mean in the CIA Triad?",
        "options": ["Data is only available to admins", "Systems and data are accessible when needed", "Passwords are stored securely", "Logs are kept for 90 days"],
        "answer": 1
    },
    {
        "q": "Which formula correctly represents risk?",
        "options": ["Risk = Threat + Vulnerability", "Risk = Threat x Vulnerability x Impact", "Risk = Impact / Threat", "Risk = Vulnerability - Control"],
        "answer": 1
    },
    {
        "q": "If a threat actor has zero capability to exploit a vulnerability, what is the risk?",
        "options": ["High", "Medium", "Low", "Zero"],
        "answer": 3
    },
    {
        "q": "What is a threat actor?",
        "options": ["A software bug", "A person or group who may cause harm to a system", "A firewall rule", "An unpatched server"],
        "answer": 1
    },
    {
        "q": "What is a vulnerability?",
        "options": ["A strong password policy", "A weakness that can be exploited", "A type of encryption", "A network protocol"],
        "answer": 1
    },
    {
        "q": "Which of the following is the first stage of the Cyber Kill Chain?",
        "options": ["Exploitation", "Weaponisation", "Reconnaissance", "Command and Control"],
        "answer": 2
    },
    {
        "q": "What is the purpose of the 'Deliver' stage in the Kill Chain?",
        "options": ["To gain persistence on a system", "To transmit the weapon to the target", "To encrypt files", "To exfiltrate data"],
        "answer": 1
    },
    {
        "q": "At which Kill Chain stage does the attacker establish remote access?",
        "options": ["Weaponise", "Install", "Command and Control", "Objectives"],
        "answer": 2
    },
    {
        "q": "What does 'defence in depth' mean?",
        "options": ["Using one very strong firewall", "Encrypting all data", "Using multiple independent layers of security controls", "Hiring more security staff"],
        "answer": 2
    },
    {
        "q": "Which layer sits at the innermost layer of defence in depth?",
        "options": ["Perimeter", "Network", "Application", "Data"],
        "answer": 3
    },
    {
        "q": "What is the primary goal of a SOC analyst?",
        "options": ["Write software code", "Monitor systems and respond to security alerts", "Configure network hardware", "Manage user accounts"],
        "answer": 1
    },
    {
        "q": "Which role focuses on finding and exploiting weaknesses in systems?",
        "options": ["GRC Analyst", "SOC Analyst", "Penetration Tester", "Cloud Engineer"],
        "answer": 2
    },
    {
        "q": "What does GRC stand for?",
        "options": ["General Risk Control", "Governance, Risk and Compliance", "Global Response Centre", "Group Risk Calculation"],
        "answer": 1
    },
    {
        "q": "Which misconception suggests small organisations don't need cybersecurity?",
        "options": ["Security through obscurity", "We are too small to be a target", "Cybersecurity is only an IT problem", "Antivirus is enough"],
        "answer": 1
    },
    {
        "q": "What is the WannaCry attack best known for?",
        "options": ["Stealing credit card numbers", "Encrypting NHS systems via an unpatched Windows flaw", "Crashing social media platforms", "Defacing government websites"],
        "answer": 1
    },
    {
        "q": "What stopped the WannaCry ransomware from spreading further?",
        "options": ["A government takedown", "A kill switch domain registered by a researcher", "An antivirus update", "A firewall rule"],
        "answer": 1
    },
    {
        "q": "Which of the following is an example of a physical security control?",
        "options": ["Firewall", "Encryption", "Locked server room door", "Password policy"],
        "answer": 2
    },
    {
        "q": "What is the term for the practice of making a system intentionally difficult to understand to hide its weaknesses?",
        "options": ["Encryption", "Security through obscurity", "Defence in depth", "Zero trust"],
        "answer": 1
    },
    {
        "q": "Which type of attacker is motivated by financial gain?",
        "options": ["Hacktivist", "Nation-state actor", "Cybercriminal", "Script kiddie"],
        "answer": 2
    },

    # ── Section B: Technical Core (Questions 24-45) ──
    {
        "q": "What is the purpose of a firewall?",
        "options": ["To speed up network traffic", "To filter network traffic based on rules", "To encrypt data in transit", "To store user passwords"],
        "answer": 1
    },
    {
        "q": "What does DNS stand for?",
        "options": ["Data Network Security", "Domain Name System", "Digital Network Service", "Direct Node Server"],
        "answer": 1
    },
    {
        "q": "What does DNS do?",
        "options": ["Encrypts web traffic", "Translates domain names to IP addresses", "Assigns MAC addresses", "Routes packets between networks"],
        "answer": 1
    },
    {
        "q": "What is a Man-in-the-Middle attack?",
        "options": ["An attacker who physically enters a building", "An attacker who intercepts and potentially modifies traffic between two parties", "A brute force password attack", "An attack that floods a server with requests"],
        "answer": 1
    },
    {
        "q": "Which protocol is used to establish a reliable connection before data is sent?",
        "options": ["UDP", "HTTP", "TCP", "ICMP"],
        "answer": 2
    },
    {
        "q": "What are the three steps of the TCP handshake?",
        "options": ["SYN, SYN-ACK, ACK", "GET, POST, PUT", "CONNECT, SEND, CLOSE", "OPEN, AUTH, DATA"],
        "answer": 0
    },
    {
        "q": "What is a SYN flood attack?",
        "options": ["Encrypting a target's files", "Sending millions of SYN packets without completing the handshake", "Redirecting DNS queries", "Stealing session cookies"],
        "answer": 1
    },
    {
        "q": "What is network segmentation?",
        "options": ["Splitting a network into isolated zones", "Encrypting all network traffic", "Assigning static IP addresses", "Installing IDS sensors"],
        "answer": 0
    },
    {
        "q": "What is the purpose of a DMZ in network architecture?",
        "options": ["To store backups", "To host internal HR systems", "To isolate public-facing services from the internal network", "To encrypt traffic between offices"],
        "answer": 2
    },
    {
        "q": "What does HTTPS provide that HTTP does not?",
        "options": ["Faster page loads", "Encrypted communication using TLS", "Larger file transfers", "Better DNS resolution"],
        "answer": 1
    },
    {
        "q": "What is DNS cache poisoning?",
        "options": ["Filling a DNS server's memory with requests", "Inserting false DNS records to redirect users to attacker servers", "Blocking DNS queries", "Changing a domain's A record"],
        "answer": 1
    },
    {
        "q": "Which of the following is a defence against Man-in-the-Middle attacks?",
        "options": ["Using HTTP", "Disabling HTTPS", "TLS with certificate validation", "Opening all firewall ports"],
        "answer": 2
    },
    {
        "q": "What is an IDS?",
        "options": ["A tool that blocks all network traffic", "A system that detects suspicious network activity", "An encryption protocol", "A type of firewall"],
        "answer": 1
    },
    {
        "q": "What does 'least privilege' mean?",
        "options": ["Users have admin access by default", "Users are given only the access they need", "All files are read-only", "Passwords expire every 90 days"],
        "answer": 1
    },
    {
        "q": "What is the OSI model used for?",
        "options": ["Classifying malware types", "Describing how data moves through network layers", "Encrypting network traffic", "Managing firewall rules"],
        "answer": 1
    },
    {
        "q": "Which authentication factor is a fingerprint?",
        "options": ["Something you know", "Something you have", "Something you are", "Something you do"],
        "answer": 2
    },
    {
        "q": "Which authentication factor is a hardware key like a YubiKey?",
        "options": ["Something you know", "Something you have", "Something you are", "Something you share"],
        "answer": 1
    },
    {
        "q": "Why is MFA more secure than a password alone?",
        "options": ["Passwords are always short", "Even if a password is stolen, an attacker still needs a second factor", "MFA encrypts the password", "MFA replaces the need for a username"],
        "answer": 1
    },
    {
        "q": "Which type of MFA is considered phishing-proof?",
        "options": ["SMS codes", "Email codes", "Hardware security keys", "Security questions"],
        "answer": 2
    },
    {
        "q": "What is a VPN used for?",
        "options": ["Speeding up internet connections", "Encrypting traffic between a device and a network", "Blocking advertisements", "Scanning for malware"],
        "answer": 1
    },
    {
        "q": "What is port scanning used for in cybersecurity?",
        "options": ["Encrypting data", "Discovering open ports and services on a system", "Backing up data", "Monitoring user activity"],
        "answer": 1
    },

    # ── Section C: Defence & Response (Questions 46-67) ──
    {
        "q": "What is phishing?",
        "options": ["A technique to speed up networks", "A social engineering attack using deceptive emails to steal credentials", "A type of encryption", "A network monitoring tool"],
        "answer": 1
    },
    {
        "q": "Which of the following makes a phishing email convincing?",
        "options": ["Poor spelling and grammar", "A spoofed sender address and urgent message", "An attachment with a .pdf extension", "A long email address"],
        "answer": 1
    },
    {
        "q": "What is spear phishing?",
        "options": ["A phishing attack targeting a specific individual or organisation", "A phishing attack using phone calls", "A mass phishing campaign", "A phishing attack using SMS"],
        "answer": 0
    },
    {
        "q": "What does SPF stand for in email security?",
        "options": ["Sender Policy Framework", "Secure Packet Filter", "System Protection Firewall", "Security Protocol Foundation"],
        "answer": 0
    },
    {
        "q": "What is ransomware?",
        "options": ["Software that speeds up computers", "Malware that encrypts files and demands payment for the decryption key", "A type of phishing email", "A network monitoring tool"],
        "answer": 1
    },
    {
        "q": "What is double extortion in ransomware attacks?",
        "options": ["Attacking two victims simultaneously", "Encrypting files and also threatening to publish stolen data", "Demanding payment in two cryptocurrencies", "Running two ransomware variants at once"],
        "answer": 1
    },
    {
        "q": "What is the best defence against ransomware data loss?",
        "options": ["Paying the ransom", "Offline backups that cannot be encrypted", "Antivirus software only", "Stronger passwords"],
        "answer": 1
    },
    {
        "q": "What is a rootkit?",
        "options": ["A tool for managing server roots", "Malware that hides its presence and provides persistent access", "A type of firewall", "A password manager"],
        "answer": 1
    },
    {
        "q": "What does EDR stand for?",
        "options": ["Endpoint Detection and Response", "Encryption Data Recovery", "Event Detection and Reporting", "External Defence Ring"],
        "answer": 0
    },
    {
        "q": "What is a SIEM used for?",
        "options": ["Encrypting data at rest", "Aggregating and analysing security logs from across an organisation", "Managing user passwords", "Scanning for malware"],
        "answer": 1
    },
    {
        "q": "What is the first phase of incident response?",
        "options": ["Containment", "Detection", "Preparation", "Recovery"],
        "answer": 2
    },
    {
        "q": "What is the purpose of the containment phase in incident response?",
        "options": ["To rebuild affected systems", "To stop the attack from spreading further", "To identify the root cause", "To notify users"],
        "answer": 1
    },
    {
        "q": "Under GDPR, how many hours do organisations have to report a data breach?",
        "options": ["24 hours", "48 hours", "72 hours", "7 days"],
        "answer": 2
    },
    {
        "q": "What is a zero-day vulnerability?",
        "options": ["A vulnerability with no patch available", "A vulnerability found on the first day of the month", "A vulnerability in zero-trust systems", "A vulnerability that causes zero damage"],
        "answer": 0
    },
    {
        "q": "What is social engineering?",
        "options": ["Building social media platforms", "Manipulating people into revealing confidential information", "Designing secure login forms", "Writing security policies"],
        "answer": 1
    },
    {
        "q": "What is a DDoS attack?",
        "options": ["Stealing data from a database", "Overwhelming a service with traffic to make it unavailable", "Installing malware on a server", "Intercepting encrypted traffic"],
        "answer": 1
    },
    {
        "q": "What is a honeypot in cybersecurity?",
        "options": ["A secure password vault", "A decoy system designed to attract and detect attackers", "A type of firewall rule", "An encrypted backup"],
        "answer": 1
    },
    {
        "q": "What does patching a system do?",
        "options": ["Speeds up the CPU", "Fixes known vulnerabilities in software", "Encrypts user data", "Monitors network traffic"],
        "answer": 1
    },
    {
        "q": "What Windows event ID corresponds to a successful logon?",
        "options": ["4625", "4648", "4624", "4720"],
        "answer": 2
    },
    {
        "q": "What does Windows event ID 4625 indicate?",
        "options": ["Successful logon", "Failed logon", "Account created", "Service installed"],
        "answer": 1
    },
    {
        "q": "What is the purpose of digital forensics?",
        "options": ["Preventing all cyberattacks", "Collecting and analysing evidence after a security incident", "Encrypting data before storage", "Scanning systems for malware"],
        "answer": 1
    },
    {
        "q": "What does the 'Learn' phase of incident response involve?",
        "options": ["Restoring systems from backup", "Reviewing what happened and improving defences", "Isolating affected systems", "Notifying law enforcement"],
        "answer": 1
    },

    # ── Section D: Career Launchpad (Questions 68-90) ──
    {
        "q": "What is cloud computing?",
        "options": ["Storing data on local servers only", "Renting computing resources from providers like AWS or Azure", "Using only on-premises hardware", "Backing up data to USB drives"],
        "answer": 1
    },
    {
        "q": "What is the shared responsibility model in cloud security?",
        "options": ["The cloud provider is responsible for everything", "The customer is responsible for everything", "Security responsibilities are split between the provider and customer depending on the service model", "All security is handled by the government"],
        "answer": 2
    },
    {
        "q": "In an IaaS model, who is responsible for securing the operating system?",
        "options": ["The cloud provider", "The customer", "A third-party auditor", "The ISP"],
        "answer": 1
    },
    {
        "q": "In a SaaS model, who manages the application security?",
        "options": ["The customer", "The cloud provider", "Both equally", "Neither"],
        "answer": 1
    },
    {
        "q": "What is the most common cause of cloud data breaches?",
        "options": ["Advanced nation-state attacks", "Misconfigured storage buckets and overly permissive IAM roles", "Weak encryption algorithms", "Physical server theft"],
        "answer": 1
    },
    {
        "q": "What does IAM stand for in cloud security?",
        "options": ["Internet Access Management", "Identity and Access Management", "Integrated Audit Module", "Incident and Alert Management"],
        "answer": 1
    },
    {
        "q": "What is GDPR?",
        "options": ["A US cybersecurity law", "A European data protection regulation", "A cloud security framework", "A type of encryption standard"],
        "answer": 1
    },
    {
        "q": "What right does GDPR give individuals regarding their personal data?",
        "options": ["The right to unlimited storage", "The right to be forgotten", "The right to sell their data", "The right to access all company data"],
        "answer": 1
    },
    {
        "q": "What is data minimisation under GDPR?",
        "options": ["Encrypting all data", "Collecting only the data necessary for the stated purpose", "Deleting all data after 30 days", "Storing data only in the EU"],
        "answer": 1
    },
    {
        "q": "What is a penetration test?",
        "options": ["A test of physical security only", "An authorised simulated attack to find vulnerabilities before real attackers do", "A malware scan", "A firewall configuration review"],
        "answer": 1
    },
    {
        "q": "What is the difference between black box and white box penetration testing?",
        "options": ["Black box testers have full system knowledge; white box testers have none", "Black box testers have no prior knowledge; white box testers have full system knowledge", "They test different operating systems", "They use different programming languages"],
        "answer": 1
    },
    {
        "q": "What is a CVE?",
        "options": ["A type of malware", "A standardised identifier for publicly known vulnerabilities", "A cloud storage format", "A network protocol"],
        "answer": 1
    },
    {
        "q": "What is threat intelligence?",
        "options": ["Information about known threats used to improve defences", "A type of antivirus software", "A network scanning tool", "A cloud security framework"],
        "answer": 0
    },
    {
        "q": "What does a Security Architect do?",
        "options": ["Responds to incidents as they happen", "Designs the overall security structure of an organisation", "Writes malware for testing", "Manages user passwords"],
        "answer": 1
    },
    {
        "q": "Which certification is most commonly associated with entry-level cybersecurity roles?",
        "options": ["CISSP", "CEH", "CompTIA Security+", "CISM"],
        "answer": 2
    },
    {
        "q": "What is TryHackMe used for?",
        "options": ["Storing code repositories", "Hands-on cybersecurity training in guided labs", "Managing cloud infrastructure", "Writing security policies"],
        "answer": 1
    },
    {
        "q": "What should you include in a cybersecurity CV to demonstrate practical skills?",
        "options": ["Only academic qualifications", "A list of tools used without context", "CTF results, home lab projects, and platform profiles like TryHackMe", "Personal hobbies unrelated to security"],
        "answer": 2
    },
    {
        "q": "What is a SOC Tier 1 analyst primarily responsible for?",
        "options": ["Designing network architecture", "Triaging and investigating initial security alerts", "Writing security policies", "Performing penetration tests"],
        "answer": 1
    },
    {
        "q": "What is the principle of zero trust?",
        "options": ["Trust all users inside the network", "Never trust, always verify — no implicit trust based on network location", "Only trust admins", "Trust external users more than internal ones"],
        "answer": 1
    },
    {
        "q": "Which of the following best describes a bug bounty programme?",
        "options": ["A reward system for reporting valid security vulnerabilities to an organisation", "A salary bonus for security staff", "A fine for introducing bugs into code", "A government grant for cybersecurity research"],
        "answer": 0
    },
    {
        "q": "What is the primary purpose of a security awareness training programme?",
        "options": ["To teach employees to write secure code", "To reduce human error as a security risk by educating staff on threats", "To replace technical security controls", "To train staff to become penetration testers"],
        "answer": 1
    },
    {
        "q": "What does 'encryption at rest' mean?",
        "options": ["Data is encrypted while being transmitted", "Data is encrypted while stored on disk", "Data is deleted after 30 days", "Data is backed up to an encrypted server"],
        "answer": 1
    },
    {
        "q": "Which of the following is the best first step when starting a career in cybersecurity with no experience?",
        "options": ["Apply for senior roles immediately", "Build foundational knowledge, get CompTIA Security+, and start hands-on labs", "Wait until you have a computer science degree", "Focus only on networking certifications"],
        "answer": 1
    },
]


def _has_course_access(user):
    return user.is_admin or CourseAccess.query.filter_by(user_id=user.id).first() is not None


def _lessons_read_count(user_id):
    return LessonRead.query.filter_by(user_id=user_id).count()


def _best_pass(user_id):
    """Return the best passing QuizAttempt for the user, or None."""
    return QuizAttempt.query.filter_by(
        user_id=user_id, passed=True
    ).order_by(QuizAttempt.score.desc()).first()


@quiz_bp.route("/")
@login_required
def quiz_home():
    if not _has_course_access(current_user):
        flash("You need course access to take the quiz.", "error")
        return redirect(url_for("main.home"))

    read_count = _lessons_read_count(current_user.id)
    all_read = read_count >= TOTAL_LESSONS
    best = _best_pass(current_user.id)

    # Latest attempt (pass or fail)
    latest = QuizAttempt.query.filter_by(
        user_id=current_user.id
    ).order_by(QuizAttempt.attempted_at.desc()).first()

    return render_template(
        "course/quiz.html",
        all_read=all_read,
        read_count=read_count,
        total_lessons=TOTAL_LESSONS,
        questions=QUESTIONS,
        total_questions=len(QUESTIONS),
        best=best,
        latest=latest,
    )


@quiz_bp.route("/submit", methods=["POST"])
@login_required
def quiz_submit():
    if not _has_course_access(current_user):
        flash("You need course access to submit the quiz.", "error")
        return redirect(url_for("main.home"))

    read_count = _lessons_read_count(current_user.id)
    if read_count < TOTAL_LESSONS:
        flash("Please complete all 20 lessons before taking the quiz.", "error")
        return redirect(url_for("quiz.quiz_home"))

    score = 0
    total = len(QUESTIONS)

    for i, q in enumerate(QUESTIONS):
        submitted = request.form.get(f"q{i}")
        if submitted is not None:
            try:
                if int(submitted) == q["answer"]:
                    score += 1
            except (ValueError, TypeError):
                pass

    passed = (score / total) >= PASS_THRESHOLD

    attempt = QuizAttempt(
        user_id=current_user.id,
        score=score,
        total=total,
        passed=passed,
        attempted_at=datetime.utcnow(),
    )
    db.session.add(attempt)
    db.session.commit()

    return redirect(url_for("quiz.quiz_result", attempt_id=attempt.id))


@quiz_bp.route("/result/<int:attempt_id>")
@login_required
def quiz_result(attempt_id):
    attempt = QuizAttempt.query.filter_by(
        id=attempt_id, user_id=current_user.id
    ).first_or_404()

    best = _best_pass(current_user.id)

    return render_template(
        "course/quiz_result.html",
        attempt=attempt,
        best=best,
        pass_threshold=int(PASS_THRESHOLD * 100),
    )