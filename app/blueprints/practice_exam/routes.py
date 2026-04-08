"""
BlizTech Academy — CompTIA Security+ Practice Exam Blueprint
app/blueprints/practice_exam/routes.py

Access gate logic (matches your existing codebase exactly):
  - Course access  → CourseAccess table  (same check as course_lesson route)
  - Certificate    → Certificate table, revoked=False  (same model you already have)

Register in app/__init__.py inside create_app(), alongside your other blueprints:

    from app.blueprints.practice_exam.routes import practice_exam_bp
    app.register_blueprint(practice_exam_bp)
"""

from datetime import datetime
from functools import wraps

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.extensions import db
from app.models import CourseAccess, Certificate, User

practice_exam_bp = Blueprint("practice_exam", __name__, url_prefix="/practice-exam")


# ── Access helpers ────────────────────────────────────────────────────────────

def _has_course_access() -> bool:
    """
    Mirrors the exact check used in your course_lesson route:
        current_user.is_admin
        OR has_course_access field
        OR CourseAccess row exists
    """
    fresh = User.query.get(current_user.id)
    return (
        fresh.is_admin
        or bool(fresh.has_course_access)
        or bool(CourseAccess.query.filter_by(user_id=current_user.id).first())
    )


def _has_certificate() -> bool:
    """
    User has an active (non-revoked) BlizTech certificate.
    Uses your existing Certificate model directly.
    Admins bypass this check so you can test without earning a cert.
    """
    fresh = User.query.get(current_user.id)
    if fresh.is_admin:
        return True
    return bool(
        Certificate.query
        .filter_by(user_id=current_user.id, revoked=False)
        .first()
    )


# ── Decorators ────────────────────────────────────────────────────────────────

def course_access_required(f):
    """
    Step 1 gate: user must be logged in and have course access.
    If not, redirect to the course landing page (same as your other course routes).
    """
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not _has_course_access():
            flash("You need to purchase the course to access this resource.", "error")
            return redirect(url_for("main.course"))
        return f(*args, **kwargs)
    return decorated


def certificate_required(f):
    """
    Step 2 gate: user must have course access AND a valid, non-revoked certificate.
    If they have course access but no certificate, they see the locked page.
    """
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not _has_course_access():
            flash("You need to purchase the course to access this resource.", "error")
            return redirect(url_for("main.course"))
        if not _has_certificate():
            return render_template("practice_exam_locked.html"), 403
        return f(*args, **kwargs)
    return decorated


# ── Question bank ─────────────────────────────────────────────────────────────

DOMAIN_META = {
    1: {"name": "General Security Concepts",              "pct": 12},
    2: {"name": "Threats, Vulnerabilities & Mitigations", "pct": 22},
    3: {"name": "Security Architecture",                  "pct": 18},
    4: {"name": "Security Operations",                    "pct": 28},
    5: {"name": "Security Program Management",            "pct": 20},
}

QUESTIONS = [
    # ── DOMAIN 1 — General Security Concepts (11 questions) ──────────────────
    {"d": 1,
     "text": "Which security control category includes policies, procedures, and governance frameworks?",
     "opts": ["Technical", "Managerial", "Operational", "Physical"],
     "ans": 1,
     "exp": "Managerial controls address security through governance, policies, and procedures — not through technology or physical barriers."},

    {"d": 1,
     "text": "A CCTV camera and motion sensors at a server room entrance are BEST categorised as which type of control?",
     "opts": ["Technical / Detective", "Physical / Detective", "Managerial / Preventive", "Operational / Corrective"],
     "ans": 1,
     "exp": "CCTV and motion sensors are physical controls that detect activity — making them physical/detective controls."},

    {"d": 1,
     "text": "Which of the following BEST ensures that a sender cannot later deny having sent a message?",
     "opts": ["Encryption", "Hashing", "Digital signatures", "Tokenisation"],
     "ans": 2,
     "exp": "Digital signatures use the sender's private key to sign a message, providing non-repudiation — cryptographic proof that the specific sender created it."},

    {"d": 1,
     "text": "An organisation deploys a fake database filled with realistic but false records to attract and identify attackers. This is BEST described as a:",
     "opts": ["Honeynet", "Honeytoken", "Honeyfile", "Honeypot"],
     "ans": 3,
     "exp": "A honeypot is a decoy system (including fake databases) designed to lure attackers and gather intelligence on their tactics."},

    {"d": 1,
     "text": "In the Zero Trust model, which component sits in the data plane and actually enforces allow/deny decisions on traffic?",
     "opts": ["Policy Administrator", "Policy Enforcement Point", "Policy Engine", "Adaptive identity"],
     "ans": 1,
     "exp": "The Policy Enforcement Point (PEP) sits in the data plane and enforces the decisions made by the Policy Engine, allowing or denying traffic in real time."},

    {"d": 1,
     "text": "A user's private key has been lost. A copy was stored with a trusted third party to enable recovery. This practice is BEST described as:",
     "opts": ["Certificate revocation", "Key escrow", "Key stretching", "Root of trust"],
     "ans": 1,
     "exp": "Key escrow is the practice of depositing a copy of a cryptographic key with a trusted third party so it can be recovered if the original is lost."},

    {"d": 1,
     "text": "Which of the following is the MOST appropriate use of salting in password storage?",
     "opts": [
         "To encrypt passwords in transit",
         "To add random data before hashing, preventing rainbow table attacks",
         "To extend the effective length of short passwords",
         "To digitally sign stored password hashes"],
     "ans": 1,
     "exp": "Salting appends a unique random value to each password before hashing. This prevents pre-computed rainbow table attacks even when users share identical passwords."},

    {"d": 1,
     "text": "A wildcard certificate is issued for *.bliztechacademy.com. Which host would this certificate NOT cover?",
     "opts": [
         "www.bliztechacademy.com",
         "app.bliztechacademy.com",
         "mail.bliztechacademy.com",
         "learn.courses.bliztechacademy.com"],
     "ans": 3,
     "exp": "A wildcard certificate covers only one level of subdomain (*.domain.com). A second-level subdomain such as learn.courses.bliztechacademy.com is NOT covered."},

    {"d": 1,
     "text": "Which of the following is the BEST example of a compensating control?",
     "opts": [
         "A firewall that blocks all inbound traffic",
         "Network segmentation applied to a legacy system that cannot be patched",
         "A security policy requiring password complexity",
         "An IDS that alerts on suspicious network traffic"],
     "ans": 1,
     "exp": "A compensating control is an alternative measure applied when the standard control cannot be implemented — e.g. segmenting an unpatched system to limit its exposure."},

    {"d": 1,
     "text": "An access control vestibule (mantrap) is BEST classified as which type of control?",
     "opts": [
         "Technical — Preventive",
         "Physical — Preventive",
         "Physical — Detective",
         "Operational — Deterrent"],
     "ans": 1,
     "exp": "An access control vestibule is a physical control (a double-door entry system) that prevents tailgating — making it physical/preventive."},

    {"d": 1,
     "text": "Which change management artefact documents the steps required to restore a system to its previous state if a change causes problems?",
     "opts": ["Impact analysis", "Maintenance window", "Backout plan", "Standard operating procedure"],
     "ans": 2,
     "exp": "A backout plan details the exact steps to reverse a change and restore the previous working state, minimising downtime if the change causes issues."},

    # ── DOMAIN 2 — Threats, Vulnerabilities & Mitigations (20 questions) ──────
    {"d": 2,
     "text": "An attacker sends a text message to employees claiming to be IT support and requesting their login credentials. This attack is BEST described as:",
     "opts": ["Phishing", "Vishing", "Smishing", "Pretexting"],
     "ans": 2,
     "exp": "Smishing is phishing conducted via SMS (text messages). Vishing uses voice calls; phishing uses email."},

    {"d": 2,
     "scenario": "A security analyst reviews logs and finds the web server is returning unusually large DNS query responses to a third-party IP address, with traffic volumes far exceeding normal baselines.",
     "text": "Which attack type is MOST consistent with this behaviour?",
     "opts": ["DNS cache poisoning", "DNS amplification DDoS", "On-path attack", "Credential replay"],
     "ans": 1,
     "exp": "DNS amplification is a reflected DDoS attack. Small spoofed queries generate large responses directed at the victim. High outbound DNS traffic to third parties is a key indicator."},

    {"d": 2,
     "text": "Which threat actor is MOST likely motivated by political beliefs and typically targets high-profile organisations to make a public statement?",
     "opts": ["Nation-state", "Organised crime", "Hacktivist", "Insider threat"],
     "ans": 2,
     "exp": "Hacktivists are motivated by political or ideological goals and often target organisations publicly to advance their cause (e.g. website defacement, DDoS protests)."},

    {"d": 2,
     "text": "A developer's application allows user-supplied input to control memory allocation without bounds checking, potentially overwriting adjacent memory. This BEST describes:",
     "opts": ["Race condition", "SQL injection", "Buffer overflow", "Memory injection"],
     "ans": 2,
     "exp": "A buffer overflow occurs when a program writes more data to a buffer than it can hold, overwriting adjacent memory — potentially enabling arbitrary code execution."},

    {"d": 2,
     "text": "An attacker positions themselves at a coffee shop Wi-Fi hotspot and silently reads all unencrypted traffic between users and the internet. This is BEST described as:",
     "opts": ["Credential replay", "On-path (MITM) attack", "Wireless DDoS", "Evil twin"],
     "ans": 1,
     "exp": "An on-path (man-in-the-middle) attack positions the attacker between communicating parties to intercept or alter traffic without either party's knowledge."},

    {"d": 2,
     "scenario": "An employee receives an urgent email appearing to be from the CFO requesting an immediate wire transfer to a new vendor account. The CFO's email address has one letter transposed.",
     "text": "Which attack technique does this BEST represent?",
     "opts": [
         "Watering hole",
         "Business email compromise combined with typosquatting",
         "Vishing",
         "Pretexting via direct impersonation"],
     "ans": 1,
     "exp": "Business email compromise (BEC) combined with typosquatting registers a near-identical domain/email to impersonate an executive and trick employees into fraudulent financial actions."},

    {"d": 2,
     "text": "Which malware type is specifically designed to remain hidden and maintain persistent privileged access to a compromised system?",
     "opts": ["Worm", "Rootkit", "Trojan", "Logic bomb"],
     "ans": 1,
     "exp": "A rootkit hides itself at the OS or firmware level to maintain persistent, privileged access while concealing its presence from standard detection tools."},

    {"d": 2,
     "text": "A vulnerability scan flags a known CVE on a fully patched system. The administrator confirms the patch is applied and the system is not actually vulnerable. This result is BEST described as:",
     "opts": ["True positive", "True negative", "False positive", "False negative"],
     "ans": 2,
     "exp": "A false positive occurs when a scan incorrectly reports a vulnerability that does not exist — in this case, a CVE that has already been remediated by a patch."},

    {"d": 2,
     "text": "Which of the following BEST describes a supply chain attack?",
     "opts": [
         "Exploiting a zero-day vulnerability in an OS kernel",
         "Compromising a trusted software vendor to distribute malware to their customers",
         "Brute-forcing credentials against an internet-facing login portal",
         "Installing a keylogger on a physical workstation"],
     "ans": 1,
     "exp": "A supply chain attack targets a less-secure vendor or supplier to compromise their product or update pipeline, which then propagates malware to all downstream customers."},

    {"d": 2,
     "text": "An attacker captures a valid authentication token and reuses it hours later to gain access to a system. This is BEST described as:",
     "opts": ["Pass-the-hash", "Credential replay", "Privilege escalation", "Session hijacking"],
     "ans": 1,
     "exp": "A credential replay attack captures a valid authentication credential (token, hash, or session cookie) and replays it to authenticate without knowing the original password."},

    {"d": 2,
     "text": "Which indicator of compromise MOST directly suggests that an account has been used from two geographically distant locations within minutes?",
     "opts": ["Resource consumption spike", "Account lockout", "Impossible travel", "Concurrent session usage"],
     "ans": 2,
     "exp": "Impossible travel is detected when authentication logs show the same account authenticating from geographically distant locations within a timeframe that makes physical travel impossible."},

    {"d": 2,
     "text": "Which vulnerability type exists in software that the vendor no longer supports with security patches?",
     "opts": ["Zero-day", "Legacy / end-of-life", "Misconfiguration", "Cloud-specific"],
     "ans": 1,
     "exp": "End-of-life/legacy vulnerabilities affect systems where the vendor has stopped releasing patches, leaving known vulnerabilities permanently unmitigated."},

    {"d": 2,
     "text": "Ransomware has encrypted all files on a file server. Which is the MOST effective mitigation to restore operations quickly without paying the attacker?",
     "opts": [
         "Restore from a clean, verified backup",
         "Pay the ransom and use the provided decryption key",
         "Run antivirus software on the encrypted files",
         "Apply the latest security patches to the server"],
     "ans": 0,
     "exp": "Restoring from a clean, verified backup is the fastest and most reliable recovery method. It avoids paying the ransom and does not depend on the attacker honouring the decryption agreement."},

    {"d": 2,
     "text": "An attacker exploits the gap between when a condition is checked and when the result is acted upon, injecting malicious input in between. This BEST describes:",
     "opts": ["Buffer overflow", "SQL injection", "Race condition (TOC/TOU)", "Memory injection"],
     "ans": 2,
     "exp": "A Time-of-Check/Time-of-Use (TOC/TOU) race condition exploits the window between checking a condition and using its result, allowing an attacker to change the state in that gap."},

    {"d": 2,
     "text": "Which social engineering technique involves creating a rogue wireless access point with the same SSID as a legitimate network to intercept user traffic?",
     "opts": ["Smishing", "Watering hole", "Evil twin", "Typosquatting"],
     "ans": 2,
     "exp": "An evil twin creates a rogue wireless AP that mimics a legitimate network's SSID, tricking users into connecting and exposing their traffic to interception."},

    {"d": 2,
     "text": "A password attack tries a single common password (e.g. 'Summer2024!') against thousands of different user accounts to avoid triggering lockout policies. This technique is:",
     "opts": ["Brute force", "Rainbow table attack", "Password spraying", "Dictionary attack"],
     "ans": 2,
     "exp": "Password spraying tries one or a few common passwords across many accounts, deliberately staying below per-account lockout thresholds — unlike brute force which exhaustively targets one account."},

    {"d": 2,
     "text": "Which hardening technique MOST directly reduces the attack surface of a newly deployed server?",
     "opts": [
         "Enabling logging and forwarding events to a SIEM",
         "Removing all unnecessary software and disabling unneeded services",
         "Installing endpoint protection software",
         "Configuring host-based firewall rules"],
     "ans": 1,
     "exp": "Removing unnecessary software and services eliminates potential attack vectors entirely. You cannot exploit what is not installed — this is the most direct attack surface reduction."},

    {"d": 2,
     "text": "An attacker injects malicious script into a web application's comment field. When other users load the page, the script executes in their browsers. This is BEST described as:",
     "opts": [
         "SQL injection",
         "Cross-site request forgery (CSRF)",
         "Stored cross-site scripting (XSS)",
         "Directory traversal"],
     "ans": 2,
     "exp": "Stored XSS persists malicious scripts in the application's database. They execute automatically in any user's browser that loads the affected page."},

    {"d": 2,
     "text": "Which mitigation technique BEST limits lateral movement after an attacker compromises a single system?",
     "opts": [
         "Encrypting all data traversing the network",
         "Network segmentation",
         "Monitoring user behaviour analytics",
         "Enforcing MFA at network boundaries"],
     "ans": 1,
     "exp": "Network segmentation contains breaches by restricting lateral movement — if one segment is compromised, attackers are prevented from freely accessing other network zones."},

    {"d": 2,
     "text": "A nation-state actor maintains long-term, stealthy access to a target network specifically for intelligence gathering without triggering alerts. This behaviour is MOST consistent with:",
     "opts": [
         "A hacktivist campaign",
         "An Advanced Persistent Threat (APT)",
         "An organised crime ransomware operation",
         "A script kiddie attack"],
     "ans": 1,
     "exp": "APTs are sophisticated, long-term intrusions typically sponsored by nation-states, focused on persistent access and intelligence collection rather than immediate disruption or financial gain."},

    # ── DOMAIN 3 — Security Architecture (16 questions) ──────────────────────
    {"d": 3,
     "text": "Which cloud service model gives the customer the MOST control over the underlying infrastructure, including the operating system?",
     "opts": ["SaaS", "PaaS", "IaaS", "FaaS"],
     "ans": 2,
     "exp": "IaaS provides virtualised compute, storage, and networking — the customer manages the OS, middleware, and applications. SaaS and PaaS abstract those layers away."},

    {"d": 3,
     "text": "A security appliance fails and defaults to allowing all traffic through rather than blocking it. This failure mode is BEST described as:",
     "opts": ["Fail-closed", "Fail-secure", "Fail-open", "Fail-safe"],
     "ans": 2,
     "exp": "Fail-open means a system defaults to an unrestricted state on failure (allowing all traffic). Fail-closed/fail-secure defaults to blocking all traffic — the more secure posture."},

    {"d": 3,
     "scenario": "An organisation operates legacy SCADA systems that control critical manufacturing equipment. These systems cannot be patched and must remain operational 24/7.",
     "text": "Which architecture approach BEST protects these systems while preserving their operational continuity?",
     "opts": [
         "Deploy an IDS in tap/monitor mode beside the SCADA network",
         "Air-gap the SCADA systems from all other networks",
         "Install endpoint antivirus on each SCADA controller",
         "Enable WPA3 on the industrial wireless network"],
     "ans": 1,
     "exp": "Air-gapping physically isolates critical systems from all other networks, preventing remote exploitation of unpatched SCADA systems while preserving operational continuity."},

    {"d": 3,
     "text": "Which of the following BEST describes the purpose of a jump server (bastion host)?",
     "opts": [
         "Load balancing inbound web traffic across application servers",
         "Providing a controlled, audited single access point into a secure network zone",
         "Terminating VPN tunnels at the network perimeter",
         "Filtering inbound HTTP/HTTPS traffic for web application attacks"],
     "ans": 1,
     "exp": "A jump server is a hardened, audited intermediary through which administrators must connect before accessing systems in secure or sensitive network zones."},

    {"d": 3,
     "text": "An organisation wants to verify its DR systems can sustain operations after losing the primary data centre, without disrupting live production systems. Which test is MOST appropriate?",
     "opts": [
         "Full interruption test",
         "Parallel processing test",
         "Tabletop exercise",
         "Simulation test"],
     "ans": 1,
     "exp": "A parallel processing test runs DR systems alongside live production systems simultaneously, verifying DR functionality without risking disruption to live operations."},

    {"d": 3,
     "text": "Which is the PRIMARY security concern with containerisation?",
     "opts": [
         "Containers cannot be encrypted at rest",
         "Container escape — a malicious container breaking out to the host OS",
         "Containers do not support network segmentation",
         "Containers cannot run on cloud infrastructure"],
     "ans": 1,
     "exp": "Container escape occurs when a vulnerability allows a process inside a container to break out and gain access to the host OS or other containers — the primary security risk of containerisation."},

    {"d": 3,
     "text": "A company's RPO is set to 4 hours. What does this mean for their backup strategy?",
     "opts": [
         "All systems must be restored within 4 hours of a disaster",
         "Backups must occur at least every 4 hours to limit acceptable data loss",
         "The organisation can tolerate 4 hours of total system downtime",
         "DR systems must be geographically separated by at least 4 hours of travel"],
     "ans": 1,
     "exp": "Recovery Point Objective (RPO) defines the maximum acceptable data loss measured in time. An RPO of 4 hours means backups must run at least every 4 hours so no more than 4 hours of data is ever lost."},

    {"d": 3,
     "text": "A laptop is stolen and the hard drive is removed and placed in another machine to be read. Which data state is MOST at risk?",
     "opts": ["Data in transit", "Data in use", "Data at rest", "Data in processing"],
     "ans": 2,
     "exp": "Data at rest on an unencrypted (or improperly encrypted) hard drive is directly accessible if the physical media is removed and read from another machine. Full-disk encryption mitigates this."},

    {"d": 3,
     "text": "Which disaster recovery site type provides the FASTEST recovery time but also carries the HIGHEST ongoing cost?",
     "opts": ["Cold site", "Warm site", "Hot site", "Mobile site"],
     "ans": 2,
     "exp": "A hot site is a fully operational replica with real-time data replication, enabling near-immediate failover. It is the most expensive option because it requires continuous infrastructure duplication."},

    {"d": 3,
     "text": "An organisation replaces sensitive card numbers in its database with random tokens that have no mathematical relationship to the originals. This is BEST described as:",
     "opts": ["Encryption", "Hashing", "Tokenisation", "Data masking"],
     "ans": 2,
     "exp": "Tokenisation replaces sensitive data with a surrogate value (token) that has no exploitable mathematical relationship to the original — unlike encryption, which can theoretically be reversed."},

    {"d": 3,
     "text": "Which network appliance monitors traffic passively, generates alerts, but does NOT block malicious activity?",
     "opts": [
         "Intrusion Prevention System (IPS)",
         "Next-generation firewall (NGFW)",
         "Intrusion Detection System (IDS)",
         "Web application firewall (WAF)"],
     "ans": 2,
     "exp": "An IDS monitors traffic passively and generates alerts. An IPS is deployed inline and can actively block malicious traffic."},

    {"d": 3,
     "text": "To reduce the risk of a cloud provider-wide outage taking down all workloads, an organisation should adopt which strategy?",
     "opts": [
         "Geographic dispersion within the same cloud provider",
         "Multi-cloud systems distributed across different providers",
         "On-premises platform diversity as a backup",
         "Load balancing across the provider's availability zones"],
     "ans": 1,
     "exp": "Multi-cloud distributes workloads across different providers so that a single provider's outage does not affect all systems. Geographic dispersion within one provider does not protect against provider-wide failures."},

    {"d": 3,
     "text": "Which of the following BEST describes Software-Defined Networking (SDN)?",
     "opts": [
         "A physical switch that enforces MAC-based port access control",
         "Decoupling the network control plane from the data plane to enable centralised, programmable management",
         "Encrypting all data as it traverses a network segment",
         "A VPN technology for connecting remote users to the corporate network"],
     "ans": 1,
     "exp": "SDN separates the control plane (deciding how traffic flows) from the data plane (forwarding packets), allowing centralised and programmatic management of the entire network infrastructure."},

    {"d": 3,
     "text": "An organisation needs to protect sensitive data at the field level in a database so that even if the DB files are breached, individual field values are unreadable. Which encryption level is MOST appropriate?",
     "opts": [
         "Full-disk encryption",
         "Database / record-level encryption",
         "Transport layer encryption (TLS)",
         "Volume encryption"],
     "ans": 1,
     "exp": "Database or record-level encryption encrypts individual fields. Even if an attacker gains access to the database files directly, they cannot read field values without the encryption keys."},

    {"d": 3,
     "text": "Which architecture converges SD-WAN networking with cloud-delivered security services (ZTNA, CASB, SWG) for distributed and remote workforces?",
     "opts": [
         "Zero Trust Network Access (ZTNA) alone",
         "Secure Access Service Edge (SASE)",
         "DMZ-based perimeter security",
         "Site-to-site IPSec VPN mesh"],
     "ans": 1,
     "exp": "SASE converges networking (SD-WAN) with cloud-delivered security services, enabling secure access for remote and distributed users without relying on traditional perimeter security."},

    {"d": 3,
     "text": "802.1X port-based network access control is BEST described as which type of control, and what does it enforce?",
     "opts": [
         "Technical / Detective — it logs all devices connecting to switch ports",
         "Technical / Preventive — it authenticates devices before granting network access",
         "Physical / Preventive — it physically locks unused switch ports",
         "Managerial / Directive — it defines acceptable use of network ports"],
     "ans": 1,
     "exp": "802.1X is a technical, preventive control that enforces NAC by requiring devices to authenticate via EAP/RADIUS before being granted any network access."},

    # ── DOMAIN 4 — Security Operations (25 questions) ────────────────────────
    {"d": 4,
     "text": "During incident response, a team disconnects a compromised host from the network but leaves it powered on to preserve volatile memory contents. Which phase are they in?",
     "opts": ["Detection", "Containment", "Eradication", "Recovery"],
     "ans": 1,
     "exp": "Containment limits the spread of an incident without necessarily eliminating it. Preserving volatile memory while isolating the host is a containment action taken before eradication begins."},

    {"d": 4,
     "text": "Which identity concept allows a user to authenticate once and then access multiple applications or systems without re-entering credentials?",
     "opts": ["Federation", "Multifactor authentication", "Single sign-on (SSO)", "Attestation"],
     "ans": 2,
     "exp": "SSO allows a user to authenticate once and access multiple applications without needing separate credentials for each individual system."},

    {"d": 4,
     "scenario": "A SOC analyst notices a user account downloaded 5 GB of intellectual property at 2 AM, then immediately attempted to email a compressed archive to a personal address. No SIEM alerts fired during this activity.",
     "text": "Which SIEM configuration issue does this MOST suggest?",
     "opts": [
         "The SIEM lacks sufficient log sources",
         "Alert tuning has suppressed the relevant detection rules",
         "The DLP policy was not configured to cover email channels",
         "Both B and C are likely contributing factors"],
     "ans": 3,
     "exp": "Missing alerts on clear data exfiltration indicators suggest both overly aggressive alert tuning (silencing relevant rules) and incomplete DLP coverage for email — both issues likely exist simultaneously."},

    {"d": 4,
     "text": "Which access control model assigns permissions to organisational roles, and users automatically inherit all permissions of their assigned role?",
     "opts": [
         "Mandatory Access Control (MAC)",
         "Discretionary Access Control (DAC)",
         "Role-Based Access Control (RBAC)",
         "Attribute-Based Access Control (ABAC)"],
     "ans": 2,
     "exp": "RBAC assigns permissions to roles rather than individuals. Users inherit permissions simply by being assigned to a role, making access management scalable across large organisations."},

    {"d": 4,
     "text": "An organisation wants to ensure employees can only log in to certain systems during business hours (08:00–18:00). Which access control feature directly enforces this?",
     "opts": [
         "Least privilege",
         "Time-of-day restrictions",
         "Attribute-based access control",
         "Mandatory access control"],
     "ans": 1,
     "exp": "Time-of-day restrictions are an access control feature that limits when users can authenticate or access resources, regardless of whether their credentials are otherwise valid."},

    {"d": 4,
     "text": "Which MFA factor does a hardware FIDO2 security key represent?",
     "opts": [
         "Something you know",
         "Something you have",
         "Something you are",
         "Somewhere you are"],
     "ans": 1,
     "exp": "A hardware security key is a physical possession factor (something you have). FIDO2 keys generate cryptographic proof of possession without transmitting any shared secret."},

    {"d": 4,
     "text": "A penetration tester is given no prior information about the target environment and must conduct all reconnaissance from scratch. This engagement type is BEST described as:",
     "opts": [
         "Known environment (white box)",
         "Partially known environment (grey box)",
         "Unknown environment (black box)",
         "Red team / assumed breach simulation"],
     "ans": 2,
     "exp": "An unknown environment (black box) test gives the tester no advance information about the target, simulating a real external attacker who has no insider knowledge."},

    {"d": 4,
     "text": "Which vulnerability management metric represents the total financial loss an organisation would suffer from a single occurrence of a specific threat event?",
     "opts": [
         "Annualized Loss Expectancy (ALE)",
         "Single Loss Expectancy (SLE)",
         "Annualized Rate of Occurrence (ARO)",
         "Exposure Factor (EF)"],
     "ans": 1,
     "exp": "SLE = Asset Value × Exposure Factor. It is the monetary loss expected from a single incident of a specific threat, before considering how frequently that threat occurs."},

    {"d": 4,
     "text": "Which tool collects, aggregates, and correlates log data from multiple sources across an environment to detect threats and generate prioritised alerts?",
     "opts": ["Vulnerability scanner", "IDS", "SIEM", "DLP"],
     "ans": 2,
     "exp": "A SIEM (Security Information and Event Management) system collects and correlates log data from across the environment to detect threat patterns and generate actionable, prioritised security alerts."},

    {"d": 4,
     "text": "After confirming that a user's simultaneous logins from three countries are all legitimate VPN connections, what should the analyst do NEXT?",
     "opts": [
         "Immediately disable the account pending full investigation",
         "Tune the alert to reduce future false positives for this user's known pattern",
         "Escalate to the incident response team",
         "Reset the user's credentials and require MFA re-enrolment"],
     "ans": 1,
     "exp": "Confirmed legitimate activity should prompt alert tuning so the rule does not generate unnecessary noise for this user's known behaviour, while preserving detection for genuinely anomalous logins."},

    {"d": 4,
     "text": "Which digital forensics concept ensures that evidence maintains its original, unaltered state from the point of collection through any legal proceedings?",
     "opts": ["Legal hold", "E-discovery", "Preservation", "Chain of custody"],
     "ans": 2,
     "exp": "Preservation ensures evidence is collected and stored in a way that maintains its integrity — using write blockers, cryptographic hashes, and secure storage — so it remains admissible and unimpeachable in court."},

    {"d": 4,
     "text": "An organisation automatically creates user accounts, mailboxes, and access permissions when HR submits a new-hire request. This is BEST described as:",
     "opts": [
         "Automated user provisioning",
         "Continuous integration",
         "Guard rail enforcement",
         "Workforce multiplier scripting"],
     "ans": 0,
     "exp": "Automated user provisioning creates accounts and assigns access automatically based on HR system triggers, reducing manual effort, provisioning delays, and human error."},

    {"d": 4,
     "text": "Which MDM deployment model allows employees to use their personal devices for work while the organisation retains control over corporate applications and data on those devices?",
     "opts": [
         "COPE — Corporate-Owned, Personally Enabled",
         "CYOD — Choose Your Own Device",
         "BYOD — Bring Your Own Device",
         "COBO — Corporate-Owned, Business Only"],
     "ans": 2,
     "exp": "BYOD allows employees to use personal devices for work. MDM policies enforce corporate controls on those devices, separating and protecting corporate data from personal data."},

    {"d": 4,
     "text": "A Web Application Firewall (WAF) is MOST effective at mitigating which category of attacks?",
     "opts": [
         "Network-layer volumetric DDoS attacks",
         "Layer 7 application attacks such as SQLi, XSS, and CSRF",
         "Wireless protocol exploitation",
         "Physical access to web server hardware"],
     "ans": 1,
     "exp": "A WAF inspects HTTP/HTTPS traffic at Layer 7 and is specifically designed to detect and block application-layer attacks including SQL injection, cross-site scripting, and request forgery."},

    {"d": 4,
     "text": "Which email authentication mechanism publishes a DNS TXT record listing all IP addresses that are authorised to send email on behalf of a domain?",
     "opts": ["DKIM", "DMARC", "SPF", "S/MIME"],
     "ans": 2,
     "exp": "SPF (Sender Policy Framework) publishes a DNS TXT record listing authorised sending IP addresses for a domain, allowing receiving mail servers to reject email from unauthorised senders."},

    {"d": 4,
     "text": "After a major security incident, the team convenes to analyse what happened, identify why controls failed, and produce improvement recommendations. This meeting represents which IR phase?",
     "opts": ["Detection", "Containment", "Eradication", "Lessons learned"],
     "ans": 3,
     "exp": "The lessons learned phase is a post-incident review that analyses root causes, identifies control and process gaps, and produces actionable recommendations to improve future security posture and response."},

    {"d": 4,
     "text": "Which type of scan identifies all open ports and running services on every host within a specified network range?",
     "opts": ["Vulnerability scan", "Packet capture", "Network mapper / port scan", "Static code analysis"],
     "ans": 2,
     "exp": "A network mapper/port scanner (e.g. Nmap) actively probes hosts to identify open ports and running services — the foundational step in both authorised security assessments and attacker reconnaissance."},

    {"d": 4,
     "text": "A password policy requires: minimum 16 characters, no reuse of the last 12 passwords, 90-day expiry. Which password security practice is NOT addressed by this policy?",
     "opts": [
         "Password length",
         "Password reuse prevention",
         "Password complexity (required character mix)",
         "Password expiration"],
     "ans": 2,
     "exp": "The policy covers length, reuse, and expiry but does NOT mandate complexity requirements such as requiring a mix of uppercase, lowercase, numbers, and special characters."},

    {"d": 4,
     "text": "Which privileged access management concept grants elevated permissions only for the duration of a specific task, then automatically revokes them when the task is complete?",
     "opts": [
         "Password vaulting",
         "Ephemeral credentials",
         "Just-in-time (JIT) permissions",
         "Attestation"],
     "ans": 2,
     "exp": "JIT permissions grant elevated access only when needed for a specific task and revoke it immediately afterward, minimising the standing privilege window and reducing the blast radius of a compromised account."},

    {"d": 4,
     "text": "A security analyst uses a tool that tracks file attributes (size, cryptographic hash, timestamps) on critical system files and generates an alert when any of them change unexpectedly. This is BEST described as:",
     "opts": [
         "Endpoint Detection and Response (EDR)",
         "File Integrity Monitoring (FIM)",
         "Data Loss Prevention (DLP)",
         "Host-based Intrusion Prevention System (HIPS)"],
     "ans": 1,
     "exp": "FIM tracks critical file attributes and generates alerts when unexpected changes occur, detecting malware modifications, unauthorised tampering, or configuration drift on critical system files."},

    {"d": 4,
     "text": "Which version of SNMP adds authentication (HMAC) and encryption (AES) to address the plaintext security weaknesses of SNMPv1 and v2?",
     "opts": ["SNMPv3", "NetFlow v9", "Syslog over TLS", "HTTPS REST API"],
     "ans": 0,
     "exp": "SNMPv3 introduces authentication (using HMAC) and encryption (DES or AES) for SNMP traffic, addressing the well-known weakness of v1 and v2 which transmit community strings in cleartext."},

    {"d": 4,
     "text": "An AUP prohibits the use of personal cloud storage for work files. A user uploads project documents to their personal Dropbox. Which control would MOST directly detect this violation?",
     "opts": [
         "IDS signature matching cloud storage protocol patterns",
         "DLP policy monitoring and inspecting outbound data transfers",
         "SPF/DKIM email authentication filtering",
         "Group Policy restricting USB mass storage devices"],
     "ans": 1,
     "exp": "A DLP solution monitors outbound data flows and can inspect content being uploaded to unapproved cloud storage services, directly enforcing the AUP at a technical level."},

    {"d": 4,
     "text": "Static code analysis (SAST) is BEST described as:",
     "opts": [
         "Testing a running application for vulnerabilities by sending crafted malicious input",
         "Reviewing source code for security flaws without executing the program",
         "Monitoring application behaviour at runtime using a sandboxed environment",
         "Scanning third-party application dependencies for known CVEs"],
     "ans": 1,
     "exp": "SAST examines source code, bytecode, or binaries without executing the application, identifying security flaws such as hardcoded credentials, injection sinks, and logic errors at development time."},

    {"d": 4,
     "text": "Which incident response phase involves re-imaging compromised systems, removing all malware and backdoors, and closing the specific vulnerability that was exploited?",
     "opts": ["Containment", "Eradication", "Recovery", "Analysis"],
     "ans": 1,
     "exp": "Eradication removes the root cause of the incident — all malware, backdoors, and the exploited vulnerability — before systems are restored to production in the recovery phase."},

    {"d": 4,
     "text": "An analyst needs to ensure that key log files and data on a compromised server are not deleted or overwritten during an ongoing investigation. Which action should be taken FIRST?",
     "opts": [
         "Isolate the server from the network immediately",
         "Acquire a forensic bit-for-bit image of the server's drives",
         "Implement a legal hold on the relevant data and logs",
         "Run a vulnerability scan to identify the exploit that was used"],
     "ans": 2,
     "exp": "A legal hold preserves evidence from routine deletion, log rotation, or overwriting, ensuring it remains available for investigation and any potential legal proceedings. This must be established before other actions that could alter the evidence state."},

    # ── DOMAIN 5 — Security Program Management & Oversight (18 questions) ─────
    {"d": 5,
     "text": "A server has an SLE of $50,000 and an ARO of 0.5. What is the Annualized Loss Expectancy (ALE)?",
     "opts": ["$100,000", "$50,000", "$25,000", "$10,000"],
     "ans": 2,
     "exp": "ALE = SLE × ARO = $50,000 × 0.5 = $25,000. ALE represents the expected annual financial loss from a specific threat to a specific asset."},

    {"d": 5,
     "text": "An organisation decides to take no further action on a specific risk because the cost of the available controls exceeds the value of the asset being protected. This strategy is BEST described as:",
     "opts": ["Risk mitigation", "Risk transfer", "Risk avoidance", "Risk acceptance"],
     "ans": 3,
     "exp": "Risk acceptance is a deliberate decision to acknowledge a risk and take no further action — typically applied when the cost of mitigation exceeds the potential impact, or the risk falls within the organisation's stated tolerance."},

    {"d": 5,
     "text": "Which agreement document legally defines the minimum performance metrics a cloud provider must meet, including uptime guarantees, support response times, and remedies for non-compliance?",
     "opts": [
         "MOU — Memorandum of Understanding",
         "SLA — Service-Level Agreement",
         "NDA — Non-Disclosure Agreement",
         "MSA — Master Service Agreement"],
     "ans": 1,
     "exp": "An SLA legally defines the minimum service standards a vendor must meet. It includes uptime guarantees, response time commitments, and contractual remedies if those standards are not met."},

    {"d": 5,
     "text": "Under GDPR, individuals have the right to request that an organisation delete their personal data under certain circumstances. This right is BEST known as:",
     "opts": [
         "Data sovereignty",
         "Right to be forgotten",
         "Data subject access request (DSAR)",
         "Controller vs. processor obligation"],
     "ans": 1,
     "exp": "The right to be forgotten (formally the right to erasure) under GDPR allows individuals to request deletion of their personal data in specific circumstances such as when the data is no longer necessary."},

    {"d": 5,
     "text": "Which governance role is responsible for classifying data and defining policies for how it should be used and protected within the organisation?",
     "opts": ["Data custodian", "Data processor", "Data owner", "Data steward"],
     "ans": 2,
     "exp": "The data owner (typically a senior business manager) is responsible for classifying data and setting policies for its use and protection. Data custodians implement those policies at a technical level."},

    {"d": 5,
     "text": "An organisation's risk appetite statement explicitly accepts significant cybersecurity risks in order to pursue aggressive growth objectives. This BEST describes which risk appetite type?",
     "opts": ["Conservative", "Neutral", "Expansionary", "Residual"],
     "ans": 2,
     "exp": "An expansionary risk appetite accepts higher risk levels in pursuit of growth or competitive advantage — the opposite of a conservative appetite which prioritises risk avoidance above growth."},

    {"d": 5,
     "text": "In a 'partially known environment' penetration test, the tester is given some information about the target. Which scenario BEST represents this type of engagement?",
     "opts": [
         "The tester receives full network diagrams, source code, and valid credentials",
         "The tester is given nothing and must enumerate all information from scratch",
         "The tester receives IP ranges and some system details but not full access",
         "The tester is an internal employee simulating an insider threat"],
     "ans": 2,
     "exp": "A grey box (partially known) test provides the tester with limited information — such as network ranges or partial credentials — simulating a scenario where an attacker has gained some initial foothold or insider knowledge."},

    {"d": 5,
     "text": "Which compliance framework specifically governs the secure handling of payment card data and mandates encryption, access control, and regular vulnerability management?",
     "opts": ["GDPR", "HIPAA", "PCI DSS", "SOX"],
     "ans": 2,
     "exp": "PCI DSS applies to all organisations that store, process, or transmit cardholder data, mandating specific security controls including encryption, strict access control, and regular vulnerability scanning and penetration testing."},

    {"d": 5,
     "text": "An organisation trains employees to recognise suspicious emails and regularly runs simulated phishing campaigns to measure and improve their responses. This is BEST described as:",
     "opts": [
         "Anomalous behaviour recognition training",
         "Security awareness training — phishing simulation",
         "Operational security (OPSEC) training",
         "Insider threat mitigation programme"],
     "ans": 1,
     "exp": "Simulated phishing campaigns are a cornerstone of security awareness training, providing real-world measurement of employee susceptibility and delivering targeted education to those who fall for the simulation."},

    {"d": 5,
     "text": "The PRIMARY purpose of a Business Impact Analysis (BIA) is to:",
     "opts": [
         "Identify all technical vulnerabilities in the environment",
         "Determine the financial and operational impact of losing specific business functions",
         "Calculate the annual budget required for security controls",
         "Assess the security posture of third-party vendors"],
     "ans": 1,
     "exp": "A BIA identifies critical business functions and quantifies the impact of their disruption, which directly informs RTO/RPO targets and prioritises which systems must be recovered first in a disaster."},

    {"d": 5,
     "text": "An agreement between two organisations that documents their mutual intentions for a project without creating legally binding contractual obligations is BEST described as:",
     "opts": ["SLA", "NDA", "MOU", "BPA"],
     "ans": 2,
     "exp": "An MOU (Memorandum of Understanding) documents mutual intentions and expectations between parties but is generally not legally binding — unlike an SLA or formal contract which create enforceable obligations."},

    {"d": 5,
     "text": "Which of the following represents a direct consequence of non-compliance with GDPR?",
     "opts": [
         "Mandatory penetration testing within 30 days",
         "Regulatory fines of up to 4% of global annual turnover and reputational damage",
         "Mandatory encryption key escrow with the supervising authority",
         "Required independent audit within 30 days of the breach"],
     "ans": 1,
     "exp": "GDPR non-compliance can result in significant fines (up to 4% of global annual turnover or €20M, whichever is higher), reputational damage, regulatory sanctions, and contractual impacts with partners."},

    {"d": 5,
     "text": "During a vendor assessment, an organisation inserts a clause giving them the legal right to independently audit the vendor's security controls at any time during the contract period. This clause is BEST described as:",
     "opts": [
         "A due diligence requirement",
         "A right-to-audit clause",
         "A conflict of interest declaration",
         "Rules of engagement"],
     "ans": 1,
     "exp": "A right-to-audit clause contractually grants the organisation the right to conduct or commission security audits of the vendor's environment at any time, ensuring ongoing compliance with security requirements."},

    {"d": 5,
     "text": "A security manager wants to demonstrate that implemented controls are measurably reducing risk levels over time. Which governance activity BEST supports this?",
     "opts": [
         "Conducting annual penetration tests",
         "Maintaining a risk register with key risk indicators (KRIs) reviewed on a regular cycle",
         "Publishing and updating an acceptable use policy",
         "Running quarterly tabletop exercises"],
     "ans": 1,
     "exp": "A risk register with KRIs tracks risk status over time. Regular review of KRI trends provides measurable, data-driven evidence of whether controls are effectively reducing risk, enabling informed governance decisions."},

    {"d": 5,
     "text": "Which of the following is the BEST example of a directive control?",
     "opts": [
         "A firewall blocking all unauthorised inbound connections",
         "A mandatory annual security awareness training policy",
         "CCTV cameras monitoring physical access to the server room",
         "Automated patch deployment for critical OS vulnerabilities"],
     "ans": 1,
     "exp": "Directive controls direct or mandate behaviour through policies and procedures — such as mandatory training requirements. They tell people what they must do, rather than technically enforcing compliance."},

    {"d": 5,
     "text": "Integrating security testing and reviews at every stage of the SDLC — rather than only performing security checks at deployment — is BEST described as:",
     "opts": [
         "Security by obscurity",
         "Shift-left security",
         "Agile security sprint gating",
         "Defence in depth"],
     "ans": 1,
     "exp": "Shift-left security moves security activities earlier in the SDLC (shifting left on the development timeline), identifying and fixing vulnerabilities when they are least costly to remediate — not after deployment."},

    {"d": 5,
     "text": "Under GDPR, which role independently monitors the organisation's compliance with data protection law and serves as the primary contact point for the supervisory authority?",
     "opts": [
         "The CISO responsible for approving the data security budget",
         "The Data Protection Officer (DPO)",
         "The IT manager responsible for implementing encryption controls",
         "An independent third-party auditor engaged annually"],
     "ans": 1,
     "exp": "Under GDPR, a DPO is an independent role that monitors compliance with data protection obligations, advises the organisation, and acts as the official contact point for supervisory authorities such as the ICO."},

    {"d": 5,
     "text": "An organisation purchases a cyber insurance policy to cover potential financial losses resulting from a ransomware attack. This risk management strategy is BEST described as:",
     "opts": ["Risk avoidance", "Risk mitigation", "Risk transference", "Risk acceptance"],
     "ans": 2,
     "exp": "Risk transference shifts the financial consequences of a risk to a third party — such as an insurer — without eliminating or reducing the underlying risk itself. The organisation still faces the operational risk; the insurer absorbs the financial loss."},
]

# ── Routes ────────────────────────────────────────────────────────────────────

@practice_exam_bp.route("/")
@certificate_required
def index():
    """
    Practice exam landing page.
    Only accessible to users with course access AND a valid, non-revoked certificate.
    """
    return render_template(
        "practice_exam.html",
        domain_meta=DOMAIN_META,
        total_questions=len(QUESTIONS),
    )


@practice_exam_bp.route("/questions")
@certificate_required
def get_questions():
    """
    JSON endpoint — returns the full question bank.
    Served only to authenticated users who have earned their certificate.
    The answer index is included to enable client-side grading
    (appropriate for a practice/study tool).
    """
    return jsonify({
        "questions":    QUESTIONS,
        "domain_meta":  DOMAIN_META,
        "total":        len(QUESTIONS),
        "pass_pct":     75,
        "duration_secs": 5400,  # 90 minutes
    })


@practice_exam_bp.route("/submit", methods=["POST"])
@certificate_required
def submit_attempt():
    """
    Records a completed exam attempt.
    POST body: { "answers": {"0": 2, "1": 1, ...}, "elapsed_seconds": 3720 }

    Imports ExamAttempt model — add that model to app/models.py first
    (see models_exam_attempt.py in the delivery package).
    """
    data     = request.get_json(silent=True) or {}
    answers  = data.get("answers", {})
    elapsed  = int(data.get("elapsed_seconds", 0))

    correct  = sum(
        1 for i, q in enumerate(QUESTIONS)
        if answers.get(str(i)) == q["ans"]
    )
    score_pct = round((correct / len(QUESTIONS)) * 100)
    passed    = score_pct >= 75

    # Persist attempt — uncomment once you add ExamAttempt to app/models.py
    # -------------------------------------------------------------------------
    # from app.models import ExamAttempt
    # attempt = ExamAttempt(
    #     user_id       = current_user.id,
    #     exam_set      = "security_plus_set1",
    #     score_pct     = score_pct,
    #     correct       = correct,
    #     total         = len(QUESTIONS),
    #     passed        = passed,
    #     elapsed_secs  = elapsed,
    #     completed_at  = datetime.utcnow(),
    # )
    # db.session.add(attempt)
    # db.session.commit()
    # -------------------------------------------------------------------------

    return jsonify({
        "correct":   correct,
        "total":     len(QUESTIONS),
        "score_pct": score_pct,
        "passed":    passed,
    })