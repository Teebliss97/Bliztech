"""
BlizTech Academy — CompTIA Security+ Practice Exam Blueprint
app/blueprints/practice_exam/routes.py

May 2026 free pivot:
  - Practice exam is PUBLIC to attempt (no login, no course access required).
  - Login REQUIRED to submit and save results to user history.
  - Anonymous users can still see their score on the result screen,
    but cannot save it or view history.

Two full 90-question practice exams.

Register in app/__init__.py inside create_app():
    from app.blueprints.practice_exam.routes import practice_exam_bp
    app.register_blueprint(practice_exam_bp)
"""

from datetime import datetime

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.extensions import db
from app.models import ExamAttempt

practice_exam_bp = Blueprint("practice_exam", __name__, url_prefix="/practice-exam")


# ── Domain metadata ───────────────────────────────────────────────────────────

DOMAIN_META = {
    1: {"name": "General Security Concepts",              "pct": 12},
    2: {"name": "Threats, Vulnerabilities & Mitigations", "pct": 22},
    3: {"name": "Security Architecture",                  "pct": 18},
    4: {"name": "Security Operations",                    "pct": 28},
    5: {"name": "Security Program Management",            "pct": 20},
}


# ══════════════════════════════════════════════════════════════════════════════
#  PRACTICE EXAM SET 1 — 90 Questions
# ══════════════════════════════════════════════════════════════════════════════

QUESTIONS_SET1 = [
    # ── DOMAIN 1 — General Security Concepts (11) ────────────────────────────
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
     "exp": "Digital signatures use the sender's private key to sign a message, providing non-repudiation — cryptographic proof the specific sender created it."},

    {"d": 1,
     "text": "An organisation deploys a fake database filled with realistic but false records to attract and identify attackers. This is BEST described as a:",
     "opts": ["Honeynet", "Honeytoken", "Honeyfile", "Honeypot"],
     "ans": 3,
     "exp": "A honeypot is a decoy system designed to lure attackers and gather intelligence on their tactics."},

    {"d": 1,
     "text": "In the Zero Trust model, which component sits in the data plane and actually enforces allow/deny decisions on traffic?",
     "opts": ["Policy Administrator", "Policy Enforcement Point", "Policy Engine", "Adaptive identity"],
     "ans": 1,
     "exp": "The Policy Enforcement Point (PEP) enforces the decisions made by the Policy Engine, allowing or denying traffic in real time."},

    {"d": 1,
     "text": "A user's private key has been lost. A copy was stored with a trusted third party to enable recovery. This practice is BEST described as:",
     "opts": ["Certificate revocation", "Key escrow", "Key stretching", "Root of trust"],
     "ans": 1,
     "exp": "Key escrow is the practice of depositing a copy of a cryptographic key with a trusted third party so it can be recovered if the original is lost."},

    {"d": 1,
     "text": "Which of the following is the MOST appropriate use of salting in password storage?",
     "opts": ["To encrypt passwords in transit", "To add random data before hashing, preventing rainbow table attacks", "To extend the effective length of short passwords", "To digitally sign stored password hashes"],
     "ans": 1,
     "exp": "Salting appends a unique random value to each password before hashing, preventing pre-computed rainbow table attacks even when users share the same password."},

    {"d": 1,
     "text": "A wildcard certificate is issued for *.bliztechacademy.com. Which host would this certificate NOT cover?",
     "opts": ["www.bliztechacademy.com", "app.bliztechacademy.com", "mail.bliztechacademy.com", "learn.courses.bliztechacademy.com"],
     "ans": 3,
     "exp": "A wildcard certificate covers only one level of subdomain. A second-level subdomain such as learn.courses.bliztechacademy.com is NOT covered."},

    {"d": 1,
     "text": "Which of the following is the BEST example of a compensating control?",
     "opts": ["A firewall that blocks all inbound traffic", "Network segmentation applied to a legacy system that cannot be patched", "A security policy requiring password complexity", "An IDS that alerts on suspicious network traffic"],
     "ans": 1,
     "exp": "A compensating control is an alternative measure applied when the standard control cannot be implemented — e.g. segmenting an unpatched system to limit its exposure."},

    {"d": 1,
     "text": "An access control vestibule (mantrap) is BEST classified as which type of control?",
     "opts": ["Technical — Preventive", "Physical — Preventive", "Physical — Detective", "Operational — Deterrent"],
     "ans": 1,
     "exp": "An access control vestibule is a physical control that prevents tailgating — making it physical/preventive."},

    {"d": 1,
     "text": "Which change management artefact documents the steps required to restore a system to its previous state if a change causes problems?",
     "opts": ["Impact analysis", "Maintenance window", "Backout plan", "Standard operating procedure"],
     "ans": 2,
     "exp": "A backout plan details the exact steps to reverse a change and restore the previous working state."},

    # ── DOMAIN 2 — Threats, Vulnerabilities & Mitigations (20) ───────────────
    {"d": 2,
     "text": "An attacker sends a text message to employees claiming to be IT support and requesting their login credentials. This attack is BEST described as:",
     "opts": ["Phishing", "Vishing", "Smishing", "Pretexting"],
     "ans": 2,
     "exp": "Smishing is phishing conducted via SMS. Vishing uses voice calls; phishing uses email."},

    {"d": 2,
     "scenario": "A security analyst reviews logs and finds the web server is returning unusually large DNS query responses to a third-party IP address, with traffic volumes far exceeding normal baselines.",
     "text": "Which attack type is MOST consistent with this behaviour?",
     "opts": ["DNS cache poisoning", "DNS amplification DDoS", "On-path attack", "Credential replay"],
     "ans": 1,
     "exp": "DNS amplification is a reflected DDoS attack. Small spoofed queries generate large responses directed at the victim."},

    {"d": 2,
     "text": "Which threat actor is MOST likely motivated by political beliefs and typically targets high-profile organisations to make a public statement?",
     "opts": ["Nation-state", "Organised crime", "Hacktivist", "Insider threat"],
     "ans": 2,
     "exp": "Hacktivists are motivated by political or ideological goals and often target organisations publicly to advance their cause."},

    {"d": 2,
     "text": "A developer's application allows user-supplied input to control memory allocation without bounds checking, potentially overwriting adjacent memory. This BEST describes:",
     "opts": ["Race condition", "SQL injection", "Buffer overflow", "Memory injection"],
     "ans": 2,
     "exp": "A buffer overflow occurs when a program writes more data to a buffer than it can hold, overwriting adjacent memory."},

    {"d": 2,
     "text": "An attacker positions themselves at a coffee shop Wi-Fi hotspot and silently reads all unencrypted traffic between users and the internet. This is BEST described as:",
     "opts": ["Credential replay", "On-path (MITM) attack", "Wireless DDoS", "Evil twin"],
     "ans": 1,
     "exp": "An on-path (MITM) attack positions the attacker between communicating parties to intercept or alter traffic."},

    {"d": 2,
     "scenario": "An employee receives an urgent email appearing to be from the CFO requesting an immediate wire transfer to a new vendor account. The CFO's email address has one letter transposed.",
     "text": "Which attack technique does this BEST represent?",
     "opts": ["Watering hole", "Business email compromise combined with typosquatting", "Vishing", "Pretexting via direct impersonation"],
     "ans": 1,
     "exp": "BEC combined with typosquatting registers a near-identical domain to impersonate an executive and trick employees into fraudulent financial actions."},

    {"d": 2,
     "text": "Which malware type is specifically designed to remain hidden and maintain persistent privileged access to a compromised system?",
     "opts": ["Worm", "Rootkit", "Trojan", "Logic bomb"],
     "ans": 1,
     "exp": "A rootkit hides itself at the OS or firmware level to maintain persistent, privileged access while concealing its presence."},

    {"d": 2,
     "text": "A vulnerability scan flags a known CVE on a fully patched system. The administrator confirms the patch is applied and the system is not actually vulnerable. This result is BEST described as:",
     "opts": ["True positive", "True negative", "False positive", "False negative"],
     "ans": 2,
     "exp": "A false positive occurs when a scan incorrectly reports a vulnerability that does not exist — a CVE already remediated by a patch."},

    {"d": 2,
     "text": "Which of the following BEST describes a supply chain attack?",
     "opts": ["Exploiting a zero-day vulnerability in an OS kernel", "Compromising a trusted software vendor to distribute malware to their customers", "Brute-forcing credentials against an internet-facing login portal", "Installing a keylogger on a physical workstation"],
     "ans": 1,
     "exp": "A supply chain attack targets a less-secure vendor to compromise their product, propagating malware to all downstream customers."},

    {"d": 2,
     "text": "An attacker captures a valid authentication token and reuses it hours later to gain access. This is BEST described as:",
     "opts": ["Pass-the-hash", "Credential replay", "Privilege escalation", "Session hijacking"],
     "ans": 1,
     "exp": "A credential replay attack captures a valid authentication credential and replays it to authenticate without knowing the original password."},

    {"d": 2,
     "text": "Which indicator of compromise MOST directly suggests an account has been used from two geographically distant locations within minutes?",
     "opts": ["Resource consumption spike", "Account lockout", "Impossible travel", "Concurrent session usage"],
     "ans": 2,
     "exp": "Impossible travel is detected when authentication logs show the same account used from locations that would be physically impossible to travel between in that time."},

    {"d": 2,
     "text": "Which vulnerability type exists in software that the vendor no longer supports with security patches?",
     "opts": ["Zero-day", "Legacy / end-of-life", "Misconfiguration", "Cloud-specific"],
     "ans": 1,
     "exp": "End-of-life/legacy vulnerabilities affect systems where the vendor has stopped releasing patches, leaving known vulnerabilities permanently unmitigated."},

    {"d": 2,
     "text": "Ransomware has encrypted all files on a file server. Which is the MOST effective mitigation to restore operations quickly without paying the attacker?",
     "opts": ["Restore from a clean, verified backup", "Pay the ransom and use the provided decryption key", "Run antivirus software on the encrypted files", "Apply the latest security patches to the server"],
     "ans": 0,
     "exp": "Restoring from a clean, verified backup is the fastest and most reliable recovery method and avoids paying the ransom."},

    {"d": 2,
     "text": "An attacker exploits the gap between when a condition is checked and when the result is acted upon, injecting malicious input in between. This BEST describes:",
     "opts": ["Buffer overflow", "SQL injection", "Race condition (TOC/TOU)", "Memory injection"],
     "ans": 2,
     "exp": "A TOC/TOU race condition exploits the window between checking a condition and using its result, allowing an attacker to change the state in that gap."},

    {"d": 2,
     "text": "Which social engineering technique involves creating a rogue wireless access point with the same SSID as a legitimate network to intercept user traffic?",
     "opts": ["Smishing", "Watering hole", "Evil twin", "Typosquatting"],
     "ans": 2,
     "exp": "An evil twin creates a rogue AP that mimics a legitimate network's SSID, tricking users into connecting and exposing their traffic."},

    {"d": 2,
     "text": "A password attack tries a single common password against thousands of different user accounts to avoid triggering lockout policies. This technique is:",
     "opts": ["Brute force", "Rainbow table attack", "Password spraying", "Dictionary attack"],
     "ans": 2,
     "exp": "Password spraying tries one or a few common passwords across many accounts, staying below per-account lockout thresholds."},

    {"d": 2,
     "text": "Which hardening technique MOST directly reduces the attack surface of a newly deployed server?",
     "opts": ["Enabling logging and forwarding events to a SIEM", "Removing all unnecessary software and disabling unneeded services", "Installing endpoint protection software", "Configuring host-based firewall rules"],
     "ans": 1,
     "exp": "Removing unnecessary software and services eliminates potential attack vectors entirely — you cannot exploit what is not installed."},

    {"d": 2,
     "text": "An attacker injects malicious script into a web application's comment field. When other users load the page, the script executes in their browsers. This is BEST described as:",
     "opts": ["SQL injection", "Cross-site request forgery (CSRF)", "Stored cross-site scripting (XSS)", "Directory traversal"],
     "ans": 2,
     "exp": "Stored XSS persists malicious scripts in the application's database and executes them automatically in any user's browser that loads the affected page."},

    {"d": 2,
     "text": "Which mitigation technique BEST limits lateral movement after an attacker compromises a single system?",
     "opts": ["Encrypting all data traversing the network", "Network segmentation", "Monitoring user behaviour analytics", "Enforcing MFA at network boundaries"],
     "ans": 1,
     "exp": "Network segmentation contains breaches by restricting lateral movement — if one segment is compromised, attackers cannot freely access other network zones."},

    {"d": 2,
     "text": "A nation-state actor maintains long-term, stealthy access to a target network for intelligence gathering without triggering alerts. This is MOST consistent with:",
     "opts": ["A hacktivist campaign", "An Advanced Persistent Threat (APT)", "An organised crime ransomware operation", "A script kiddie attack"],
     "ans": 1,
     "exp": "APTs are sophisticated, long-term intrusions typically sponsored by nation-states, focused on persistent access and intelligence collection."},

    # ── DOMAIN 3 — Security Architecture (16) ────────────────────────────────
    {"d": 3,
     "text": "Which cloud service model gives the customer the MOST control over the underlying infrastructure including the operating system?",
     "opts": ["SaaS", "PaaS", "IaaS", "FaaS"],
     "ans": 2,
     "exp": "IaaS provides virtualised compute, storage, and networking — the customer manages the OS, middleware, and applications."},

    {"d": 3,
     "text": "A security appliance fails and defaults to allowing all traffic through rather than blocking it. This failure mode is BEST described as:",
     "opts": ["Fail-closed", "Fail-secure", "Fail-open", "Fail-safe"],
     "ans": 2,
     "exp": "Fail-open means a system defaults to an unrestricted state on failure. Fail-closed defaults to blocking all traffic — the more secure posture."},

    {"d": 3,
     "scenario": "An organisation operates legacy SCADA systems that control critical manufacturing equipment. These systems cannot be patched and must remain operational 24/7.",
     "text": "Which architecture approach BEST protects these systems while preserving their operational continuity?",
     "opts": ["Deploy an IDS in tap/monitor mode beside the SCADA network", "Air-gap the SCADA systems from all other networks", "Install endpoint antivirus on each SCADA controller", "Enable WPA3 on the industrial wireless network"],
     "ans": 1,
     "exp": "Air-gapping physically isolates critical systems from all other networks, preventing remote exploitation of unpatched SCADA systems."},

    {"d": 3,
     "text": "Which of the following BEST describes the purpose of a jump server (bastion host)?",
     "opts": ["Load balancing inbound web traffic", "Providing a controlled, audited single access point into a secure network zone", "Terminating VPN tunnels at the network perimeter", "Filtering inbound HTTP/HTTPS traffic for web application attacks"],
     "ans": 1,
     "exp": "A jump server is a hardened, audited intermediary through which administrators must connect before accessing systems in secure network zones."},

    {"d": 3,
     "text": "An organisation wants to verify DR systems can sustain operations after losing the primary data centre without disrupting live production. Which test is MOST appropriate?",
     "opts": ["Full interruption test", "Parallel processing test", "Tabletop exercise", "Simulation test"],
     "ans": 1,
     "exp": "A parallel processing test runs DR systems alongside live systems simultaneously, verifying DR functionality without risking production disruption."},

    {"d": 3,
     "text": "Which is the PRIMARY security concern with containerisation?",
     "opts": ["Containers cannot be encrypted at rest", "Container escape — a malicious container breaking out to the host OS", "Containers do not support network segmentation", "Containers cannot run on cloud infrastructure"],
     "ans": 1,
     "exp": "Container escape occurs when a vulnerability allows a process inside a container to break out and gain access to the host OS."},

    {"d": 3,
     "text": "A company's RPO is set to 4 hours. What does this mean for their backup strategy?",
     "opts": ["All systems must be restored within 4 hours of a disaster", "Backups must occur at least every 4 hours to limit acceptable data loss", "The organisation can tolerate 4 hours of total system downtime", "DR systems must be geographically separated by 4 hours of travel"],
     "ans": 1,
     "exp": "RPO defines the maximum acceptable data loss measured in time. An RPO of 4 hours means backups must run at least every 4 hours."},

    {"d": 3,
     "text": "A laptop is stolen and the hard drive is removed and placed in another machine to be read. Which data state is MOST at risk?",
     "opts": ["Data in transit", "Data in use", "Data at rest", "Data in processing"],
     "ans": 2,
     "exp": "Data at rest on an unencrypted hard drive is directly accessible if the physical media is removed and read from another machine."},

    {"d": 3,
     "text": "Which disaster recovery site type provides the FASTEST recovery time but also carries the HIGHEST ongoing cost?",
     "opts": ["Cold site", "Warm site", "Hot site", "Mobile site"],
     "ans": 2,
     "exp": "A hot site is a fully operational replica with real-time data replication, enabling near-immediate failover at the highest cost."},

    {"d": 3,
     "text": "An organisation replaces sensitive card numbers in its database with random tokens that have no mathematical relationship to the originals. This is BEST described as:",
     "opts": ["Encryption", "Hashing", "Tokenisation", "Data masking"],
     "ans": 2,
     "exp": "Tokenisation replaces sensitive data with a surrogate value that has no exploitable mathematical relationship to the original."},

    {"d": 3,
     "text": "Which network appliance monitors traffic passively, generates alerts, but does NOT block malicious activity?",
     "opts": ["Intrusion Prevention System (IPS)", "Next-generation firewall (NGFW)", "Intrusion Detection System (IDS)", "Web application firewall (WAF)"],
     "ans": 2,
     "exp": "An IDS monitors traffic passively and generates alerts. An IPS is deployed inline and can actively block malicious traffic."},

    {"d": 3,
     "text": "To reduce the risk of a cloud provider-wide outage taking down all workloads, an organisation should adopt which strategy?",
     "opts": ["Geographic dispersion within the same cloud provider", "Multi-cloud systems distributed across different providers", "On-premises platform diversity as a backup", "Load balancing across the provider's availability zones"],
     "ans": 1,
     "exp": "Multi-cloud distributes workloads across different providers so a single provider's outage does not affect all systems."},

    {"d": 3,
     "text": "Which of the following BEST describes Software-Defined Networking (SDN)?",
     "opts": ["A physical switch that enforces MAC-based port access control", "Decoupling the network control plane from the data plane to enable centralised, programmable management", "Encrypting all data as it traverses a network segment", "A VPN technology for connecting remote users to the corporate network"],
     "ans": 1,
     "exp": "SDN separates the control plane from the data plane, enabling centralised and programmatic management of the entire network infrastructure."},

    {"d": 3,
     "text": "Which encryption level protects individual database fields so that even if DB files are breached, field values remain unreadable?",
     "opts": ["Full-disk encryption", "Database / record-level encryption", "Transport layer encryption (TLS)", "Volume encryption"],
     "ans": 1,
     "exp": "Database or record-level encryption encrypts individual fields. Even if an attacker accesses database files, they cannot read values without the encryption keys."},

    {"d": 3,
     "text": "Which architecture converges SD-WAN networking with cloud-delivered security services (ZTNA, CASB, SWG) for distributed workforces?",
     "opts": ["Zero Trust Network Access (ZTNA) alone", "Secure Access Service Edge (SASE)", "DMZ-based perimeter security", "Site-to-site IPSec VPN mesh"],
     "ans": 1,
     "exp": "SASE converges networking with cloud-delivered security services, enabling secure access for remote users without traditional perimeter security."},

    {"d": 3,
     "text": "802.1X port-based network access control is BEST described as which type of control, and what does it enforce?",
     "opts": ["Technical / Detective — it logs all devices connecting to switch ports", "Technical / Preventive — it authenticates devices before granting network access", "Physical / Preventive — it physically locks unused switch ports", "Managerial / Directive — it defines acceptable use of network ports"],
     "ans": 1,
     "exp": "802.1X is a technical, preventive control that enforces NAC by requiring devices to authenticate via EAP/RADIUS before gaining network access."},

    # ── DOMAIN 4 — Security Operations (25) ──────────────────────────────────
    {"d": 4,
     "text": "During incident response, a team disconnects a compromised host from the network but leaves it powered on to preserve volatile memory. Which phase are they in?",
     "opts": ["Detection", "Containment", "Eradication", "Recovery"],
     "ans": 1,
     "exp": "Containment limits the spread of an incident. Preserving volatile memory while isolating the host is a containment action before eradication begins."},

    {"d": 4,
     "text": "Which identity concept allows a user to authenticate once and then access multiple applications without re-entering credentials?",
     "opts": ["Federation", "Multifactor authentication", "Single sign-on (SSO)", "Attestation"],
     "ans": 2,
     "exp": "SSO allows a user to authenticate once and access multiple applications without needing separate credentials for each."},

    {"d": 4,
     "scenario": "A SOC analyst notices a user account downloaded 5 GB of intellectual property at 2 AM, then immediately attempted to email a compressed archive to a personal address. No SIEM alerts fired.",
     "text": "Which SIEM configuration issue does this MOST suggest?",
     "opts": ["The SIEM lacks sufficient log sources", "Alert tuning has suppressed the relevant detection rules", "The DLP policy was not configured to cover email channels", "Both B and C are likely contributing factors"],
     "ans": 3,
     "exp": "Missing alerts on clear data exfiltration indicators suggest both overly aggressive alert tuning and incomplete DLP coverage for email."},

    {"d": 4,
     "text": "Which access control model assigns permissions to organisational roles, and users automatically inherit all permissions of their assigned role?",
     "opts": ["Mandatory Access Control (MAC)", "Discretionary Access Control (DAC)", "Role-Based Access Control (RBAC)", "Attribute-Based Access Control (ABAC)"],
     "ans": 2,
     "exp": "RBAC assigns permissions to roles rather than individuals. Users inherit permissions by being assigned to a role."},

    {"d": 4,
     "text": "An organisation wants to ensure employees can only log in to certain systems during business hours. Which access control feature directly enforces this?",
     "opts": ["Least privilege", "Time-of-day restrictions", "Attribute-based access control", "Mandatory access control"],
     "ans": 1,
     "exp": "Time-of-day restrictions limit when users can authenticate or access resources, regardless of whether their credentials are otherwise valid."},

    {"d": 4,
     "text": "Which MFA factor does a hardware FIDO2 security key represent?",
     "opts": ["Something you know", "Something you have", "Something you are", "Somewhere you are"],
     "ans": 1,
     "exp": "A hardware security key is a physical possession factor (something you have). FIDO2 keys generate cryptographic proof of possession."},

    {"d": 4,
     "text": "A penetration tester is given no prior information about the target environment and must conduct all reconnaissance from scratch. This is BEST described as:",
     "opts": ["Known environment (white box)", "Partially known environment (grey box)", "Unknown environment (black box)", "Red team / assumed breach simulation"],
     "ans": 2,
     "exp": "An unknown environment (black box) test gives the tester no advance information, simulating a real external attacker."},

    {"d": 4,
     "text": "Which vulnerability management metric represents the total financial loss an organisation would suffer from a single occurrence of a specific threat event?",
     "opts": ["Annualized Loss Expectancy (ALE)", "Single Loss Expectancy (SLE)", "Annualized Rate of Occurrence (ARO)", "Exposure Factor (EF)"],
     "ans": 1,
     "exp": "SLE = Asset Value × Exposure Factor. It is the monetary loss expected from a single incident of a specific threat."},

    {"d": 4,
     "text": "Which tool collects, aggregates, and correlates log data from multiple sources to detect threats and generate prioritised alerts?",
     "opts": ["Vulnerability scanner", "IDS", "SIEM", "DLP"],
     "ans": 2,
     "exp": "A SIEM collects and correlates log data from across the environment to detect threat patterns and generate actionable alerts."},

    {"d": 4,
     "text": "After confirming that a user's simultaneous logins from three countries are all legitimate VPN connections, what should the analyst do NEXT?",
     "opts": ["Immediately disable the account", "Tune the alert to reduce future false positives for this user's known pattern", "Escalate to the incident response team", "Reset the user's credentials and require MFA re-enrolment"],
     "ans": 1,
     "exp": "Confirmed legitimate activity should prompt alert tuning so the rule does not generate unnecessary noise for this user's known behaviour."},

    {"d": 4,
     "text": "Which digital forensics concept ensures that evidence maintains its original, unaltered state from collection through legal proceedings?",
     "opts": ["Legal hold", "E-discovery", "Preservation", "Chain of custody"],
     "ans": 2,
     "exp": "Preservation ensures evidence is collected and stored in a way that maintains integrity using write blockers, cryptographic hashes, and secure storage."},

    {"d": 4,
     "text": "An organisation automatically creates user accounts, mailboxes, and access permissions when HR submits a new-hire request. This is BEST described as:",
     "opts": ["Automated user provisioning", "Continuous integration", "Guard rail enforcement", "Workforce multiplier scripting"],
     "ans": 0,
     "exp": "Automated user provisioning creates accounts and assigns access automatically based on HR system triggers, reducing manual effort and errors."},

    {"d": 4,
     "text": "Which MDM deployment model allows employees to use personal devices for work while the organisation retains control over corporate apps and data on those devices?",
     "opts": ["COPE — Corporate-Owned, Personally Enabled", "CYOD — Choose Your Own Device", "BYOD — Bring Your Own Device", "COBO — Corporate-Owned, Business Only"],
     "ans": 2,
     "exp": "BYOD allows employees to use personal devices for work. MDM policies enforce corporate controls on those devices."},

    {"d": 4,
     "text": "A WAF is MOST effective at mitigating which category of attacks?",
     "opts": ["Network-layer volumetric DDoS attacks", "Layer 7 application attacks such as SQLi, XSS, and CSRF", "Wireless protocol exploitation", "Physical access to web server hardware"],
     "ans": 1,
     "exp": "A WAF inspects HTTP/HTTPS traffic at Layer 7 and is specifically designed to detect and block application-layer attacks."},

    {"d": 4,
     "text": "Which email authentication mechanism publishes a DNS TXT record listing all IP addresses authorised to send email on behalf of a domain?",
     "opts": ["DKIM", "DMARC", "SPF", "S/MIME"],
     "ans": 2,
     "exp": "SPF publishes a DNS TXT record listing authorised sending IP addresses, allowing receiving mail servers to reject email from unauthorised senders."},

    {"d": 4,
     "text": "After a major security incident, the team convenes to analyse what happened, why controls failed, and produce improvement recommendations. This represents which IR phase?",
     "opts": ["Detection", "Containment", "Eradication", "Lessons learned"],
     "ans": 3,
     "exp": "The lessons learned phase analyses the incident, identifies control gaps, and produces recommendations to improve future security posture."},

    {"d": 4,
     "text": "Which type of scan identifies all open ports and running services on every host within a specified network range?",
     "opts": ["Vulnerability scan", "Packet capture", "Network mapper / port scan", "Static code analysis"],
     "ans": 2,
     "exp": "A network mapper/port scanner actively probes hosts to identify open ports and running services."},

    {"d": 4,
     "text": "A password policy requires 16+ characters, no reuse of the last 12, and 90-day expiry. Which password security practice is NOT addressed?",
     "opts": ["Password length", "Password reuse prevention", "Password complexity (required character mix)", "Password expiration"],
     "ans": 2,
     "exp": "The policy covers length, reuse, and expiry but does NOT mandate a required mix of character types."},

    {"d": 4,
     "text": "Which PAM concept grants elevated permissions only for the duration of a specific task, then automatically revokes them?",
     "opts": ["Password vaulting", "Ephemeral credentials", "Just-in-time (JIT) permissions", "Attestation"],
     "ans": 2,
     "exp": "JIT permissions grant elevated access only when needed and revoke it immediately afterward, minimising standing privilege exposure."},

    {"d": 4,
     "text": "A tool tracks file attributes (size, hash, timestamps) on critical system files and alerts when any change unexpectedly. This is BEST described as:",
     "opts": ["Endpoint Detection and Response (EDR)", "File Integrity Monitoring (FIM)", "Data Loss Prevention (DLP)", "Host-based Intrusion Prevention System (HIPS)"],
     "ans": 1,
     "exp": "FIM tracks critical file attributes and generates alerts when unexpected changes occur, detecting malware modifications or unauthorised tampering."},

    {"d": 4,
     "text": "Which version of SNMP adds authentication (HMAC) and encryption (AES) to address the plaintext weaknesses of SNMPv1 and v2?",
     "opts": ["SNMPv3", "NetFlow v9", "Syslog over TLS", "HTTPS REST API"],
     "ans": 0,
     "exp": "SNMPv3 introduces authentication and encryption for SNMP traffic, addressing the weakness of v1 and v2 which transmit community strings in cleartext."},

    {"d": 4,
     "text": "An AUP prohibits personal cloud storage for work files. A user uploads project documents to personal Dropbox. Which control MOST directly detects this?",
     "opts": ["IDS signature matching cloud storage protocol patterns", "DLP policy monitoring and inspecting outbound data transfers", "SPF/DKIM email authentication filtering", "Group Policy restricting USB mass storage devices"],
     "ans": 1,
     "exp": "A DLP solution monitors outbound data flows and can inspect content being uploaded to unapproved cloud storage services."},

    {"d": 4,
     "text": "Static code analysis (SAST) is BEST described as:",
     "opts": ["Testing a running application by sending crafted malicious input", "Reviewing source code for security flaws without executing the program", "Monitoring application behaviour at runtime using a sandboxed environment", "Scanning third-party dependencies for known CVEs"],
     "ans": 1,
     "exp": "SAST examines source code without executing the application, identifying security flaws at development time."},

    {"d": 4,
     "text": "Which IR phase involves re-imaging compromised systems, removing all malware and backdoors, and closing the exploited vulnerability?",
     "opts": ["Containment", "Eradication", "Recovery", "Analysis"],
     "ans": 1,
     "exp": "Eradication removes the root cause — all malware, backdoors, and the exploited vulnerability — before systems are restored in recovery."},

    {"d": 4,
     "text": "An analyst needs to ensure log files on a compromised server are not deleted during an investigation. Which action should be taken FIRST?",
     "opts": ["Isolate the server from the network", "Acquire a forensic bit-for-bit image of the server's drives", "Implement a legal hold on the relevant data and logs", "Run a vulnerability scan to identify the exploit used"],
     "ans": 2,
     "exp": "A legal hold preserves evidence from routine deletion or overwriting, ensuring it remains available for investigation and legal proceedings."},

    # ── DOMAIN 5 — Security Program Management (18) ──────────────────────────
    {"d": 5,
     "text": "A server has an SLE of $50,000 and an ARO of 0.5. What is the Annualized Loss Expectancy (ALE)?",
     "opts": ["$100,000", "$50,000", "$25,000", "$10,000"],
     "ans": 2,
     "exp": "ALE = SLE × ARO = $50,000 × 0.5 = $25,000. ALE is the expected annual financial loss from a specific threat to a specific asset."},

    {"d": 5,
     "text": "An organisation decides to take no further action on a risk because the cost of available controls exceeds the value of the asset. This strategy is BEST described as:",
     "opts": ["Risk mitigation", "Risk transfer", "Risk avoidance", "Risk acceptance"],
     "ans": 3,
     "exp": "Risk acceptance is a deliberate decision to acknowledge a risk and take no further action, typically when mitigation cost exceeds the potential impact."},

    {"d": 5,
     "text": "Which document legally defines the minimum performance metrics a cloud provider must meet, including uptime guarantees and remedies for non-compliance?",
     "opts": ["MOU", "SLA", "NDA", "MSA"],
     "ans": 1,
     "exp": "An SLA legally defines the minimum service standards a vendor must meet, including uptime guarantees and contractual remedies."},

    {"d": 5,
     "text": "Under GDPR, individuals have the right to request that an organisation delete their personal data. This right is BEST known as:",
     "opts": ["Data sovereignty", "Right to be forgotten", "Data subject access request (DSAR)", "Controller vs. processor obligation"],
     "ans": 1,
     "exp": "The right to be forgotten (right to erasure) under GDPR allows individuals to request deletion of their personal data in specific circumstances."},

    {"d": 5,
     "text": "Which governance role is responsible for classifying data and defining policies for how it should be used and protected?",
     "opts": ["Data custodian", "Data processor", "Data owner", "Data steward"],
     "ans": 2,
     "exp": "The data owner is responsible for classifying data and setting policies for its use and protection. Data custodians implement those policies technically."},

    {"d": 5,
     "text": "An organisation's risk appetite statement explicitly accepts significant cybersecurity risks to pursue aggressive growth. This BEST describes which risk appetite type?",
     "opts": ["Conservative", "Neutral", "Expansionary", "Residual"],
     "ans": 2,
     "exp": "An expansionary risk appetite accepts higher risk levels in pursuit of growth — the opposite of a conservative appetite."},

    {"d": 5,
     "text": "In a 'partially known environment' penetration test, the tester is given some information. Which scenario BEST represents this?",
     "opts": ["The tester receives full network diagrams, source code, and valid credentials", "The tester is given nothing and must enumerate all information from scratch", "The tester receives IP ranges and some system details but not full access", "The tester is an internal employee simulating an insider threat"],
     "ans": 2,
     "exp": "A grey box test provides limited information such as network ranges, simulating a scenario where an attacker has some initial foothold or partial knowledge."},

    {"d": 5,
     "text": "Which compliance framework specifically governs the secure handling of payment card data and mandates encryption, access control, and regular vulnerability management?",
     "opts": ["GDPR", "HIPAA", "PCI DSS", "SOX"],
     "ans": 2,
     "exp": "PCI DSS applies to all organisations that store, process, or transmit cardholder data, mandating specific security controls."},

    {"d": 5,
     "text": "An organisation trains employees to recognise suspicious emails and runs simulated phishing campaigns. This is BEST described as:",
     "opts": ["Anomalous behaviour recognition training", "Security awareness training — phishing simulation", "Operational security (OPSEC) training", "Insider threat mitigation programme"],
     "ans": 1,
     "exp": "Simulated phishing campaigns are a cornerstone of security awareness training, measuring real-world susceptibility and delivering targeted education."},

    {"d": 5,
     "text": "The PRIMARY purpose of a Business Impact Analysis (BIA) is to:",
     "opts": ["Identify all technical vulnerabilities in the environment", "Determine the financial and operational impact of losing specific business functions", "Calculate the annual budget required for security controls", "Assess the security posture of third-party vendors"],
     "ans": 1,
     "exp": "A BIA identifies critical business functions and quantifies the impact of their disruption, informing RTO/RPO targets and recovery priorities."},

    {"d": 5,
     "text": "An agreement that documents mutual intentions between two organisations without creating legally binding obligations is BEST described as:",
     "opts": ["SLA", "NDA", "MOU", "BPA"],
     "ans": 2,
     "exp": "An MOU documents mutual intentions but is generally not legally binding — unlike an SLA or formal contract."},

    {"d": 5,
     "text": "Which is a direct consequence of non-compliance with GDPR?",
     "opts": ["Mandatory penetration testing within 30 days", "Regulatory fines of up to 4% of global annual turnover and reputational damage", "Mandatory encryption key escrow with the supervising authority", "Required independent audit within 30 days of the breach"],
     "ans": 1,
     "exp": "GDPR non-compliance can result in fines up to 4% of global annual turnover, reputational damage, sanctions, and contractual impacts."},

    {"d": 5,
     "text": "During a vendor assessment, an organisation inserts a clause giving them the legal right to independently audit the vendor's security controls at any time. This is BEST described as:",
     "opts": ["A due diligence requirement", "A right-to-audit clause", "A conflict of interest declaration", "Rules of engagement"],
     "ans": 1,
     "exp": "A right-to-audit clause contractually grants the organisation the right to audit the vendor's environment at any time."},

    {"d": 5,
     "text": "A security manager wants to demonstrate that controls are measurably reducing risk over time. Which governance activity BEST supports this?",
     "opts": ["Conducting annual penetration tests", "Maintaining a risk register with key risk indicators (KRIs) reviewed regularly", "Publishing and updating an acceptable use policy", "Running quarterly tabletop exercises"],
     "ans": 1,
     "exp": "A risk register with KRIs tracks risk status over time, providing measurable evidence of whether controls are effectively reducing risk."},

    {"d": 5,
     "text": "Which of the following is the BEST example of a directive control?",
     "opts": ["A firewall blocking all unauthorised inbound connections", "A mandatory annual security awareness training policy", "CCTV cameras monitoring physical access to the server room", "Automated patch deployment for critical OS vulnerabilities"],
     "ans": 1,
     "exp": "Directive controls direct or mandate behaviour through policies such as mandatory training requirements."},

    {"d": 5,
     "text": "Integrating security testing at every SDLC phase rather than only at deployment is BEST described as:",
     "opts": ["Security by obscurity", "Shift-left security", "Agile security sprint gating", "Defence in depth"],
     "ans": 1,
     "exp": "Shift-left security moves security activities earlier in the SDLC, identifying vulnerabilities when they are least costly to remediate."},

    {"d": 5,
     "text": "Under GDPR, which role independently monitors the organisation's compliance with data protection law and serves as the primary contact for the supervisory authority?",
     "opts": ["The CISO responsible for approving the data security budget", "The Data Protection Officer (DPO)", "The IT manager responsible for implementing encryption controls", "An independent third-party auditor engaged annually"],
     "ans": 1,
     "exp": "A DPO is an independent role that monitors compliance with data protection obligations and acts as the official contact for supervisory authorities."},

    {"d": 5,
     "text": "An organisation purchases a cyber insurance policy to cover financial losses from a ransomware attack. This risk strategy is BEST described as:",
     "opts": ["Risk avoidance", "Risk mitigation", "Risk transference", "Risk acceptance"],
     "ans": 2,
     "exp": "Risk transference shifts the financial consequences of a risk to a third party (insurer) without eliminating the underlying risk itself."},
]


# ══════════════════════════════════════════════════════════════════════════════
#  PRACTICE EXAM SET 2 — 90 New Questions
# ══════════════════════════════════════════════════════════════════════════════

QUESTIONS_SET2 = [
    # ── DOMAIN 1 — General Security Concepts (11) ────────────────────────────
    {"d": 1,
     "text": "Security cameras installed in a car park to discourage vandalism are BEST classified as which type of control?",
     "opts": ["Physical / Preventive", "Physical / Deterrent", "Technical / Detective", "Operational / Corrective"],
     "ans": 1,
     "exp": "Deterrent controls discourage potential attackers from attempting an action. Cameras visible in a car park deter vandalism without technically blocking it."},

    {"d": 1,
     "text": "Which component of the Zero Trust architecture is responsible for making the policy decision — whether to grant or deny a request — based on evaluated signals?",
     "opts": ["Policy Enforcement Point", "Policy Administrator", "Policy Engine", "Adaptive identity module"],
     "ans": 2,
     "exp": "The Policy Engine evaluates signals (identity, device health, location, etc.) and makes the grant/deny decision. The PEP enforces that decision; the PA communicates it."},

    {"d": 1,
     "text": "An organisation discovers that a symmetric encryption key used for ten years has been compromised. The BEST immediate remediation is:",
     "opts": ["Re-encrypt all data with the same key using a stronger algorithm", "Rotate to a new key and re-encrypt all data protected by the compromised key", "Hash the compromised key and use the hash as a replacement", "Increase the key length of the existing key"],
     "ans": 1,
     "exp": "A compromised key must be retired immediately. All data it protected must be re-encrypted under a new key generated through a secure key generation process."},

    {"d": 1,
     "text": "A security engineer deploys a system that records every keystroke made by an attacker who connects to a decoy SSH server. This is BEST described as a:",
     "opts": ["Honeyfile", "Honeytoken", "Honeypot", "Honeynet"],
     "ans": 2,
     "exp": "A honeypot is a decoy system designed to attract attackers and capture their actions. A honeynet is a network of honeypots; a honeytoken/honeyfile is a fake data item, not a system."},

    {"d": 1,
     "text": "Which of the following BEST describes the purpose of a Certificate Revocation List (CRL)?",
     "opts": ["A list of trusted root certificate authorities", "A list of certificates that have been invalidated before their expiry date", "A list of pending certificate signing requests awaiting approval", "A list of certificates due to expire within 30 days"],
     "ans": 1,
     "exp": "A CRL is published by a CA and lists certificates that have been revoked (invalidated before expiry), allowing relying parties to check certificate validity."},

    {"d": 1,
     "text": "Which cryptographic concept involves applying a work factor that deliberately makes the hashing process slower to resist brute-force attacks?",
     "opts": ["Salting", "Key escrow", "Key stretching", "Tokenisation"],
     "ans": 2,
     "exp": "Key stretching (e.g. bcrypt, PBKDF2, Argon2) deliberately adds computational work to the hashing process, making brute-force and dictionary attacks significantly slower."},

    {"d": 1,
     "text": "An organisation's security policy states that all employees must complete annual security awareness training. This policy is BEST described as which type of control?",
     "opts": ["Technical / Preventive", "Managerial / Directive", "Operational / Detective", "Physical / Corrective"],
     "ans": 1,
     "exp": "A mandatory training policy is a managerial directive control — it governs behaviour through documented requirements rather than technical enforcement."},

    {"d": 1,
     "text": "Which of the following is the PRIMARY security benefit of using asymmetric encryption for key exchange?",
     "opts": ["It is significantly faster than symmetric encryption", "It allows two parties to establish a shared secret over an untrusted channel without pre-sharing a key", "It eliminates the need for digital certificates", "It provides stronger encryption than any symmetric algorithm"],
     "ans": 1,
     "exp": "Asymmetric encryption solves the key distribution problem — parties can exchange a shared secret over an untrusted network without having previously shared a secret key."},

    {"d": 1,
     "text": "A security architect wants to ensure that even if an attacker compromises the network layer, they cannot read database traffic. Which control BEST achieves this?",
     "opts": ["Full-disk encryption on the database server", "Transport Layer Security (TLS) between the application and database", "Network segmentation between the application tier and database tier", "A host-based firewall on the database server"],
     "ans": 1,
     "exp": "TLS encrypts data in transit between the application and database, ensuring that even if network traffic is captured, the data cannot be read."},

    {"d": 1,
     "text": "Which of the following BEST describes steganography as a data obfuscation technique?",
     "opts": ["Replacing sensitive data fields with non-sensitive placeholders", "Hiding data inside another file or medium so its existence is concealed", "Scrambling data so it is unreadable without a decryption key", "Adding random noise to data to prevent statistical analysis"],
     "ans": 1,
     "exp": "Steganography conceals the very existence of data by hiding it inside another file (e.g. an image or audio file), unlike encryption which makes data unreadable but still visible."},

    {"d": 1,
     "text": "A change management process requires that all proposed changes include documentation of potential negative outcomes and their likelihood. This requirement BEST describes which change management element?",
     "opts": ["Backout plan", "Maintenance window", "Impact analysis", "Standard operating procedure"],
     "ans": 2,
     "exp": "An impact analysis identifies and documents the potential negative outcomes of a proposed change, including their likelihood and business impact, before approval is granted."},

    # ── DOMAIN 2 — Threats, Vulnerabilities & Mitigations (20) ───────────────
    {"d": 2,
     "text": "An attacker calls an employee, pretends to be from the IT help desk, and convinces them to reveal their password by claiming an urgent system issue. This BEST describes:",
     "opts": ["Smishing", "Vishing", "Phishing", "Impersonation"],
     "ans": 1,
     "exp": "Vishing (voice phishing) uses telephone calls to deceive victims into revealing sensitive information, often by impersonating trusted entities such as IT support."},

    {"d": 2,
     "text": "A piece of malware activates and destroys data on a specific date without any interaction from the attacker. This is BEST described as a:",
     "opts": ["Worm", "Trojan", "Logic bomb", "Rootkit"],
     "ans": 2,
     "exp": "A logic bomb is malicious code that executes based on a specific trigger — such as a date/time — without requiring attacker interaction at the time of execution."},

    {"d": 2,
     "scenario": "A financial institution notices that small, irregular amounts are being deducted from thousands of customer accounts and deposited to a single offshore account. Individual deductions are below fraud detection thresholds.",
     "text": "This attack technique is BEST described as:",
     "opts": ["Credential stuffing", "Salami attack", "Account takeover", "Replay attack"],
     "ans": 1,
     "exp": "A salami attack involves making many small, individually undetectable fraudulent transactions that collectively amount to significant theft."},

    {"d": 2,
     "text": "Which type of malware self-replicates across a network without requiring a host file or user interaction to spread?",
     "opts": ["Virus", "Worm", "Trojan", "Spyware"],
     "ans": 1,
     "exp": "A worm self-replicates and spreads across networks autonomously, without needing to attach to a host file or requiring user interaction to propagate."},

    {"d": 2,
     "text": "An attacker registers the domain 'microsоft.com' using a Cyrillic 'о' instead of the Latin 'o'. Users who visit the site see a convincing Microsoft login page. This attack is BEST described as:",
     "opts": ["Typosquatting", "Homograph attack", "Brand impersonation", "Watering hole attack"],
     "ans": 1,
     "exp": "A homograph (or homoglyph) attack exploits visually similar characters from different Unicode scripts to register deceptive domain names that appear identical to legitimate ones."},

    {"d": 2,
     "text": "A developer writes code that reads beyond the end of an allocated buffer. An attacker can exploit this to read sensitive memory contents. This vulnerability is BEST described as:",
     "opts": ["Buffer overflow", "Memory injection", "Out-of-bounds read", "Race condition"],
     "ans": 2,
     "exp": "An out-of-bounds read vulnerability allows a program to read memory outside its allocated buffer, potentially exposing sensitive data such as cryptographic keys or passwords."},

    {"d": 2,
     "scenario": "An employee's workstation begins connecting to external IP addresses on port 443 at regular 5-minute intervals, even when the employee is not at their desk. Network logs show small data transfers each time.",
     "text": "This behaviour MOST likely indicates:",
     "opts": ["A misconfigured update service", "Command-and-control (C2) communication from malware", "An employee using a VPN", "Normal cloud backup activity"],
     "ans": 1,
     "exp": "Regular, periodic connections to external IPs with small data transfers are characteristic of C2 beaconing — malware checking in with its command-and-control server for instructions."},

    {"d": 2,
     "text": "Which type of vulnerability scan is performed from the perspective of an authenticated internal user with valid credentials?",
     "opts": ["External scan", "Credentialed scan", "Passive scan", "Agent-based scan"],
     "ans": 1,
     "exp": "A credentialed (authenticated) scan uses valid credentials to log in to systems and performs a deeper assessment, identifying vulnerabilities that are only visible to authenticated users."},

    {"d": 2,
     "text": "An attacker floods a target web server with HTTP GET requests from thousands of compromised IoT devices, making the site unavailable to legitimate users. This is BEST described as:",
     "opts": ["A reflected DDoS attack", "An amplified DDoS attack", "A volumetric DDoS attack", "A protocol DDoS attack"],
     "ans": 2,
     "exp": "Flooding a target with high volumes of traffic from multiple sources to exhaust resources is a volumetric DDoS attack. Reflected attacks use third-party servers; amplified attacks exploit protocols that magnify response size."},

    {"d": 2,
     "text": "Which mobile device vulnerability arises when a user installs applications from unofficial app stores outside the manufacturer's official distribution channel?",
     "opts": ["Jailbreaking", "Side loading", "Firmware exploit", "RFID cloning"],
     "ans": 1,
     "exp": "Side loading involves installing apps from unofficial sources, bypassing the app store's security vetting process and exposing the device to potentially malicious applications."},

    {"d": 2,
     "text": "An attacker compromises a popular JavaScript library used by thousands of websites and inserts malicious code into an update. Websites that pull the update automatically begin exfiltrating user credentials. This is BEST described as:",
     "opts": ["A zero-day exploit", "A supply chain attack via software dependency", "Cross-site scripting", "A watering hole attack"],
     "ans": 1,
     "exp": "Compromising a shared software dependency to distribute malicious code to all downstream users is a supply chain attack — targeting the supply chain rather than individual victims."},

    {"d": 2,
     "text": "Which of the following BEST describes the purpose of a bug bounty programme?",
     "opts": ["To reward employees for reporting internal policy violations", "To incentivise external researchers to responsibly disclose discovered vulnerabilities", "To compensate vendors for fixing critical vulnerabilities in their products", "To fund the development of new security patches"],
     "ans": 1,
     "exp": "A bug bounty programme pays external security researchers to find and responsibly disclose vulnerabilities, expanding the organisation's security testing beyond its internal team."},

    {"d": 2,
     "text": "An attacker sends a specially crafted input to a web application that causes the application to retrieve a file from the server's filesystem using '../../../etc/passwd'. This is BEST described as:",
     "opts": ["SQL injection", "Command injection", "Directory traversal", "XML injection"],
     "ans": 2,
     "exp": "Directory traversal uses '../' sequences to navigate outside the intended web root and access files elsewhere on the server's filesystem."},

    {"d": 2,
     "text": "Which indicator would MOST directly suggest that a server is participating in a botnet?",
     "opts": ["High CPU usage during business hours", "Outbound connections to known C2 IP addresses at regular intervals", "Failed login attempts from internal users", "Increased inbound SMTP traffic"],
     "ans": 1,
     "exp": "Regular outbound connections to known C2 infrastructure (beaconing) is the most direct indicator of botnet participation, as compromised bots regularly check in with their controllers."},

    {"d": 2,
     "text": "An organisation uses a third-party vendor for HR software. The vendor is compromised, and attackers gain access to the organisation's employee data through the vendor's integration. This is BEST described as:",
     "opts": ["An insider threat", "A supply chain attack via managed service provider", "A watering hole attack", "A credential stuffing attack"],
     "ans": 1,
     "exp": "When attackers compromise a managed service provider or vendor and use that access to breach the organisation's data, it is a supply chain attack through an MSP."},

    {"d": 2,
     "text": "Which cryptographic attack attempts to find two different inputs that produce the same hash output?",
     "opts": ["Downgrade attack", "Birthday attack", "Rainbow table attack", "Brute force attack"],
     "ans": 1,
     "exp": "A birthday attack exploits the birthday problem in probability theory to find hash collisions — two different inputs that produce the same hash value."},

    {"d": 2,
     "text": "A vulnerability exists in software before the vendor is aware of it and before a patch is available. This is BEST described as a:",
     "opts": ["Legacy vulnerability", "Zero-day vulnerability", "Misconfiguration vulnerability", "End-of-life vulnerability"],
     "ans": 1,
     "exp": "A zero-day vulnerability is one that is unknown to the vendor (or for which no patch yet exists), giving defenders zero days to prepare a fix before potential exploitation."},

    {"d": 2,
     "text": "Which of the following BEST describes the principle of least privilege as a mitigation technique?",
     "opts": ["Users are granted the maximum permissions needed for any possible task", "Users and systems are granted only the minimum access rights needed for their specific role", "Privileged accounts are shared among multiple administrators to prevent single points of failure", "Access rights are automatically escalated when a user requests additional permissions"],
     "ans": 1,
     "exp": "Least privilege limits the damage from compromised accounts or insider threats by ensuring every user and system has only the minimum access needed to perform its function."},

    {"d": 2,
     "text": "An attacker sends a phishing email to a specific senior executive, including personalised details about their recent business activities. This targeted approach is BEST described as:",
     "opts": ["Smishing", "Spear phishing / whaling", "Vishing", "Brand impersonation"],
     "ans": 1,
     "exp": "Spear phishing targets specific individuals using personalised information. When directed at senior executives, it is specifically called whaling."},

    {"d": 2,
     "text": "A security team isolates a compromised server to prevent further spread of malware across the network. This action is part of which mitigation technique?",
     "opts": ["Patching", "Encryption", "Segmentation / isolation", "Decommissioning"],
     "ans": 2,
     "exp": "Isolation (a form of segmentation) contains an active threat by cutting off the compromised system from the rest of the network, preventing lateral movement."},

    # ── DOMAIN 3 — Security Architecture (16) ────────────────────────────────
    {"d": 3,
     "text": "An organisation deploys workloads across AWS, Azure, and Google Cloud simultaneously to avoid dependency on a single provider. This architecture strategy is BEST described as:",
     "opts": ["Geographic dispersion", "Multi-cloud", "High availability clustering", "Platform diversity"],
     "ans": 1,
     "exp": "Multi-cloud deliberately distributes workloads across multiple different cloud providers to eliminate single-vendor dependency and reduce the impact of provider-specific outages."},

    {"d": 3,
     "text": "Which of the following is the PRIMARY difference between a hot site and a warm site in disaster recovery?",
     "opts": ["A hot site is located overseas; a warm site is domestic", "A hot site has fully replicated, up-to-date data and can failover immediately; a warm site has some infrastructure but requires data restoration", "A hot site is owned by the organisation; a warm site is leased from a third party", "A hot site supports only cloud workloads; a warm site supports only on-premises workloads"],
     "ans": 1,
     "exp": "A hot site has real-time data replication and can assume operations immediately. A warm site has infrastructure in place but requires data to be restored before it can fully operate."},

    {"d": 3,
     "text": "Which cloud deployment model is MOST appropriate for an organisation that needs to maintain sensitive data on-premises while using cloud resources for less sensitive workloads?",
     "opts": ["Public cloud", "Private cloud", "Hybrid cloud", "Community cloud"],
     "ans": 2,
     "exp": "A hybrid cloud combines on-premises (private) infrastructure with public cloud resources, allowing sensitive data to remain on-premises while leveraging cloud scalability for other workloads."},

    {"d": 3,
     "text": "A network engineer configures a switch so that any device connecting to a port must authenticate using 802.1X before the port is activated. Unauthenticated devices are placed in a restricted VLAN. This is BEST described as:",
     "opts": ["Network segmentation", "Network Access Control (NAC)", "Port security via MAC address filtering", "A honeynet configuration"],
     "ans": 1,
     "exp": "NAC enforces security policy on devices before granting network access. 802.1X-based NAC with a restricted VLAN for unauthenticated devices is a classic NAC implementation."},

    {"d": 3,
     "text": "Which of the following BEST describes the concept of Infrastructure as Code (IaC) from a security perspective?",
     "opts": ["It allows developers to write application code that runs directly on physical servers", "It enables infrastructure to be defined, version-controlled, and deployed consistently, reducing configuration drift and misconfigurations", "It replaces the need for firewalls by embedding security into application logic", "It is a method of encrypting infrastructure configuration files"],
     "ans": 1,
     "exp": "IaC defines infrastructure in code, enabling version control, automated testing, peer review, and consistent deployment — reducing the misconfigurations and drift that come from manual provisioning."},

    {"d": 3,
     "text": "An organisation's RTO is 2 hours. What does this mean?",
     "opts": ["Backups must occur every 2 hours to limit data loss", "Systems must be fully restored and operational within 2 hours of a disaster", "The organisation can tolerate losing 2 hours of data", "DR drills must be conducted every 2 hours"],
     "ans": 1,
     "exp": "Recovery Time Objective (RTO) defines the maximum acceptable time for restoring a system or service after a disruption. An RTO of 2 hours means systems must be operational within 2 hours."},

    {"d": 3,
     "text": "Which of the following BEST describes a microservices architecture from a security perspective?",
     "opts": ["It consolidates all application functions into a single deployable unit, simplifying security management", "It breaks an application into small, independently deployable services, increasing the attack surface but enabling granular security controls", "It eliminates the need for API security by running all services on the same server", "It is only suitable for on-premises deployments"],
     "ans": 1,
     "exp": "Microservices increase the attack surface due to more network communication between services, but allow granular security controls, independent patching, and blast radius reduction if one service is compromised."},

    {"d": 3,
     "text": "A security architect recommends that a critical industrial control system be placed on a network with no connection to any other network, including the internet. This is BEST described as:",
     "opts": ["Network segmentation", "VLAN isolation", "Air-gapping", "Software-defined perimeter"],
     "ans": 2,
     "exp": "Air-gapping physically isolates a system from all other networks, including the internet, providing the strongest possible isolation for critical systems that cannot risk remote access."},

    {"d": 3,
     "text": "Which backup type captures only the data that has changed since the LAST FULL backup, regardless of whether incremental backups have occurred since?",
     "opts": ["Incremental backup", "Differential backup", "Full backup", "Snapshot backup"],
     "ans": 1,
     "exp": "A differential backup captures all changes since the last full backup. Restoration requires only the last full backup and the last differential. An incremental backup captures only changes since the last backup of any type."},

    {"d": 3,
     "text": "An organisation wants to use a cloud service but is concerned about who is responsible for securing the operating system. Under which cloud model does the CUSTOMER retain responsibility for OS security?",
     "opts": ["SaaS", "PaaS", "IaaS", "All cloud models"],
     "ans": 2,
     "exp": "In IaaS, the customer is responsible for the OS, middleware, and applications. In PaaS, the provider manages the OS. In SaaS, the provider manages everything above the hardware."},

    {"d": 3,
     "text": "Which of the following is the BEST description of a load balancer's role in security architecture?",
     "opts": ["It encrypts all traffic between users and servers", "It distributes traffic across multiple servers, improving availability and enabling traffic inspection at a single point", "It replaces the need for a firewall by filtering malicious requests", "It assigns dynamic IP addresses to servers to obscure their locations"],
     "ans": 1,
     "exp": "A load balancer distributes incoming traffic across multiple servers, improving availability and resilience. It can also act as a single inspection point for traffic filtering and SSL termination."},

    {"d": 3,
     "text": "Which of the following BEST describes data sovereignty?",
     "opts": ["The right of individuals to control their own personal data", "The legal principle that data is subject to the laws of the country where it is stored", "The organisation's exclusive right to encrypt and protect its data", "The concept that data belongs to its creator regardless of where it is stored"],
     "ans": 1,
     "exp": "Data sovereignty means that data stored in a particular country is subject to that country's laws and regulations, which can affect how cloud providers store and process data across borders."},

    {"d": 3,
     "text": "A security engineer needs to provide remote administrative access to servers in a highly secured network zone. They configure a single, hardened server that all administrators must connect through first. This server is BEST described as a:",
     "opts": ["Proxy server", "Jump server (bastion host)", "VPN concentrator", "Reverse proxy"],
     "ans": 1,
     "exp": "A jump server (bastion host) is a hardened, audited intermediary that serves as the only gateway for administrative access to systems in a secure network zone."},

    {"d": 3,
     "text": "Which of the following BEST describes the shared responsibility model in cloud computing?",
     "opts": ["The cloud provider is responsible for all security, including customer data", "Security responsibilities are divided between the cloud provider and the customer, with the split depending on the service model (IaaS/PaaS/SaaS)", "The customer is responsible for all security once data enters the cloud", "Security is entirely the responsibility of third-party auditors"],
     "ans": 1,
     "exp": "The shared responsibility model divides security duties between provider and customer based on the service model. The provider always owns physical security; the customer's scope grows from SaaS (least) to IaaS (most)."},

    {"d": 3,
     "text": "Which network device inspects application-layer traffic and can block specific web application attacks such as SQL injection, even when traffic is encrypted via HTTPS?",
     "opts": ["Stateful firewall", "Web Application Firewall (WAF)", "IDS in promiscuous mode", "Next-generation firewall acting as a packet filter"],
     "ans": 1,
     "exp": "A WAF inspects HTTP/HTTPS application layer traffic and can terminate SSL/TLS to inspect content, blocking web application attacks that a standard firewall would pass through."},

    {"d": 3,
     "text": "An organisation implements redundant power supplies, multiple internet connections, and geographically dispersed data centres. These measures are BEST described as supporting which security goal?",
     "opts": ["Confidentiality", "Integrity", "Availability", "Non-repudiation"],
     "ans": 2,
     "exp": "Redundancy, multiple connections, and geographic dispersion are all architectural strategies that support availability — ensuring systems remain accessible even when components fail."},

    # ── DOMAIN 4 — Security Operations (25) ──────────────────────────────────
    {"d": 4,
     "text": "A security analyst discovers a process running on a server that is not in the approved software inventory and is making outbound connections. Which step of the incident response process should occur FIRST?",
     "opts": ["Eradication — terminate the process immediately", "Recovery — restore the server from backup", "Analysis — investigate the process to understand its nature and scope", "Lessons learned — document the incident for future reference"],
     "ans": 2,
     "exp": "Analysis should precede eradication. Understanding the nature, scope, and origin of the threat informs an effective containment and eradication strategy and prevents premature action that could destroy forensic evidence."},

    {"d": 4,
     "text": "Which access control model allows the data owner to determine who can access their resources, and they can grant or revoke access at their discretion?",
     "opts": ["Mandatory Access Control (MAC)", "Discretionary Access Control (DAC)", "Role-Based Access Control (RBAC)", "Rule-Based Access Control"],
     "ans": 1,
     "exp": "DAC gives the data owner discretion over who can access their resources. They can grant or revoke permissions to other users at will, unlike MAC where a central authority enforces classification-based controls."},

    {"d": 4,
     "text": "An organisation requires users to present a smart card AND enter a PIN to access a secure facility. This is an example of which authentication concept?",
     "opts": ["Single-factor authentication using two inputs", "Multifactor authentication combining something you have and something you know", "Biometric authentication", "Federated identity management"],
     "ans": 1,
     "exp": "A smart card (something you have) combined with a PIN (something you know) satisfies two different authentication factors — making this genuine multifactor authentication."},

    {"d": 4,
     "text": "Which of the following BEST describes the purpose of DMARC in email security?",
     "opts": ["It encrypts email content in transit using TLS", "It allows domain owners to specify how receiving servers should handle email that fails SPF or DKIM checks", "It scans email attachments for malware before delivery", "It digitally signs individual email messages using the sender's private key"],
     "ans": 1,
     "exp": "DMARC (Domain-based Message Authentication Reporting and Conformance) lets domain owners publish a policy instructing receiving servers to quarantine or reject email that fails SPF and DKIM authentication."},

    {"d": 4,
     "text": "An administrator notices that a user's account is generating authentication requests from IP addresses in different countries simultaneously. After investigation, the logins are confirmed as unauthorised. Which incident response action should be taken FIRST?",
     "opts": ["Disable the account immediately to stop unauthorised access", "Collect forensic evidence before taking any action", "Notify the user and ask them to change their password", "Run a vulnerability scan on the affected systems"],
     "ans": 0,
     "exp": "When unauthorised access is confirmed, the first priority is containment — disabling the account immediately to stop the ongoing breach, then collecting evidence and investigating the extent of compromise."},

    {"d": 4,
     "text": "Which of the following BEST describes the purpose of a Security Orchestration, Automation, and Response (SOAR) platform?",
     "opts": ["To replace human analysts in a SOC entirely", "To automate repetitive security tasks and coordinate responses across security tools when alerts are triggered", "To provide real-time threat intelligence from external sources", "To perform vulnerability scanning across the enterprise"],
     "ans": 1,
     "exp": "SOAR platforms automate repetitive analyst tasks (e.g. enrichment, triage, containment actions) and orchestrate responses across multiple security tools, improving response speed and freeing analysts for complex work."},

    {"d": 4,
     "text": "A user reports that their computer is running slowly and they see pop-up advertisements even when no browser is open. Which type of malware is MOST likely responsible?",
     "opts": ["Ransomware", "Rootkit", "Adware / spyware", "Logic bomb"],
     "ans": 2,
     "exp": "Adware and spyware are characterised by performance degradation, unsolicited advertisements, and background activity tracking user behaviour — consistent with the described symptoms."},

    {"d": 4,
     "text": "Which of the following BEST describes the difference between vulnerability scanning and penetration testing?",
     "opts": ["Vulnerability scanning identifies potential weaknesses; penetration testing actively exploits them to demonstrate real-world impact", "Vulnerability scanning is performed externally; penetration testing is performed internally", "Vulnerability scanning requires credentials; penetration testing never uses credentials", "Vulnerability scanning is a manual process; penetration testing is fully automated"],
     "ans": 0,
     "exp": "Vulnerability scanning identifies and catalogues potential weaknesses. Penetration testing goes further by actively exploiting vulnerabilities to demonstrate the real-world impact of successful attacks."},

    {"d": 4,
     "text": "An analyst reviews NetFlow data and notices an internal server transferring 40 GB to an external IP at 3 AM that is not associated with any scheduled backup or update. This MOST likely indicates:",
     "opts": ["A misconfigured backup job running at the wrong time", "Data exfiltration", "A DDoS attack originating from the internal server", "Normal cloud synchronisation activity"],
     "ans": 1,
     "exp": "Large, unscheduled outbound data transfers to external IPs during off-hours are a primary indicator of data exfiltration — a key concern for both insider threats and external attackers."},

    {"d": 4,
     "text": "Which of the following BEST describes the concept of ephemeral credentials in privileged access management?",
     "opts": ["Passwords that never expire", "Short-lived credentials generated for a specific session and automatically invalidated when the session ends", "Shared administrative credentials stored in a password vault", "Credentials that require biometric verification to retrieve"],
     "ans": 1,
     "exp": "Ephemeral credentials are short-lived, session-specific credentials that are automatically revoked when the session ends, eliminating standing privileges and reducing the risk of credential theft."},

    {"d": 4,
     "text": "A security engineer configures a rule in the SIEM to alert when any user account authenticates successfully from more than three distinct countries within a 24-hour period. This is an example of:",
     "opts": ["Alert tuning to reduce false positives", "Threat hunting", "User behaviour analytics (UBA) detection rule", "A blacklist-based detection approach"],
     "ans": 2,
     "exp": "Creating detection rules based on unusual patterns in user behaviour — such as logins from abnormal locations — is a user behaviour analytics (UBA) approach to threat detection."},

    {"d": 4,
     "text": "Which of the following BEST describes the purpose of sandboxing in application security?",
     "opts": ["Encrypting application code to prevent reverse engineering", "Executing potentially malicious code in an isolated environment to observe its behaviour without risk to production systems", "Restricting application network access using a host-based firewall", "Testing application performance under simulated high-load conditions"],
     "ans": 1,
     "exp": "Sandboxing runs potentially malicious code in an isolated, controlled environment, allowing analysts to observe its behaviour (file modifications, network connections, registry changes) without risking production systems."},

    {"d": 4,
     "text": "An organisation implements a policy requiring all privileged access to production systems to be approved by a second administrator before it is granted. This is an example of:",
     "opts": ["Least privilege", "Separation of duties", "Just-in-time access", "Mandatory access control"],
     "ans": 1,
     "exp": "Separation of duties requires that sensitive actions (like granting privileged access to production) require approval from a second person, preventing any single individual from having unchecked control."},

    {"d": 4,
     "text": "Which log source would be MOST useful for investigating whether a user exfiltrated data via a USB drive?",
     "opts": ["Firewall logs", "DNS logs", "Endpoint / OS security logs", "NetFlow data"],
     "ans": 2,
     "exp": "Endpoint and OS security logs record events such as USB device insertions, file copies to removable media, and drive mount/unmount events — making them the most relevant source for USB exfiltration investigations."},

    {"d": 4,
     "text": "A forensic investigator creates a bit-for-bit copy of a hard drive and verifies it using a cryptographic hash before beginning their analysis. The PRIMARY reason for hashing is to:",
     "opts": ["Encrypt the forensic image to prevent unauthorised access", "Prove that the forensic copy is identical to the original and has not been altered", "Compress the forensic image to reduce storage requirements", "Identify malware signatures within the forensic image"],
     "ans": 1,
     "exp": "Hashing a forensic image and comparing it to the original proves integrity — that the copy is bit-for-bit identical and has not been altered — which is essential for evidence admissibility."},

    {"d": 4,
     "text": "Which of the following wireless security settings provides the STRONGEST protection for a corporate wireless network?",
     "opts": ["WEP with a complex passphrase", "WPA2-Personal with AES encryption", "WPA3-Enterprise with 802.1X authentication", "WPA2-Personal with TKIP encryption"],
     "ans": 2,
     "exp": "WPA3-Enterprise with 802.1X provides individual user authentication via RADIUS, eliminating shared passphrases, and uses stronger encryption than WPA2, making it the strongest option for corporate networks."},

    {"d": 4,
     "text": "A SOC analyst receives an alert that a critical server's firewall has been disabled. Before investigating further, they re-enable the firewall. This action is BEST described as:",
     "opts": ["Eradication", "Containment", "Evidence preservation", "Lessons learned"],
     "ans": 1,
     "exp": "Re-enabling the firewall to stop ongoing exposure while the incident is investigated is a containment action — limiting the immediate risk while analysis and eradication are planned."},

    {"d": 4,
     "text": "An organisation uses a tool that continuously monitors all endpoints for suspicious behaviour, records telemetry, and can automatically isolate a compromised endpoint from the network. This tool is BEST described as:",
     "opts": ["Antivirus software", "Host-based IDS (HIDS)", "Endpoint Detection and Response (EDR)", "Data Loss Prevention (DLP)"],
     "ans": 2,
     "exp": "EDR continuously monitors endpoint behaviour, records rich telemetry for investigation, and can perform automated or guided response actions such as network isolation — going far beyond traditional antivirus."},

    {"d": 4,
     "text": "Which of the following BEST describes the concept of password vaulting in privileged access management?",
     "opts": ["Storing all user passwords in a spreadsheet accessible to IT administrators", "Centralised, encrypted storage of privileged credentials with automated rotation and access logging", "Requiring users to memorise complex passwords without writing them down", "Hashing all stored passwords using a strong algorithm"],
     "ans": 1,
     "exp": "Password vaulting stores privileged credentials in an encrypted, access-controlled repository with audit logging and automated rotation, ensuring credentials are never directly exposed to administrators."},

    {"d": 4,
     "text": "A threat hunter proactively searches through network logs and endpoint telemetry looking for indicators of compromise that automated tools have not flagged. This activity is BEST described as:",
     "opts": ["Incident response", "Vulnerability management", "Threat hunting", "Penetration testing"],
     "ans": 2,
     "exp": "Threat hunting is a proactive, hypothesis-driven search through security data to find threats that evade automated detection — distinguishing it from reactive incident response which begins after an alert."},

    {"d": 4,
     "text": "Which of the following BEST describes the purpose of a playbook in incident response?",
     "opts": ["A legal document defining the organisation's liability in a security incident", "A predefined, step-by-step procedure for responding to a specific type of security incident", "A log of all previous security incidents for compliance reporting", "A training manual for new SOC analysts"],
     "ans": 1,
     "exp": "An IR playbook documents specific, repeatable steps for responding to a defined incident type (e.g. ransomware, phishing), ensuring consistent, effective response even under pressure."},

    # ── DOMAIN 5 — Security Program Management (18) ──────────────────────────
    {"d": 5,
     "text": "An organisation's security team conducts a workshop where they walk through a simulated cyberattack scenario using a whiteboard and discussion, without actually activating DR systems. This exercise is BEST described as:",
     "opts": ["Parallel processing test", "Full interruption test", "Tabletop exercise", "Simulation test"],
     "ans": 2,
     "exp": "A tabletop exercise involves key stakeholders discussing their response to a hypothetical scenario in a low-pressure, discussion-based format without activating actual systems or disrupting operations."},

    {"d": 5,
     "text": "A company calculates that a specific server has a 30% chance of being hit by ransomware in any given year and the cost of a successful attack would be $200,000. What is the ALE?",
     "opts": ["$200,000", "$60,000", "$140,000", "$600,000"],
     "ans": 1,
     "exp": "ALE = SLE × ARO = $200,000 × 0.30 = $60,000. The ARO of 0.30 represents a 30% annual probability of occurrence."},

    {"d": 5,
     "text": "An organisation decides to stop offering a particular high-risk online service entirely rather than invest in securing it. This risk management strategy is BEST described as:",
     "opts": ["Risk acceptance", "Risk mitigation", "Risk avoidance", "Risk transference"],
     "ans": 2,
     "exp": "Risk avoidance eliminates the risk entirely by ceasing the activity that creates it. Unlike mitigation (reducing risk) or acceptance (tolerating risk), avoidance removes the risk source completely."},

    {"d": 5,
     "text": "Which type of audit is conducted by the organisation's own staff rather than an external party?",
     "opts": ["Regulatory audit", "Third-party audit", "Internal audit", "Compliance examination"],
     "ans": 2,
     "exp": "An internal audit is performed by the organisation's own audit function. External audits are performed by independent third parties, often for regulatory compliance or certification purposes."},

    {"d": 5,
     "text": "Under GDPR, an organisation that determines the purposes and means of processing personal data is defined as the:",
     "opts": ["Data processor", "Data subject", "Data controller", "Data custodian"],
     "ans": 2,
     "exp": "The data controller determines why and how personal data is processed. The data processor processes data on the controller's behalf. The data subject is the individual whose data is processed."},

    {"d": 5,
     "text": "An organisation requires all new software vendors to complete a security questionnaire and provide evidence of their most recent penetration test results before being approved. This process is BEST described as:",
     "opts": ["Supply chain risk management", "Vendor due diligence", "Third-party risk assessment", "All of the above are accurate descriptions"],
     "ans": 3,
     "exp": "Requiring vendors to complete security questionnaires and provide assurance evidence is simultaneously supply chain risk management, vendor due diligence, and third-party risk assessment — all three terms accurately describe this practice."},

    {"d": 5,
     "text": "Which of the following BEST describes the difference between a policy and a standard in security governance?",
     "opts": ["A policy is technical; a standard is managerial", "A policy states what must be done at a high level; a standard defines the specific, measurable requirements that implement the policy", "A policy applies to all staff; a standard applies only to IT staff", "A policy is optional; a standard is mandatory"],
     "ans": 1,
     "exp": "A policy provides high-level, principle-based direction (e.g. 'data must be encrypted'). A standard provides specific, measurable implementation requirements (e.g. 'AES-256 must be used for data at rest')."},

    {"d": 5,
     "text": "An organisation experiences a ransomware attack that encrypts its primary database. The organisation restores from a backup that is 6 hours old, losing 6 hours of transactions. The 6-hour data loss represents which metric being exceeded?",
     "opts": ["Recovery Time Objective (RTO)", "Recovery Point Objective (RPO)", "Mean Time to Repair (MTTR)", "Mean Time Between Failures (MTBF)"],
     "ans": 1,
     "exp": "RPO defines the maximum acceptable data loss. Losing 6 hours of data means the RPO was exceeded — the backup frequency was insufficient to meet the RPO target."},

    {"d": 5,
     "text": "A company signs an agreement with a cloud provider that specifies the provider will maintain 99.9% uptime and will pay financial penalties if this threshold is not met. This agreement is BEST described as a:",
     "opts": ["Memorandum of Understanding (MOU)", "Non-Disclosure Agreement (NDA)", "Service-Level Agreement (SLA)", "Business Partners Agreement (BPA)"],
     "ans": 2,
     "exp": "An SLA is a formal contract defining measurable service standards (such as uptime) and the remedies (such as financial penalties) that apply if those standards are not met."},

    {"d": 5,
     "text": "Which of the following BEST describes the concept of privacy by design?",
     "opts": ["Implementing privacy controls retroactively after a system is built", "Building privacy protections into systems and processes from the initial design stage, rather than adding them later", "Allowing users to opt in to data collection rather than opt out", "Encrypting all personal data stored in databases"],
     "ans": 1,
     "exp": "Privacy by design is a principle that embeds privacy protections into the design of systems, processes, and products from the outset, rather than treating privacy as an afterthought."},

    {"d": 5,
     "text": "An organisation's risk register shows a risk rated as 'high likelihood, high impact'. The security team proposes implementing additional controls to reduce both the likelihood and impact. This approach is BEST described as:",
     "opts": ["Risk acceptance", "Risk avoidance", "Risk transference", "Risk mitigation"],
     "ans": 3,
     "exp": "Risk mitigation involves implementing controls to reduce the likelihood of a risk occurring, its potential impact, or both — directly addressing the risk rather than avoiding, accepting, or transferring it."},

    {"d": 5,
     "text": "Which of the following BEST describes the purpose of a Business Continuity Plan (BCP)?",
     "opts": ["To define how the organisation will recover IT systems after a cyberattack", "To ensure the organisation can continue critical business functions during and after a disruptive event", "To document the organisation's incident response procedures", "To specify how data backups will be performed and tested"],
     "ans": 1,
     "exp": "A BCP ensures the organisation can maintain critical business functions during any disruptive event (not just IT incidents). It is broader than a Disaster Recovery Plan, which focuses specifically on IT system recovery."},

    {"d": 5,
     "text": "An organisation's legal team advises that data related to an ongoing investigation must not be deleted or modified. The security team issues a directive to preserve all relevant logs and records. This directive is BEST described as:",
     "opts": ["Chain of custody", "E-discovery", "Legal hold", "Data retention policy enforcement"],
     "ans": 2,
     "exp": "A legal hold (litigation hold) is a directive to preserve data that may be relevant to legal proceedings, overriding normal retention schedules to prevent spoliation of evidence."},

    {"d": 5,
     "text": "Which of the following frameworks provides a common language for describing and categorising adversary tactics, techniques, and procedures (TTPs)?",
     "opts": ["NIST CSF", "ISO 27001", "MITRE ATT&CK", "CIS Controls"],
     "ans": 2,
     "exp": "MITRE ATT&CK is a globally-accessible knowledge base of adversary TTPs based on real-world observations, providing a common taxonomy for threat intelligence, detection, and response activities."},

    {"d": 5,
     "text": "A security manager reviews the organisation's data classification policy and finds that customer payment card data has been classified as 'Internal Use Only' rather than 'Confidential'. This finding MOST directly affects which compliance obligation?",
     "opts": ["GDPR right to be forgotten requirements", "PCI DSS requirements for protecting cardholder data", "SOX financial reporting controls", "HIPAA protected health information safeguards"],
     "ans": 1,
     "exp": "PCI DSS requires that cardholder data be appropriately classified and protected with specific controls. Misclassifying it as 'Internal Use Only' could result in insufficient protection and PCI DSS non-compliance."},

    {"d": 5,
     "text": "Which of the following BEST describes the difference between qualitative and quantitative risk analysis?",
     "opts": ["Qualitative analysis uses numerical values and financial figures; quantitative analysis uses subjective ratings", "Qualitative analysis uses descriptive ratings (high/medium/low); quantitative analysis uses numerical values and financial calculations", "Qualitative analysis is more accurate; quantitative analysis is used only when data is unavailable", "Qualitative analysis is used for IT risks; quantitative analysis is used for physical risks"],
     "ans": 1,
     "exp": "Qualitative analysis rates risks using descriptive categories (e.g. high/medium/low likelihood and impact). Quantitative analysis assigns specific numerical values and financial figures (SLE, ALE, ARO) to calculate monetary risk exposure."},

    {"d": 5,
     "text": "An organisation's penetration testing team uses OSINT to gather information about the target without interacting with its systems. This phase is BEST described as:",
     "opts": ["Active reconnaissance", "Passive reconnaissance", "Vulnerability scanning", "Exploitation"],
     "ans": 1,
     "exp": "Passive reconnaissance gathers information about a target using publicly available sources (OSINT) without directly interacting with or probing the target's systems, avoiding detection."},
]


# ── Helper ────────────────────────────────────────────────────────────────────

def _strip_answers(questions: list) -> list:
    """Remove ans and exp fields before sending to client."""
    return [
        {k: v for k, v in q.items() if k not in ("ans", "exp")}
        for q in questions
    ]


# ══════════════════════════════════════════════════════════════════════════════
#  Routes — May 2026 pivot: PUBLIC to attempt, login required to save results
# ══════════════════════════════════════════════════════════════════════════════

@practice_exam_bp.route("/")
def index():
    """
    Practice exam landing page — PUBLIC.
    Anyone can land here and start the exam. The template should check
    `current_user.is_authenticated` to decide whether to show "Sign in to save
    your results" prompts.
    """
    return render_template(
        "practice_exam.html",
        domain_meta=DOMAIN_META,
        total_questions=len(QUESTIONS_SET1),
    )


@practice_exam_bp.route("/questions")
def get_questions_set1():
    """JSON endpoint — Practice Exam Set 1 (90 questions), answers stripped. PUBLIC."""
    return jsonify({
        "questions":     _strip_answers(QUESTIONS_SET1),
        "domain_meta":   DOMAIN_META,
        "total":         len(QUESTIONS_SET1),
        "pass_pct":      75,
        "duration_secs": 5400,
        "set":           1,
    })


@practice_exam_bp.route("/questions/set2")
def get_questions_set2():
    """JSON endpoint — Practice Exam Set 2 (90 questions), answers stripped. PUBLIC."""
    return jsonify({
        "questions":     _strip_answers(QUESTIONS_SET2),
        "domain_meta":   DOMAIN_META,
        "total":         len(QUESTIONS_SET2),
        "pass_pct":      75,
        "duration_secs": 5400,
        "set":           2,
    })


@practice_exam_bp.route("/grade", methods=["POST"])
def grade_attempt():
    """
    PUBLIC grading endpoint. Returns the score WITHOUT saving to DB.
    Anonymous users hit this — they see their score but cannot save history.

    POST body: { "answers": {"0": 2, "1": 1, ...}, "elapsed_seconds": 3720, "set": 1 }
    Returns: { correct, total, score_pct, passed, set, saved: false, login_required: true|false }
    """
    data     = request.get_json(silent=True) or {}
    answers  = data.get("answers", {})
    exam_set = int(data.get("set", 1))

    questions = QUESTIONS_SET1 if exam_set == 1 else QUESTIONS_SET2

    correct = sum(
        1 for i, q in enumerate(questions)
        if answers.get(str(i)) == q["ans"]
    )
    score_pct = round((correct / len(questions)) * 100)
    passed    = score_pct >= 75

    return jsonify({
        "correct":        correct,
        "total":          len(questions),
        "score_pct":      score_pct,
        "passed":         passed,
        "set":            exam_set,
        "saved":          False,
        "login_required": not current_user.is_authenticated,
    })


@practice_exam_bp.route("/submit", methods=["POST"])
@login_required
def submit_attempt():
    """
    LOGGED-IN-ONLY endpoint. Grades the attempt AND saves it to ExamAttempt.

    POST body: { "answers": {"0": 2, "1": 1, ...}, "elapsed_seconds": 3720, "set": 1 }
    Returns: { correct, total, score_pct, passed, set, saved: true, attempt_id }
    """
    data     = request.get_json(silent=True) or {}
    answers  = data.get("answers", {})
    elapsed  = int(data.get("elapsed_seconds", 0))
    exam_set = int(data.get("set", 1))

    questions = QUESTIONS_SET1 if exam_set == 1 else QUESTIONS_SET2

    correct = sum(
        1 for i, q in enumerate(questions)
        if answers.get(str(i)) == q["ans"]
    )
    score_pct = round((correct / len(questions)) * 100)
    passed    = score_pct >= 75

    # Save to user history
    attempt = ExamAttempt(
        user_id=current_user.id,
        exam_set=f"security_plus_set{exam_set}",
        score_pct=score_pct,
        correct=correct,
        total=len(questions),
        passed=passed,
        elapsed_secs=elapsed,
        completed_at=datetime.utcnow(),
    )
    db.session.add(attempt)
    db.session.commit()

    return jsonify({
        "correct":    correct,
        "total":      len(questions),
        "score_pct":  score_pct,
        "passed":     passed,
        "set":        exam_set,
        "saved":      True,
        "attempt_id": attempt.id,
    })


@practice_exam_bp.route("/review", methods=["POST"])
def review_attempt():
    """
    PUBLIC review endpoint — returns each question with the correct answer
    and explanation, plus the user's submitted answer marked correct/wrong.

    Called by the frontend AFTER /grade or /submit, only on the results screen,
    so live exam-takers never see answers. We intentionally do not log or
    save anything from this endpoint — it's read-only.

    POST body: { "answers": {"0": 2, "1": 1, ...}, "set": 1 }
    Returns: {
      "set": 1,
      "items": [
        {
          "idx": 0,
          "domain": 1,
          "domain_name": "General Security Concepts",
          "text": "...",
          "opts": ["...", "...", "...", "..."],
          "correct_idx": 1,
          "chosen_idx": 2,           // null if unanswered
          "is_correct": false,
          "explanation": "..."
        },
        ...
      ]
    }
    """
    data     = request.get_json(silent=True) or {}
    answers  = data.get("answers", {})
    exam_set = int(data.get("set", 1))

    questions = QUESTIONS_SET1 if exam_set == 1 else QUESTIONS_SET2

    items = []
    for i, q in enumerate(questions):
        chosen_raw = answers.get(str(i))
        try:
            chosen = int(chosen_raw) if chosen_raw is not None else None
        except (TypeError, ValueError):
            chosen = None

        domain_id = q.get("d")
        items.append({
            "idx":          i,
            "domain":       domain_id,
            "domain_name":  DOMAIN_META.get(domain_id, {}).get("name", ""),
            "text":         q["text"],
            "opts":         q["opts"],
            "correct_idx":  q["ans"],
            "chosen_idx":   chosen,
            "is_correct":   (chosen == q["ans"]),
            "explanation":  q.get("exp", ""),
        })

    return jsonify({
        "set":   exam_set,
        "total": len(questions),
        "items": items,
    })


@practice_exam_bp.route("/history")
@login_required
def history():
    """
    LOGGED-IN-ONLY: view your past exam attempts.
    """
    attempts = (
        ExamAttempt.query
        .filter_by(user_id=current_user.id)
        .order_by(ExamAttempt.completed_at.desc())
        .limit(50)
        .all()
    )
    return render_template("practice_exam_history.html", attempts=attempts)