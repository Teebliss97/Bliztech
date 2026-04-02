from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, current_user
from datetime import datetime

from app.extensions import db
from app.models import CourseAccess, LessonRead, QuizAttempt

quiz_bp = Blueprint("quiz", __name__, url_prefix="/course/quiz")

TOTAL_LESSONS = 20
PASS_THRESHOLD = 0.70  # 70%

# ─────────────────────────────────────────────
#  90 questions — answers distributed evenly across A(0), B(1), C(2), D(3)
#  Target: ~22-23 per option
# ─────────────────────────────────────────────
QUESTIONS = [
    # ── Section A: Foundation ──

    # A=0
    {
        "q": "Which of the following best defines cybersecurity?",
        "options": [
            "The practice of protecting systems, networks, and data from attack or damage",
            "The process of writing secure software code",
            "The management of hardware infrastructure",
            "The deployment of antivirus software across an organisation"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "In the CIA Triad, what does 'Integrity' mean?",
        "options": [
            "Systems are always available to users",
            "Data is accurate and has not been tampered with",
            "Only authorised users can access data",
            "All data is encrypted at rest"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What does 'Availability' mean in the CIA Triad?",
        "options": [
            "Data is encrypted when stored",
            "Only admins can access systems",
            "Systems and data are accessible when needed by authorised users",
            "Passwords are rotated every 90 days"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "Which formula correctly represents risk?",
        "options": [
            "Risk = Threat + Vulnerability",
            "Risk = Impact / Threat",
            "Risk = Vulnerability - Control",
            "Risk = Threat x Vulnerability x Impact"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is a threat actor?",
        "options": [
            "A person or group who may cause harm to a system",
            "A software vulnerability that can be exploited",
            "A firewall rule that blocks traffic",
            "A type of encryption algorithm"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is the first stage of the Cyber Kill Chain?",
        "options": [
            "Exploitation",
            "Reconnaissance",
            "Weaponisation",
            "Command and Control"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "At which Kill Chain stage does the attacker establish remote access?",
        "options": [
            "Weaponise",
            "Install",
            "Command and Control",
            "Objectives"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What does 'defence in depth' mean?",
        "options": [
            "Using one very powerful firewall",
            "Encrypting all data at rest and in transit",
            "Hiring more security staff to monitor systems",
            "Using multiple independent layers of security controls"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "Which layer sits at the innermost layer of defence in depth?",
        "options": [
            "Data",
            "Network",
            "Application",
            "Perimeter"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What stopped the WannaCry ransomware from spreading further?",
        "options": [
            "A government takedown operation",
            "A kill switch domain registered by a researcher",
            "An antivirus update from Microsoft",
            "A firewall rule deployed across NHS systems"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "Which type of attacker is primarily motivated by financial gain?",
        "options": [
            "Hacktivist",
            "Nation-state actor",
            "Cybercriminal",
            "Script kiddie"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is 'security through obscurity'?",
        "options": [
            "Encrypting data to hide its contents",
            "Using a VPN to mask network traffic",
            "Restricting access based on job role",
            "Relying on keeping system design secret to provide security"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is a vulnerability in cybersecurity?",
        "options": [
            "A weakness that can be exploited by a threat actor",
            "A type of encryption standard",
            "A network monitoring protocol",
            "A category of firewall rule"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "Which misconception suggests small organisations don't need cybersecurity?",
        "options": [
            "Cybersecurity is only an IT problem",
            "We are too small to be a target",
            "Antivirus is enough protection",
            "Security through obscurity is sufficient"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is the primary goal of a SOC analyst?",
        "options": [
            "Write and review security policies",
            "Perform penetration tests on internal systems",
            "Monitor systems and respond to security alerts",
            "Configure and manage network hardware"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What does GRC stand for in cybersecurity?",
        "options": [
            "General Risk Control",
            "Global Response Centre",
            "Group Risk Calculation",
            "Governance, Risk and Compliance"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "Which role focuses on finding and exploiting weaknesses in systems?",
        "options": [
            "Penetration Tester",
            "GRC Analyst",
            "SOC Analyst",
            "Cloud Security Engineer"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is the WannaCry attack best known for?",
        "options": [
            "Stealing millions of credit card numbers from retailers",
            "Encrypting NHS systems via an unpatched Windows vulnerability",
            "Defacing thousands of government websites",
            "Taking down major social media platforms"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "If a threat actor has zero capability to exploit a vulnerability, what is the resulting risk?",
        "options": [
            "High — the vulnerability still needs patching",
            "Medium — it depends on the impact",
            "Zero — all three factors must be non-zero for risk to exist",
            "Low — but it should still be monitored"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "Which of the following is an example of a physical security control?",
        "options": [
            "A firewall blocking external traffic",
            "Encrypting data on a laptop",
            "A strong password policy",
            "A locked server room door"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What does 'Confidentiality' mean in the CIA Triad?",
        "options": [
            "Only authorised people can access data",
            "Data cannot be modified without detection",
            "Systems remain online during an attack",
            "Passwords are encrypted before storage"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "Which Kill Chain stage involves transmitting the weapon to the target?",
        "options": [
            "Reconnaissance",
            "Deliver",
            "Exploit",
            "Install"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is the purpose of the 'Objectives' stage in the Kill Chain?",
        "options": [
            "To establish persistence on the compromised system",
            "To deliver malware to the target",
            "To achieve the attacker's final goals such as data theft or disruption",
            "To set up command and control infrastructure"
        ],
        "answer": 2
    },

    # ── Section B: Technical Core ──

    # D=3
    {
        "q": "What does DNS stand for?",
        "options": [
            "Data Network Security",
            "Digital Network Service",
            "Direct Node Server",
            "Domain Name System"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is the primary purpose of a firewall?",
        "options": [
            "To filter network traffic based on defined rules",
            "To encrypt data as it crosses the network",
            "To scan files for malware signatures",
            "To assign IP addresses to devices"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What are the three steps of the TCP handshake in the correct order?",
        "options": [
            "ACK, SYN, SYN-ACK",
            "SYN, SYN-ACK, ACK",
            "SYN-ACK, SYN, ACK",
            "CONNECT, AUTH, OPEN"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is a Man-in-the-Middle attack?",
        "options": [
            "An attacker who physically enters a secure building",
            "A brute force attack against a login form",
            "An attacker who intercepts and potentially modifies traffic between two parties",
            "An attack that floods a server with requests"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is the purpose of a DMZ in network architecture?",
        "options": [
            "To store encrypted backups of critical data",
            "To host internal HR and finance systems",
            "To encrypt traffic between branch offices",
            "To isolate public-facing services from the internal network"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What does HTTPS provide that HTTP does not?",
        "options": [
            "Encrypted communication using TLS",
            "Faster page load times",
            "Larger file transfer limits",
            "Better DNS resolution"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is DNS cache poisoning?",
        "options": [
            "Filling a DNS server's memory with excessive requests",
            "Inserting false DNS records to redirect users to attacker-controlled servers",
            "Blocking all DNS queries at the firewall",
            "Changing a domain's MX record without authorisation"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is network segmentation?",
        "options": [
            "Encrypting all traffic between network zones",
            "Assigning static IP addresses to all devices",
            "Dividing a network into isolated zones to limit the spread of attacks",
            "Installing IDS sensors at the network perimeter"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "Which protocol is used to establish a reliable connection before data transmission?",
        "options": [
            "UDP",
            "HTTP",
            "ICMP",
            "TCP"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "Which authentication factor is a fingerprint scan?",
        "options": [
            "Something you are",
            "Something you know",
            "Something you have",
            "Something you share"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "Why is MFA more secure than a password alone?",
        "options": [
            "MFA encrypts the password before transmission",
            "Even if a password is stolen, an attacker still needs a second factor",
            "MFA replaces the need for a username",
            "MFA prevents all forms of phishing"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is a SYN flood attack?",
        "options": [
            "Encrypting a target system's files for ransom",
            "Redirecting DNS queries to malicious servers",
            "Sending millions of SYN packets without completing the handshake to exhaust server resources",
            "Stealing session cookies via a man-in-the-middle attack"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "Which type of MFA is considered phishing-proof?",
        "options": [
            "SMS one-time codes",
            "Email verification codes",
            "Time-based authenticator apps",
            "Hardware security keys"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What does 'least privilege' mean in access control?",
        "options": [
            "Users are given only the minimum access they need to do their job",
            "All users have the same level of access",
            "Admins have unrestricted access to all systems",
            "Passwords must be changed every 30 days"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is a VPN primarily used for?",
        "options": [
            "Speeding up internet connections",
            "Encrypting traffic between a device and a remote network",
            "Blocking advertisements on websites",
            "Scanning devices for malware"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is the OSI model used for?",
        "options": [
            "Classifying types of malware",
            "Managing firewall rule sets",
            "Describing how data moves through network layers",
            "Encrypting data during transmission"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "Which authentication factor is a hardware key like a YubiKey?",
        "options": [
            "Something you are",
            "Something you know",
            "Something you do",
            "Something you have"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is port scanning used for in cybersecurity?",
        "options": [
            "Discovering open ports and running services on a system",
            "Encrypting data before it leaves the network",
            "Backing up configuration files",
            "Monitoring user activity on endpoints"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "Which defence helps protect against Man-in-the-Middle attacks?",
        "options": [
            "Using HTTP instead of HTTPS",
            "TLS with proper certificate validation",
            "Disabling HTTPS on internal networks",
            "Opening all firewall ports for transparency"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is an IDS?",
        "options": [
            "A tool that blocks all inbound network traffic",
            "A type of hardware firewall",
            "A system that detects and alerts on suspicious network activity",
            "An encryption protocol for VPN connections"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What does DNS do in a network?",
        "options": [
            "Encrypts web traffic between client and server",
            "Assigns MAC addresses to network devices",
            "Routes packets between different networks",
            "Translates domain names into IP addresses"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is HSTS used for?",
        "options": [
            "Forcing browsers to only connect to a site over HTTPS",
            "Hashing passwords before storage",
            "Scanning HTTP traffic for malware",
            "Terminating TLS connections at the load balancer"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "Which step comes after SYN in the TCP three-way handshake?",
        "options": [
            "ACK",
            "SYN-ACK",
            "DATA",
            "CONNECT"
        ],
        "answer": 1
    },

    # ── Section C: Defence & Response ──

    # C=2
    {
        "q": "What is phishing?",
        "options": [
            "A technique used to speed up network connections",
            "A type of firewall bypass technique",
            "A social engineering attack using deceptive emails to steal credentials or install malware",
            "A method of encrypting email communications"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is ransomware?",
        "options": [
            "Software that monitors network traffic for threats",
            "A type of phishing email targeting executives",
            "A tool used by penetration testers to find vulnerabilities",
            "Malware that encrypts files and demands payment for the decryption key"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is the best defence against ransomware data loss?",
        "options": [
            "Offline backups that cannot be encrypted by the ransomware",
            "Paying the ransom promptly to minimise downtime",
            "Installing antivirus software on all endpoints",
            "Using stronger passwords on all accounts"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is double extortion in ransomware attacks?",
        "options": [
            "Attacking two separate victims simultaneously",
            "Encrypting files and also threatening to publish stolen data unless paid",
            "Demanding payment in two different cryptocurrencies",
            "Running two ransomware variants at the same time"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What does EDR stand for?",
        "options": [
            "Encryption Data Recovery",
            "Event Detection and Reporting",
            "Endpoint Detection and Response",
            "External Defence Ring"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is a SIEM used for?",
        "options": [
            "Encrypting data at rest across the organisation",
            "Managing and rotating user passwords",
            "Scanning endpoints for malware signatures",
            "Aggregating and analysing security logs from across an organisation"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is the first phase of the incident response lifecycle?",
        "options": [
            "Preparation",
            "Detection",
            "Containment",
            "Recovery"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "Under GDPR, how many hours do organisations have to report a personal data breach?",
        "options": [
            "24 hours",
            "72 hours",
            "48 hours",
            "7 days"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is a zero-day vulnerability?",
        "options": [
            "A vulnerability that causes zero damage",
            "A vulnerability in systems with zero users",
            "A vulnerability for which no patch is yet available",
            "A vulnerability discovered on the first day of the month"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is social engineering?",
        "options": [
            "Building secure social media platforms",
            "Designing login forms to prevent credential stuffing",
            "Writing security policies for human resources",
            "Manipulating people into revealing confidential information or taking harmful actions"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is a DDoS attack?",
        "options": [
            "Overwhelming a service with traffic from multiple sources to make it unavailable",
            "Stealing data from a database using SQL injection",
            "Installing malware on a web server",
            "Intercepting encrypted traffic between two parties"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What does patching a system do?",
        "options": [
            "Increases the CPU speed of the server",
            "Fixes known vulnerabilities in software to prevent exploitation",
            "Encrypts user data before it is stored",
            "Monitors network traffic for suspicious activity"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is spear phishing?",
        "options": [
            "A mass phishing campaign sent to millions of users",
            "A phishing attack conducted using SMS messages",
            "A targeted phishing attack aimed at a specific individual or organisation",
            "A phishing attack that uses phone calls instead of email"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is the purpose of the containment phase in incident response?",
        "options": [
            "To restore affected systems from clean backups",
            "To identify the root cause of the incident",
            "To notify affected users and regulators",
            "To stop the attack from spreading further across the organisation"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What Windows Event ID corresponds to a successful logon?",
        "options": [
            "4624",
            "4625",
            "4648",
            "4720"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What does Windows Event ID 4625 indicate?",
        "options": [
            "A new user account was created",
            "A failed logon attempt",
            "A service was installed on the system",
            "A scheduled task was created"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is a honeypot in cybersecurity?",
        "options": [
            "A secure encrypted password vault",
            "A type of next-generation firewall",
            "A decoy system designed to attract and detect attackers",
            "A backup system used during disaster recovery"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is a rootkit?",
        "options": [
            "A tool used by administrators to manage server root access",
            "A type of application layer firewall",
            "A password manager for privileged accounts",
            "Malware that hides its presence and provides persistent privileged access"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What does SPF stand for in email security?",
        "options": [
            "Sender Policy Framework",
            "Secure Packet Filter",
            "System Protection Firewall",
            "Security Protocol Foundation"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is the purpose of the 'Learn' phase in incident response?",
        "options": [
            "To restore systems from verified clean backups",
            "To review what happened and improve defences to prevent recurrence",
            "To isolate affected systems from the network",
            "To notify law enforcement about the incident"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is digital forensics used for?",
        "options": [
            "Preventing all future cyberattacks",
            "Encrypting evidence before it is stored",
            "Collecting and analysing evidence after a security incident",
            "Scanning systems for malware in real time"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "Which of the following makes a phishing email convincing?",
        "options": [
            "Poor spelling and obvious grammatical errors",
            "A very long and complicated email address",
            "An attachment with an unusual file extension",
            "A spoofed sender address combined with an urgent or threatening message"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is the purpose of DMARC in email security?",
        "options": [
            "To tell receiving mail servers what to do with emails that fail SPF or DKIM checks",
            "To encrypt the body of all outbound emails",
            "To scan attachments for malware before delivery",
            "To manage mailing list subscriptions"
        ],
        "answer": 0
    },

    # ── Section D: Career Launchpad ──

    # B=1
    {
        "q": "What is cloud computing?",
        "options": [
            "Storing all data on local on-premises servers only",
            "Renting computing resources from providers like AWS, Azure, or GCP over the internet",
            "Using only physical hardware owned by the organisation",
            "Backing up data to encrypted USB drives"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is the shared responsibility model in cloud security?",
        "options": [
            "The cloud provider is solely responsible for all security",
            "The customer is solely responsible for all security",
            "Security responsibilities are split between the provider and customer depending on the service model",
            "All cloud security is regulated and enforced by government bodies"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "In an IaaS model, who is responsible for securing the operating system?",
        "options": [
            "The cloud provider manages all OS security",
            "A third-party security auditor",
            "The internet service provider",
            "The customer is responsible for OS and above"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is the most common cause of cloud data breaches?",
        "options": [
            "Misconfigured storage buckets and overly permissive IAM roles",
            "Advanced nation-state hacking tools",
            "Weak encryption algorithms used by cloud providers",
            "Physical theft of cloud provider hardware"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What does IAM stand for in cloud security?",
        "options": [
            "Internet Access Management",
            "Identity and Access Management",
            "Integrated Audit Module",
            "Incident and Alert Management"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What right does GDPR give individuals regarding their personal data?",
        "options": [
            "The right to unlimited cloud storage",
            "The right to sell their data to third parties",
            "The right to be forgotten — to request deletion of their personal data",
            "The right to access all data held by any company"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is data minimisation under GDPR?",
        "options": [
            "Encrypting all personal data before storage",
            "Deleting all personal data after 30 days",
            "Storing personal data only within the EU",
            "Collecting only the personal data that is necessary for the stated purpose"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is a penetration test?",
        "options": [
            "An authorised simulated attack to find vulnerabilities before real attackers do",
            "A test of physical security controls only",
            "A malware scan run on production systems",
            "A firewall configuration review by a third party"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is the difference between black box and white box penetration testing?",
        "options": [
            "Black box uses automated tools; white box is manual only",
            "In black box testing the tester has no prior knowledge; in white box they have full system knowledge",
            "Black box tests external systems; white box tests internal systems only",
            "Black box is for networks; white box is for applications"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is a CVE?",
        "options": [
            "A type of network scanning tool",
            "A cloud storage format used by AWS",
            "A standardised identifier for publicly known software vulnerabilities",
            "A certificate issued after completing a cybersecurity course"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What does a Security Architect do?",
        "options": [
            "Responds to active security incidents as they happen",
            "Writes malware samples for internal testing",
            "Manages day-to-day user account administration",
            "Designs the overall security structure and strategy of an organisation"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "Which certification is most commonly associated with entry-level cybersecurity roles?",
        "options": [
            "CompTIA Security+",
            "CISSP",
            "CISM",
            "CEH"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What is TryHackMe used for?",
        "options": [
            "Storing and sharing code repositories",
            "Hands-on cybersecurity training through guided labs and challenges",
            "Managing cloud infrastructure and deployments",
            "Writing and publishing security policies"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is the principle of zero trust?",
        "options": [
            "Trust all users who are already inside the network perimeter",
            "Only trust administrators with elevated privileges",
            "Never trust, always verify — no implicit trust based on network location",
            "Trust external partners more than internal employees"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What is a bug bounty programme?",
        "options": [
            "A salary bonus paid to security staff for finding internal bugs",
            "A fine imposed on developers who introduce vulnerabilities into code",
            "A government grant for academic cybersecurity research",
            "A programme that rewards researchers for responsibly reporting valid security vulnerabilities"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is threat intelligence?",
        "options": [
            "Information about known and emerging threats used to improve an organisation's defences",
            "A type of antivirus software that uses AI",
            "A network scanning tool used during penetration tests",
            "A cloud-based security information framework"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "What should you include in a cybersecurity CV to demonstrate practical skills?",
        "options": [
            "Only formal academic qualifications and degrees",
            "CTF results, home lab projects, and platform profiles like TryHackMe or Hack The Box",
            "A list of security tools without context or results",
            "Personal hobbies unrelated to technology"
        ],
        "answer": 1
    },
    # C=2
    {
        "q": "What is a SOC Tier 1 analyst primarily responsible for?",
        "options": [
            "Designing the organisation's network architecture",
            "Writing and enforcing security policies",
            "Triaging and investigating initial security alerts from the SIEM",
            "Performing red team penetration tests"
        ],
        "answer": 2
    },
    # D=3
    {
        "q": "What does 'encryption at rest' mean?",
        "options": [
            "Data is encrypted while being transmitted across the network",
            "Data is encrypted before being sent to a cloud provider",
            "Data is deleted after a set period of inactivity",
            "Data is encrypted while stored on disk or in a database"
        ],
        "answer": 3
    },
    # A=0
    {
        "q": "What is the primary purpose of a security awareness training programme?",
        "options": [
            "To reduce human error as a security risk by educating staff on threats and safe behaviour",
            "To teach all employees to write secure code",
            "To replace technical security controls with human vigilance",
            "To train non-technical staff to become penetration testers"
        ],
        "answer": 0
    },
    # B=1
    {
        "q": "In a SaaS model, who manages the application security?",
        "options": [
            "The customer manages all application security settings",
            "The cloud provider manages the application and its underlying security",
            "Both the customer and provider share equal responsibility",
            "A third-party auditor is responsible for SaaS security"
        ],
        "answer": 1
    },
]


def _has_course_access(user):
    return user.is_admin or CourseAccess.query.filter_by(user_id=user.id).first() is not None


def _lessons_read_count(user_id):
    return LessonRead.query.filter_by(user_id=user_id).count()


def _best_pass(user_id):
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
    wrong = []

    for i, q in enumerate(QUESTIONS):
        submitted = request.form.get(f"q{i}")
        correct = False
        chosen = None
        if submitted is not None:
            try:
                chosen = int(submitted)
                if chosen == q["answer"]:
                    score += 1
                    correct = True
            except (ValueError, TypeError):
                pass
        if not correct:
            wrong.append({
                "index": i,
                "q": q["q"],
                "options": q["options"],
                "answer": q["answer"],
                "chosen": chosen,
            })

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

    # Store wrong answers in session for result page
    session[f"quiz_wrong_{attempt.id}"] = wrong

    return redirect(url_for("quiz.quiz_result", attempt_id=attempt.id))


@quiz_bp.route("/result/<int:attempt_id>")
@login_required
def quiz_result(attempt_id):
    attempt = QuizAttempt.query.filter_by(
        id=attempt_id, user_id=current_user.id
    ).first_or_404()

    best = _best_pass(current_user.id)
    wrong = session.get(f"quiz_wrong_{attempt.id}", [])

    return render_template(
        "course/quiz_result.html",
        attempt=attempt,
        best=best,
        pass_threshold=int(PASS_THRESHOLD * 100),
        wrong=wrong,
    )