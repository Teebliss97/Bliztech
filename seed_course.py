"""
Run this once after migration to load all 20 course lessons into the database.

Usage:
    flask shell
    >>> from seed_course import seed
    >>> seed()

Or directly:
    python seed_course.py
"""

LESSONS = [
    # ── SECTION A ──────────────────────────────────────────
    {
        "slug": "gic-a1",
        "section": "A",
        "lesson_number": 1,
        "order": 1,
        "title": "Introduction to Modern Cybersecurity",
        "body": """## What cybersecurity actually is

Cybersecurity is the practice of protecting systems, networks, and data from unauthorised access, damage, or attack. That definition is accurate but incomplete. In practice, cybersecurity is about managing risk — understanding what you have, what threatens it, and what you are willing to do about it.

The word "cyber" has become noise. Strip it away and what remains is a straightforward problem: people build systems, other people try to break them, and organisations need to decide how much effort to put into stopping that from happening.

## Why it matters now

Digital systems underpin almost everything. Banking, healthcare, transport, energy, communication — all of it depends on software and networks. When those systems fail or are compromised, the consequences are not abstract. Hospitals cancel operations. People lose savings. Governments lose classified information. Businesses collapse.

The scale of the problem has grown in proportion to how dependent we have become on technology. In 2023, the average cost of a data breach globally was over $4 million. Ransomware attacks on critical infrastructure have shut down fuel pipelines, hospital networks, and government services. This is not a niche technical problem — it is an economic and national security issue.

## The threat landscape today

The modern threat landscape has several defining characteristics:

**Attackers are organised.** Many operate as businesses, with development teams, customer support for their ransomware victims, and structured revenue models. Nation-state groups have budgets, long-term objectives, and sophisticated capabilities.

**Attacks are automated.** Scanning the entire internet for vulnerable systems takes minutes. Attackers do not need to target you specifically — their tools find you.

**The attack surface keeps expanding.** Every new device, application, cloud service, and remote worker is a potential entry point. Organisations are trying to defend a perimeter that no longer has clear edges.

**People remain the weakest point.** The majority of breaches begin with a phishing email or stolen credentials. Technical controls can be bypassed if a user can be deceived into handing over access.

## Who works in cybersecurity

Cybersecurity is not a single role. It is a broad field with specialisations that range from highly technical to policy-focused:

- **SOC analysts** monitor systems for suspicious activity and respond to alerts
- **Penetration testers** are paid to find vulnerabilities before attackers do
- **Incident responders** investigate breaches and contain damage
- **Security engineers** build and maintain the controls that protect systems
- **GRC professionals** manage policy, regulation, and risk frameworks
- **Threat intelligence analysts** track attacker groups and techniques
- **Cloud security engineers** secure infrastructure hosted on platforms like AWS and Azure

## What this course covers

This course moves through four sections. Foundation covers core concepts and how the field thinks about security. Technical Core covers the systems and protocols that underpin everything. Defence and Response covers the practical skills used to protect systems and react when things go wrong. Career Launchpad covers how to turn this knowledge into employment.""",
        "lab": None,
    },
    {
        "slug": "gic-a2",
        "section": "A",
        "lesson_number": 2,
        "order": 2,
        "title": "Types of Threats and Attackers",
        "body": """## Not all attackers are the same

A common mistake is to think of "hackers" as a single type of person with a single motivation. In reality, the threat landscape is made up of distinct groups with different capabilities, objectives, and methods. Understanding who is attacking — and why — changes how you think about defence.

## Nation-state actors

Nation-state groups are sponsored or operated by governments. Their objectives are political, economic, or military: stealing intellectual property, disrupting critical infrastructure, gathering intelligence, or influencing elections.

These groups are among the most capable attackers in the world. They have significant budgets, access to zero-day vulnerabilities, and the patience to conduct operations over months or years without being detected.

## Cybercriminal groups

Cybercriminals are motivated by money. This category includes:

**Ransomware operators** who compromise systems, encrypt data, and demand payment for the decryption key. Some operate as ransomware-as-a-service businesses, providing technical tools to affiliates in exchange for a cut of proceeds.

**Financial fraud groups** who steal banking credentials, conduct business email compromise attacks, and commit payment fraud.

**Data brokers** who steal personal data at scale and sell it on dark web marketplaces.

## Hacktivists

Hacktivists use cyber attacks to make political or ideological statements. Their tactics typically include website defacement, DDoS attacks, and data leaks.

## Insider threats

Insider threats come from within an organisation. There are two broad categories:

**Malicious insiders** deliberately steal data, sabotage systems, or assist external attackers.

**Negligent insiders** cause breaches through carelessness — clicking phishing links, misconfiguring systems, or handling data improperly.

## Opportunistic attackers

A large portion of attacks are opportunistic — automated tools scan for known vulnerabilities, and anything exposed gets attacked regardless of who owns it. This is why patching and basic hardening matter so much.

## The attack lifecycle

Regardless of who the attacker is, most attacks follow a recognisable pattern:

1. **Reconnaissance** — gathering information about the target
2. **Weaponisation** — preparing the attack tool or payload
3. **Delivery** — getting the attack to the target
4. **Exploitation** — triggering the vulnerability or deceiving the user
5. **Installation** — establishing a foothold
6. **Command and control** — communicating with the compromised system
7. **Actions on objectives** — doing whatever the attacker came to do""",
        "lab": None,
    },
    {
        "slug": "gic-a3",
        "section": "A",
        "lesson_number": 3,
        "order": 3,
        "title": "CIA Triad and Security Principles",
        "body": """## The foundation of security thinking

Every decision in cybersecurity comes back to three core properties: Confidentiality, Integrity, and Availability — the CIA triad.

## Confidentiality

Confidentiality means that information is accessible only to those who are authorised to access it.

Controls that protect confidentiality include encryption, access controls, authentication, and data classification.

## Integrity

Integrity means that information and systems can be trusted to be accurate and unmodified.

Controls that protect integrity include hashing, digital signatures, version control, audit logs, and input validation.

## Availability

Availability means that systems and data are accessible when needed by authorised users.

Controls that protect availability include redundancy, DDoS mitigation, disaster recovery planning, and regular backups.

## The tensions between CIA properties

The three properties are not always compatible:

**Confidentiality vs Availability:** Adding authentication and encryption makes data more confidential but can make systems slower and harder to access.

**Integrity vs Availability:** Requiring extensive verification improves integrity but can slow systems.

**Confidentiality vs Integrity:** End-to-end encryption protects confidentiality but can prevent security tools from inspecting traffic for malware.

## Additional principles

**Non-repudiation** means that actions can be attributed to the person who performed them, and that person cannot credibly deny having done so.

**Authenticity** means that data and communications are genuine — they come from who they claim to come from.""",
        "lab": None,
    },
    {
        "slug": "gic-a4",
        "section": "A",
        "lesson_number": 4,
        "order": 4,
        "title": "Risk, Vulnerabilities, and Attack Surface",
        "body": """## How security professionals think about risk

Risk is not binary. The formal definition is:

**Risk = Threat × Vulnerability × Impact**

- **Threat** — the possibility that something bad will happen
- **Vulnerability** — a weakness that a threat can exploit
- **Impact** — the consequence if the threat succeeds

## What a vulnerability is

A vulnerability is any weakness in a system, process, or control that could be exploited. Vulnerabilities exist in:

**Software** — bugs in code that allow attackers to execute commands, bypass authentication, or access data they should not reach.

**Configuration** — systems set up incorrectly. Default passwords, unnecessary services, excessive permissions, sensitive data exposed to the internet.

**Processes** — weak or absent procedures. No process for revoking access when an employee leaves. No verification before making a wire transfer.

**People** — human behaviour that can be exploited through social engineering.

## Vulnerability management

Vulnerability management is the ongoing process of identifying, assessing, and remediating vulnerabilities:

- **Scanning** — automated tools test systems for known vulnerabilities
- **Prioritisation** — assessing severity, exploitability, and business context
- **Remediation** — patching, reconfiguring, or implementing compensating controls
- **Tracking** — maintaining records of what has been found and fixed

## The attack surface

The attack surface is the total sum of points where an attacker could attempt to enter or extract data. Every component that is accessible is part of the attack surface: websites, email systems, remote access tools, cloud services, employee devices, third-party software.

## Residual risk

After controls are applied, some risk always remains. Organisations must decide what to do with it:

- **Accept** — acknowledge the risk is within tolerance
- **Transfer** — shift financial consequences through insurance
- **Avoid** — stop doing the activity that creates the risk
- **Mitigate** — apply additional controls""",
        "lab": None,
    },
    {
        "slug": "gic-a5",
        "section": "A",
        "lesson_number": 5,
        "order": 5,
        "title": "Defence in Depth",
        "body": """## Why no single control is enough

Every control has weaknesses. Defence in depth uses multiple layers so that if one fails, others continue to provide protection.

## The layers of defence

**Perimeter controls** — firewalls, intrusion detection systems, email filtering. Stop a large volume of attacks at the boundary.

**Network controls** — network segmentation divides the environment into zones. A breach in one zone does not automatically give access to others.

**Endpoint controls** — antivirus, EDR, patch management, device encryption.

**Application controls** — authentication requirements, authorisation checks, input validation, logging.

**Data controls** — encryption at rest and in transit, data loss prevention, access controls.

**Human controls** — security awareness training, clear policies, processes that reduce human error.

## Principle of least privilege

Every user, system, and process should have the minimum level of access needed to perform its function, and no more. Least privilege limits the damage an attacker can do if they compromise a single account.

## Separation of duties

Critical actions cannot be completed by a single person acting alone. A payment requiring approval from two different people means a single compromised or malicious insider cannot complete it unilaterally.

## Zero trust

Zero trust challenges the assumption that everything inside the network perimeter can be trusted. In a zero trust model, no user, device, or system is trusted by default. Every access request must be authenticated and authorised, every time.

## The honest limitation

Defence in depth reduces risk. It does not eliminate it. The goal is to make the attack difficult enough, and detection fast enough, that the attacker either gives up or is caught before achieving their objective.""",
        "lab": """## Map your own attack surface

Work through the following categories and record every item that applies to you.

**Devices**
- How many devices do you own that connect to the internet?
- Which have automatic updates enabled?
- Which have a PIN, password, or biometric lock?

**Accounts**
- Estimate how many online accounts you have
- How many use a unique password?
- How many have two-factor authentication enabled?

**Network access**
- Do you use public Wi-Fi? How often?
- Does your home router use the default admin password?

**Data**
- What sensitive data do you store digitally?
- Where is it stored? Is it encrypted?

**Risk assessment**

For each category, rate your current exposure on a scale of 1 to 5, where 1 is well-protected and 5 is significantly exposed. Identify the two areas where your attack surface is largest and write one specific action you could take this week to reduce it.""",
    },

    # ── SECTION B ──────────────────────────────────────────
    {
        "slug": "gic-b1",
        "section": "B",
        "lesson_number": 6,
        "order": 6,
        "title": "Networking Fundamentals for Cyber",
        "body": """## Why networking matters in cybersecurity

Every attack that involves a remote system travels across a network. Phishing emails arrive over the internet. Malware communicates with attacker infrastructure over the internet. Lateral movement inside a compromised organisation happens across internal networks. You cannot defend what you do not understand.

## What a network is

A network is a collection of devices that can communicate with each other through a combination of physical infrastructure and agreed-upon rules called protocols.

## How data moves — packets

Data is broken into small chunks called packets. Each packet contains a portion of the data, plus header information that tells the network where it came from, where it is going, and how to reassemble it at the destination.

## The OSI model

| Layer | Name | Function |
|-------|------|----------|
| 7 | Application | HTTP, DNS, SMTP |
| 6 | Presentation | Data formatting, encryption |
| 5 | Session | Managing connections |
| 4 | Transport | TCP, UDP |
| 3 | Network | IP addresses, routing |
| 2 | Data Link | MAC addresses |
| 1 | Physical | Cables, wireless signals |

Firewalls primarily work at layers 3 and 4. Web application firewalls work at layer 7.

## Key networking hardware

**Router** — connects different networks, determines the best path for packets.

**Switch** — connects devices within the same network, sends traffic only to the intended device.

**Firewall** — monitors and controls traffic based on rules.

**Proxy server** — sits between clients and servers, forwarding requests on behalf of clients.

## Network security fundamentals

**Network segmentation** — dividing a network into separate zones with controlled access between them.

**DMZ** — a network segment between the internal network and the internet, used for publicly accessible services.

**VPN** — creates an encrypted tunnel between a device and a network for secure remote access.

**Network monitoring** — capturing and analysing traffic to detect anomalies and suspicious connections.""",
        "lab": None,
    },
    {
        "slug": "gic-b2",
        "section": "B",
        "lesson_number": 7,
        "order": 7,
        "title": "IP Addresses, Ports, and Protocols",
        "body": """## IP addresses

Every device on a network has an IP address — a numerical label that identifies the device and its location.

**IPv4** addresses are 32-bit numbers written as four groups separated by dots — e.g. 192.168.1.1. Approximately 4.3 billion possible addresses.

**IPv6** addresses are 128-bit numbers written in hexadecimal — e.g. 2001:0db8:85a3::8a2e:0370:7334. Vastly larger address space.

## Public and private IP addresses

**Public IPs** are globally unique and routable on the internet.

**Private IP ranges** are used within local networks:
- 10.0.0.0 – 10.255.255.255
- 172.16.0.0 – 172.31.255.255
- 192.168.0.0 – 192.168.255.255

## Common ports

| Port | Service |
|------|---------|
| 22 | SSH |
| 25 | SMTP (email sending) |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB (Windows file sharing) |
| 3306 | MySQL |
| 3389 | RDP (Remote Desktop) |

## Key protocols

**TCP** — reliable, ordered delivery. Establishes a connection before sending data. Used where accuracy matters.

**UDP** — faster, no connection, no delivery confirmation. Used where speed matters more than accuracy.

**HTTP** — web traffic, unencrypted.

**HTTPS** — HTTP with TLS encryption. Encrypts communication between browser and server.

**TLS** — the encryption protocol securing HTTPS, email, and many other communications.""",
        "lab": None,
    },
    {
        "slug": "gic-b3",
        "section": "B",
        "lesson_number": 8,
        "order": 8,
        "title": "DNS, Domains, and Web Traffic",
        "body": """## What DNS is

The Domain Name System translates human-readable domain names into IP addresses. When you type a URL into a browser, DNS resolves that domain name into an IP address your computer uses to connect.

## DNS record types

**A record** — maps a domain to an IPv4 address.

**MX record** — specifies which mail servers handle email for the domain.

**CNAME record** — an alias pointing one domain to another.

**TXT record** — stores text information, used for email authentication (SPF, DKIM).

## DNS attacks

**DNS spoofing** — injecting false records into a resolver's cache, directing users to malicious servers.

**DNS hijacking** — compromising domain registrar accounts to redirect traffic.

**DNS tunnelling** — encoding data inside DNS queries to exfiltrate information or communicate with malware.

**Typosquatting** — registering domains resembling legitimate ones (gooogle.com, paypa1.com).

## How web traffic works

1. DNS resolution translates the domain to an IP address
2. Browser initiates TCP connection to port 80 (HTTP) or 443 (HTTPS)
3. TLS handshake if HTTPS — server presents certificate, encrypted session established
4. Browser sends HTTP request
5. Server sends HTTP response
6. Browser renders content

## HTTP status codes

| Code | Meaning |
|------|---------|
| 200 | OK — success |
| 301/302 | Redirect |
| 401 | Unauthorised — authentication required |
| 403 | Forbidden — not authorised |
| 404 | Not found |
| 500 | Server error |

## TLS certificates

A TLS certificate encrypts communication and verifies the server's identity. A valid certificate does not mean a website is safe — phishing sites routinely obtain valid certificates to display the padlock.""",
        "lab": None,
    },
    {
        "slug": "gic-b4",
        "section": "B",
        "lesson_number": 9,
        "order": 9,
        "title": "Windows and Linux Basics",
        "body": """## Why operating systems matter in security

Almost every attack ultimately targets or interacts with an operating system. Security professionals need to be comfortable with both Windows and Linux.

## Windows fundamentals

**Key directories:**
- `C:\\Windows\\System32` — core OS files
- `C:\\Users\\[username]` — user profile
- `C:\\Program Files` — installed applications

**The registry** — stores configuration settings. Malware frequently modifies registry Run keys to establish persistence.

**Windows Event Logs** — security logs capture authentication events, policy changes, privilege use. Key event IDs:
- 4624 — successful logon
- 4625 — failed logon
- 4688 — new process created
- 7045 — new service installed

**PowerShell** — widely used for administration and widely abused by attackers to download malware and move laterally.

## Linux fundamentals

**Key directories:**
- `/etc` — configuration files
- `/var/log` — log files
- `/home/[username]` — user home directories
- `/tmp` — temporary files (often targeted by attackers)

**Essential commands:**
```
ls -la          List directory contents including hidden files
cd              Change directory
cat             Display file contents
grep            Search for text within files
ps aux          List running processes
netstat -tulpn  Show network connections
sudo            Execute with administrator privileges
```

**File permissions** — set for owner, group, and other users. Displayed as `-rwxr-xr--`. Incorrect permissions are a common misconfiguration vulnerability.

**Log files:**
- `/var/log/auth.log` — authentication events
- `/var/log/syslog` — general system messages""",
        "lab": None,
    },
    {
        "slug": "gic-b5",
        "section": "B",
        "lesson_number": 10,
        "order": 10,
        "title": "Users, Permissions, and Access Control",
        "body": """## Authentication vs authorisation

**Authentication** verifies identity — confirming that a user is who they claim to be.

**Authorisation** determines what an authenticated user is permitted to do.

Both must work correctly. Authentication without authorisation means once logged in you can do anything.

## Authentication factors

**Something you know** — passwords, PINs. Vulnerable to theft and phishing.

**Something you have** — security key, authenticator app. Harder to steal remotely.

**Something you are** — biometrics. Convenient but cannot be changed if compromised.

**MFA** combines two or more factors. Even with a stolen password, an attacker cannot authenticate without the second factor.

## Access control models

**DAC (Discretionary Access Control)** — the resource owner decides who can access it. Familiar file permissions model.

**RBAC (Role-Based Access Control)** — permissions assigned to roles, users assigned to roles. The dominant enterprise model.

**ABAC (Attribute-Based Access Control)** — decisions based on attributes of the user, resource, and environment. More flexible but complex.

## Least privilege in practice

- Avoid using administrator accounts for routine tasks
- Grant time-limited access for specific tasks
- Conduct regular access reviews
- Use service accounts with minimal permissions

## Identity lifecycle

**Provisioning** — creating accounts and granting appropriate access.

**De-provisioning** — revoking access promptly when a user leaves. Failure is a major insider threat risk.

**Access reviews** — periodically verifying current access assignments are still appropriate.""",
        "lab": """## Network commands lab

Work through each command and record the output.

**Part 1: Network configuration**

Windows: `ipconfig /all`
Linux/macOS: `ip addr show`

Record: your IP address, subnet mask, default gateway, DNS server addresses.

**Part 2: Trace a route**

Windows: `tracert google.com`
Linux/macOS: `traceroute google.com`

Record: how many hops to google.com, the IP address of the first three hops.

**Part 3: DNS lookups**

`nslookup bliztechacademy.com`
`nslookup -type=MX gmail.com`

Record: the IP address returned for bliztechacademy.com, the mail servers for gmail.com.

**Part 4: Network connections**

Windows: `netstat -an`
Linux/macOS: `ss -tulpn`

Record: which ports your device is listening on, any established connections.

**Part 5: Reflection**

Answer these questions based on your outputs:
1. What is the IP address of your router?
2. How many hops does traffic take to reach google.com?
3. What DNS server is your device using?
4. Are there any listening ports you cannot identify?""",
    },

    # ── SECTION C ──────────────────────────────────────────
    {
        "slug": "gic-c1",
        "section": "C",
        "lesson_number": 11,
        "order": 11,
        "title": "Password Security, MFA, and Identity Protection",
        "body": """## How passwords are attacked

**Brute force** — trying every possible combination until the correct password is found.

**Dictionary attacks** — trying a list of common words and known passwords.

**Credential stuffing** — using username/password combinations from one breach to attack other services.

**Password spraying** — trying a small number of common passwords against many accounts to avoid lockouts.

**Phishing** — tricking users into entering credentials on fake login pages.

## What makes a password strong

- **Length** — minimum 12 characters; 16+ for sensitive accounts
- **Uniqueness** — every account needs a different password
- **Randomness** — avoid predictable patterns
- **No personal information** — names and dates appear in targeted attacks

## Password managers

The only practical way to use long, unique, random passwords for every account. Leading options: Bitwarden (open source, free), 1Password, Dashlane.

## How passwords are stored

Systems store a hash — the output of a one-way function applied to the password. Strong algorithms (bcrypt, Argon2) are deliberately slow, making cracking impractical for strong passwords. Salting adds a unique random value before hashing, preventing rainbow table attacks.

## Multi-factor authentication

**Authenticator apps** — time-based one-time passwords changing every 30 seconds. Significantly more secure than SMS.

**SMS codes** — better than no MFA but vulnerable to SIM swapping attacks.

**Hardware security keys** — the strongest form. Resistant to phishing because they cryptographically verify the site.

**MFA fatigue** — attackers flood users with push requests hoping they approve one out of frustration.

## Identity attacks beyond passwords

**Pass-the-hash** — extracting hashed credentials from memory and using them directly without cracking.

**Token theft** — stealing session tokens that grant access without requiring a password.

**Account takeover via recovery** — exploiting weak account recovery mechanisms.""",
        "lab": None,
    },
    {
        "slug": "gic-c2",
        "section": "C",
        "lesson_number": 12,
        "order": 12,
        "title": "Email Security and Phishing Investigation",
        "body": """## How email is delivered

1. Your client connects to your mail server using SMTP
2. Your server looks up the MX record for the recipient's domain
3. Your server connects to the recipient's server and delivers the message
4. The recipient retrieves the message using IMAP or POP3

Email was designed with no authentication — any server can claim to send from any domain.

## SPF, DKIM, and DMARC

**SPF** — a DNS TXT record specifying which servers are authorised to send email for the domain.

**DKIM** — a cryptographic signature added to outgoing emails, verified using a public key in DNS.

**DMARC** — specifies what to do with emails that fail SPF/DKIM: none, quarantine, or reject.

## Reading email headers

**From:** — the display name and email address. Can be freely spoofed.

**Reply-To:** — if set, replies go here instead of the From address.

**Authentication-Results:** — SPF, DKIM, and DMARC check results added by the receiving server.

**Received:** — each mail server the message passed through. Read bottom to top to trace the path.

## Phishing investigation process

1. Do not click anything
2. Check the actual email address, not just the display name
3. View full headers — check authentication results
4. Examine links by hovering, not clicking
5. Look up originating IP on AbuseIPDB or VirusTotal
6. Analyse attachments by hash lookup, not by opening
7. Consider context — was this expected?

## Common phishing techniques

**Spear phishing** — targeted, personalised attacks using information from LinkedIn or previous breaches.

**BEC (Business Email Compromise)** — impersonating executives or suppliers to request wire transfers.

**Smishing** — phishing via SMS. **Vishing** — phishing via voice call. **Quishing** — phishing via QR code.""",
        "lab": None,
    },
    {
        "slug": "gic-c3",
        "section": "C",
        "lesson_number": 13,
        "order": 13,
        "title": "Secure Browsing and Website Trust",
        "body": """## HTTPS and what it actually means

HTTPS provides:

**Confidentiality** — communication cannot be read by anyone intercepting traffic between browser and server.

**Authentication** — the TLS certificate verifies you are communicating with the genuine server.

What HTTPS does not mean:
- The website is legitimate or safe
- The content is not malicious
- The company is trustworthy

Phishing sites use HTTPS routinely.

## Certificate types

**DV (Domain Validated)** — CA verifies domain control only. Issued quickly and cheaply. Phishing sites use DV certificates.

**OV (Organisation Validated)** — CA verifies the organisation's identity in addition to domain control.

**EV (Extended Validation)** — most rigorous verification. Contains the organisation's name.

## Browser security

- Keep the browser updated — browser vulnerabilities are actively exploited
- Use a reputable ad blocker — malvertising is a significant threat vector
- Be cautious with extensions — they have significant permissions and can read page content
- Consider a DNS-based content filter

## Assessing website trustworthiness

**Domain** — is it what you would expect? Check the actual domain, not just the page display.

**Age** — newly registered domains are higher risk.

**Content** — poor grammar and generic images can indicate a fraudulent site.

**Contact information** — no phone number or physical address are warning signs.

## Browser privacy

**Cookies** — third-party cookies track activity across the web.

**Browser fingerprinting** — identifies users based on technical characteristics without cookies.

Browsers like Firefox with privacy settings or Brave provide stronger defaults than Chrome.""",
        "lab": None,
    },
    {
        "slug": "gic-c4",
        "section": "C",
        "lesson_number": 14,
        "order": 14,
        "title": "Malware Basics and How Infections Happen",
        "body": """## Types of malware

**Virus** — attaches to legitimate files and replicates when executed.

**Worm** — replicates across networks without user action, exploiting vulnerabilities.

**Trojan** — disguised as legitimate software, performs malicious actions in the background.

**Ransomware** — encrypts files and demands payment. Often combined with data exfiltration (double extortion).

**Spyware** — monitors user activity and exfiltrates information silently.

**Rootkit** — hides its presence, often modifying the OS. Difficult to detect and remove.

**Fileless malware** — lives in memory using legitimate system tools. No malicious file to scan.

**Botnet** — network of infected machines controlled remotely. Used for DDoS, spam, and further attacks.

## How infections happen

**Phishing** — the most common method. User clicks a malicious link or opens a malicious attachment.

**Exploitation of vulnerabilities** — unpatched software exploited to execute code. Drive-by downloads occur by simply visiting a compromised website.

**Malicious downloads** — software from unofficial sources often contains malware.

**Supply chain compromise** — malware inserted into legitimate software during development.

**Exposed remote services** — brute-forcing or exploiting RDP and VPN vulnerabilities.

## Persistence mechanisms

- Windows registry Run keys
- Scheduled tasks
- Windows services
- Startup scripts in Linux

## Malware defences

**EDR** — monitors behaviour, detecting suspicious activity even without known malware signatures.

**Patching** — removes vulnerabilities that delivery methods exploit.

**Email filtering** — blocks malicious attachments and links before reaching users.

**Network monitoring** — detects unusual outbound connections to command-and-control infrastructure.""",
        "lab": None,
    },
    {
        "slug": "gic-c5",
        "section": "C",
        "lesson_number": 15,
        "order": 15,
        "title": "Logging, Alerts, and Incident Basics",
        "body": """## Why logging matters

Logs are the primary source of evidence in security investigations. Without logs, investigations are blind. Logs also support proactive security — reviewing them for suspicious patterns can detect attacks in progress.

## What gets logged

**OS logs** — authentication events, process creation, file system changes, network connections.

**Network logs** — firewall logs, DNS queries, proxy logs, NetFlow.

**Application logs** — web server access logs, authentication events, errors.

**Security tool logs** — antivirus alerts, IDS alerts, WAF alerts.

## Key Windows event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | New process created |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4740 | Account locked out |
| 7045 | New service installed |

## SIEM

A SIEM collects logs from across an environment, normalises them, and provides tools for searching, correlating, and alerting. Correlation rules detect patterns — for example, the same IP failing authentication on three systems within five minutes.

## Incident response lifecycle

**1. Preparation** — policies, training, tools, communication plans, practice exercises.

**2. Detection and Analysis** — identifying that an incident occurred and understanding scope.

**3. Containment, Eradication, Recovery** — stopping spread, removing attacker presence, restoring systems.

**4. Post-Incident Activity** — reviewing what happened, updating defences, documenting.

## Evidence handling

- **Preserve** — create forensic images rather than working on originals
- **Document** — record every action with timestamps
- **Chain of custody** — maintain records of who had access to evidence
- **Volatile data first** — capture memory and active connections before powering off""",
        "lab": """## Investigate a phishing email

Analyse the following sample email headers:

```
Received: from mail.suspicious-domain.xyz [185.220.101.42]
From: "PayPal Security Team" <security@paypa1-verify.com>
Reply-To: collect@attacker-email.net
Subject: Urgent: Your account has been limited

Authentication-Results:
  spf=fail (185.220.101.42 not permitted sender)
  dkim=none
  dmarc=fail action=none
```

Answer these questions:

1. What is the display name in the From field? What is the actual email address?
2. Where would a reply go if you replied to this email?
3. What was the result of SPF authentication? What does this mean?
4. Was DKIM present? What does its absence suggest?
5. Look up 185.220.101.42 on abuseipdb.com. What does it show?
6. Write a one-paragraph incident summary with your assessment.

Then find a real suspicious email in your spam folder, view its headers, and work through the same questions.""",
    },

    # ── SECTION D ──────────────────────────────────────────
    {
        "slug": "gic-d1",
        "section": "D",
        "lesson_number": 16,
        "order": 16,
        "title": "Cloud Security Fundamentals",
        "body": """## The shared responsibility model

Cloud providers and customers share responsibility for security. Where the boundary lies depends on the service type:

**IaaS** — provider manages physical infrastructure. Customer manages OS, applications, data.

**PaaS** — provider manages infrastructure and runtime. Customer manages applications and data.

**SaaS** — provider manages everything except user access and data configuration.

A common mistake is assuming the cloud provider is responsible for more than they are.

## Common cloud misconfigurations

**Publicly accessible storage buckets** — AWS S3, Azure Blob, or Google Cloud Storage exposed to the internet. Billions of records have been exposed through this single error.

**Overly permissive IAM roles** — granting more permissions than needed. A compromised credential causes significantly more damage.

**Exposed management interfaces** — SSH, RDP, or management consoles accessible from the internet.

**Disabled logging** — not enabling CloudTrail, Azure Monitor, or GCP Cloud Logging.

**Default credentials** — databases and management consoles deployed with unchanged defaults.

## Cloud-specific attacks

**Metadata service abuse** — SSRF vulnerabilities exploited to access the instance metadata service and steal IAM credentials.

**Credential exposure** — developers accidentally committing cloud credentials to public repositories.

**Lateral movement** — using the permissions of a compromised resource to access others.

## Cloud security controls

- Enable MFA on all accounts, especially root/global admin
- Apply least privilege IAM — every user and service gets only what it needs
- Enable all available logging services
- Use CSPM tools to continuously scan for misconfigurations
- Encrypt data at rest and in transit
- Conduct regular access reviews""",
        "lab": None,
    },
    {
        "slug": "gic-d2",
        "section": "D",
        "lesson_number": 17,
        "order": 17,
        "title": "Data Protection and Privacy Basics",
        "body": """## What personal data is

Personal data is any information relating to an identified or identifiable individual — broader than most people assume. This includes names, email addresses, IP addresses, location data, biometrics, health information, and browsing history.

## GDPR

The General Data Protection Regulation applies to any organisation processing personal data of EU individuals, regardless of where the organisation is based. UK GDPR mirrors the EU version with minor modifications.

**Six lawful bases for processing:**
1. Consent
2. Contract
3. Legal obligation
4. Vital interests
5. Public task
6. Legitimate interests

## Key GDPR principles

- **Lawfulness, fairness, transparency** — process data lawfully and transparently
- **Purpose limitation** — collect only for specified, legitimate purposes
- **Data minimisation** — only collect what is necessary
- **Accuracy** — keep data accurate and up to date
- **Storage limitation** — do not keep data longer than necessary
- **Integrity and confidentiality** — process data securely

## Individual rights

- Right to access their personal data
- Right to rectification of inaccurate data
- Right to erasure in certain circumstances
- Right to data portability
- Right to object to certain processing

## Breach notification

Under GDPR, organisations must notify the supervisory authority (ICO in the UK) within 72 hours of becoming aware of a qualifying breach. If high risk to individuals, they must also be notified directly.

## Data classification

**Public** — intended for public distribution.
**Internal** — for use within the organisation, not sensitive.
**Confidential** — sensitive, requires access controls and encryption.
**Restricted** — most sensitive, strict controls and audit logging required.""",
        "lab": None,
    },
    {
        "slug": "gic-d3",
        "section": "D",
        "lesson_number": 18,
        "order": 18,
        "title": "Cybersecurity Job Roles Explained",
        "body": """## SOC Analyst

**What they do:** Monitor alerts, investigate suspicious events, triage incidents, escalate genuine threats.

**Day to day:** Reviewing SIEM alerts, investigating logs, determining genuine threats vs false positives, documenting findings.

**Entry point:** One of the most accessible entry-level roles. Level 1 SOC analyst requires foundational knowledge.

**Progression:** L1 → L2 → L3 → Incident Responder / Threat Hunter / SOC Manager

## Incident Responder

**What they do:** Investigate confirmed breaches, contain attacker presence, restore systems, write reports.

**Skills:** Digital forensics, log analysis, MITRE ATT&CK framework, clear communication.

## Penetration Tester

**What they do:** Attempt to breach systems under authorised conditions to find vulnerabilities before real attackers.

**Day to day:** Reconnaissance, exploitation, report writing explaining vulnerabilities in business terms.

**Entry point:** Requires strong technical foundation. CTFs and TryHackMe/HackTheBox build demonstrable skills.

## Security Engineer

**What they do:** Design, build, and maintain security controls and infrastructure.

**Day to day:** Configuring firewalls and EDR, designing secure architecture, automating security processes.

## GRC Analyst

**What they do:** Manage governance framework, risk management, and compliance with regulations.

**Day to day:** Risk assessments, compliance management (GDPR, ISO 27001), writing policies, supporting audits.

**Entry point:** One of the most accessible roles for people from non-technical backgrounds.

## Cloud Security Engineer

**What they do:** Secure cloud infrastructure. One of the highest-demand roles currently.

**Skills:** At least one major cloud platform (AWS, Azure, GCP), IAM, scripting, DevSecOps.

## Which role suits you

- Enjoy analysis and investigation → SOC analyst, incident responder
- Enjoy building → security engineer, cloud security
- Enjoy finding weaknesses → penetration tester
- Enjoy policy and risk management → GRC
- Want the most accessible entry point → SOC analyst or GRC""",
        "lab": None,
    },
    {
        "slug": "gic-d4",
        "section": "D",
        "lesson_number": 19,
        "order": 19,
        "title": "Beginner Tools and Safe Practice",
        "body": """## TryHackMe

Browser-based learning platform with guided, hands-on exercises. No local setup required.

Recommended starting paths:
- **Pre-Security** — foundational networking, web, and Linux
- **SOC Level 1** — defensive skills for analyst roles
- **Jr Penetration Tester** — introduction to offensive techniques

## HackTheBox

More advanced than TryHackMe. Provides vulnerable machines without guided instructions. Best approached after building foundational skills on TryHackMe.

## VirusTotal

Analyses files, URLs, and IP addresses using dozens of antivirus engines simultaneously.

Use cases:
- Check whether a file is known malware before opening it
- Analyse suspicious URLs without visiting them
- Look up IP address reputation

Do not submit files containing sensitive information.

## Wireshark

Network protocol analyser — captures and displays network traffic in detail. Allows you to see exactly what is being sent over a network connection.

Use cases:
- Analysing captured traffic for malicious activity
- Understanding how protocols work in practice
- Investigating network-based attacks

## Nmap

Network scanning tool that discovers hosts and services on a network.

```
nmap 192.168.1.1          # Scan a single host
nmap 192.168.1.0/24       # Scan a subnet
nmap -sV 192.168.1.1      # Detect service versions
```

Only run Nmap against networks you own or have explicit permission to scan.

## Setting up a home lab

**VirtualBox** — free virtualisation platform. Run multiple operating systems simultaneously.

**Kali Linux** — Linux distribution with hundreds of security tools pre-installed. Run as a VM.

**Metasploitable** — deliberately vulnerable VM for practising exploitation. Run on an isolated network only.

## Legal boundaries

Only test systems you own or have explicit written permission to test. Unauthorised access is a criminal offence under the Computer Misuse Act 1990 (UK) and equivalent laws elsewhere.

Practise on: your own machines, deliberately vulnerable systems, TryHackMe/HackTheBox, bug bounty programmes.""",
        "lab": None,
    },
    {
        "slug": "gic-d5",
        "section": "D",
        "lesson_number": 20,
        "order": 20,
        "title": "How to Start a Career in Cybersecurity",
        "body": """## The honest picture

Breaking into cybersecurity takes time. There is no shortcut that replaces foundational knowledge and demonstrable skills. The demand for security professionals significantly exceeds supply, entry-level roles are accessible without years of experience, and the field offers genuine career progression.

## Step 1: Build foundational knowledge

You have done this. Continue building through TryHackMe learning paths, reading security blogs, and following the security community.

## Step 2: Choose a direction

For most people without deep technical backgrounds, the most accessible starting points are SOC analyst and GRC analyst. For those with existing technical backgrounds, security engineer and cloud security are more direct paths.

## Step 3: Get certified

**CompTIA Security+** — most widely recognised entry-level certification. Required by many employers as a minimum.

**ISC2 Certified in Cybersecurity (CC)** — free entry-level certification. No experience requirement.

**CompTIA CySA+** — analyst-focused, following Security+.

**OSCP** — most respected penetration testing certification. Requires significant practical skill.

## Step 4: Build a portfolio

- TryHackMe profile showing completed rooms and learning paths
- Write-ups of completed rooms published on a blog
- Home lab documentation
- GitHub with any relevant scripts or tools
- LinkedIn updated with certifications and projects

## Step 5: Apply strategically

Target entry-level roles — junior security analyst, security operations roles. Tailor your CV to highlight certifications and practical work. Prepare for scenario, technical, and behavioural interview questions.

## Your 90-day action plan

**Days 1–30:** Complete TryHackMe Pre-Security path. Begin studying for Security+. Set up LinkedIn. Install VirtualBox and Kali Linux.

**Days 31–60:** Start TryHackMe SOC Level 1 or Jr Penetration Tester. Take the Security+ exam. Begin publishing write-ups. Apply for ISC2 CC.

**Days 61–90:** Complete at least 50 TryHackMe rooms. Have five published write-ups. Update LinkedIn. Begin applying for entry-level roles. Attend virtual security meetups.""",
        "lab": """## Three tasks to complete

**Task 1: TryHackMe first room**

Create a free account at tryhackme.com. Complete the "Introduction to Cyber Security" room. Take a screenshot of your completed room and profile showing points earned.

**Task 2: VirusTotal analysis**

Find a suspicious URL from your spam folder or a security blog. Submit it to virustotal.com. Document:
- The URL submitted
- Number of vendors that flagged it
- Category of threat identified
- Three specific vendors and what they reported

**Task 3: Write your 90-day plan**

Write your personal 90-day plan, being specific:
- Which TryHackMe path will you complete first?
- Which certification will you target, and by what date?
- What will your home lab consist of?
- What role are you targeting?
- What does your LinkedIn profile need to say?""",
    },
]


def seed():
    from app.models import CourseTopic
    from app.extensions import db

    created = 0
    updated = 0

    for lesson in LESSONS:
        existing = CourseTopic.query.filter_by(slug=lesson["slug"]).first()
        if existing:
            for key, value in lesson.items():
                setattr(existing, key, value)
            updated += 1
        else:
            topic = CourseTopic(**lesson)
            db.session.add(topic)
            created += 1

    db.session.commit()
    print(f"Done — {created} created, {updated} updated.")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()