"""
seed_section_c_expanded.py
--------------------------
Run from your project root:
    PYTHONPATH=/opt/render/project/src .venv/bin/python seed_section_c_expanded.py
"""

LESSONS = [
    {
        "slug": "gic-c1",
        "section": "C",
        "lesson_number": 11,
        "order": 11,
        "title": "Password Security, MFA, and Identity Protection",
        "body": """<h2>Why passwords are still the primary attack vector</h2>

<p>Despite decades of alternatives being proposed and billions of dollars spent on security technology, passwords remain the dominant authentication mechanism across most systems — and the most consistently exploited weakness in cybersecurity. The majority of breaches involve compromised credentials in some form.</p>

<p>Understanding why passwords fail, how they are attacked, and what defences actually work is essential for anyone working in security — whether you are advising users, configuring systems, or investigating incidents.</p>

<h2>How passwords are attacked</h2>

<p><strong>Brute force</strong> — Trying every possible combination until the correct password is found. Against an online system with rate limiting (that locks accounts after failed attempts), brute force is impractical against any reasonable password. Against an offline hash database (where the attacker has stolen the password file and is cracking it locally), modern hardware can try billions of combinations per second.</p>

<p>A GPU cluster can crack an 8-character password using all character types in hours. A 12-character random password using the same character set would take thousands of years with current technology. Length matters enormously.</p>

<p><strong>Dictionary attacks</strong> — Rather than trying every combination, dictionary attacks try words, common passwords, and known patterns first. Most users choose passwords based on words, names, dates, and simple substitutions (p@ssw0rd, Password123). Dictionary attacks exploit this predictability and crack these passwords almost instantly.</p>

<p><strong>Credential stuffing</strong> — When a service is breached and password hashes are cracked (or passwords are stored in plaintext), attackers obtain lists of email/password combinations. They then try those exact combinations against other services — banking, email, social media. This works because the majority of users reuse passwords across multiple services.</p>

<p>In 2018, a study found that 52% of people use the same password for multiple accounts. When one of those accounts is breached, all of them are at risk. This is why credential stuffing attacks are so effective — the attacker does not need to crack anything; they just try combinations that already work somewhere.</p>

<p><strong>Password spraying</strong> — Rather than trying many passwords against one account (which triggers lockouts), spraying tries one common password (like "Summer2024!") against thousands of accounts. Most accounts will not use this password, but a small percentage will, and no individual account gets locked out because only one attempt is made per account.</p>

<p><strong>Phishing</strong> — Tricking users into entering their credentials on a fake login page. The most effective attack because it completely bypasses password strength — a 30-character random password is just as vulnerable to phishing as "password123". The user types it themselves into the attacker's form.</p>

<p><strong>Keylogging</strong> — Malware that captures keystrokes and sends them to an attacker. Every password you type on an infected device is captured, regardless of its strength or complexity.</p>

<h2>What makes a strong password</h2>

<p>Password strength is primarily determined by two factors: length and unpredictability.</p>

<p><strong>Length</strong> is the most important factor. Each additional character exponentially increases the number of combinations an attacker must try. A 12-character password is not twice as hard to crack as a 6-character password — it is orders of magnitude harder. Minimum recommendations:</p>
<ul>
<li>General accounts: minimum 12 characters</li>
<li>Sensitive accounts (email, banking, work): 16+ characters</li>
<li>Master password for a password manager: 20+ characters, memorised</li>
</ul>

<p><strong>Unpredictability</strong> — A 20-character password made of a common phrase ("ilovemydogmaxverymuch") is far easier to crack than a 12-character random string ("Kj#9mP@2qL$x"). Attackers' dictionaries include common phrases and patterns.</p>

<p><strong>Uniqueness</strong> — Every account must use a different password. Password reuse is what makes credential stuffing devastating. If your password for a gaming forum is the same as your work email, a breach of the gaming forum compromises your work account.</p>

<p><strong>What to avoid:</strong></p>
<ul>
<li>Dictionary words, even with simple substitutions (p@ssw0rd, secur1ty)</li>
<li>Personal information — names, birthdays, pet names, addresses</li>
<li>Keyboard patterns (qwerty, 123456, asdfgh)</li>
<li>Reuse of any password used on another service</li>
<li>Modifications of old passwords (Password1, Password2, Password3)</li>
</ul>

<h2>Password managers — the only practical solution</h2>

<p>The only practical way to have long, unique, random passwords for every account is to use a password manager. A password manager generates and stores strong passwords for every account, encrypted behind a single master password.</p>

<p>You only need to remember one strong password — the master password. The password manager handles generating and storing a unique, random, strong password for every other account. When you log into a site, the password manager fills in the credentials automatically.</p>

<p><strong>Benefits beyond convenience:</strong></p>
<ul>
<li>Auto-fill is bound to the specific domain — a password manager will not autofill credentials on paypa1.com when the credentials are registered to paypal.com. This provides passive phishing protection.</li>
<li>Generated passwords are random — no personal information, no patterns, no predictability</li>
<li>Password breach monitoring — many managers alert you when a site you use has been breached</li>
</ul>

<p><strong>Recommended options:</strong> Bitwarden (open source, free tier is excellent), 1Password (excellent for teams and families), Dashlane. Avoid browser-built-in password managers for sensitive accounts — they are convenient but lack the advanced features of dedicated managers.</p>

<h2>How passwords are stored — what happens server-side</h2>

<p>When you create a password on a website, the server should never store your actual password. Instead, it stores a hash — the output of running your password through a one-way mathematical function. The same input always produces the same hash, but you cannot reverse the hash to find the original password.</p>

<p>When you log in, the server hashes your entered password and compares it to the stored hash. If they match, you are authenticated.</p>

<p><strong>Good hashing algorithms</strong> for passwords are designed to be deliberately slow — bcrypt, Argon2, scrypt. Slow hashing means that even if an attacker steals the hash database, cracking each hash takes significant time. A hash that takes 0.1 seconds to compute means an attacker can try 10 passwords per second per core — making brute force impractical for long passwords.</p>

<p><strong>Salting</strong> adds a unique random value to each password before hashing. This prevents rainbow table attacks (precomputed tables of hash values) and means that two users with the same password will have different stored hashes. Unsalted hashes are trivially cracked using rainbow tables available online.</p>

<p><strong>Bad practices:</strong> Storing passwords in plaintext (shockingly common — "Have I Been Pwned" has billions of plaintext passwords from breaches), using fast hashing algorithms like MD5 or SHA-1 (designed for speed, not password storage), and failing to salt hashes.</p>

<p>When you hear that a company was breached and passwords were "encrypted" — be sceptical of this terminology. "Encrypted" often means "hashed," and the quality of the hashing matters enormously. A breach of bcrypt hashes is far less immediately dangerous than a breach of MD5 hashes or plaintext passwords.</p>

<h2>Identity attacks beyond passwords</h2>

<p><strong>Pass-the-hash</strong> — On Windows systems, password hashes are stored in memory and can be extracted by tools like Mimikatz when an attacker has administrator access. Rather than cracking the hash, the attacker uses it directly to authenticate to other systems — the protocol accepts the hash in place of the actual password. This technique is extensively used during lateral movement after an initial compromise.</p>

<p><strong>Pass-the-ticket</strong> — Similar to pass-the-hash but targeting Kerberos authentication tickets used in Windows Active Directory environments. Attackers can extract these tickets from memory and use them to impersonate users across the network.</p>

<p><strong>Token theft</strong> — Web applications use session tokens to maintain authenticated sessions. Once you log in, the server issues a token (typically stored in a cookie) that proves you are authenticated. If an attacker steals this token — through cross-site scripting, network interception, or malware — they can use it to access your account without knowing your password or completing MFA. This is why MFA does not protect against account takeover if an attacker can steal a valid session token.</p>

<p><strong>Account takeover via recovery</strong> — Password reset mechanisms are often the weakest link in authentication. "What is your mother's maiden name?" is trivially researched. SMS-based recovery is vulnerable to SIM swapping. Email-based recovery means that whoever controls the recovery email controls the account — making email account security critical for all other accounts.</p>

<h2>Common misconceptions about passwords and identity</h2>

<p><strong>"Complex password requirements improve security."</strong> Complexity requirements (must contain uppercase, lowercase, number, symbol) often make passwords harder to remember without making them harder to crack. Users respond to complexity requirements by making minimal changes: Password1! Password1@ Password1#. The result is predictable patterns that attackers' dictionaries already contain. Length requirements are more effective than complexity requirements.</p>

<p><strong>"Changing passwords regularly improves security."</strong> Mandatory regular password changes (change every 90 days) often produce weaker passwords because users make predictable incremental changes. NIST (the US National Institute of Standards and Technology) updated their guidelines in 2017 to recommend against mandatory periodic password changes unless there is evidence of compromise. Change passwords when they may have been compromised, not on a calendar.</p>

<p><strong>"Security questions add meaningful protection."</strong> Security questions are effectively a second, weaker password — one whose answers are often publicly available (mother's maiden name, high school mascot, first car). They provide a false sense of security while creating an easily exploitable recovery path. Where possible, use a random string as the answer and store it in your password manager.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-c2",
        "section": "C",
        "lesson_number": 12,
        "order": 12,
        "title": "Email Security and Phishing Investigation",
        "body": """<h2>Why email is the primary attack vector</h2>

<p>Email is the single most common initial attack vector in cybersecurity breaches. Phishing emails deliver malware, steal credentials, initiate business email compromise fraud, and are the starting point for the majority of ransomware infections. Understanding how email works, how it can be abused, and how to investigate suspicious messages is one of the most practical skills a security professional can have.</p>

<p>The reason email is so effective as an attack vector is that it combines technical exploitation with human psychology. An attacker does not need to find a software vulnerability — they just need to craft a convincing enough message that a human does something they should not.</p>

<h2>How email delivery works</h2>

<p>Understanding the email delivery process helps you understand where authentication checks occur and where attacks can be inserted.</p>

<ol>
<li><strong>Composition and sending</strong> — You write an email in your client (Outlook, Gmail) and click send. Your client connects to your organisation's mail server using SMTP (Simple Mail Transfer Protocol) on port 587 or 465.</li>
<li><strong>DNS lookup</strong> — Your mail server looks up the MX (Mail Exchange) record for the recipient's domain to find their mail server's address.</li>
<li><strong>Server-to-server delivery</strong> — Your mail server connects to the recipient's mail server using SMTP on port 25 and delivers the message.</li>
<li><strong>Retrieval</strong> — The recipient's mail client retrieves the message from their mail server using IMAP or POP3.</li>
</ol>

<p>The critical security problem with this design is that email was created in 1971 with no authentication — any server can claim to send from any address. The "From" field in an email is entirely unverified by the basic protocol. Anyone can send an email claiming to be from ceo@yourcompany.com without owning that domain.</p>

<p>Three DNS-based standards were developed to address this: SPF, DKIM, and DMARC.</p>

<h2>SPF — Sender Policy Framework</h2>

<p>SPF allows a domain owner to specify which mail servers are authorised to send email on behalf of their domain. This is done through a TXT record in the domain's DNS.</p>

<p>Example SPF record for example.com:</p>
<pre><code>v=spf1 include:_spf.google.com ip4:203.0.113.0/24 ~all</code></pre>

<p>This record says: email from example.com is legitimate if it comes from Google's mail servers (include:_spf.google.com) or from the IP range 203.0.113.0/24. The ~all at the end means "soft fail" — mail from other sources should be treated with suspicion but not automatically rejected.</p>

<p>When a receiving mail server gets an email claiming to be from example.com, it checks the SPF record and verifies whether the sending server's IP address is listed. If not, SPF fails.</p>

<p><strong>Limitation:</strong> SPF checks the server that sent the message, not the address shown in the "From" field that users see. An attacker can still send from a different domain with a valid SPF record and display your domain in the From field.</p>

<h2>DKIM — DomainKeys Identified Mail</h2>

<p>DKIM adds a cryptographic signature to outgoing emails. The sending mail server signs the message with a private key, and publishes the corresponding public key in DNS. Receiving servers verify the signature using the public key.</p>

<p>If the email was modified in transit — even a single character changed — the signature will not verify. DKIM therefore provides both authentication (this message was sent by someone controlling the domain's private key) and integrity (the message was not modified in transit).</p>

<p>When you view email headers and see <code>dkim=pass</code>, it means the DKIM signature was valid — the email genuinely came from the signing domain and was not modified.</p>

<h2>DMARC — Domain-based Message Authentication, Reporting and Conformance</h2>

<p>DMARC builds on SPF and DKIM by telling receiving servers what to do with messages that fail these checks. A DMARC policy is published in DNS and specifies:</p>
<ul>
<li>What to do with failing messages: none (take no action, just report), quarantine (send to spam), or reject (do not deliver)</li>
<li>Where to send reports of failed messages (giving domain owners visibility into who is sending on their behalf)</li>
</ul>

<p>Example DMARC record:</p>
<pre><code>v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com</code></pre>

<p>This says: reject messages that fail both SPF and DKIM, and send failure reports to dmarc-reports@example.com.</p>

<p>A domain with a strict DMARC policy (p=reject) makes it very difficult to spoof that domain — receiving servers will reject messages that do not pass authentication. Many major email providers (Google, Microsoft) have strict DMARC policies, which is why phishing emails claiming to be from gmail.com or microsoft.com typically use lookalike domains instead.</p>

<h2>Reading email headers — the key skill</h2>

<p>Email headers contain metadata about a message's journey from sender to recipient. They are the primary source of evidence in a phishing investigation. Headers are typically hidden by default but can be viewed in most email clients.</p>

<p>In Gmail: Open the email → click the three dots menu → "Show original"<br>
In Outlook: Open the email → File → Properties → "Internet headers"</p>

<p>Key headers to examine:</p>

<p><strong>From:</strong> — The sender's display name and email address. This is what users see. It can be completely fabricated — the display name can be anything, and in many clients, the email address is only shown if you hover over or click on the name. Attackers use this to display "PayPal Security Team" while the actual email address is something like support@random-domain.xyz.</p>

<p><strong>Reply-To:</strong> — If set, replies go to this address rather than the From address. Attackers use this to display a legitimate-looking From address while directing replies (and potentially credentials from link clicks) to an attacker-controlled address.</p>

<p><strong>Received:</strong> — Each mail server that handled the message adds a Received header. Read these from bottom to top to trace the message's journey. The bottom-most Received header was added by the first server that touched the message — the closest to the actual origin. The top-most was added by the receiving server.</p>

<p><strong>Authentication-Results:</strong> — Added by the receiving server, this shows the results of SPF, DKIM, and DMARC checks. This is the most important header for determining whether a message is legitimate.</p>

<p>Example of a suspicious authentication-results header:</p>
<pre><code>Authentication-Results: mx.google.com;
   spf=fail (google.com: domain of support@paypal-verify.net does not designate 
   185.220.101.42 as permitted sender) smtp.mailfrom=support@paypal-verify.net;
   dkim=none;
   dmarc=fail (p=REJECT)</code></pre>

<p>This tells us: SPF failed (the sending IP is not authorised for this domain), no DKIM signature was present, and DMARC failed. This email is almost certainly fraudulent.</p>

<h2>Phishing investigation — a step-by-step process</h2>

<p>When you receive a suspicious email, here is how to investigate it systematically without putting yourself at risk:</p>

<p><strong>Step 1: Do not click anything.</strong> Do not click links, open attachments, or reply. The investigation must be done safely.</p>

<p><strong>Step 2: Check the actual sender address.</strong> Look beyond the display name. Is the email address from the expected domain? Is the domain a lookalike (paypa1.com, microsoft-support.net)? Does the domain match what the email claims to be?</p>

<p><strong>Step 3: View the full headers.</strong> Check the authentication results — did SPF, DKIM, and DMARC pass? Trace the Received headers to see where the message actually originated. Look at the Reply-To address.</p>

<p><strong>Step 4: Examine links without clicking.</strong> Hover over links to see the actual URL (visible in the status bar). Look for mismatched domains, URL shorteners, or domains you do not recognise. If you need to analyse a URL, use urlscan.io or VirusTotal — they will visit the URL in a safe environment and show you what it leads to.</p>

<p><strong>Step 5: Check the originating IP.</strong> From the Received headers, identify the IP address of the originating server. Look it up on AbuseIPDB (abuseipdb.com) to see if it has been reported for sending spam or phishing. Look it up on VirusTotal to check against threat intelligence.</p>

<p><strong>Step 6: Analyse attachments safely.</strong> Do not open attachments. If you need to analyse them, use VirusTotal — you can upload a file or submit a hash. If the file is sensitive and should not be uploaded to a public service, use a sandboxed environment.</p>

<p><strong>Step 7: Consider the context.</strong> Did you expect this email? Does the request make sense? Is there urgency or pressure? Urgency and fear are the primary emotional levers phishing emails use.</p>

<h2>Common phishing techniques</h2>

<p><strong>Spear phishing</strong> — Targeted phishing using personal information gathered from LinkedIn, social media, company websites, or previous breaches. Instead of a generic "Dear Customer," a spear phishing email addresses you by name, references your employer, mentions a colleague, or references a recent event. The personalisation dramatically increases the success rate.</p>

<p><strong>Business Email Compromise (BEC)</strong> — Impersonating executives or trusted partners to request fraudulent wire transfers or gift card purchases. The attacker either compromises the executive's actual email account or uses a lookalike domain. A typical BEC email: "Hi [name], I am in a meeting and cannot talk. Please process an urgent wire transfer of £45,000 to this account by end of day. I will explain later. Do not discuss with anyone else." The urgency, authority, and secrecy are all designed to bypass normal verification processes.</p>

<p>BEC attacks have caused over $50 billion in losses globally. The average BEC loss per incident is over $130,000. These attacks succeed not through technical sophistication but through social engineering.</p>

<p><strong>Smishing</strong> — Phishing via SMS. "Your package is being held — click here to reschedule delivery." Or "Your bank account has been frozen — verify your details immediately." Text messages feel more personal and urgent than emails, and users are less trained to be suspicious of them.</p>

<p><strong>Vishing</strong> — Phishing via voice call. Attackers call victims claiming to be from their bank, IT support, HMRC, or the police, using urgency and authority to extract information or credentials. AI voice cloning has made this significantly more sophisticated — attackers can clone the voice of a CEO or colleague to make vishing calls more convincing.</p>

<p><strong>Quishing</strong> — Phishing via QR code. A QR code in a physical location or email directs to a malicious URL. Users are generally less suspicious of QR codes than links, and QR code destination URLs are not visible before scanning.</p>

<h2>Common misconceptions</h2>

<p><strong>"I can tell a phishing email by poor grammar."</strong> Historically, phishing emails often had spelling errors and broken English. Modern attacks — especially spear phishing and AI-generated campaigns — are indistinguishable from legitimate communications in terms of language quality. Grammar is an unreliable indicator.</p>

<p><strong>"The padlock means the site is genuine."</strong> As discussed in the previous lesson — HTTPS means encrypted, not trustworthy. Phishing sites routinely use HTTPS. The padlock tells you nothing about whether the site is legitimate.</p>

<p><strong>"We have email filtering, so phishing emails cannot reach us."</strong> Email filtering blocks a large proportion of phishing attempts, but attackers continuously evolve to evade filters. Some percentage of phishing always gets through. Human awareness and clear reporting procedures are necessary layers alongside technical filtering.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-c3",
        "section": "C",
        "lesson_number": 13,
        "order": 13,
        "title": "Secure Browsing and Website Trust",
        "body": """<h2>The browser as an attack surface</h2>

<p>Your web browser is the most complex piece of software most people use daily, and consequently one of the largest attack surfaces on any device. The browser executes code from thousands of websites, handles sensitive data including passwords and payment information, and has deep integration with the underlying operating system.</p>

<p>Understanding how to assess website security, what browser security features protect you, and what practices reduce your risk is practical knowledge that applies both personally and professionally — security professionals are frequently asked to assess websites and advise users.</p>

<h2>HTTPS — what it actually provides</h2>

<p>HTTPS (HTTP Secure) adds TLS encryption to standard HTTP web traffic. When you connect to an HTTPS site, two things happen: an encrypted channel is established (so traffic cannot be read by someone intercepting it), and the server's identity is verified (through its TLS certificate).</p>

<p><strong>What HTTPS guarantees:</strong></p>
<ul>
<li>Traffic between your browser and the server is encrypted — an attacker who intercepts the traffic cannot read it</li>
<li>The server controls the domain name in the certificate — you are communicating with the server that owns example.com, not an impostor</li>
<li>The certificate was issued by a trusted Certificate Authority (CA) that performed some level of verification</li>
</ul>

<p><strong>What HTTPS does not guarantee:</strong></p>
<ul>
<li>The website is safe or legitimate</li>
<li>The website will not steal your data</li>
<li>The organisation behind the website is trustworthy</li>
<li>The content of the site is not malicious</li>
</ul>

<p>The padlock has been catastrophically misrepresented in security awareness training. For years, users were told "look for the padlock — it means the site is safe." This is false. It means the connection is encrypted. A phishing site, a malware distribution site, and a fraudulent shopping site can all have valid HTTPS certificates and show a padlock.</p>

<p>Over 83% of phishing sites now use HTTPS. The padlock should not be trusted as a safety indicator — the domain name is what matters.</p>

<h2>TLS certificate types and what they verify</h2>

<p><strong>Domain Validated (DV)</strong> — The Certificate Authority (CA) verifies only that the applicant controls the domain. This is done automatically through DNS records or file uploads to the server. DV certificates are free (Let's Encrypt) or cheap, issued in minutes, and verify nothing about the organisation behind the domain. The vast majority of phishing sites use DV certificates.</p>

<p><strong>Organisation Validated (OV)</strong> — The CA verifies the domain and also confirms the legal existence of the organisation. This involves checking business registration records. OV certificates take longer to issue and cost more. The organisation's name is included in the certificate details (visible by clicking the padlock in most browsers).</p>

<p><strong>Extended Validation (EV)</strong> — The most rigorous verification. The CA performs extensive checks on the organisation's identity, legal standing, and physical existence. EV certificates historically displayed the organisation name prominently in the browser address bar, but most modern browsers have removed this visual distinction. EV certificates are most commonly used by banks and financial institutions.</p>

<p>For assessing whether a site is genuine: check the domain name precisely (not just the organisation name, which can be spoofed in display), look at the certificate details (who issued it, what organisation is listed), and consider whether the domain is what you would expect for this organisation.</p>

<h2>Assessing website trustworthiness</h2>

<p>When assessing whether a website can be trusted — whether you are shopping, logging in, or evaluating a site for security purposes — consider these factors:</p>

<p><strong>The domain name</strong> — Is it what you would expect? A website claiming to be PayPal at paypal-security-verify.com is suspicious. Look for:</p>
<ul>
<li>Lookalike domains (paypa1.com, paypal.com.account-verify.net — the actual domain is account-verify.net)</li>
<li>Hyphens added to legitimate names (pay-pal.com, microsoft-support.com)</li>
<li>Wrong TLD (paypal.net instead of paypal.com)</li>
<li>Subdomain tricks (paypal.com.malicious-domain.com — the actual domain is malicious-domain.com)</li>
</ul>

<p><strong>Domain age</strong> — Newly registered domains are high risk. Attackers register domains specifically for phishing campaigns and use them briefly before they are blocklisted. You can check domain registration date using whois lookup tools.</p>

<p><strong>The certificate</strong> — Who issued it? Is the organisation name what you would expect? A DV certificate on a site claiming to be a major bank is a warning sign.</p>

<p><strong>Content quality</strong> — Poor grammar, low-quality images, generic stock photos, and inconsistent formatting can indicate a fraudulent site. However, sophisticated phishing sites copy legitimate sites exactly, so this is not a reliable indicator.</p>

<p><strong>Contact information</strong> — No phone number, no physical address, no verifiable company registration are warning signs for commercial sites.</p>

<p><strong>WHOIS information</strong> — Is the domain registration information hidden (privacy protection) or does it show a clearly legitimate registrant? For major brands, you would expect to see corporate registration information, not privacy-protected personal registrations.</p>

<h2>Browser security features and settings</h2>

<p><strong>Keep your browser updated.</strong> Browser vulnerabilities are among the most actively exploited software flaws. Attackers use drive-by download attacks — visiting a malicious website with a vulnerable browser can result in malware installation without any user interaction beyond visiting the page. Modern browsers update automatically; ensure this is enabled.</p>

<p><strong>Use a reputable ad blocker.</strong> Malvertising — delivering malware through advertising networks — is a significant threat vector. Malicious ads can redirect users to exploit pages or directly serve malware. Ad blockers like uBlock Origin block these ads before they load, significantly reducing exposure to this attack vector. This is one of the most impactful security improvements an average user can make.</p>

<p><strong>Be cautious with browser extensions.</strong> Extensions can read and modify content on every page you visit — they have access to your passwords, banking information, and everything else. Only install extensions from sources you trust, and periodically audit what extensions are installed. Extensions that are sold or transferred to new developers have been used to distribute malware to all existing users.</p>

<p><strong>Use a DNS-based content filter.</strong> DNS filtering blocks known malicious domains at the DNS level — before your browser even connects. Services like Cloudflare 1.1.1.1 for Families (1.1.1.2) or Quad9 (9.9.9.9) provide free DNS filtering that blocks access to domains known to distribute malware or host phishing sites.</p>

<p><strong>Enable Enhanced Safe Browsing (Chrome) or equivalent.</strong> Most major browsers have built-in phishing and malware protection that warns you before visiting known dangerous sites. Ensure this is enabled.</p>

<h2>Privacy considerations</h2>

<p><strong>Third-party cookies</strong> track your activity across websites. When a news site includes a Facebook "Like" button, Facebook can see that you visited that page even if you did not click the button — the request to load the button is itself tracking. This cross-site tracking builds detailed profiles of browsing behaviour.</p>

<p><strong>Browser fingerprinting</strong> identifies users based on technical characteristics without cookies — your screen resolution, fonts, browser version, time zone, hardware capabilities, and other attributes can be combined to create a unique fingerprint that persists even if you clear cookies. Even in private/incognito mode, fingerprinting works.</p>

<p>From a security perspective, extensive tracking creates data about user behaviour that can be exploited — if an attacker obtains your browsing history, they know your interests, behaviours, and potentially when you are not home.</p>

<p>Privacy-focused alternatives: Firefox with privacy settings configured, Brave browser (built on Chrome but with tracking protection built in). The Tor Browser provides the strongest privacy but is significantly slower.</p>

<h2>Public Wi-Fi and man-in-the-middle attacks</h2>

<p>On public Wi-Fi — in coffee shops, airports, hotels — your traffic travels through a network you do not control. A malicious actor on the same network, or who controls the access point itself, can potentially intercept your traffic.</p>

<p>HTTPS protects most modern web traffic because it is encrypted end-to-end. However, risks on public Wi-Fi include:</p>
<ul>
<li>Connecting to a malicious access point that impersonates a legitimate one (evil twin attack)</li>
<li>SSL stripping attacks that downgrade HTTPS connections to HTTP (mitigated by HSTS)</li>
<li>Interception of unencrypted traffic (applications that do not use HTTPS)</li>
</ul>

<p>Using a VPN on public Wi-Fi encrypts all traffic before it leaves your device, protecting against interception at the network level. However, VPN providers can see your traffic — choose a reputable provider with a verified no-logs policy, or use your organisation's corporate VPN.</p>

<h2>Common misconceptions</h2>

<p><strong>"Incognito/private browsing makes me anonymous."</strong> Private browsing prevents your browser from storing history, cookies, and form data locally — it does not make you anonymous online. Your ISP, employer, and the websites you visit can still see your traffic. Private browsing is useful for preventing local history storage (on a shared computer), not for anonymity.</p>

<p><strong>"A website cannot harm me if I do not download anything."</strong> Drive-by downloads — malware installed through visiting a malicious page without any user action — are real and actively exploited. A vulnerable browser visiting a page serving an exploit kit can result in malware installation without downloading anything explicitly. Keeping browsers updated is the primary defence.</p>

<p><strong>"I use a Mac/Linux so I am safe from web-based attacks."</strong> While Windows has historically been the primary target for malware, phishing and credential theft work regardless of operating system — you are always the target, not just your device. And Mac and Linux malware is increasingly common as adoption of these systems grows.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-c4",
        "section": "C",
        "lesson_number": 14,
        "order": 14,
        "title": "Malware Basics and How Infections Happen",
        "body": """<h2>What malware is</h2>

<p>Malware — malicious software — is any software designed to damage, disrupt, gain unauthorised access to, or exfiltrate data from systems it infects. It is not a single thing but a broad category encompassing many different types with different behaviours, objectives, and delivery mechanisms.</p>

<p>Understanding the different types of malware, how infections occur, and how they can be detected and prevented is foundational security knowledge — whether you are investigating an incident, advising on defences, or simply trying to understand what happened when a system is compromised.</p>

<h2>Types of malware</h2>

<p><strong>Virus</strong> — Attaches itself to legitimate files and replicates when those files are executed. When an infected file runs, the virus copies itself into other files. Viruses require user action — running an infected file — to spread. Classic file-infecting viruses are less common than they used to be, having been largely supplanted by more sophisticated threats.</p>

<p><strong>Worm</strong> — Replicates across networks without requiring user action, exploiting vulnerabilities to spread automatically. WannaCry was a worm — once it infected one machine, it automatically scanned the network for other vulnerable systems and infected them without any user interaction. Worms can spread across entire organisations in minutes.</p>

<p><strong>Trojan</strong> — Disguised as legitimate software, a trojan performs malicious actions when executed. Unlike viruses, trojans do not self-replicate — they rely on users installing them, deceived by the legitimate appearance. A pirated application, a fake PDF reader, or a game downloaded from an unofficial source might be a trojan containing a Remote Access Trojan (RAT) that gives attackers persistent access.</p>

<p><strong>Ransomware</strong> — Encrypts files on the victim's system and demands payment for the decryption key. Modern ransomware operations are sophisticated criminal enterprises. The Conti group, before being disrupted, had structured teams for development, operations, and negotiations. "Double extortion" ransomware also exfiltrates data before encrypting it — attackers threaten to publish the data if the ransom is not paid, creating pressure even for victims with good backups.</p>

<p><strong>Real-world example: the NHS WannaCry infection</strong></p>

<p>In May 2017, WannaCry ransomware infected approximately 80 of 236 NHS trusts in England. Unpatched Windows XP systems (for which Microsoft had released a patch but many NHS computers had not applied it) were encrypted. 19,000 appointments were cancelled. Several hospitals had to divert ambulances. The estimated cost was £92 million.</p>

<p>The patch that would have prevented the infection had been available for two months. The vulnerability was known. The failure was not technical sophistication — it was patch management.</p>

<p><strong>Spyware</strong> — Monitors user activity and exfiltrates information without the user's knowledge. Keyloggers capture every keystroke — capturing passwords, credit card numbers, and sensitive communications. Screen capture spyware records what is displayed. Banking trojans specifically target financial application interactions to steal credentials and intercept transactions.</p>

<p><strong>Rootkit</strong> — Designed to hide the presence of malware from the operating system and security tools. A rootkit modifies the OS itself — altering system calls, hiding processes, files, and network connections. A rootkit-infected system effectively lies to its owner about its own state. Detecting and removing rootkits often requires booting from external media to bypass the compromised OS.</p>

<p><strong>Fileless malware</strong> — Does not write files to disk, instead running entirely in memory using legitimate system tools (PowerShell, WMI, cmd.exe). Because there is no malicious file for antivirus to scan, traditional signature-based detection is largely ineffective. Fileless malware is increasingly common in sophisticated attacks because it evades many security controls. It only persists until the system is rebooted, but attackers establish other persistence mechanisms.</p>

<p><strong>Botnet</strong> — A network of compromised machines controlled by a command-and-control server. Individual infected machines (bots or zombies) receive instructions and perform tasks: sending spam, participating in DDoS attacks, mining cryptocurrency, or spreading further infections. The Mirai botnet, which caused the 2016 DDoS attack that knocked out major websites, consisted of approximately 600,000 compromised IoT devices.</p>

<p><strong>Adware and potentially unwanted programs (PUPs)</strong> — Software that displays unwanted advertisements or collects data. Often installed through bundling with legitimate software. Usually more annoying than dangerous, but can serve as a delivery mechanism for more serious malware.</p>

<h2>How infections happen — delivery mechanisms</h2>

<p><strong>Phishing</strong> — The most common initial infection vector. A malicious email contains either a link to a site that delivers malware or an attachment that, when opened, executes malicious code. Common malicious attachment types include:</p>
<ul>
<li>Office documents with malicious macros — when the user enables macros, the macro downloads and runs malware</li>
<li>PDF files with embedded exploits targeting vulnerabilities in PDF readers</li>
<li>Archive files (ZIP, RAR) containing malicious executables disguised as other file types</li>
<li>LNK files (Windows shortcuts) that execute malicious commands when opened</li>
</ul>

<p><strong>Drive-by downloads</strong> — Visiting a compromised or malicious website can trigger malware installation without any user interaction, by exploiting vulnerabilities in the browser, browser plugins (Flash, Java), or the operating system. This is why browser and plugin updates are critical — the attack surface is reduced with every patch.</p>

<p><strong>Malicious downloads</strong> — Software downloaded from unofficial sources: pirated applications, keygens, cracked games, and fake software updates. These are extremely high-risk downloads because the user is explicitly running software of unknown provenance.</p>

<p><strong>Supply chain compromise</strong> — Malware inserted into legitimate software during development or distribution, so that users who download and install legitimate-looking software unknowingly install malware. The SolarWinds attack was a supply chain compromise — malicious code was inserted into legitimate software updates. This attack vector is particularly dangerous because users are doing the right thing (installing software updates) and still become infected.</p>

<p><strong>Removable media</strong> — USB drives containing malware. The Stuxnet worm, which damaged Iranian nuclear centrifuges, was delivered via USB drives into air-gapped (internet-isolated) systems. Autorun features (now largely disabled by default in modern Windows) previously executed code automatically when a drive was inserted.</p>

<p><strong>Exposed remote services</strong> — Brute-forcing or exploiting vulnerabilities in services exposed to the internet: RDP (Remote Desktop Protocol), SSH, VPN endpoints. Ransomware groups frequently gain initial access by brute-forcing exposed RDP services or exploiting unpatched VPN vulnerabilities.</p>

<h2>Malware persistence mechanisms</h2>

<p>After infection, malware needs to survive system reboots to maintain access. Common persistence mechanisms:</p>

<ul>
<li><strong>Registry Run keys</strong> (Windows) — Entries in HKEY_CURRENT_USER\...\Run or HKEY_LOCAL_MACHINE\...\Run cause the malware to execute at login</li>
<li><strong>Scheduled tasks</strong> (Windows) / Cron jobs (Linux) — Malware creates a task that runs at specified intervals</li>
<li><strong>Windows services</strong> — Malware installs itself as a service that starts automatically</li>
<li><strong>Startup scripts</strong> — Malware adds itself to startup directories or login scripts</li>
<li><strong>Boot sector modification</strong> — Some sophisticated malware modifies the boot sector, executing before the OS loads</li>
</ul>

<p>Checking these locations during an investigation is standard practice — they are the first places to look for evidence of persistent malware.</p>

<h2>Indicators of compromise (IoCs)</h2>

<p>Indicators of compromise are evidence that a system may have been compromised. They fall into several categories:</p>

<ul>
<li><strong>File-based</strong>: malicious file hashes, unusual files in temp directories, modified system files</li>
<li><strong>Network-based</strong>: connections to known malicious IP addresses, unusual outbound traffic, DNS queries to newly registered or suspicious domains</li>
<li><strong>Host-based</strong>: unusual processes, unexpected registry modifications, new scheduled tasks, unusual user accounts</li>
<li><strong>Behavioural</strong>: unexpected administrative tool usage, lateral movement between systems, large data transfers</li>
</ul>

<h2>Malware defences</h2>

<p><strong>Endpoint Detection and Response (EDR)</strong> — Modern endpoint security that monitors behaviour rather than just matching signatures. EDR tools look for suspicious patterns: a Word document spawning PowerShell, a process injecting code into another process, unusual registry modifications. EDR can detect novel malware that has never been seen before because it is looking at what the code does, not what it looks like.</p>

<p><strong>Application control (allowlisting)</strong> — Only permits pre-approved applications to run. Any executable not on the approved list is blocked. This prevents malware from executing even if it is delivered successfully. Challenging to manage in large environments but extremely effective.</p>

<p><strong>Email filtering</strong> — Blocks malicious attachments and links before they reach users. Modern email security systems detonate attachments in sandboxed environments — they execute the file in an isolated virtual machine to observe its behaviour before deciding whether to deliver it.</p>

<p><strong>Patching</strong> — Removes the vulnerabilities that exploit-based delivery mechanisms rely on. Many malware infections could have been prevented by applying available patches.</p>

<p><strong>Network monitoring</strong> — Detects the command-and-control traffic that malware uses to receive instructions and exfiltrate data. Malware needs to communicate. Detecting unusual outbound connections, DNS queries to suspicious domains, or large unexpected data transfers can identify infections before significant damage is done.</p>

<h2>Common misconceptions</h2>

<p><strong>"Antivirus will protect against all malware."</strong> Traditional antivirus detects known malware by matching signatures — patterns in the file that match previously seen malware. This is ineffective against new malware (zero-day), modified variants of known malware, and fileless malware that does not write files to disk. EDR is significantly more effective but antivirus remains a useful baseline layer.</p>

<p><strong>"I can tell if my computer is infected."</strong> Modern malware is designed to be invisible. It does not display symptoms, does not slow down the computer noticeably, and does not announce its presence. A system can be actively exfiltrating data, participating in DDoS attacks, or serving as a pivot point for attacking other systems while the user notices nothing. Many infections are only discovered weeks or months later.</p>

<p><strong>"Malware only affects Windows."</strong> Windows is the most common target because of its market share, but malware exists for macOS, Linux, Android, and iOS. Linux servers are regularly compromised and turned into cryptocurrency miners or botnet members. macOS malware has become increasingly sophisticated as Mac adoption in enterprises has grown.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-c5",
        "section": "C",
        "lesson_number": 15,
        "order": 15,
        "title": "Logging, Alerts, and Incident Basics",
        "body": """<h2>Why logging is the foundation of security visibility</h2>

<p>Logs are the primary source of evidence in security investigations, the basis for detecting attacks in progress, and the record that allows you to reconstruct what happened after a breach. Without logs, security is blind — you cannot detect what you cannot see, and you cannot investigate what was not recorded.</p>

<p>The importance of logging is consistently underestimated until an incident occurs and investigators discover that critical information was not being logged. At that point, it is too late. The time to think about what needs to be logged is before an incident, not during one.</p>

<h2>What should be logged and why</h2>

<p><strong>Authentication events</strong> — Who logged in, when, from where, using what method, and whether the attempt succeeded or failed. Authentication logs are the most important category for most investigations because attackers need to authenticate to do almost anything — or their failures to authenticate reveal their attempts.</p>

<p>What to capture: successful and failed logins, account lockouts, password changes, MFA events, privilege escalation, account creation and deletion.</p>

<p><strong>Network traffic logs</strong> — What connections were made, between which addresses, on which ports, with how much data transferred. Network logs reveal lateral movement, data exfiltration, and command-and-control communication.</p>

<p>Types of network logs:</p>
<ul>
<li><strong>Firewall logs</strong> — what traffic was allowed or blocked at the perimeter</li>
<li><strong>DNS logs</strong> — what domain names were queried by which systems. DNS is often overlooked but is one of the most valuable log sources — every network connection starts with a DNS query, and malware that uses DNS tunnelling or connects to command-and-control infrastructure will leave traces in DNS logs</li>
<li><strong>Proxy logs</strong> — HTTP/HTTPS requests made through a web proxy, providing visibility into web browsing at the organisation level</li>
<li><strong>NetFlow</strong> — metadata about network connections (who talked to whom, when, how much data) without the actual content</li>
</ul>

<p><strong>Endpoint logs</strong> — What happened on individual devices: processes that ran, files that were created or modified, registry changes, scheduled tasks created. On Windows, the Event Log provides this. On Linux, /var/log/ files. EDR tools provide significantly more detailed endpoint visibility.</p>

<p><strong>Application logs</strong> — What happened within applications: web server access logs, database query logs, application authentication events. Web server access logs capture every HTTP request — who requested what, from where, the response code, and how much data was transferred. These logs can reveal scanning, injection attempts, and exploitation.</p>

<h2>Key Windows Event IDs — expanded</h2>

<table>
<thead>
<tr><th>Event ID</th><th>Description</th><th>Investigation value</th></tr>
</thead>
<tbody>
<tr><td>4624</td><td>Successful logon</td><td>Logon type 3 (network) at unusual hours or from unexpected locations is suspicious</td></tr>
<tr><td>4625</td><td>Failed logon</td><td>Many failures from one source = brute force; failures across many accounts = spraying</td></tr>
<tr><td>4648</td><td>Logon with explicit credentials</td><td>Common in pass-the-hash and lateral movement — an account using another account's credentials</td></tr>
<tr><td>4672</td><td>Special privileges assigned</td><td>Administrator-equivalent access granted — should only occur for known admin accounts</td></tr>
<tr><td>4688</td><td>Process creation</td><td>The most valuable event for detecting malicious activity — shows every program that ran</td></tr>
<tr><td>4698</td><td>Scheduled task created</td><td>Persistence mechanism — attackers create tasks to maintain access through reboots</td></tr>
<tr><td>4720</td><td>User account created</td><td>Attackers create backdoor accounts — any unexpected account creation is significant</td></tr>
<tr><td>4726</td><td>User account deleted</td><td>Attackers may delete evidence of their activities</td></tr>
<tr><td>4740</td><td>Account locked out</td><td>Brute force or spraying indicator</td></tr>
<tr><td>4776</td><td>Credential validation</td><td>NTLM authentication — pass-the-hash attacks show here</td></tr>
<tr><td>7045</td><td>New service installed</td><td>Malware that installs as a service to maintain persistence</td></tr>
</tbody>
</table>

<h2>SIEM — Security Information and Event Management</h2>

<p>A SIEM is a platform that collects logs from across the entire environment — endpoints, network devices, servers, applications, cloud services — normalises them into a common format, and provides tools for searching, correlating, and alerting.</p>

<p>The value of a SIEM is correlation: detecting patterns that span multiple systems. A single failed login is noise. 500 failed logins from the same IP against 50 different accounts over 10 minutes is a password spraying attack. A SIEM can detect this pattern in real time, where manual log review never would.</p>

<p>SIEM use cases:</p>
<ul>
<li><strong>Real-time alerting</strong> — triggering alerts when correlation rules detect suspicious patterns</li>
<li><strong>Investigation support</strong> — searching across all log sources to reconstruct what an attacker did</li>
<li><strong>Threat hunting</strong> — proactively searching for indicators of compromise that did not trigger alerts</li>
<li><strong>Compliance reporting</strong> — demonstrating that required logging is in place and generating evidence for audits</li>
</ul>

<p>Common SIEM platforms: Splunk (industry standard, expensive), Microsoft Sentinel (cloud-native, integrates well with Microsoft environments), IBM QRadar, and open-source options like Elastic Security (ELK Stack) and Wazuh.</p>

<h2>Incident response — the lifecycle</h2>

<p>Incident response is the structured approach to handling security incidents. Having a defined process before an incident occurs — practiced through exercises and tabletop simulations — is what separates organisations that recover quickly from those that struggle for months.</p>

<p><strong>Phase 1: Preparation</strong></p>

<p>Preparation is everything that happens before an incident. Policies defining what constitutes an incident and how it should be handled. An incident response team with defined roles. Tools and access pre-configured. Communication plans established. Contact lists maintained and tested. Tabletop exercises that walk through hypothetical scenarios.</p>

<p>The most common failure in incident response is discovering that critical decisions — who has authority to take a system offline, who contacts law enforcement, who talks to the press — were never made before the incident. Under pressure, with an attacker active in your systems, is the worst time to have these discussions.</p>

<p><strong>Phase 2: Detection and Analysis</strong></p>

<p>Identifying that an incident has occurred and understanding what happened. Detection comes from SIEM alerts, EDR alerts, user reports, external notifications (law enforcement, security researchers), or visible symptoms (encrypted files, defaced websites, suspicious transactions).</p>

<p>Analysis determines scope: what systems are affected, what data may have been accessed or stolen, how the attacker got in, and what they have done. This phase can take hours to days and requires careful evidence collection.</p>

<p><strong>Phase 3: Containment</strong></p>

<p>Stopping the spread and limiting the damage. Containment decisions involve trade-offs: isolating a compromised system stops the attacker but may also stop business operations. Shutting down a server destroys volatile evidence (memory contents) but may be necessary to prevent further damage.</p>

<p>Short-term containment (immediate actions to stop bleeding) and long-term containment (sustainable measures that allow business to continue while the incident is resolved) are distinct phases.</p>

<p><strong>Phase 4: Eradication</strong></p>

<p>Removing the attacker's presence from the environment. This includes: removing malware, closing the initial access point, removing backdoor accounts, revoking compromised credentials, and addressing the vulnerabilities that allowed the attack. Eradication must be thorough — leaving any foothold allows the attacker to regain access.</p>

<p><strong>Phase 5: Recovery</strong></p>

<p>Restoring systems to normal operation. This involves rebuilding compromised systems from clean images, restoring data from known-good backups, validating that systems are clean, and gradually returning to normal operations with enhanced monitoring.</p>

<p><strong>Phase 6: Post-Incident Activity (Lessons Learned)</strong></p>

<p>After the incident is resolved, a structured review of what happened, what went well, what went poorly, and what changes should be made. This review should produce concrete action items, not just a retrospective narrative. The goal is to ensure the same incident cannot occur again.</p>

<h2>Evidence handling — critical principles</h2>

<p>Evidence collected during an incident must be handled correctly to be useful in any subsequent legal proceedings and to maintain its integrity as an investigative record.</p>

<p><strong>Preserve before analysing.</strong> Create forensic images — byte-for-byte copies — of storage media before examining them. Work from the copy, not the original. Examining an original disk can modify timestamps and other metadata, potentially contaminating evidence.</p>

<p><strong>Capture volatile data first.</strong> Memory (RAM) contents, active network connections, and running processes are lost when a system is powered off. These must be captured before any other action if they are needed for the investigation.</p>

<p><strong>Document everything.</strong> Record every action taken during the investigation with timestamps, who performed the action, and what was observed. This creates the investigation record and supports any legal proceedings.</p>

<p><strong>Chain of custody.</strong> Maintain a record of everyone who had access to evidence. This demonstrates that evidence has not been tampered with and is admissible in legal proceedings.</p>

<h2>Common misconceptions</h2>

<p><strong>"We will know immediately if we are breached."</strong> The average dwell time — the period between initial compromise and detection — exceeds 200 days. Many organisations are notified of breaches by law enforcement, journalists, or security researchers who found their data for sale, not by their own monitoring systems. Logging and SIEM improve detection time, but without them, many breaches are never detected.</p>

<p><strong>"We should shut everything down immediately to contain the breach."</strong> Immediate shutdown destroys volatile evidence and may cause more damage than the attack itself — especially for ransomware where the encryption may already be complete. Containment decisions require understanding the situation first. The impulse to "pull the plug" must be balanced against preserving evidence and maintaining business continuity.</p>

<p><strong>"Incident response is a technical function only."</strong> Incident response involves legal, communications, human resources, executive leadership, and potentially law enforcement and regulators. Who talks to the media? When do you notify regulators (GDPR requires notification within 72 hours)? When do you notify affected individuals? Do you involve law enforcement? These decisions require organisational coordination far beyond the technical response team.</p>""",
        "lab": """<h2>Practical Lab: Phishing Email Investigation</h2>

<p>This lab walks you through investigating a suspicious email using the techniques from Section C. Work through each step using the sample headers provided, then apply the same process to a real suspicious email from your spam folder.</p>

<h3>Sample email to investigate</h3>

<pre><code>From: "PayPal Security Team" &lt;security@paypal-account-verify.net&gt;
Reply-To: collect@data-harvest.xyz
Subject: Urgent: Your PayPal account has been limited - Action Required
Date: Mon, 30 Mar 2026 03:42:15 +0000

Received: from mail.suspicious-domain.xyz (mail.suspicious-domain.xyz [185.220.101.42])
        by mx.google.com with ESMTP id a12si1234567qkd.45.2026.03.30
        for &lt;victim@gmail.com&gt;;
        Mon, 30 Mar 2026 03:42:17 +0000

Authentication-Results: mx.google.com;
   spf=fail (google.com: domain of security@paypal-account-verify.net does not
   designate 185.220.101.42 as permitted sender)
   smtp.mailfrom=security@paypal-account-verify.net;
   dkim=none (message not signed);
   dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal-account-verify.net</code></pre>

<h3>Step 1: Analyse the From address</h3>

<p>Answer these questions:</p>
<ol>
<li>What display name does the email show?</li>
<li>What is the actual email address (not the display name)?</li>
<li>Is the domain paypal.com? What is it instead?</li>
<li>Is the domain a convincing lookalike? What makes it suspicious?</li>
</ol>

<h3>Step 2: Check the Reply-To</h3>

<ol>
<li>What is the Reply-To address?</li>
<li>If you replied to this email, where would your reply go?</li>
<li>What does this tell you about the attacker's intent?</li>
</ol>

<h3>Step 3: Trace the origin</h3>

<ol>
<li>What IP address did this email originate from? (Find it in the Received header)</li>
<li>Visit abuseipdb.com and search for 185.220.101.42. What does the database show about this IP? How many reports are there and for what type of activity?</li>
<li>Visit virustotal.com and search for the same IP. What do the threat intelligence feeds say?</li>
</ol>

<h3>Step 4: Interpret the authentication results</h3>

<ol>
<li>Did SPF pass or fail? What does this mean?</li>
<li>Was DKIM present? What does the absence of DKIM tell you?</li>
<li>What was the DMARC result? What action does PayPal's DMARC policy specify (p=REJECT)?</li>
<li>Based on authentication results alone, is this email legitimate?</li>
</ol>

<h3>Step 5: Write your assessment</h3>

<p>Write a brief incident summary (3-5 sentences) covering:</p>
<ul>
<li>What type of attack this is</li>
<li>The indicators that identify it as malicious</li>
<li>What the attacker's likely objective is</li>
<li>What action you would take (report to IT security, block the domain, etc.)</li>
</ul>

<h3>Step 6: Investigate a real email</h3>

<p>Find a suspicious email in your spam folder (do not open any attachments or click any links). Using your email client's "show original" or "view headers" feature:</p>

<ol>
<li>Identify the actual sender address and domain</li>
<li>Check the authentication results (SPF, DKIM, DMARC)</li>
<li>Trace the originating IP address from the Received headers</li>
<li>Look up the originating IP on AbuseIPDB</li>
<li>Write a brief assessment: phishing, spam, or legitimate?</li>
</ol>

<h3>Reflection questions</h3>

<ol>
<li>Why do phishing emails often use display names that look legitimate even when the actual email address is suspicious?</li>
<li>If an email passes SPF but the display name says "PayPal" while the actual domain is paypal-verify.net, is it legitimate? Why?</li>
<li>Why might a legitimate email fail DMARC? (Think about forwarding scenarios)</li>
<li>What would you tell a non-technical colleague to look for before clicking a link in an email?</li>
</ol>""",
    },
]


def seed():
    from app.models import CourseTopic
    from app.extensions import db

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
            updated += 1

    db.session.commit()
    print(f"Done — {updated} Section C lessons updated.")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()