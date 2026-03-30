"""
seed_section_a_expanded.py
--------------------------
Run from your project root:
    python seed_section_a_expanded.py

Updates Section A lessons (gic-a1 to gic-a5) with expanded premium content.
"""

LESSONS = [
    {
        "slug": "gic-a1",
        "section": "A",
        "lesson_number": 1,
        "order": 1,
        "title": "Introduction to Modern Cybersecurity",
        "body": """<h2>What cybersecurity actually is</h2>

<p>Cybersecurity is the practice of protecting systems, networks, and data from unauthorised access, damage, or attack. That definition is accurate but incomplete. In practice, cybersecurity is about managing risk — understanding what you have, what threatens it, and what you are willing to do about it.</p>

<p>The word "cyber" has become noise. Strip it away and what remains is a straightforward problem: people build systems, other people try to break them, and organisations need to decide how much effort to put into stopping that from happening. Every organisation — a hospital, a bank, a school, a small business — faces this problem in some form.</p>

<p>Here is a useful way to think about it: cybersecurity is not about making systems impossible to attack. Nothing is impossible to attack. It is about making attacks difficult enough, and detection fast enough, that attackers either give up or get caught before they cause serious damage.</p>

<h2>A real-world example: the 2017 WannaCry attack</h2>

<p>In May 2017, a piece of ransomware called WannaCry spread across the world in a matter of hours. It exploited a vulnerability in Windows called EternalBlue — a flaw that Microsoft had already released a patch for two months earlier.</p>

<p>Organisations that had applied the patch were unaffected. Organisations that had not — including large parts of the UK's National Health Service — found their systems encrypted and unusable. Hospitals cancelled thousands of appointments. Surgeries were postponed. Ambulances were redirected. The estimated cost to the NHS alone was £92 million.</p>

<p>This is the reality of cybersecurity failures. The consequences are not abstract. A missed software update caused real patients to be turned away from emergency care.</p>

<p>The attack was stopped not by a sophisticated defence, but because a security researcher found a kill switch buried in the malware's code — a domain name that, when registered, caused the malware to stop spreading. It was an accident of design that saved thousands more systems.</p>

<h2>Why it matters now more than ever</h2>

<p>Digital systems underpin almost everything. Banking, healthcare, transport, energy, communication — all of it depends on software and networks. When those systems fail or are compromised, the consequences are not abstract. Hospitals cancel operations. People lose savings. Governments lose classified information. Businesses collapse.</p>

<p>The scale of the problem has grown in proportion to how dependent we have become on technology. Consider these figures:</p>

<ul>
<li>In 2023, the average cost of a data breach globally was over $4 million — and that figure rises to over $9 million for breaches in the healthcare sector</li>
<li>Ransomware attacks increased by over 95% in 2023 compared to the previous year</li>
<li>The average time to identify and contain a breach is 277 days — nearly nine months of an attacker having access before the organisation even knows</li>
<li>Over 80% of breaches involve human elements — phishing, stolen credentials, or social engineering</li>
</ul>

<p>This is not a niche technical problem. It is an economic and national security issue that affects every organisation and every individual who uses digital technology.</p>

<h2>The threat landscape today</h2>

<p>The modern threat landscape has several defining characteristics that distinguish it from the threats of even ten years ago.</p>

<p><strong>Attackers are organised.</strong> Many operate as businesses, with development teams, customer support for their ransomware victims, and structured revenue models. The Conti ransomware group, before it was disrupted in 2022, operated like a corporation — with HR processes, performance reviews, and an estimated annual revenue of over $180 million. Nation-state groups have budgets, long-term objectives, and sophisticated capabilities that rival intelligence agencies.</p>

<p><strong>Attacks are automated.</strong> Scanning the entire internet for vulnerable systems takes minutes using tools like Shodan or Masscan. Attackers do not need to target you specifically — their tools find you. Within hours of a new vulnerability being disclosed, automated scanners are already hunting for unpatched systems.</p>

<p><strong>The attack surface keeps expanding.</strong> Every new device, application, cloud service, and remote worker is a potential entry point. The average organisation now uses over 130 different software-as-a-service applications. Each one is a potential weak link. Organisations are trying to defend a perimeter that no longer has clear edges.</p>

<p><strong>People remain the weakest point.</strong> The majority of breaches begin with a phishing email or stolen credentials. Technical controls can be bypassed if a user can be deceived into handing over access. A £10 million firewall offers no protection against an employee clicking a convincing fake login page.</p>

<h2>Common misconceptions about cybersecurity</h2>

<p><strong>"We are too small to be a target."</strong> This is one of the most dangerous misconceptions in cybersecurity. Attackers using automated tools do not choose targets based on size — they target whoever is vulnerable. Small businesses are frequently attacked precisely because they tend to have weaker defences than large organisations. Ransomware groups specifically target small and medium businesses because they are more likely to pay quickly rather than spend weeks attempting recovery.</p>

<p><strong>"We have antivirus, so we are protected."</strong> Antivirus is one layer of defence, not a complete solution. Modern attacks frequently use techniques that bypass traditional antivirus — fileless malware that runs in memory, legitimate system tools repurposed for malicious use, and zero-day exploits that antivirus has never seen before. Antivirus is necessary but nowhere near sufficient.</p>

<p><strong>"Cybersecurity is an IT problem."</strong> Cybersecurity is a business problem that IT helps to address. The decisions that create the most risk — whether to patch systems immediately or wait, how much to spend on security, whether to allow remote access — are business decisions. Security professionals advise on risk, but the organisation's leadership is responsible for accepting or mitigating it.</p>

<h2>Who works in cybersecurity</h2>

<p>Cybersecurity is not a single role. It is a broad field with specialisations that range from highly technical to policy-focused. Understanding the different roles helps you identify where you might fit.</p>

<p><strong>SOC analysts</strong> work in Security Operations Centres, monitoring systems for suspicious activity and responding to alerts. Entry-level SOC analyst is one of the most accessible starting points in the field. The work involves reviewing logs, investigating alerts, and determining whether something is a genuine threat or a false positive.</p>

<p><strong>Penetration testers</strong> are paid to find vulnerabilities before attackers do. They use the same techniques as malicious attackers — with explicit written permission. The work requires strong technical skills and the ability to think creatively about how systems can be broken.</p>

<p><strong>Incident responders</strong> investigate breaches after they occur. When an organisation discovers it has been compromised, incident responders contain the damage, determine how the attacker got in, what they accessed, and how to prevent it happening again.</p>

<p><strong>Security engineers</strong> build and maintain the controls that protect systems — firewalls, endpoint detection tools, identity management systems, and the architecture of secure networks.</p>

<p><strong>GRC professionals</strong> manage the governance, risk, and compliance side of security. They develop policies, manage risk assessments, and ensure the organisation meets its legal and regulatory obligations. This is one of the most accessible routes for people without a deep technical background.</p>

<p><strong>Threat intelligence analysts</strong> track attacker groups, their techniques, and their targets. They produce reports that help organisations understand what threats are relevant to them and how to prioritise defences.</p>

<p><strong>Cloud security engineers</strong> specialise in securing infrastructure hosted on platforms like AWS, Azure, and Google Cloud. As organisations move more of their infrastructure to the cloud, this has become one of the highest-demand specialisations in the field.</p>

<h2>What this course will cover</h2>

<p>This course moves through four sections. Section A (Foundation) covers core concepts and how the security field thinks about risk, threats, and defence. Section B (Technical Core) covers the systems and protocols that underpin everything — networking, operating systems, access control. Section C (Defence and Response) covers the practical skills used to protect systems and respond when things go wrong. Section D (Career Launchpad) covers how to turn this knowledge into employment.</p>

<p>By the end, you will have a working understanding of how cybersecurity professionals think, what they do day to day, and what steps you need to take to begin building a career in this field.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-a2",
        "section": "A",
        "lesson_number": 2,
        "order": 2,
        "title": "Types of Threats and Attackers",
        "body": """<h2>Not all attackers are the same</h2>

<p>A common mistake is to think of "hackers" as a single type of person with a single motivation. In reality, the threat landscape is made up of distinct groups with very different capabilities, objectives, and methods. Understanding who is attacking — and why — fundamentally changes how you think about defence.</p>

<p>A hospital defending against a nation-state group needs different controls than a retailer defending against opportunistic ransomware. A law firm protecting client confidentiality faces different risks than a utility company protecting critical infrastructure. Knowing your threat actors helps you prioritise your defences intelligently.</p>

<h2>Nation-state actors</h2>

<p>Nation-state groups are sponsored or operated by governments. Their objectives are political, economic, or military: stealing intellectual property, disrupting critical infrastructure, gathering intelligence, or influencing elections.</p>

<p>These groups are among the most capable attackers in the world. They have significant budgets, access to zero-day vulnerabilities — flaws in software that are unknown to the vendor and therefore have no available patch — and the patience to conduct operations over months or years without being detected. Their goal is often not to cause immediate damage but to maintain persistent access and gather intelligence over time.</p>

<p><strong>Real-world example: SolarWinds (2020)</strong></p>

<p>In 2020, it was discovered that Russian state-sponsored hackers (attributed to a group called Cozy Bear or APT29) had compromised SolarWinds, a company that makes IT management software used by thousands of organisations worldwide, including US government agencies.</p>

<p>The attackers inserted malicious code into a software update that SolarWinds distributed to its customers. When customers installed the update — something they were supposed to do for security reasons — they unknowingly installed a backdoor that gave the attackers access to their networks.</p>

<p>The attack went undetected for approximately nine months. During that time, the attackers had access to the networks of the US Treasury, the Department of Homeland Security, and dozens of major corporations. The breach was eventually discovered not by any automated security tool but by a security company (FireEye) that noticed unusual activity on its own network.</p>

<p>This attack illustrates several characteristics of nation-state operations: patience, sophistication, supply chain targeting, and a focus on persistent access rather than immediate disruption.</p>

<p>Most organisations will never be directly targeted by nation-state actors. However, the tools and techniques these groups develop — and sometimes leak — eventually spread to criminal groups. EternalBlue, the vulnerability used in the WannaCry attack, was originally developed by the US National Security Agency.</p>

<h2>Cybercriminal groups</h2>

<p>Cybercriminals are motivated by money. Unlike nation-state actors who might accept low visibility for years, criminals want to monetise their access quickly. This category includes several distinct types.</p>

<p><strong>Ransomware operators</strong> compromise systems, encrypt data, and demand payment for the decryption key. Some operate as "ransomware-as-a-service" (RaaS) businesses, providing the technical tools to affiliates who carry out the attacks in exchange for a percentage of the ransom payments.</p>

<p><strong>Real-world example: The Colonial Pipeline attack (2021)</strong></p>

<p>In May 2021, the DarkSide ransomware group attacked Colonial Pipeline, which supplies approximately 45% of the fuel consumed on the US East Coast. The attackers gained access through a compromised VPN password — there was no multi-factor authentication on the account.</p>

<p>Colonial Pipeline shut down its pipeline operations proactively to prevent the ransomware from spreading further. This caused fuel shortages across the southeastern United States, with petrol stations running dry and panic buying making the situation worse. The company paid approximately $4.4 million in ransom. The US government later recovered around $2.3 million of it.</p>

<p>The entry point was a single leaked password with no second factor of authentication. A control that costs almost nothing to implement would have prevented a crisis that affected millions of people.</p>

<p><strong>Financial fraud groups</strong> steal banking credentials, conduct business email compromise (BEC) attacks, and commit payment fraud. BEC attacks involve compromising or impersonating executive email accounts to trick employees into making fraudulent wire transfers. The FBI estimates that BEC attacks have caused over $50 billion in losses globally since 2013.</p>

<p><strong>Data brokers</strong> steal personal data at scale — names, email addresses, passwords, credit card numbers — and sell it on dark web marketplaces. This stolen data then fuels further attacks: credential stuffing, identity theft, and targeted phishing.</p>

<h2>Hacktivists</h2>

<p>Hacktivists use cyber attacks to make political or ideological statements. Their tactics typically include website defacement (replacing a site's content with their own message), distributed denial of service (DDoS) attacks that make services unavailable, and data leaks intended to embarrass organisations.</p>

<p>Anonymous, the loosely organised hacktivist collective, has targeted government websites, corporations, and organisations it considers unethical. In 2010, following WikiLeaks controversies, Anonymous launched "Operation Payback" — DDoS attacks against MasterCard, Visa, and PayPal after those companies stopped processing donations to WikiLeaks.</p>

<p>The impact of hacktivism is usually reputational rather than financially severe, though DDoS attacks can cause significant service disruption and the cost of recovery from defacement or data leaks is not trivial.</p>

<h2>Insider threats</h2>

<p>Insider threats come from within an organisation — employees, contractors, or partners who misuse their legitimate access. This category is particularly challenging because traditional perimeter defences are largely irrelevant: the attacker is already inside.</p>

<p><strong>Malicious insiders</strong> deliberately steal data, sabotage systems, or assist external attackers. Motivations include financial gain, grievance against the employer, coercion by external parties, and ideology.</p>

<p><strong>Real-world example: Edward Snowden</strong></p>

<p>In 2013, NSA contractor Edward Snowden exfiltrated thousands of classified documents and leaked them to journalists. He had legitimate access to these systems as part of his job. The NSA's technical controls were insufficient to detect or prevent an insider with authorised access systematically copying sensitive data. Regardless of your view of Snowden's motivations, this is a textbook insider threat case study.</p>

<p><strong>Negligent insiders</strong> cause breaches through carelessness rather than malice — clicking phishing links, misconfiguring systems, emailing sensitive data to the wrong recipient, or losing unencrypted devices. This category accounts for a significant proportion of incidents and is in many ways harder to address than malicious insiders because no amount of suspicion is appropriate for normal employees simply doing their jobs carelessly.</p>

<h2>Opportunistic attackers and script kiddies</h2>

<p>A large portion of attacks are opportunistic — automated tools scan for known vulnerabilities across the internet, and anything exposed gets attacked regardless of who owns it. These attackers are not targeting you specifically; they are targeting anyone running vulnerable software.</p>

<p>Script kiddies are low-skill attackers who use tools and exploits built by others, without understanding how they work. They are often motivated by curiosity, reputation, or mischief rather than financial gain. While they lack sophistication, they can still cause real damage to organisations that have not applied basic security controls.</p>

<p>The key insight about opportunistic attacks is that they are indiscriminate. Your organisation does not need to be interesting or valuable — it just needs to be vulnerable and reachable. This is why basic hygiene — patching, disabling unnecessary services, strong authentication — prevents the majority of attacks that most organisations will ever face.</p>

<h2>The attack lifecycle</h2>

<p>Regardless of who the attacker is, most attacks follow a recognisable pattern. Understanding this pattern helps defenders know where to place controls and how to detect attacks in progress.</p>

<p><strong>1. Reconnaissance</strong> — The attacker gathers information about the target. This might include searching LinkedIn for employee names and roles, looking up the organisation's IP ranges, identifying what software they use from job postings, and scanning for open ports. This phase often leaves minimal traces and is difficult to detect.</p>

<p><strong>2. Weaponisation</strong> — The attacker prepares the attack — crafting a phishing email, developing an exploit, or purchasing access from a broker who has already compromised the target.</p>

<p><strong>3. Delivery</strong> — The attack reaches the target. This might be a phishing email, a malicious attachment, exploitation of a public-facing vulnerability, or a compromised software update.</p>

<p><strong>4. Exploitation</strong> — The vulnerability is triggered or the user is deceived. Code executes, credentials are captured, or access is granted.</p>

<p><strong>5. Installation</strong> — The attacker establishes persistence — a mechanism to maintain access even if the system is restarted. This might be a scheduled task, a new service, or a modification to startup scripts.</p>

<p><strong>6. Command and control</strong> — The compromised system communicates back to attacker infrastructure, allowing the attacker to issue commands and receive data.</p>

<p><strong>7. Actions on objectives</strong> — The attacker does whatever they came to do: encrypt files for ransom, exfiltrate data, move laterally to other systems, or establish a long-term presence for future use.</p>

<p>This framework — often called the Cyber Kill Chain — is useful because defenders can interrupt the attack at any stage. Blocking the delivery (email filtering) prevents exploitation. Detecting the installation (endpoint monitoring) allows response before the attacker achieves their objective. Monitoring for unusual outbound connections can identify command and control activity.</p>

<h2>Common misconceptions about attackers</h2>

<p><strong>"Attackers are lone individuals in hoodies."</strong> The popular image of a hacker is wildly inaccurate. Modern cybercriminal groups operate like businesses, with specialised roles — initial access brokers who sell entry points, ransomware developers who build the tools, affiliates who deploy the attacks, and negotiators who handle ransom communications. Nation-state groups are staffed by professional intelligence operatives.</p>

<p><strong>"Strong passwords will protect us."</strong> Password strength matters, but many attacks bypass passwords entirely — through phishing (the user types their password into a fake site), session token theft (the attacker steals the authentication token rather than the password), or exploiting vulnerabilities that do not require authentication at all.</p>

<p><strong>"We would know if we had been breached."</strong> The average dwell time — the period between an attacker gaining access and being discovered — is over 200 days. Many organisations discover breaches only when contacted by law enforcement, when data appears for sale online, or when attackers choose to reveal themselves by deploying ransomware. Silent, patient attackers often go completely undetected.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-a3",
        "section": "A",
        "lesson_number": 3,
        "order": 3,
        "title": "CIA Triad and Security Principles",
        "body": """<h2>The foundation of security thinking</h2>

<p>Every decision in cybersecurity comes back to three core properties: Confidentiality, Integrity, and Availability — the CIA triad. These three properties form the conceptual foundation of the entire field. When a security professional evaluates a risk, designs a control, or responds to an incident, they are almost always thinking in terms of which of these properties has been or might be compromised.</p>

<p>Understanding the CIA triad is not just academic. It gives you a framework for thinking clearly about security problems. When something goes wrong — or when you are asked to protect something — the first question to ask is: which properties matter most here, and what threatens them?</p>

<h2>Confidentiality</h2>

<p>Confidentiality means that information is accessible only to those who are authorised to access it. Unauthorised disclosure — whether deliberate or accidental — is a breach of confidentiality.</p>

<p>Confidentiality is not just about keeping secrets from outsiders. It also means appropriate access within an organisation. A hospital employee should be able to access the records of patients they are treating, but not the records of every patient in the system. A junior accountant should see their clients' financial data, but perhaps not the salaries of senior executives. This principle of need-to-know is fundamental to confidentiality.</p>

<p><strong>Controls that protect confidentiality include:</strong></p>
<ul>
<li><strong>Encryption</strong> — converting data into a form that cannot be read without a decryption key. Encrypted data that is stolen is useless to an attacker without the key.</li>
<li><strong>Access controls</strong> — restricting who can read, modify, or delete data based on their identity and role.</li>
<li><strong>Authentication</strong> — verifying that users are who they claim to be before granting access.</li>
<li><strong>Data classification</strong> — categorising data by sensitivity so that appropriate protections can be applied.</li>
</ul>

<p><strong>Real-world example: the Equifax breach (2017)</strong></p>

<p>In 2017, attackers exploited a vulnerability in a web application framework called Apache Struts to gain access to Equifax's systems. Over approximately 78 days, they exfiltrated the personal information of 147 million people — names, Social Security numbers, birth dates, addresses, and credit card numbers.</p>

<p>This was a catastrophic breach of confidentiality. The data was used for identity theft, fraudulent credit applications, and targeted fraud for years afterward. Equifax ultimately paid over $700 million in settlements.</p>

<p>The vulnerability had a patch available for two months before the attack. The organisation had failed to apply it. A confidentiality failure caused by a patch management failure caused by a process failure — a chain of weaknesses that combined to produce a catastrophic outcome.</p>

<h2>Integrity</h2>

<p>Integrity means that information and systems can be trusted to be accurate and unmodified. Data has integrity when you can be confident that it has not been altered — either by an attacker or through accidental corruption — without authorisation.</p>

<p>Integrity matters in ways that are not always obvious. Consider a hospital's medication dosage records. A confidentiality breach might expose a patient's medical history — serious, but the patient is not immediately harmed. An integrity breach that changes a patient's recorded medication dosage could kill them. In many contexts, integrity is the most critical property.</p>

<p><strong>Controls that protect integrity include:</strong></p>
<ul>
<li><strong>Hashing</strong> — generating a fixed-length fingerprint of data. If the data changes, the hash changes. Hashes are used to verify that files have not been tampered with.</li>
<li><strong>Digital signatures</strong> — cryptographic signatures that verify both the identity of the sender and that the data has not been modified since signing.</li>
<li><strong>Version control</strong> — maintaining a history of changes so that unauthorised modifications can be detected and reversed.</li>
<li><strong>Audit logs</strong> — recording who made what changes, when, providing an evidence trail for detecting and investigating integrity violations.</li>
<li><strong>Input validation</strong> — ensuring that data entered into systems meets expected formats, preventing attackers from injecting malicious content.</li>
</ul>

<p><strong>Real-world example: DNS cache poisoning</strong></p>

<p>DNS (Domain Name System) translates domain names like bliztechacademy.com into IP addresses. In a DNS cache poisoning attack, an attacker inserts false records into a DNS resolver's cache, causing users to be directed to a malicious server instead of the legitimate one.</p>

<p>This is an integrity attack. The DNS records — data that should accurately reflect where services are located — have been corrupted. Users who type the correct address into their browser are silently redirected to an attacker-controlled site that may look identical to the real one, capturing their credentials or serving malware.</p>

<h2>Availability</h2>

<p>Availability means that systems and data are accessible when needed by authorised users. A system that is completely secure but inaccessible when needed provides no value. Security measures that make systems so locked down that legitimate users cannot do their work have failed, even if they prevent every possible attack.</p>

<p>Availability is often the most visible property when it fails — a website that is down, a payment system that cannot process transactions, or a hospital system that is inaccessible during an emergency are immediately obvious in a way that confidentiality and integrity breaches often are not.</p>

<p><strong>Controls that protect availability include:</strong></p>
<ul>
<li><strong>Redundancy</strong> — having backup systems that can take over if primary systems fail. Redundant servers, power supplies, internet connections, and data centres all protect availability.</li>
<li><strong>DDoS mitigation</strong> — services and technologies that absorb or filter distributed denial of service attacks, which flood systems with traffic to make them unavailable.</li>
<li><strong>Disaster recovery planning</strong> — documented processes for restoring systems after a failure or attack, including regular testing of those processes.</li>
<li><strong>Regular backups</strong> — copies of data that allow restoration after ransomware encryption or accidental deletion. Backups must be tested, stored separately from primary systems, and protected from attackers who specifically target backups to increase pressure to pay ransoms.</li>
</ul>

<p><strong>Real-world example: the 2016 Mirai botnet attack</strong></p>

<p>In October 2016, a massive DDoS attack targeted Dyn, a DNS provider. The attack used a botnet called Mirai — a network of compromised Internet of Things devices including security cameras, routers, and digital video recorders — to flood Dyn's infrastructure with traffic.</p>

<p>The result was that major websites including Twitter, Netflix, Reddit, CNN, and The Guardian became unavailable for large parts of the day across the United States and Europe. The attack did not breach confidentiality or integrity — no data was stolen or modified. It simply made services unavailable. Availability had been comprehensively violated.</p>

<p>The compromised devices were vulnerable because they used default or weak passwords. Availability of major internet services was brought down by poorly secured consumer devices that most people do not think of as security risks at all.</p>

<h2>The tensions between CIA properties</h2>

<p>Understanding the CIA triad also means understanding the tensions between the three properties. Security decisions frequently require trading off one property against another.</p>

<p><strong>Confidentiality vs Availability:</strong> Adding authentication and encryption makes data more confidential but can make systems harder to access. In an emergency, a doctor who cannot quickly access patient records because of a complex authentication system faces a real problem. Too much confidentiality control can kill availability.</p>

<p><strong>Integrity vs Availability:</strong> Requiring extensive verification and approval processes before data can be modified improves integrity but can slow systems to the point where they are practically unavailable. Financial systems that require multiple approvals for every transaction are more resistant to fraud but slower to use.</p>

<p><strong>Confidentiality vs Integrity:</strong> End-to-end encryption protects confidentiality — only the sender and recipient can read the message. But it also means that security tools cannot inspect that traffic for malware or data exfiltration. Encrypted channels that protect confidentiality can also be used to smuggle malicious content past defences.</p>

<p>There is no universal answer to these tensions. The right balance depends on the context — the value of the data, the nature of the threats, the needs of the users, and the risk tolerance of the organisation. A security professional's job is to understand these trade-offs and help the organisation make informed decisions.</p>

<h2>Additional principles: non-repudiation and authenticity</h2>

<p><strong>Non-repudiation</strong> means that actions can be attributed to the person who performed them, and that person cannot credibly deny having done so. In a legal or contractual context, this is critical. If someone makes a fraudulent bank transfer and later claims they never authorised it, non-repudiation evidence — a digital signature, an audit log, an authentication record — can prove they did.</p>

<p>Digital signatures provide non-repudiation for documents and messages. When you sign a document with a private key that only you hold, and the signature can be verified with your public key, it is cryptographically impossible to deny having signed it.</p>

<p><strong>Authenticity</strong> means that data and communications are genuine — they come from who they claim to come from and have not been fabricated. A website's TLS certificate provides authenticity — it cryptographically proves that the server you are connecting to is genuinely controlled by the organisation the certificate was issued to.</p>

<h2>Common misconceptions about the CIA triad</h2>

<p><strong>"CIA stands for the Central Intelligence Agency."</strong> In security contexts, CIA always means Confidentiality, Integrity, and Availability. The acronym predates common usage in cybersecurity and comes from information security theory.</p>

<p><strong>"Confidentiality is always the most important property."</strong> It depends entirely on the context. For medical systems, integrity (accurate data) may be more critical than confidentiality. For operational technology controlling physical infrastructure, availability often takes priority — a power plant control system that is inaccessible during an emergency can cause physical harm.</p>

<p><strong>"These properties are independent."</strong> They interact constantly. A ransomware attack — encrypting data and making it unavailable — is primarily an availability attack. But the data may also be exfiltrated (confidentiality) and the encrypted data is no longer trustworthy even after recovery (integrity). Most significant attacks affect multiple properties simultaneously.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-a4",
        "section": "A",
        "lesson_number": 4,
        "order": 4,
        "title": "Risk, Vulnerabilities, and Attack Surface",
        "body": """<h2>How security professionals think about risk</h2>

<p>Security professionals do not think in terms of "secure" and "insecure." They think in terms of risk — the probability and impact of something going wrong. This distinction matters enormously, because it changes how decisions are made.</p>

<p>If you think about security in binary terms, you will either try to achieve impossible perfection or give up because perfect security is unattainable. If you think in terms of risk, you can make rational, proportionate decisions: reducing the risks that matter most, accepting the risks that are small or costly to mitigate, and continually reassessing as circumstances change.</p>

<p>The formal definition of risk in security contexts is:</p>

<p><strong>Risk = Threat × Vulnerability × Impact</strong></p>

<ul>
<li><strong>Threat</strong> — a potential cause of harm. Nation-state attackers, ransomware groups, phishing emails, and disgruntled employees are all threats.</li>
<li><strong>Vulnerability</strong> — a weakness that a threat can exploit. An unpatched software flaw, a weak password policy, or an employee who has not received phishing awareness training are all vulnerabilities.</li>
<li><strong>Impact</strong> — the consequence if the threat successfully exploits the vulnerability. Financial loss, reputational damage, operational disruption, and legal liability are all potential impacts.</li>
</ul>

<p>If any of these three factors is zero, the risk is zero. A threat that has no vulnerability to exploit poses no risk. A vulnerability with no credible threat does not need immediate attention. An incident with no meaningful impact is not worth expensive controls. This framework helps prioritise: focus on high-threat, high-vulnerability, high-impact combinations first.</p>

<h2>What a vulnerability is — in detail</h2>

<p>A vulnerability is any weakness in a system, process, or control that could be exploited to cause harm. Vulnerabilities exist in many forms, and understanding the different categories helps you think more broadly about where weaknesses might exist.</p>

<p><strong>Software vulnerabilities</strong> are flaws in code. They might allow an attacker to execute arbitrary commands, bypass authentication, access data they should not reach, or crash a system. Software vulnerabilities are assigned CVE numbers (Common Vulnerabilities and Exposures) — identifiers that allow security professionals and automated tools to track specific flaws.</p>

<p><strong>Real-world example: Log4Shell (2021)</strong></p>

<p>In December 2021, a vulnerability was discovered in Log4j — a logging library used by an enormous number of Java applications. The vulnerability (CVE-2021-44228) allowed attackers to execute arbitrary code on affected systems simply by causing a specific string to be logged. Because Log4j is embedded in thousands of products, the attack surface was almost unimaginably large — from enterprise software to video games to cloud services.</p>

<p>Within days of disclosure, organisations were seeing millions of exploitation attempts. The vulnerability was rated 10/10 in severity. The response required security teams worldwide to inventory every application they operated and determine whether it used Log4j — a task that revealed how little visibility many organisations had into their own software.</p>

<p><strong>Configuration vulnerabilities</strong> are systems set up incorrectly. Default passwords that were never changed, unnecessary services left running, excessive permissions granted for convenience, and sensitive data accidentally exposed to the internet are all configuration vulnerabilities. These are often more common than software vulnerabilities and frequently easier to exploit, because no sophisticated technique is required — just finding an open door that should have been closed.</p>

<p><strong>Process vulnerabilities</strong> are weaknesses in how things are done. No process for revoking access when an employee leaves. No requirement to verify identity before resetting a password. No separation between who can authorise a payment and who can execute it. These weaknesses cannot be patched with a software update — they require changes to how people work.</p>

<p><strong>Human vulnerabilities</strong> are weaknesses in human behaviour that can be exploited through social engineering. People who trust authority figures, who want to be helpful, who are busy and distracted, or who are not trained to recognise manipulation are all exploitable. Technical defences cannot fully compensate for human vulnerabilities.</p>

<h2>Vulnerability management — how organisations track and fix vulnerabilities</h2>

<p>Vulnerability management is the ongoing process of identifying, assessing, prioritising, and remediating vulnerabilities before attackers can exploit them. It is not a one-time exercise — new vulnerabilities are discovered daily, and the environment changes constantly.</p>

<p><strong>Step 1: Scanning</strong> — Automated tools (such as Nessus, Qualys, or Tenable) scan systems and applications for known vulnerabilities. These tools compare what they find against databases of known flaws and report what is present, how severe it is, and whether exploit code is publicly available.</p>

<p><strong>Step 2: Prioritisation</strong> — Not all vulnerabilities can be patched immediately. The Common Vulnerability Scoring System (CVSS) provides a severity score from 0 to 10. But CVSS alone is not enough — a 9.8-severity vulnerability in a system with no internet exposure and no sensitive data may be less urgent than a 6.5-severity vulnerability in a public-facing authentication system. Prioritisation requires combining technical severity with business context.</p>

<p><strong>Step 3: Remediation</strong> — Fixing the vulnerability, which might mean applying a vendor-provided patch, changing a configuration, disabling a service, or implementing a compensating control (a measure that reduces risk when a direct fix is not possible or immediate).</p>

<p><strong>Step 4: Tracking</strong> — Maintaining records of what vulnerabilities were found, when, what was done about them, and verifying that remediation was effective. This documentation is also essential for demonstrating compliance with regulations.</p>

<h2>The attack surface</h2>

<p>The attack surface is the total sum of all the points where an attacker could attempt to enter a system or extract data. Every internet-facing service, every employee's device, every third-party software library, every cloud service, and every partner with network access is part of the attack surface.</p>

<p>Modern organisations have vastly larger attack surfaces than they did even a decade ago, for several reasons:</p>

<ul>
<li><strong>Cloud adoption</strong> — moving services to cloud platforms creates new exposure points and requires understanding a shared responsibility model for security</li>
<li><strong>Remote work</strong> — employees working from home connect to corporate systems over home networks and personal devices, each of which may be compromised</li>
<li><strong>Third-party integrations</strong> — the average organisation has dozens of software vendors and partners with some level of access to their systems</li>
<li><strong>IoT and operational technology</strong> — physical devices from cameras to building management systems now connect to networks that were previously isolated</li>
</ul>

<p><strong>Attack surface reduction</strong> is one of the most effective security strategies: minimise what is exposed, disable what is not needed, and ensure everything that is exposed is properly secured. A system that does not exist cannot be compromised.</p>

<h2>Threat modelling — thinking like an attacker</h2>

<p>Threat modelling is the structured practice of identifying what could go wrong, from an attacker's perspective, before building or deploying a system. Rather than waiting to discover vulnerabilities after deployment, threat modelling anticipates them.</p>

<p>A simple threat modelling exercise asks four questions:</p>
<ol>
<li><strong>What are we building?</strong> — What does the system do, what data does it hold, and who uses it?</li>
<li><strong>What could go wrong?</strong> — Who might attack this, what would they be trying to achieve, and how might they try to do it?</li>
<li><strong>What are we going to do about it?</strong> — Which threats do we mitigate, which do we accept, and how?</li>
<li><strong>Did we do a good enough job?</strong> — Review and validate that the controls are adequate.</li>
</ol>

<h2>Residual risk — what remains after controls are applied</h2>

<p>After controls are applied, some risk always remains. No organisation can eliminate all risk — the goal is to reduce it to an acceptable level. The risk that remains after controls are in place is called residual risk.</p>

<p>Organisations must make an explicit decision about what to do with residual risk. The four options are:</p>

<p><strong>Accept</strong> — acknowledge that the risk exists and is within the organisation's tolerance. This is appropriate when the cost of mitigation exceeds the expected cost of the risk materialising, or when the risk is genuinely low. Risk acceptance must be a conscious, documented decision — not simply forgetting to address something.</p>

<p><strong>Transfer</strong> — shift the financial consequences of the risk to another party, typically through insurance. Cyber insurance policies cover costs associated with breaches including incident response, legal fees, and regulatory fines. Insurance does not prevent the breach — it helps recover from it financially.</p>

<p><strong>Avoid</strong> — stop doing the activity that creates the risk entirely. If a particular service creates unacceptable risk and is not essential, not offering it at all eliminates the risk.</p>

<p><strong>Mitigate</strong> — apply additional controls to reduce the likelihood or impact of the risk. This is the most common response and encompasses most of what security teams do day to day.</p>

<h2>Common misconceptions about risk and vulnerabilities</h2>

<p><strong>"We patched everything, so we are secure."</strong> Patching addresses known software vulnerabilities, but the attack surface is far broader. Configuration weaknesses, process gaps, and human vulnerabilities are not fixed by patching. Patching is necessary but not sufficient.</p>

<p><strong>"We need to eliminate all vulnerabilities."</strong> This is impossible. New vulnerabilities are discovered constantly, and some vulnerabilities in legacy systems may have no available patch. The goal is to manage vulnerabilities intelligently — prioritising the ones most likely to be exploited with the highest potential impact.</p>

<p><strong>"Risk assessments are a compliance exercise."</strong> Risk assessments done purely for compliance produce paperwork, not security. A genuine risk assessment changes how an organisation allocates security resources and makes decisions. The value is in the thinking, not the documentation.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-a5",
        "section": "A",
        "lesson_number": 5,
        "order": 5,
        "title": "Defence in Depth",
        "body": """<h2>Why no single control is enough</h2>

<p>Imagine a single lock on a door. If the lock fails — whether because it is picked, the key is copied, or the door frame gives way — there is nothing left to stop an intruder. The entire defence depends on one control not failing. This is the fundamental problem with relying on any single security control.</p>

<p>Every control has weaknesses. Every technology has vulnerabilities. Every process can be circumvented. Defence in depth is the answer: rather than relying on one strong control, use multiple independent layers so that if one fails, others continue to provide protection.</p>

<p>The concept comes from military strategy — the idea of positioning defences in layers so that an attacker who breaks through the outer line still faces resistance further in. Medieval castles were designed this way: a moat, then outer walls, then inner walls, then the keep. No single barrier was expected to stop all attackers. The combination of barriers made assault costly and slow — giving defenders time to respond.</p>

<p>In cybersecurity, the principle is identical. An attacker who bypasses your firewall should encounter endpoint controls. An attacker who compromises a user account should find that the account has minimal permissions. An attacker who accesses a database should find the data encrypted. Each layer adds cost and complexity to the attack.</p>

<h2>The layers of defence</h2>

<p>Defence in depth is typically visualised as concentric layers, each providing a different type of protection against different attack techniques.</p>

<p><strong>Perimeter controls — the outermost layer</strong></p>

<p>Firewalls, intrusion detection systems (IDS), intrusion prevention systems (IPS), and web application firewalls (WAF) filter traffic before it reaches internal systems. Email filtering catches phishing attempts and malicious attachments before they reach users. These controls stop a large volume of attacks at the boundary, before they have any contact with internal systems.</p>

<p>The limitation of perimeter controls is that the perimeter no longer has clear edges. With remote workers, cloud services, and mobile devices, there is no defined inside and outside. Perimeter controls remain important but cannot be the primary line of defence.</p>

<p><strong>Network controls — inside the perimeter</strong></p>

<p>Network segmentation divides the environment into separate zones with controlled access between them. A breach in one zone does not automatically give access to others. A server in the customer-facing web zone should not be able to directly communicate with the database server containing sensitive data — requests must pass through application logic.</p>

<p>A DMZ (demilitarised zone) is a network segment positioned between the internal network and the internet, used to host services that need to be publicly accessible (like web servers) while keeping them isolated from internal systems. If a web server in the DMZ is compromised, the attacker has not automatically gained access to the internal network.</p>

<p><strong>Endpoint controls — on individual devices</strong></p>

<p>Endpoint detection and response (EDR) tools monitor devices for malicious activity, looking for behavioural patterns that indicate compromise rather than just matching known malware signatures. This allows detection of novel threats that traditional antivirus would miss.</p>

<p>Patch management keeps software up to date, closing known vulnerabilities. Device encryption protects data if a laptop is stolen or lost — without the encryption key, the data on the disk is unreadable. Application control restricts which software can run on a device, preventing users from installing unauthorised software that might be malicious.</p>

<p><strong>Application controls — within software</strong></p>

<p>Authentication requirements verify identity before granting access. Authorisation checks ensure that authenticated users can only access what they are permitted to. Input validation prevents attackers from injecting malicious content into applications. Logging records what actions were taken and when, providing evidence for incident investigation.</p>

<p>Applications should be built assuming that the network they run on may already be compromised. This means encrypting sensitive data even within internal systems, validating all inputs regardless of their source, and not trusting requests just because they came from inside the network.</p>

<p><strong>Data controls — the innermost layer</strong></p>

<p>Encryption of sensitive data at rest (stored on disk) and in transit (moving across networks) ensures that data is useless to an attacker who manages to access it without the decryption key. Data loss prevention (DLP) tools monitor data movement and can block sensitive data from being emailed to external addresses or uploaded to unauthorised cloud services. Access controls ensure that data can only be read or modified by those who are authorised to do so.</p>

<p><strong>Human controls — often overlooked but critical</strong></p>

<p>Security awareness training helps users recognise phishing attempts, understand safe practices, and know what to do when something seems suspicious. Clear policies establish what is expected of employees. Processes that reduce the likelihood of human error — such as requiring confirmation before executing large transfers — address the reality that humans are consistently the most exploited layer.</p>

<h2>Principle of least privilege — the most important supporting principle</h2>

<p>One of the most powerful supporting principles of defence in depth is least privilege: every user, system, and process should have the minimum level of access needed to perform its function, and no more.</p>

<p>A user who only needs to read documents should not have permission to delete them. A web server that needs to query a database should not have permission to drop tables. An administrator account should not be used for day-to-day tasks — it should be used only when elevated privileges are actually required, and only for as long as needed.</p>

<p><strong>Real-world example: the Target breach (2013)</strong></p>

<p>In 2013, attackers compromised Target's systems by first breaching a third-party HVAC contractor that had network access to Target's systems. The contractor's credentials gave access to a vendor portal. From there, attackers were able to move laterally into Target's point-of-sale systems and install malware that captured payment card data from approximately 40 million customers.</p>

<p>The HVAC contractor had network access for legitimate business reasons — to monitor and manage heating and cooling systems remotely. However, that access was not properly segmented. The contractor's credentials — which had no business reason to access payment systems — provided a path to those systems.</p>

<p>Least privilege and network segmentation could have contained this breach. The HVAC contractor should have had access only to the specific systems needed for their work, with no ability to reach payment infrastructure.</p>

<h2>Separation of duties</h2>

<p>Separation of duties requires that critical actions cannot be completed by a single person acting alone. This principle reduces both the risk of insider fraud and the impact of a compromised account.</p>

<p>In financial systems, the person who can authorise a payment is different from the person who executes it. The person who creates a new supplier in the accounting system is different from the person who approves payments to that supplier. This means that a single malicious or compromised insider cannot complete a fraudulent transaction unilaterally.</p>

<p>In technical environments, code changes should be reviewed and approved by a second person before being deployed to production. Database administrators should not be able to delete audit logs that record their own actions. System administrators with the ability to create user accounts should not also be able to approve their own access requests.</p>

<h2>Zero trust — rethinking the model</h2>

<p>Zero trust is a security model that challenges the traditional assumption that everything inside the network perimeter can be trusted. The old model — "trust but verify" inside the network, verify everything outside — has broken down in a world where attackers routinely achieve internal access and where the perimeter has dissolved.</p>

<p>In a zero trust model, no user, device, or system is trusted by default — regardless of where they are. Every access request must be authenticated and authorised, every time, based on multiple signals: who the user is, what device they are using, where they are connecting from, what they are trying to access, and whether the request is consistent with their normal behaviour.</p>

<p>Zero trust is not a product you buy — it is an architecture and a philosophy. Implementing it requires strong identity management, device health verification, network micro-segmentation, and continuous monitoring. Large organisations are increasingly moving toward zero trust models precisely because the traditional perimeter has become difficult to define and defend.</p>

<h2>Defence in depth in practice — a worked example</h2>

<p>A realistic example: a company wants to protect its customer database containing names, email addresses, and payment information.</p>

<ul>
<li><strong>Perimeter:</strong> Firewall rules block all inbound connections to the database server except from the application server. Web application firewall inspects traffic to the web application for injection attacks.</li>
<li><strong>Network:</strong> The database sits in a separate network segment from the web servers and everything else. Traffic between segments is logged and inspected.</li>
<li><strong>Endpoint:</strong> The database server is kept patched and runs only the database service — no unnecessary software that could be exploited. EDR monitors for unusual process activity.</li>
<li><strong>Application:</strong> The application uses parameterised queries to prevent SQL injection. All database access goes through a service account with only the permissions needed — read access for most operations, write access only for specific functions.</li>
<li><strong>Data:</strong> Payment card data is encrypted in the database. Cardholder data beyond what is necessary is not stored at all. Backups are encrypted and stored separately from the primary database.</li>
<li><strong>Human:</strong> Database administrators require multi-factor authentication. Access to production data requires logging a justification that is reviewed by a manager. Developers cannot access production data — they use anonymised copies for testing.</li>
</ul>

<p>If an attacker bypasses the firewall, they still face network segmentation. If they reach the application, parameterised queries prevent SQL injection. If they compromise the application's service account, that account cannot access administrative functions. If they manage to read the database, payment card data is encrypted. Each layer provides an independent barrier.</p>

<h2>Common misconceptions about defence in depth</h2>

<p><strong>"More controls means more security."</strong> More controls means more complexity, and complexity is the enemy of security. Controls that are too numerous, poorly integrated, or difficult to manage create alert fatigue, create gaps where responsibility is unclear, and can introduce new vulnerabilities. The goal is the right controls, well implemented, not the maximum number of controls.</p>

<p><strong>"Defence in depth is only for large organisations."</strong> The principles scale to any size. A small business can implement multi-factor authentication, keep software patched, use email filtering, encrypt sensitive data, and maintain offsite backups — all of which provide meaningful layered defence without large budgets or dedicated security teams.</p>

<p><strong>"If we have defence in depth, we are safe."</strong> Defence in depth reduces risk. It does not eliminate it. A sufficiently capable and motivated attacker with enough time and resources will find a way through any set of controls. The goal is to make attacks difficult enough, expensive enough, and detectable enough that most attackers give up or are caught. Detection and response capabilities matter as much as prevention.</p>""",
        "lab": """<h2>Practical Lab: Map your own attack surface</h2>

<p>This exercise applies the concepts from Section A to your own digital life. It takes approximately 30–45 minutes and will give you a concrete, personal understanding of what attack surface means in practice.</p>

<h3>Part 1: Inventory your attack surface</h3>

<p>Work through each category below and list every item that applies to you. Be thorough — the value of this exercise is in the honesty of the inventory.</p>

<p><strong>Devices</strong></p>
<ul>
<li>List every device you own that connects to the internet: laptop, desktop, phone, tablet, smart TV, gaming console, smart speaker, smart home devices (thermostats, cameras, doorbells), wearables</li>
<li>For each device, note: Is the operating system up to date? Is it set to update automatically? Does it have a PIN, password, or biometric lock?</li>
<li>Which devices have you not updated in the last three months?</li>
</ul>

<p><strong>Accounts</strong></p>
<ul>
<li>Estimate the total number of online accounts you have across all services — email, social media, shopping, banking, subscriptions, work tools, gaming</li>
<li>How many use a unique password that you do not use anywhere else?</li>
<li>How many have two-factor authentication enabled?</li>
<li>Are any using the same email and password combination as accounts that have appeared in known data breaches? (Check haveibeenpwned.com)</li>
<li>Are there accounts you no longer use that still exist?</li>
</ul>

<p><strong>Network access</strong></p>
<ul>
<li>Do you use public Wi-Fi? If so, how often and for what activities?</li>
<li>Does your home router use the default admin password, or have you changed it?</li>
<li>When did you last update your home router's firmware?</li>
<li>Do you know what devices are connected to your home network?</li>
</ul>

<p><strong>Data</strong></p>
<ul>
<li>What sensitive data do you store digitally? Consider: financial documents, tax records, identification documents, health records, passwords, legal documents, private communications</li>
<li>Where is each type stored? On a device, in cloud storage, in email?</li>
<li>Is any of it encrypted? Is it backed up?</li>
<li>Who else might have access to it?</li>
</ul>

<h3>Part 2: Risk assessment</h3>

<p>For each of the four categories above, rate your current exposure on a scale of 1 to 5:</p>
<ul>
<li><strong>1</strong> — Well protected. Controls are in place and regularly reviewed.</li>
<li><strong>2</strong> — Mostly protected with minor gaps.</li>
<li><strong>3</strong> — Some protection but significant gaps exist.</li>
<li><strong>4</strong> — Minimal protection. Significant exposure.</li>
<li><strong>5</strong> — Little to no protection. High exposure.</li>
</ul>

<h3>Part 3: Threat analysis</h3>

<p>For each area where you rated yourself 3 or above, consider:</p>
<ul>
<li>What is the most realistic threat? (Opportunistic attacker, credential stuffing, phishing, device theft?)</li>
<li>What is the most likely impact if that threat materialised? (Financial loss, identity theft, privacy violation, access to workplace systems?)</li>
<li>What single control would most reduce this risk?</li>
</ul>

<h3>Part 4: Action plan</h3>

<p>Identify the two highest-risk areas from your assessment and write one specific, actionable step you will take this week to reduce each one. Be specific — not "improve passwords" but "enable two-factor authentication on my email account and Google account today."</p>

<p>This exercise applies exactly the same thinking that a security professional would apply to an organisation: understand what exists, assess what is exposed, identify realistic threats, and prioritise effort based on risk rather than trying to fix everything at once.</p>""",
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
    print(f"Done — {updated} Section A lessons updated.")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()