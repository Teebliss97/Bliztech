"""
seed_section_d_expanded.py
--------------------------
Run from your project root:
    PYTHONPATH=/opt/render/project/src .venv/bin/python seed_section_d_expanded.py
"""

LESSONS = [
    {
        "slug": "gic-d1",
        "section": "D",
        "lesson_number": 16,
        "order": 16,
        "title": "Cloud Security Fundamentals",
        "body": """<h2>Why cloud security is a distinct discipline</h2>

<p>Cloud computing has fundamentally changed how organisations build and run systems. Rather than owning and operating physical servers in a data centre, they rent computing resources from providers like Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP). This shift has created significant security implications — both new risks and new capabilities.</p>

<p>Cloud security has become one of the highest-demand specialisations in cybersecurity because organisations have moved workloads to the cloud faster than they have developed the expertise to secure them. Misconfigurations in cloud environments have caused some of the largest data breaches in history — not through sophisticated attacks, but through basic configuration errors.</p>

<h2>The shared responsibility model</h2>

<p>The most important concept in cloud security is shared responsibility: cloud providers and customers each have security responsibilities, and the boundary depends on what type of service is being used.</p>

<p><strong>IaaS (Infrastructure as a Service)</strong> — The provider manages the physical infrastructure: data centres, networking hardware, hypervisors, and physical security. The customer manages everything from the operating system upward: the OS, patching, applications, data, and access management. AWS EC2, Azure Virtual Machines, and Google Compute Engine are IaaS services.</p>

<p><strong>PaaS (Platform as a Service)</strong> — The provider manages infrastructure and the runtime environment. The customer manages their application code and data. AWS Elastic Beanstalk, Azure App Service, and Google App Engine are PaaS services.</p>

<p><strong>SaaS (Software as a Service)</strong> — The provider manages everything except user access and data configuration. The customer is responsible for who has access and how data is configured within the application. Microsoft 365, Salesforce, and Google Workspace are SaaS services.</p>

<p>The critical mistake organisations make is assuming the cloud provider is responsible for more than they are. Moving to the cloud does not transfer responsibility for data security, access management, or application security to the provider. These remain the customer's responsibility regardless of the service model.</p>

<p><strong>Real-world example: Capital One breach (2019)</strong></p>

<p>A former AWS employee exploited a misconfigured web application firewall at Capital One to perform a Server-Side Request Forgery (SSRF) attack. This allowed access to the AWS Instance Metadata Service, which returned temporary IAM credentials. Using those credentials, the attacker accessed over 100 million customer records stored in S3 buckets.</p>

<p>AWS's infrastructure was not compromised. The provider's systems worked as designed. The failure was in Capital One's configuration — a misconfigured WAF and overly permissive IAM role. Under the shared responsibility model, these were Capital One's responsibilities, not AWS's.</p>

<h2>Common cloud misconfigurations</h2>

<p><strong>Publicly accessible storage buckets</strong> — Cloud storage services (AWS S3, Azure Blob Storage, Google Cloud Storage) allow storing files that can be accessed over the internet. A single configuration error — setting a bucket to public — can expose vast amounts of sensitive data to anyone who knows the URL (and bucket names are often predictable).</p>

<p>Since 2017, publicly exposed S3 buckets have been responsible for some of the largest data exposures in history: Verizon (14 million customer records), WWE (3 million customer records), voter registration data for virtually every US state. In most cases, there was no sophisticated attack — just a public bucket that anyone could access.</p>

<p>AWS now warns about publicly accessible buckets and has added controls to help prevent accidental exposure. However, misconfigurations continue because organisations often have hundreds of buckets, not all managed with equal care.</p>

<p><strong>Overly permissive IAM roles</strong> — IAM (Identity and Access Management) controls what actions users and services can perform. Cloud environments make it easy to grant broad permissions — "just give it admin access and worry about it later" — and that granular restriction never happens. The result is service accounts and users with far more access than they need.</p>

<p>When these over-privileged accounts are compromised, the impact is proportionally larger. An attacker who compromises a service account with administrator access to all S3 buckets in an account can read everything. The same attacker compromising a service account with read access to one specific bucket causes far less damage.</p>

<p><strong>Exposed management interfaces</strong> — Databases, management consoles, and administrative interfaces left accessible from the internet without adequate authentication. A MongoDB or Elasticsearch database accessible from the internet with no authentication has been the cause of countless data exposures. Search engines like Shodan actively index these exposed services.</p>

<p><strong>Disabled or insufficient logging</strong> — Cloud providers offer comprehensive logging services (AWS CloudTrail, Azure Monitor, GCP Cloud Audit Logs) that record every API call and management action. These logs are essential for security monitoring and incident investigation. Organisations that do not enable logging have no visibility into what is happening in their cloud environment and no evidence when something goes wrong.</p>

<p><strong>Default credentials and configurations</strong> — Services deployed with unchanged default usernames and passwords. Default configurations optimised for ease of use rather than security. These are trivially exploited by attackers who simply try known default credentials.</p>

<h2>Cloud-specific attacks</h2>

<p><strong>Metadata service abuse</strong> — Cloud instances have access to a metadata service at a well-known IP address (169.254.169.254 on AWS) that provides information about the instance, including temporary IAM credentials. SSRF (Server-Side Request Forgery) vulnerabilities in web applications can be exploited to make the application query this metadata service, returning credentials that give the attacker access to other cloud resources. The Capital One breach used exactly this technique.</p>

<p><strong>Credential exposure in code repositories</strong> — Developers accidentally commit cloud credentials (API keys, access keys, secrets) to code repositories, including public ones like GitHub. Automated bots scan GitHub continuously for newly committed credentials and attempt to use them within seconds of exposure. A committed AWS access key can result in thousands of dollars of charges (from cryptocurrency mining) within hours.</p>

<p>This is so common that AWS automatically scans GitHub for AWS credentials and revokes them when found. However, the window between exposure and revocation is enough for automated abuse.</p>

<p><strong>Lateral movement in cloud environments</strong> — Using the permissions of a compromised resource to access other resources. An attacker who compromises a web server with an IAM role can use that role to list S3 buckets, query databases, invoke Lambda functions, or create new IAM users. Cloud environments make lateral movement particularly dangerous because resources often have permissions to access many other resources.</p>

<p><strong>Cryptojacking</strong> — Using compromised cloud resources to mine cryptocurrency, with the cost billed to the victim's account. Attackers who gain access to cloud credentials or exploit vulnerabilities in cloud-hosted applications frequently deploy cryptocurrency mining software. The victim discovers the breach when they receive an unexpected cloud bill.</p>

<h2>Cloud security controls and best practices</h2>

<p><strong>Identity and Access Management</strong></p>
<ul>
<li>Enable MFA on all accounts, especially root/global administrator accounts</li>
<li>Apply least privilege — every user and service role should have only the permissions it actually needs</li>
<li>Rotate access keys regularly and remove unused credentials</li>
<li>Use service accounts and instance roles rather than sharing personal credentials</li>
<li>Conduct regular access reviews to identify and remove unnecessary permissions</li>
</ul>

<p><strong>Network security</strong></p>
<ul>
<li>Use Virtual Private Clouds (VPCs) to isolate resources</li>
<li>Configure security groups and network ACLs to allow only necessary traffic</li>
<li>Never expose management interfaces (RDP, SSH, database ports) directly to the internet — use bastion hosts or VPN</li>
<li>Enable VPC Flow Logs to capture network traffic metadata</li>
</ul>

<p><strong>Data protection</strong></p>
<ul>
<li>Enable encryption at rest for all storage — most cloud providers offer this with minimal configuration</li>
<li>Ensure data in transit is encrypted (HTTPS, TLS)</li>
<li>Audit storage bucket permissions regularly — use cloud-native tools to detect public buckets</li>
<li>Implement data lifecycle policies to ensure data is not retained longer than necessary</li>
</ul>

<p><strong>Monitoring and detection</strong></p>
<ul>
<li>Enable all available logging services (CloudTrail, CloudWatch, Azure Monitor)</li>
<li>Set up alerts for high-risk events: root account usage, IAM changes, security group modifications, public bucket creation</li>
<li>Use Cloud Security Posture Management (CSPM) tools that continuously scan for misconfigurations</li>
<li>Review billing alerts for unexpected charges that may indicate cryptojacking</li>
</ul>

<h2>Common misconceptions</h2>

<p><strong>"Cloud is more secure than on-premises."</strong> Cloud providers invest heavily in physical security and infrastructure security, which is often better than what small and medium organisations could achieve themselves. However, cloud security depends entirely on how the customer configures it. A misconfigured cloud environment can be significantly less secure than a well-managed on-premises system.</p>

<p><strong>"The cloud provider is responsible for our data security."</strong> As the shared responsibility model makes clear, the customer is responsible for data classification, access controls, and configuration — regardless of where the data is hosted. The cloud provider secures the infrastructure; the customer secures what they put on it.</p>

<p><strong>"We do not need to worry about cloud security because we use enterprise-tier services."</strong> The level of service tier does not change the shared responsibility model. Enterprise agreements provide enhanced support and SLAs, not enhanced security configurations. Capital One was an enterprise AWS customer.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-d2",
        "section": "D",
        "lesson_number": 17,
        "order": 17,
        "title": "Data Protection and Privacy Basics",
        "body": """<h2>Why data protection matters in security</h2>

<p>Data protection and privacy are not just legal obligations — they are security disciplines. The controls that protect personal data (access management, encryption, data minimisation, breach response) are the same controls that protect all sensitive data. Understanding the legal framework gives security professionals the language and obligations that drive business decisions about data security.</p>

<p>In the UK and EU, the primary legal framework is GDPR and UK GDPR. Violations can result in fines of up to 4% of global annual turnover or £17.5 million (UK) / €20 million (EU), whichever is higher. These are not theoretical — the ICO (Information Commissioner's Office) has issued multi-million pound fines against organisations including British Airways and Marriott.</p>

<h2>What counts as personal data</h2>

<p>Personal data is any information relating to an identified or identifiable individual. The definition is broader than most people assume:</p>

<ul>
<li><strong>Obvious examples:</strong> name, email address, phone number, postal address, date of birth, National Insurance number, passport number</li>
<li><strong>Less obvious examples:</strong> IP addresses, cookie identifiers, location data, device identifiers, browsing history (when linked to an individual)</li>
<li><strong>Special category data</strong> (subject to stricter requirements): health data, biometric data, genetic data, racial or ethnic origin, political opinions, religious beliefs, trade union membership, sexual orientation</li>
</ul>

<p>The test is identifiability: if information can be used — alone or in combination with other information — to identify a specific person, it is personal data. Pseudonymised data (where names are replaced with identifiers) can still be personal data if re-identification is possible.</p>

<h2>GDPR — the key principles</h2>

<p>GDPR is built on six data protection principles that apply to all personal data processing:</p>

<p><strong>1. Lawfulness, fairness, and transparency</strong> — Processing must have a legal basis, must be fair to the individual, and individuals must be informed about how their data is used. You cannot collect data secretly or deceive people about what you will do with it.</p>

<p><strong>2. Purpose limitation</strong> — Data collected for one specific purpose cannot simply be repurposed for something else. Data collected to process a purchase cannot then be used for marketing without a separate legal basis.</p>

<p><strong>3. Data minimisation</strong> — Only collect data that is actually needed for the specified purpose. If you can achieve your goal with less data, you must use less. This principle directly conflicts with the "collect everything, figure out the use later" approach common in many organisations.</p>

<p><strong>4. Accuracy</strong> — Personal data must be kept accurate and up to date. Inaccurate data about individuals can cause serious harm — incorrect medical records, wrong credit information, outdated contact details used in emergencies.</p>

<p><strong>5. Storage limitation</strong> — Data should not be kept longer than necessary for its purpose. Organisations must have data retention policies that specify how long different categories of data are kept and ensure data is deleted when no longer needed. Keeping data indefinitely "just in case" violates this principle.</p>

<p><strong>6. Integrity and confidentiality</strong> — Data must be processed securely — protected against unauthorised access, loss, destruction, or damage. This is where data protection law and cybersecurity directly intersect: the legal obligation to protect data requires technical security controls.</p>

<h2>Lawful bases for processing</h2>

<p>Under GDPR, every instance of personal data processing must have a legal basis. There are six:</p>

<ol>
<li><strong>Consent</strong> — The individual has given clear, informed, specific, and freely given consent. Consent must be as easy to withdraw as to give. Pre-ticked boxes and bundled consent ("by using our service you agree to marketing") do not meet the standard.</li>
<li><strong>Contract</strong> — Processing is necessary to perform a contract with the individual, or to take steps at their request before entering a contract. Processing payment information to fulfil an order is justified under this basis.</li>
<li><strong>Legal obligation</strong> — Processing is required to comply with a legal obligation. Employers must process employee data for tax reporting. Banks must retain transaction records for anti-money laundering purposes.</li>
<li><strong>Vital interests</strong> — Processing is necessary to protect someone's life. Rare in commercial contexts but relevant in healthcare emergencies.</li>
<li><strong>Public task</strong> — Processing is necessary for a task carried out in the public interest or in the exercise of official authority. Primarily relevant to government organisations and public bodies.</li>
<li><strong>Legitimate interests</strong> — Processing is necessary for the organisation's legitimate interests, provided those interests are not overridden by the individual's rights. This is the most flexible basis but requires a balancing test and cannot be used for special category data without additional justification.</li>
</ol>

<h2>Individual rights under GDPR</h2>

<p>GDPR grants individuals specific rights over their personal data. Organisations must be able to respond to these requests within one month:</p>

<p><strong>Right to access</strong> — Individuals can request a copy of all personal data held about them and information about how it is being processed. This is a Subject Access Request (SAR). Organisations cannot charge for SARs and must provide comprehensive information about what data is held.</p>

<p><strong>Right to rectification</strong> — Inaccurate data must be corrected. If your records show a wrong address or incorrect information, the individual can require you to fix it.</p>

<p><strong>Right to erasure ("right to be forgotten")</strong> — Individuals can request deletion of their data in certain circumstances: when the data is no longer needed, when consent is withdrawn, when there is no legitimate interest that overrides the request. This right is not absolute — legal obligations may require retention.</p>

<p><strong>Right to data portability</strong> — Individuals can request their data in a machine-readable format to transfer to another service. Primarily relevant where processing is based on consent or contract and carried out by automated means.</p>

<p><strong>Right to object</strong> — Individuals can object to processing based on legitimate interests or for direct marketing. For direct marketing, objection must be honoured without question and without needing justification.</p>

<h2>Breach notification obligations</h2>

<p>Under GDPR, a personal data breach — any accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to personal data — must be handled in a defined way:</p>

<p><strong>Risk assessment</strong> — Not all breaches require notification. The organisation must assess the risk to individuals. A breach of encrypted data with no decryption key poses minimal risk. A breach of unencrypted health data poses high risk.</p>

<p><strong>Supervisory authority notification</strong> — If the breach is likely to result in risk to individuals' rights and freedoms, the supervisory authority (ICO in the UK) must be notified within 72 hours of becoming aware of the breach. If notification takes longer, the reasons for the delay must be explained.</p>

<p><strong>Individual notification</strong> — If the breach is likely to result in high risk to individuals, they must also be notified directly without undue delay. The notification must describe the breach, the likely consequences, and what measures have been taken.</p>

<p>The 72-hour clock starts when the organisation "becomes aware" — which means when there is reasonable certainty that a breach has occurred, not when every detail has been determined. Many organisations have fallen foul of this by investigating thoroughly before notifying, by which point the 72-hour window has passed.</p>

<h2>Data classification</h2>

<p>Data classification is the process of categorising data by its sensitivity so that appropriate protections can be applied. A common classification scheme:</p>

<table>
<thead>
<tr><th>Classification</th><th>Description</th><th>Controls required</th></tr>
</thead>
<tbody>
<tr><td>Public</td><td>Intended for public distribution</td><td>Minimal — standard publishing controls</td></tr>
<tr><td>Internal</td><td>For internal use, not sensitive</td><td>Access controls, no external sharing</td></tr>
<tr><td>Confidential</td><td>Sensitive business or personal data</td><td>Access controls, encryption, monitoring</td></tr>
<tr><td>Restricted</td><td>Highly sensitive — financial, health, legal</td><td>Strict access controls, encryption, audit logging, DLP</td></tr>
</tbody>
</table>

<p>Classification enables proportionate protection: not everything needs the same level of security. Knowing that a dataset is "Restricted" tells everyone who handles it what protections are required without needing to assess it each time.</p>

<h2>Common misconceptions</h2>

<p><strong>"GDPR only applies to EU organisations."</strong> GDPR applies to any organisation that processes personal data of EU individuals, regardless of where the organisation is based. A US company serving EU customers must comply with GDPR. UK GDPR (post-Brexit) has essentially the same requirements for organisations processing data of UK residents.</p>

<p><strong>"Anonymised data is not subject to GDPR."</strong> Truly anonymised data — where re-identification is impossible — falls outside GDPR's scope. However, anonymisation is technically difficult. Data that has had names removed but retains enough attributes (age, location, job title, rare conditions) to allow re-identification through combination or inference is pseudonymised, not anonymised, and remains subject to GDPR.</p>

<p><strong>"Consent is always the safest legal basis."</strong> Many organisations default to consent because it feels the most intuitive. But consent has strict requirements — it must be freely given, specific, informed, and unambiguous. It can be withdrawn at any time, which creates ongoing management obligations. Other bases like contract or legitimate interests may be more appropriate and more sustainable for many use cases.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-d3",
        "section": "D",
        "lesson_number": 18,
        "order": 18,
        "title": "Cybersecurity Job Roles Explained",
        "body": """<h2>Understanding the job market</h2>

<p>Cybersecurity is not a single career path — it is a broad field with dozens of distinct specialisations, each requiring different skills, different temperaments, and offering different day-to-day experiences. One of the most common mistakes aspiring security professionals make is having a vague goal of "getting into cybersecurity" without understanding what specific roles exist and which might actually suit them.</p>

<p>This lesson maps the major roles in detail: what people actually do day to day, what skills and experience are typically required, what the realistic entry paths look like, and how roles connect to career progression. Understanding this landscape lets you make an informed choice about where to focus your effort.</p>

<h2>SOC Analyst (Security Operations Centre Analyst)</h2>

<p><strong>What they do:</strong> SOC analysts are the first line of defence for monitoring environments and responding to security events. They review alerts generated by security tools (SIEM, EDR, network monitoring), investigate suspicious activity, determine whether alerts are genuine threats or false positives, escalate genuine incidents, and document their findings.</p>

<p><strong>A realistic day:</strong> Arrive and check the overnight alert queue. Review 30-50 alerts from the SIEM — most are false positives (automated scanners, misconfigured systems generating noise). Three look interesting: investigate each by correlating with other log sources, researching the indicators, checking threat intelligence. Two are false positives. One is a genuine suspicious PowerShell execution — escalate to Level 2 with a summary of findings. Document everything. Review threat intelligence feeds for new indicators. Attend a brief handover at shift end.</p>

<p><strong>Levels and progression:</strong></p>
<ul>
<li><strong>L1 SOC Analyst</strong> — triage alerts, follow playbooks, escalate. Entry-level, no prior experience required for some roles</li>
<li><strong>L2 SOC Analyst</strong> — deeper investigation, incident response, some threat hunting. 1-2 years experience</li>
<li><strong>L3 SOC Analyst / Senior Analyst</strong> — complex investigations, playbook development, mentoring L1/L2. 3-5 years</li>
<li><strong>SOC Manager / Lead</strong> — team management, SOC strategy, metrics. 5+ years</li>
</ul>

<p><strong>Skills needed:</strong> Understanding of networking and common protocols, familiarity with Windows and Linux, ability to read logs and correlate events, knowledge of common attack techniques, SIEM experience (Splunk, Sentinel). Soft skills: attention to detail, ability to work under pressure, clear written communication.</p>

<p><strong>Entry reality:</strong> L1 SOC analyst is one of the most accessible entry points in cybersecurity. Many organisations hire candidates with CompTIA Security+, TryHackMe/HackTheBox experience, and enthusiasm over candidates with degrees but no practical skills. It is shift work — many SOCs operate 24/7, which means nights, weekends, and holidays are part of the job.</p>

<h2>Incident Responder</h2>

<p><strong>What they do:</strong> Incident responders investigate confirmed security incidents — active breaches, malware infections, data theft. They determine how attackers got in, what they accessed, how far they moved, and what damage was caused. They guide containment (stopping the spread), eradication (removing the attacker's presence), and recovery (restoring systems). They produce detailed reports explaining the incident to technical and non-technical audiences.</p>

<p><strong>A realistic day:</strong> On a quiet day — review previous incident reports, update playbooks, practise forensic skills on lab environments, study emerging attack techniques. On an active incident day — brief from the client about what they have observed, access to their environment, hours of log analysis to reconstruct the attacker's timeline, calls with the client to update them on findings, producing a preliminary report while the investigation continues. High pressure, long hours, significant responsibility.</p>

<p><strong>Skills needed:</strong> Strong foundation in Windows and Linux internals, understanding of the full attack lifecycle, forensic investigation techniques, ability to analyse malware behaviour (not necessarily reverse engineer it), excellent written communication for technical reports. Experience with forensic tools (Autopsy, Volatility for memory forensics, FTK).</p>

<p><strong>Entry reality:</strong> Most incident response roles require 2-3 years of prior experience, typically in a SOC. Some firms hire junior IR analysts who work under senior investigators. This is a high-stress, often-reactive role — incidents do not happen on schedule.</p>

<h2>Penetration Tester (Pentester)</h2>

<p><strong>What they do:</strong> Pentesters are paid to attack systems — with explicit written permission — to find vulnerabilities before real attackers do. They simulate the techniques, tactics, and procedures of real threat actors against their clients' systems, applications, and networks. The output is a detailed report explaining what was found, how it was exploited, what the impact would be, and how to fix it.</p>

<p><strong>Types of penetration testing:</strong></p>
<ul>
<li><strong>Network/infrastructure</strong> — testing external and internal network security</li>
<li><strong>Web application</strong> — testing web applications for OWASP Top 10 vulnerabilities and beyond</li>
<li><strong>Mobile application</strong> — testing iOS and Android apps</li>
<li><strong>Social engineering</strong> — testing human controls through phishing simulations and physical intrusion testing</li>
<li><strong>Red team operations</strong> — full-scope, extended engagements simulating a realistic adversary</li>
</ul>

<p><strong>Skills needed:</strong> Strong technical foundation across networking, operating systems, and web technologies. Ability to think creatively and adversarially. Proficiency with security tools (Nmap, Burp Suite, Metasploit, BloodHound). Programming/scripting skills (Python, Bash). Report writing — the ability to explain technical findings clearly to executive audiences is as important as finding the vulnerabilities.</p>

<p><strong>Entry reality:</strong> Penetration testing is technical and competitive. Entry without significant demonstrated skills is difficult. The path is typically: build skills on TryHackMe/HackTheBox → achieve OSCP (Offensive Security Certified Professional) → junior penetration tester role. OSCP is practically mandatory for most pentesting roles — it involves a 24-hour practical exam where candidates must compromise a series of machines.</p>

<h2>Security Engineer</h2>

<p><strong>What they do:</strong> Security engineers design, build, and maintain the technical controls and infrastructure that protect an organisation's systems. This includes configuring and managing security tools (firewalls, EDR, SIEM, identity systems), designing secure network architecture, developing security automation, and integrating security into development processes.</p>

<p><strong>A realistic day:</strong> Working on a SIEM deployment — ingesting new log sources, writing detection rules, testing and tuning to reduce false positives. Reviewing a proposed network architecture change for security implications. Scripting a process to automatically revoke access for terminated employees. Attending a meeting with the development team about secure coding practices for a new application.</p>

<p><strong>Skills needed:</strong> Strong technical background — typically prior experience in systems administration, networking, or software development. Understanding of security tools and how to configure them. Scripting (Python, PowerShell). Cloud platform expertise is increasingly important. Security architecture knowledge.</p>

<p><strong>Entry reality:</strong> Pure security engineering roles typically require a technical background. A systems administrator or network engineer who develops security skills is better positioned for a security engineering role than someone coming from a non-technical background. Cloud security engineering specifically is one of the highest-paid and most in-demand specialisations currently.</p>

<h2>GRC Analyst (Governance, Risk and Compliance)</h2>

<p><strong>What they do:</strong> GRC professionals manage the governance, risk management, and compliance functions of an organisation's security programme. They develop security policies and standards, conduct risk assessments, manage compliance with regulations (GDPR, ISO 27001, Cyber Essentials, PCI DSS), support internal and external audits, and produce reports for executive leadership and board-level stakeholders.</p>

<p><strong>A realistic day:</strong> Reviewing a third-party supplier's security questionnaire responses. Updating the risk register with new findings from a recent penetration test. Meeting with the legal team about GDPR breach notification obligations. Drafting a policy for acceptable use of AI tools. Preparing a quarterly security report for the board. Coordinating an ISO 27001 audit.</p>

<p><strong>Skills needed:</strong> Understanding of security frameworks and standards (ISO 27001, NIST, Cyber Essentials). Knowledge of relevant legislation (GDPR, NIS Regulations). Risk management methodology. Strong written communication — GRC involves significant documentation. Stakeholder management and the ability to translate technical risks into business language.</p>

<p><strong>Entry reality:</strong> GRC is one of the most accessible entry points for people coming from non-technical backgrounds. Legal, compliance, audit, and project management backgrounds transfer well. A foundational security qualification (CompTIA Security+) combined with understanding of GDPR and ISO 27001 is often sufficient for junior GRC roles.</p>

<h2>Threat Intelligence Analyst</h2>

<p><strong>What they do:</strong> Track threat actor groups, their techniques, infrastructure, and targets. Produce intelligence reports that help organisations understand which threats are relevant to them. Monitor dark web forums and marketplaces for stolen data or threat activity targeting specific organisations or sectors. Brief security teams and executives on emerging threats.</p>

<p><strong>Skills needed:</strong> Strong analytical and research skills. OSINT (Open Source Intelligence) techniques. Understanding of threat actor groups and the MITRE ATT&CK framework. Often benefits from foreign language skills. Report writing for both technical and executive audiences.</p>

<h2>Cloud Security Engineer</h2>

<p><strong>What they do:</strong> Secure cloud infrastructure across AWS, Azure, and/or GCP. Configure IAM policies, security groups, logging, and monitoring. Implement CSPM (Cloud Security Posture Management). Integrate security into DevOps pipelines (DevSecOps). Conduct cloud security assessments.</p>

<p><strong>Why it matters now:</strong> The migration of organisational infrastructure to the cloud has created enormous demand for people who understand both cloud platforms and security. Cloud security engineers are among the highest-paid roles in the field.</p>

<p><strong>Entry path:</strong> Cloud platform certifications (AWS Certified Security Specialty, Azure Security Engineer) combined with security fundamentals. Prior cloud operations experience is valuable.</p>

<h2>Which role is right for you?</h2>

<table>
<thead>
<tr><th>You enjoy...</th><th>Consider...</th></tr>
</thead>
<tbody>
<tr><td>Analysis, investigation, finding patterns in data</td><td>SOC Analyst, Threat Intelligence, Incident Response</td></tr>
<tr><td>Building and configuring systems</td><td>Security Engineer, Cloud Security Engineer</td></tr>
<tr><td>Finding and exploiting weaknesses</td><td>Penetration Tester, Red Team</td></tr>
<tr><td>Writing, policy, risk management, working with stakeholders</td><td>GRC Analyst</td></tr>
<tr><td>The most accessible entry point without deep technical background</td><td>GRC Analyst or L1 SOC Analyst</td></tr>
<tr><td>The highest earning potential</td><td>Cloud Security Engineer, Senior Penetration Tester, Security Architect</td></tr>
</tbody>
</table>""",
        "lab": None,
    },
    {
        "slug": "gic-d4",
        "section": "D",
        "lesson_number": 19,
        "order": 19,
        "title": "Beginner Tools and Safe Practice",
        "body": """<h2>Learning by doing</h2>

<p>Cybersecurity is a practical discipline. Reading about how SQL injection works is useful. Actually exploiting a vulnerable application in a safe environment cements the knowledge in a way that passive learning never can. The tools and platforms in this lesson allow you to develop and demonstrate practical skills in legal, safe environments — which is exactly what employers look for.</p>

<p>Before covering the tools, the most important principle: only use security tools against systems you own or have explicit written permission to test. The Computer Misuse Act 1990 (UK) and equivalent laws elsewhere make unauthorised access a criminal offence, regardless of intent. "I was just practising" is not a defence. Everything in this lesson is about practising legally.</p>

<h2>TryHackMe — the recommended starting point</h2>

<p>TryHackMe is a browser-based learning platform that provides guided, hands-on exercises in virtual environments. You do not need to install anything — the vulnerable machines run in the cloud, and you connect through your browser. This makes it the most accessible entry point for practical skills.</p>

<p><strong>How it works:</strong> Rooms are guided exercises that walk you through concepts step by step, providing hints and explanations. Paths are curated sequences of rooms that build skills progressively. A learning subscription provides access to all rooms and paths.</p>

<p><strong>Recommended learning paths for this course's audience:</strong></p>

<ul>
<li><strong>Pre-Security</strong> (free) — Foundational networking, web fundamentals, and Linux basics. Complete this first if you feel uncertain about technical fundamentals.</li>
<li><strong>SOC Level 1</strong> — Defensive skills directly relevant to analyst roles: log analysis, SIEM use, alert triage, threat intelligence. Directly maps to what L1 SOC analysts do daily.</li>
<li><strong>Jr Penetration Tester</strong> — Introduction to offensive security: network scanning, web application vulnerabilities, exploitation basics. Requires more technical background but excellent for those targeting technical roles.</li>
<li><strong>Cyber Defence</strong> — Blue team skills: threat hunting, incident response, digital forensics.</li>
</ul>

<p><strong>Practical advice:</strong> Consistency beats intensity. 30 minutes daily produces better skill development than 8 hours once a week. When you complete a room, write a brief walkthrough — this becomes portfolio content and reinforces the learning.</p>

<h2>HackTheBox — for advancing skills</h2>

<p>HackTheBox is more advanced than TryHackMe and takes a different approach — machines are provided without guided instructions. You must research, attempt, fail, research more, and eventually find the path to compromise. This problem-solving process is closer to real penetration testing than guided exercises.</p>

<p>Start HackTheBox after completing at least one TryHackMe path. The "Starting Point" machines on HackTheBox provide some guidance for beginners. The forums and community provide hints without complete solutions.</p>

<p>HackTheBox also offers Academy, which is more structured and provides theoretical content alongside practical exercises — a good complement to TryHackMe for those who want more structure.</p>

<h2>VirusTotal — essential for analysis</h2>

<p>VirusTotal analyses files, URLs, IP addresses, and domain names using dozens of antivirus engines and threat intelligence feeds simultaneously, providing a comprehensive assessment in seconds.</p>

<p><strong>Practical use cases:</strong></p>

<ul>
<li><strong>File analysis</strong> — Upload a file to check whether any antivirus engines flag it as malicious. Useful for checking downloaded files before execution. Note: do not upload files containing sensitive data — uploaded files are accessible to VirusTotal's subscribers.</li>
<li><strong>URL analysis</strong> — Submit a suspicious URL without visiting it. VirusTotal will access the URL and report what it finds, including which security vendors flag it as malicious.</li>
<li><strong>IP address lookup</strong> — Check whether an IP address is known to be associated with malicious activity, what domains are hosted on it, and what threat intelligence feeds say about it.</li>
<li><strong>Hash lookup</strong> — If you have the hash (MD5, SHA1, or SHA256) of a file, you can look it up without uploading the file. This is the preferred approach for potentially sensitive files.</li>
</ul>

<p><strong>Interpreting results:</strong> A file flagged by 2/70 vendors may be a false positive. A file flagged by 45/70 is almost certainly malicious. Context matters — zero detections does not necessarily mean clean, especially for new or targeted malware that engines have not yet seen.</p>

<h2>Wireshark — understanding network traffic</h2>

<p>Wireshark is the industry-standard network protocol analyser. It captures network traffic and displays it in human-readable form, allowing you to see exactly what is being transmitted across a network connection.</p>

<p><strong>What Wireshark shows you:</strong></p>
<ul>
<li>Every packet — source and destination addresses, ports, protocol</li>
<li>Protocol details — HTTP request headers, DNS queries and responses, TCP handshakes</li>
<li>Data content — for unencrypted traffic, the actual content being transmitted</li>
<li>Traffic patterns — conversation summaries, bandwidth usage, protocol distribution</li>
</ul>

<p><strong>Learning uses:</strong> Understanding how protocols work by seeing them in action. Analysing captured network traffic from malware samples (available from MalwareBazaar and similar repositories) to understand attacker behaviour. Practising for Wireshark challenges on TryHackMe and HackTheBox.</p>

<p><strong>Legal note:</strong> Only capture traffic on networks you own or have explicit permission to monitor. Capturing traffic on a corporate network without authorisation may violate company policy and law. Practise on your home network or in virtual environments.</p>

<h2>Nmap — network scanning</h2>

<p>Nmap is the standard tool for network discovery and port scanning. It sends packets to target hosts and analyses the responses to determine what is online, what ports are open, and what services are running.</p>

<p>Basic usage:</p>
<pre><code># Scan a single host — show open ports
nmap 192.168.1.1

# Scan a subnet — discover all hosts
nmap 192.168.1.0/24

# Detect service versions on open ports
nmap -sV 192.168.1.1

# Comprehensive scan — OS detection, version detection, script scanning
nmap -A 192.168.1.1

# Scan specific ports only
nmap -p 22,80,443,3389 192.168.1.1</code></pre>

<p><strong>Legal and ethical use:</strong> Only scan your own systems or systems you have explicit permission to scan. Port scanning is not inherently illegal, but scanning systems without permission may violate terms of service and could be construed as preparation for an attack. Practise on your home network, TryHackMe environments, or your own virtual machines.</p>

<h2>Setting up a home lab</h2>

<p>A home lab is a personal learning environment where you can practise security skills on systems you control. Modern hardware and free virtualisation software make this accessible for anyone with a reasonably modern computer.</p>

<p><strong>VirtualBox</strong> — Free, open-source virtualisation software from Oracle. Allows you to run multiple operating systems simultaneously on your computer, each isolated in its own virtual machine. This is the foundation of a home lab.</p>

<p><strong>Recommended virtual machines to build your lab:</strong></p>

<ul>
<li><strong>Kali Linux</strong> — The standard security testing distribution, containing hundreds of pre-installed security tools. Download as a VirtualBox image from kali.org. Use this as your "attacker" machine.</li>
<li><strong>Windows 10 evaluation</strong> — Microsoft provides free 90-day evaluation versions of Windows for testing purposes. Use this as a target for practising Windows-specific techniques.</li>
<li><strong>Metasploitable2 or DVWA</strong> — Deliberately vulnerable virtual machines and web applications designed for practising exploitation. Run these in a host-only network (not connected to the internet) so they cannot be accessed externally.</li>
<li><strong>Ubuntu Server</strong> — Free Linux server installation. Practise Linux administration, log analysis, and defensive configurations.</li>
</ul>

<p><strong>Network configuration:</strong> When practising attacks between virtual machines, configure them on a "host-only" or "internal network" adapter in VirtualBox. This keeps vulnerable machines isolated from your real network and the internet. Never connect Metasploitable or other intentionally vulnerable machines to the internet.</p>

<h2>Other useful tools and resources</h2>

<p><strong>Burp Suite Community Edition</strong> — The standard web application security testing tool. Intercepts and manipulates HTTP/HTTPS traffic between your browser and web servers. The community edition is free and sufficient for learning. Essential for web application testing.</p>

<p><strong>Shodan</strong> (shodan.io) — A search engine for internet-connected devices. Shows what services are running on IP addresses and what they expose to the internet. Useful for understanding the external attack surface of an organisation, researching specific technologies, and understanding what attackers see when they look for targets.</p>

<p><strong>AbuseIPDB</strong> (abuseipdb.com) — Database of IP addresses reported for malicious activity. Essential for investigating suspicious connections during incident response.</p>

<p><strong>MITRE ATT&CK</strong> (attack.mitre.org) — A comprehensive knowledge base of attacker tactics, techniques, and procedures based on real-world observations. Free and essential reference for understanding how attacks work, describing incidents, and building detections.</p>

<p><strong>Have I Been Pwned</strong> (haveibeenpwned.com) — Check whether an email address or password has appeared in known data breaches. Created by security researcher Troy Hunt. Essential for understanding credential exposure.</p>

<h2>Common misconceptions</h2>

<p><strong>"I need expensive tools to learn cybersecurity."</strong> The most valuable tools (Nmap, Wireshark, Burp Suite Community Edition, Kali Linux) are free. TryHackMe has a substantial free tier. The investment required is time and effort, not money.</p>

<p><strong>"Practising on systems without permission is fine if I am just learning."</strong> It is not. "Educational purposes" is not a legal defence for accessing systems without authorisation. The platforms and lab environments in this lesson exist precisely so you can practise legally. Use them.</p>

<p><strong>"I need to complete everything before I am ready to apply for jobs."</strong> No one completes everything. Employers are looking for curiosity, demonstrated practical skills, and the ability to learn — not comprehensive coverage of every tool. A TryHackMe profile showing 50+ completed rooms and a few published writeups demonstrates more than a CV listing tools you have read about.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-d5",
        "section": "D",
        "lesson_number": 20,
        "order": 20,
        "title": "How to Start a Career in Cybersecurity",
        "body": """<h2>The honest picture</h2>

<p>Breaking into cybersecurity takes time and effort — but it is genuinely achievable, and the demand for security professionals significantly exceeds the supply. The gap between available cybersecurity positions and qualified candidates to fill them is estimated at over 3 million globally. This is not a field you will struggle to enter if you develop real skills and present them effectively.</p>

<p>What it takes: foundational knowledge (which this course has provided), demonstrable practical skills (built through platforms like TryHackMe), relevant certifications (which signal commitment and baseline knowledge to employers), and the ability to present your skills compellingly. None of these require a computer science degree or years of prior IT experience.</p>

<p>What it does not take: hacking into things to practise. Paying for overpriced bootcamps that promise guaranteed employment. Knowing everything before you start applying.</p>

<h2>Step 1: Know where you want to go</h2>

<p>The previous lesson mapped the major roles in cybersecurity. Before investing significant time and money in certifications and skills development, identify a target role — even a provisional one that you might refine later.</p>

<p>Two questions to guide this:</p>
<ol>
<li>What kind of work do I find genuinely interesting? (Analysis and investigation vs building systems vs finding vulnerabilities vs policy and risk)</li>
<li>What is my current technical level honestly? (Comfortable with computers but no IT background vs IT/systems experience vs programming background)</li>
</ol>

<p>For most people completing this course without prior IT experience, the most realistic starting points are:</p>
<ul>
<li><strong>L1 SOC Analyst</strong> — Defensive, analytical, accessible with foundational knowledge and a CompTIA Security+</li>
<li><strong>Junior GRC Analyst</strong> — Policy and compliance focused, accessible from non-technical backgrounds with regulatory knowledge</li>
</ul>

<p>Both are valid starting points. Both lead to strong careers. The key is to choose one and focus your effort on building the specific skills and credentials that role requires, rather than vaguely building "cybersecurity skills."</p>

<h2>Step 2: Build demonstrable practical skills</h2>

<p>Employers hiring for entry-level roles understand that candidates will not have professional experience. What distinguishes candidates is demonstrated initiative and practical skill — evidence that you have done the work, not just read about it.</p>

<p><strong>TryHackMe</strong> — Complete at least one full learning path relevant to your target role. For SOC analyst: complete SOC Level 1. For GRC: complete the relevant governance and compliance rooms. For penetration testing: complete Jr Penetration Tester. Your TryHackMe profile is public and shows employers what you have completed.</p>

<p><strong>Write-ups</strong> — For each TryHackMe room or HackTheBox machine you complete, write a brief walkthrough explaining what you did and what you learned. Publish these on a blog (Medium, GitHub Pages, a personal site). This demonstrates technical communication skills — a critical skill in every security role — and creates a portfolio that hiring managers can read.</p>

<p>Write-ups do not need to be comprehensive. Two to three paragraphs explaining the vulnerability, how you exploited it, and what the defence would be is sufficient. The act of writing forces you to understand what you did rather than just following steps.</p>

<p><strong>Home lab</strong> — Document your home lab setup and what you have done with it. Screenshots, configuration notes, and explanations of what you were practising and what you learned. This demonstrates hands-on technical work beyond guided exercises.</p>

<h2>Step 3: Get the right certifications</h2>

<p>Certifications serve two purposes: they validate knowledge to employers who cannot assess it otherwise, and they structure your learning. Not all certifications are worth the investment — focus on the ones that employers actually ask for.</p>

<p><strong>CompTIA Security+</strong> — The single most recognised entry-level security certification. Required or preferred in the majority of entry-level security job postings in the UK and US. Covers a broad range of foundational security topics. The exam is multiple-choice and scenario-based, typically requiring 2-3 months of focused study. Cost: approximately £300-350 for the exam.</p>

<p><strong>ISC2 Certified in Cybersecurity (CC)</strong> — Free to sit, free study materials, no experience requirement. Provides a recognised credential with minimal financial risk. A good first step before tackling Security+. ISC2 (the organisation behind CISSP) offers free access to their training materials for this certification.</p>

<p><strong>CompTIA CySA+</strong> — Analyst-focused certification that follows Security+. More relevant to SOC analyst roles. Typically pursued after 1-2 years of experience, but can be studied alongside entry-level roles.</p>

<p><strong>For GRC roles:</strong> ISACA CISA (Certified Information Systems Auditor) and ISC2 CCSP (cloud security) are valuable at more senior levels. At entry level, demonstrating knowledge of ISO 27001, GDPR, and NIST frameworks through self-study and relevant projects is often sufficient.</p>

<p><strong>For penetration testing:</strong> CompTIA PenTest+ is a stepping stone, but OSCP (Offensive Security Certified Professional) is the gold standard. The OSCP exam is a 24-hour practical exam requiring candidates to compromise a set of machines — it is challenging and respected precisely because it cannot be passed by memorising answers. Expect to spend 6-12 months preparing seriously.</p>

<p><strong>For cloud security:</strong> AWS Certified Security Specialty or Microsoft Azure Security Engineer (AZ-500) combined with foundational cloud certifications (AWS Solutions Architect Associate, AZ-900/AZ-104).</p>

<h2>Step 4: Build a compelling profile</h2>

<p><strong>LinkedIn</strong> — Update your LinkedIn to clearly position yourself for cybersecurity. Add certifications as you earn them. Post occasional content about what you are learning — sharing a TryHackMe writeup, commenting on a security news story, documenting what you set up in your home lab. This signals active engagement to recruiters who will search LinkedIn for candidates.</p>

<p><strong>GitHub</strong> — Host your writeups, scripts, and home lab documentation. A GitHub profile with regular commits demonstrates practical technical work. Even small scripts (a Python script that parses log files, a tool that checks for common misconfigurations) demonstrate initiative.</p>

<p><strong>TryHackMe profile</strong> — Your public TryHackMe profile shows exactly what rooms and paths you have completed. This is directly relevant evidence that employers can check. Include the link in your CV.</p>

<p><strong>CV</strong> — Structure your CV to highlight security-relevant experience and skills, even if they were not in security roles. IT support experience demonstrates technical troubleshooting and systems knowledge. Customer service experience demonstrates communication skills. Management experience demonstrates leadership. Everyone has transferable skills — the work is identifying and articulating them in security-relevant terms.</p>

<p>For entry-level roles, a two-page CV is appropriate. Include: a brief professional summary positioning you for security, technical skills (specific tools, platforms, and technologies you know), certifications, education, and work experience. Do not include a photo, date of birth, or other information not relevant to the role.</p>

<h2>Step 5: Apply strategically</h2>

<p><strong>Target entry-level roles specifically.</strong> Job titles to search for: Junior Security Analyst, L1 SOC Analyst, Security Operations Analyst, Information Security Analyst, Junior GRC Analyst, Cyber Security Graduate. Avoid applying for roles requiring 5+ years of experience — you will not get interviews and the rejection is discouraging rather than informative.</p>

<p><strong>Read job descriptions carefully.</strong> Note what specific skills, tools, and certifications appear repeatedly in the roles you want. This tells you exactly what to prioritise in your preparation. If every L1 SOC role you see requires Splunk experience, get Splunk experience (TryHackMe has a free Splunk learning path).</p>

<p><strong>Apply broadly.</strong> Entry-level positions are competitive. Apply to 20-30 roles rather than carefully selecting 5. Rejection is a normal part of the process and provides no information about your suitability — it usually means a candidate with slightly more experience applied.</p>

<p><strong>Use your network.</strong> Many roles are filled through connections before being advertised. Attend virtual security meetups (BSides events, OWASP chapter meetings, ISACA events). Engage with security communities on LinkedIn and Twitter/X. Many security professionals are genuinely willing to answer questions from people who are clearly putting in the effort to learn.</p>

<h2>Interview preparation</h2>

<p><strong>Technical questions</strong> — You will be asked about fundamental concepts. Practise explaining: what the CIA triad is, how TCP/IP works, what happens in a phishing attack, how you would investigate a suspicious login, what a SQL injection attack is. Be honest about what you know and what you are still learning — interviewers respect intellectual honesty.</p>

<p><strong>Scenario questions</strong> — "How would you respond if a user reported their computer was running slowly and you suspected malware?" Walk through your thinking: what would you check first, what evidence would you look for, when would you escalate. The answer matters less than demonstrating a structured, logical approach.</p>

<p><strong>Behavioural questions</strong> — "Tell me about a time you solved a difficult problem." "How do you handle learning something new?" Prepare examples from any context — work, education, personal projects — that demonstrate the qualities relevant to the role.</p>

<p><strong>Questions to ask</strong> — Asking thoughtful questions demonstrates genuine interest. Ask about: the team's incident response process, what the most common alerts the SOC sees are, what tools the team uses, what career development looks like, what a typical week involves. These questions also help you assess whether the role is actually what you want.</p>

<h2>Your 90-day action plan</h2>

<p><strong>Days 1-30</strong></p>
<ul>
<li>Create a TryHackMe account and complete the Pre-Security path if needed</li>
<li>Begin studying for CompTIA Security+ using Professor Messer's free video series and the CompTIA study guide</li>
<li>Set up LinkedIn and begin positioning for security roles</li>
<li>Install VirtualBox and set up Kali Linux</li>
<li>Write your first TryHackMe room writeup and publish it</li>
</ul>

<p><strong>Days 31-60</strong></p>
<ul>
<li>Begin TryHackMe SOC Level 1 or Jr Penetration Tester path (based on your target role)</li>
<li>Sit the ISC2 CC exam (free — no excuse not to)</li>
<li>Book your CompTIA Security+ exam date (having a date creates accountability)</li>
<li>Have five TryHackMe writeups published</li>
<li>Begin applying for entry-level roles — even if you do not feel ready, the process of applying teaches you what employers want</li>
</ul>

<p><strong>Days 61-90</strong></p>
<ul>
<li>Sit CompTIA Security+ exam</li>
<li>Complete at least one full TryHackMe learning path</li>
<li>Have ten published writeups</li>
<li>Update your LinkedIn with certifications and showcase your TryHackMe profile</li>
<li>Actively applying to 2-3 roles per week</li>
<li>Attend one virtual security event or community meetup</li>
</ul>

<h2>The realistic timeline</h2>

<p>Most people who follow a structured approach — consistently building skills, completing certifications, and actively applying — find their first security role within 6-18 months. The variance is wide and depends on local job market conditions, how much time you can invest weekly, and some unavoidable randomness in hiring processes.</p>

<p>Six months is achievable for someone who can invest 10-15 hours per week consistently. Eighteen months is realistic for someone balancing full-time work, family commitments, and part-time study. Both are valid paths. The only path that does not work is waiting until you feel "ready enough" to start applying — that feeling never comes, and applications are how you discover what you actually need to work on.</p>

<p>The cybersecurity field needs people who are curious, diligent, and motivated to protect systems that matter. You have the knowledge. Now build the skills, earn the credentials, and apply.</p>""",
        "lab": """<h2>Practical Lab: Three tasks to complete this week</h2>

<p>This lab focuses on taking concrete, real actions rather than working through exercises. By the end of this lab, you will have taken three steps that directly advance your career.</p>

<h3>Task 1: Create your TryHackMe profile and complete your first room</h3>

<ol>
<li>Go to tryhackme.com and create a free account</li>
<li>Complete the "Introduction to Cyber Security" room (free, approximately 2 hours)</li>
<li>Take a screenshot of your completed room and your profile showing your points and badges earned</li>
<li>Write a brief paragraph (3-5 sentences) summarising what you learned and what surprised you</li>
</ol>

<p>Your TryHackMe profile URL is public — note it down, as you will include it in your CV.</p>

<h3>Task 2: VirusTotal analysis exercise</h3>

<p>Find a suspicious URL from your spam folder or a link referenced in a security blog post about recent phishing campaigns. Submit it to virustotal.com for analysis.</p>

<p>Document the following:</p>
<ul>
<li>The URL you submitted (redact any personal information if it came from your email)</li>
<li>How many of VirusTotal's vendors flagged it as malicious</li>
<li>What category of threat was identified (phishing, malware, spam, etc.)</li>
<li>The names of three specific vendors and what they reported</li>
<li>Whether the URL led to any additional URLs or downloads</li>
<li>Your overall assessment: is this a genuine threat? What evidence supports your conclusion?</li>
</ul>

<h3>Task 3: Write your personal 90-day plan</h3>

<p>Based on the career guidance in this lesson, write a specific 90-day plan for yourself. Be precise — vague intentions do not produce action. Answer each question:</p>

<p><strong>Target role:</strong> Which specific job title are you targeting? (L1 SOC Analyst / Junior GRC Analyst / etc.)</p>

<p><strong>TryHackMe path:</strong> Which learning path will you complete first, and what is your weekly time commitment?</p>

<p><strong>First certification:</strong> Will you start with ISC2 CC or CompTIA Security+? What is your target exam date? (Pick a specific date 8-12 weeks from now)</p>

<p><strong>Home lab:</strong> What will you set up in your home lab? What will you practise with it?</p>

<p><strong>LinkedIn:</strong> What needs to change on your LinkedIn profile today to position you for your target role?</p>

<p><strong>Applications:</strong> On what date will you send your first job application? (This should be within 60 days, even if you do not feel ready)</p>

<p><strong>Accountability:</strong> How will you track your progress? Who will you share your progress with?</p>

<h3>Reflection</h3>

<p>Complete this course has given you a foundation that most people applying for entry-level cybersecurity roles do not have. You understand how attackers operate, how organisations defend themselves, how networks and systems work, and what careers in this field look like.</p>

<p>The next step is entirely in your hands. The 90-day plan you have just written is your roadmap. The tools and platforms in this lesson are your practice grounds. The certification path is your credentialling route.</p>

<p>The cybersecurity field genuinely needs more people. The question is whether you will be one of them.</p>""",
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
    print(f"Done — {updated} Section D lessons updated.")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()