"""
seed_section_b_expanded.py
--------------------------
Run from your project root:
    PYTHONPATH=/opt/render/project/src .venv/bin/python seed_section_b_expanded.py
"""

LESSONS = [
    {
        "slug": "gic-b1",
        "section": "B",
        "lesson_number": 6,
        "order": 6,
        "title": "Networking Fundamentals for Cyber",
        "body": """<h2>Why networking matters in cybersecurity</h2>

<p>Every attack that involves a remote system — which is most attacks — travels across a network. Phishing emails arrive over the internet. Malware communicates with attacker infrastructure over the internet. Lateral movement inside a compromised organisation happens across internal networks. Data exfiltration leaves through a network connection.</p>

<p>You cannot defend what you do not understand. A security professional who does not understand how networks work is limited to following checklists without knowing why. When you understand networks, you can read a firewall log and understand what it is telling you, identify suspicious traffic patterns, and make intelligent decisions about where to place controls.</p>

<p>This lesson builds that foundation — not to make you a network engineer, but to give you enough understanding to work effectively as a security professional.</p>

<h2>What a network is</h2>

<p>A network is a collection of devices that can communicate with each other. That communication happens through a combination of physical infrastructure (cables, wireless signals, hardware) and agreed-upon rules called protocols.</p>

<p>The internet is a network of networks — millions of individual networks, each owned and operated by different organisations, connected together through a shared set of standards that allow any device on any network to communicate with any other device, anywhere in the world. No single organisation owns or controls the internet. It works because everyone agrees to follow the same protocols.</p>

<h2>How data moves — packets</h2>

<p>Data does not travel across networks as a single continuous stream. It is broken into small chunks called packets. Each packet contains a portion of the data being sent, plus header information: where it came from (source address), where it is going (destination address), and how to reassemble it with other packets at the destination.</p>

<p>This approach — called packet switching — is efficient and resilient. If one path through the network is congested or broken, packets can take different routes and still arrive at the destination. The internet was originally designed this way specifically to survive partial destruction — a network that could route around damage was more resilient than one that depended on fixed circuits.</p>

<p>From a security perspective, packets can be inspected, filtered, logged, and analysed. Firewalls make decisions about whether to allow or block traffic based on packet information. Intrusion detection systems look for patterns in packets that indicate attacks. Understanding packets is fundamental to understanding how these controls work.</p>

<h2>The OSI model — a framework for understanding networks</h2>

<p>The Open Systems Interconnection (OSI) model describes how network communication works in seven layers. Each layer has a specific function and communicates with the layers above and below it. You do not need to memorise every detail, but understanding the layers helps you reason about where different attacks and defences operate.</p>

<table>
<thead>
<tr><th>Layer</th><th>Name</th><th>Function</th><th>Examples</th></tr>
</thead>
<tbody>
<tr><td>7</td><td>Application</td><td>User-facing protocols</td><td>HTTP, DNS, SMTP, FTP</td></tr>
<tr><td>6</td><td>Presentation</td><td>Data formatting, encryption</td><td>TLS, SSL, compression</td></tr>
<tr><td>5</td><td>Session</td><td>Managing connections</td><td>Session establishment and teardown</td></tr>
<tr><td>4</td><td>Transport</td><td>Reliable delivery</td><td>TCP, UDP</td></tr>
<tr><td>3</td><td>Network</td><td>Addressing and routing</td><td>IP, ICMP</td></tr>
<tr><td>2</td><td>Data Link</td><td>Local delivery</td><td>Ethernet, MAC addresses, ARP</td></tr>
<tr><td>1</td><td>Physical</td><td>Raw transmission</td><td>Cables, wireless signals, switches</td></tr>
</tbody>
</table>

<p><strong>Why this matters for security:</strong></p>
<ul>
<li>Firewalls primarily operate at layers 3 and 4 — they filter traffic based on IP addresses and ports</li>
<li>Web application firewalls (WAF) operate at layer 7 — they inspect the content of HTTP requests</li>
<li>TLS encryption operates at layer 6 — protecting data as it moves between systems</li>
<li>ARP spoofing attacks target layer 2 — manipulating the mapping between IP and MAC addresses on local networks</li>
<li>DDoS attacks often target layers 3, 4, or 7 — overwhelming systems at the network, transport, or application level</li>
</ul>

<p>When a security professional talks about a "layer 7 attack," they mean an attack targeting the application layer — more sophisticated than simply flooding with traffic because it mimics legitimate requests.</p>

<h2>Key networking hardware</h2>

<p><strong>Router</strong> — connects different networks together and determines the best path for packets to travel between them. Your home router connects your home network to your internet service provider's network. Enterprise routers connect corporate networks to the internet and to each other. Routers operate at layer 3, making decisions based on IP addresses.</p>

<p><strong>Switch</strong> — connects devices within the same network. Unlike older hubs that broadcast all traffic to all devices, switches send traffic only to the intended recipient based on MAC addresses. This makes the network more efficient and means that traffic is not visible to devices it is not intended for — though attackers can use ARP spoofing to circumvent this.</p>

<p><strong>Firewall</strong> — monitors and controls network traffic based on configured rules. Rules specify what traffic is allowed (permit) or denied (deny) based on source and destination addresses, ports, and protocols. Firewalls are the most fundamental network security control — the boundary between trusted and untrusted networks.</p>

<p><strong>Proxy server</strong> — sits between clients and servers, forwarding requests on behalf of clients. Users connect to the proxy, the proxy connects to the destination on their behalf. This provides several security benefits: the destination server never sees the client's real IP address, the proxy can inspect and filter content, and all web traffic passes through a single point that can be logged and monitored.</p>

<p><strong>Load balancer</strong> — distributes incoming traffic across multiple servers. From a security perspective, load balancers can absorb some DDoS traffic, hide the number and addresses of backend servers, and provide a central point for TLS termination and inspection.</p>

<h2>Network security concepts</h2>

<p><strong>Network segmentation</strong> is the practice of dividing a network into separate zones with controlled access between them. The key principle is that a compromise in one zone should not automatically provide access to others.</p>

<p>A well-segmented network might have:</p>
<ul>
<li>A DMZ for public-facing servers (web, email)</li>
<li>A corporate network for internal users and workstations</li>
<li>A server network for internal application and database servers</li>
<li>An OT/IoT network for operational technology and connected devices</li>
<li>A management network for administrative access to infrastructure</li>
</ul>

<p>Traffic between zones is explicitly permitted only where needed and is logged and inspected. An attacker who compromises a web server in the DMZ cannot directly reach the database server on the server network without passing through controls that can detect and block the attempt.</p>

<p><strong>VPN (Virtual Private Network)</strong> creates an encrypted tunnel between a device and a network. Remote workers use VPNs to connect securely to corporate networks over the internet. The traffic between the remote device and the VPN gateway is encrypted, preventing interception on untrusted networks like public Wi-Fi.</p>

<p>Site-to-site VPNs connect two networks together securely over the internet — for example, connecting a branch office to headquarters as if they were on the same local network.</p>

<p><strong>Network monitoring</strong> — capturing and analysing traffic to detect anomalies, suspicious connections, and signs of compromise. Tools like Wireshark capture and display individual packets. NetFlow analysis examines traffic patterns — who is talking to whom, how much data is flowing, and whether the pattern is consistent with normal behaviour.</p>

<h2>Real-world example: how network segmentation contained a breach</h2>

<p>In 2014, JP Morgan Chase suffered a data breach affecting 76 million households. Attackers gained access through a single server that had not been updated with dual-factor authentication. However, the breach was ultimately limited because the compromised server was in a segmented part of the network — the attackers could not move from there into systems containing financial account data.</p>

<p>The segmentation that limited the breach was not perfect — personal contact information was still exposed — but the financial data that would have enabled account takeover at scale was protected by network controls that the attackers could not bypass.</p>

<h2>Common misconceptions about networking and security</h2>

<p><strong>"We have a firewall, so our network is secure."</strong> A firewall is one control, not a complete solution. Firewalls block traffic that does not match permitted rules, but they cannot inspect encrypted traffic (without additional tools), they cannot prevent attacks that use permitted ports and protocols, and they do nothing to protect against threats that originate inside the network.</p>

<p><strong>"Wi-Fi with a password is secure."</strong> WPA2 and WPA3 encrypt traffic between devices and the access point, preventing interception by other devices on the same network. However, the password can be brute-forced if it is weak, and enterprise networks need additional controls (certificate-based authentication, network access control) to properly secure wireless access.</p>

<p><strong>"Internal traffic does not need to be monitored."</strong> Many attacks involve lateral movement — an attacker who has gained initial access moving through the internal network to reach more valuable systems. Monitoring internal traffic (east-west traffic) is as important as monitoring traffic to and from the internet.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-b2",
        "section": "B",
        "lesson_number": 7,
        "order": 7,
        "title": "IP Addresses, Ports, and Protocols",
        "body": """<h2>Why these fundamentals matter</h2>

<p>IP addresses, ports, and protocols are the addressing and communication system of the internet. Every network connection you make — loading a webpage, sending an email, connecting to a VPN — uses these concepts. Security professionals read them in firewall logs, use them to investigate incidents, and rely on them to understand what is happening on a network.</p>

<p>When you see a firewall log entry showing a connection from 185.220.101.42 to your server on port 22, you need to understand that 185.220.101.42 is an external IP address, port 22 is SSH (remote access), and this is likely an automated attempt to gain unauthorised remote access to your server. That interpretation requires understanding the concepts in this lesson.</p>

<h2>IP addresses</h2>

<p>Every device on a network is identified by an IP (Internet Protocol) address. Think of it like a postal address — it identifies where a device is located on the network so that traffic can be delivered to the right destination.</p>

<p><strong>IPv4</strong> addresses are 32-bit numbers, written as four groups of numbers separated by dots. Each group ranges from 0 to 255. For example: 192.168.1.1, 10.0.0.1, 203.0.113.45. IPv4 provides approximately 4.3 billion possible addresses — a number that seemed enormous when the internet was designed but proved insufficient as billions of devices connected.</p>

<p><strong>IPv6</strong> addresses are 128-bit numbers, written in hexadecimal separated by colons. For example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334. The address space is so vast — 340 undecillion addresses — that it will not be exhausted in any foreseeable future. IPv6 adoption is increasing as IPv4 addresses have been fully allocated.</p>

<h2>Public and private IP addresses</h2>

<p>Not all IP addresses are accessible from the internet. There is an important distinction between public and private addresses.</p>

<p><strong>Public IP addresses</strong> are globally unique and routable on the internet. When you connect to a website, your traffic appears to come from a public IP address — usually your internet service provider's address, shared among many customers through a technique called NAT (Network Address Translation).</p>

<p><strong>Private IP address ranges</strong> are reserved for use within local networks and are not routable on the internet:</p>
<ul>
<li>10.0.0.0 – 10.255.255.255 (10.x.x.x) — commonly used in enterprise networks</li>
<li>172.16.0.0 – 172.31.255.255 — less commonly seen</li>
<li>192.168.0.0 – 192.168.255.255 — the range you almost certainly see on your home network (192.168.1.x or 192.168.0.x)</li>
</ul>

<p>If you see a private IP address in a firewall log, it means the traffic originated from inside the network. If you see a public IP address, it came from outside. This distinction is fundamental to reading network logs.</p>

<p><strong>Special addresses to know:</strong></p>
<ul>
<li>127.0.0.1 — loopback address, refers to the local machine itself (also called "localhost")</li>
<li>0.0.0.0 — represents all IP addresses on the local machine</li>
<li>255.255.255.255 — broadcast address, sends to all devices on the local network</li>
</ul>

<h2>Ports — what they are and why they matter</h2>

<p>An IP address identifies a device. A port identifies a specific service or application running on that device. Think of the IP address as a building's street address and the port as the apartment number — the address gets you to the right building, the port gets you to the right service.</p>

<p>Ports are numbered from 0 to 65535. The range 0–1023 contains "well-known ports" assigned to standard services:</p>

<table>
<thead>
<tr><th>Port</th><th>Protocol</th><th>Service</th><th>Security notes</th></tr>
</thead>
<tbody>
<tr><td>21</td><td>TCP</td><td>FTP (File Transfer)</td><td>Transmits data and credentials in plaintext — avoid using</td></tr>
<tr><td>22</td><td>TCP</td><td>SSH (Secure Shell)</td><td>Encrypted remote access — frequently targeted by brute force</td></tr>
<tr><td>23</td><td>TCP</td><td>Telnet</td><td>Unencrypted remote access — never use on modern systems</td></tr>
<tr><td>25</td><td>TCP</td><td>SMTP (Email sending)</td><td>Should be restricted to authorised mail servers only</td></tr>
<tr><td>53</td><td>TCP/UDP</td><td>DNS</td><td>DNS tunnelling uses this port to exfiltrate data</td></tr>
<tr><td>80</td><td>TCP</td><td>HTTP</td><td>Unencrypted web traffic — should redirect to HTTPS</td></tr>
<tr><td>443</td><td>TCP</td><td>HTTPS</td><td>Encrypted web traffic</td></tr>
<tr><td>445</td><td>TCP</td><td>SMB (Windows file sharing)</td><td>Used by WannaCry and many other attacks — block at perimeter</td></tr>
<tr><td>3306</td><td>TCP</td><td>MySQL database</td><td>Should never be exposed to the internet</td></tr>
<tr><td>3389</td><td>TCP</td><td>RDP (Remote Desktop)</td><td>Frequently targeted — restrict access strictly</td></tr>
<tr><td>8080</td><td>TCP</td><td>HTTP alternate</td><td>Often used for development servers or proxies</td></tr>
</tbody>
</table>

<p>From a security perspective, knowing which ports are open on a system tells you a great deal about its attack surface. A server with port 3389 (RDP) exposed to the internet is almost certainly receiving brute-force login attempts continuously. A database server with port 3306 visible from the internet is a misconfiguration that attackers actively scan for.</p>

<p>Port scanning — checking which ports are open on a target system — is one of the first things attackers do during reconnaissance. Tools like Nmap make this trivially easy. Defenders use the same tools to audit their own systems and identify unexpected open ports.</p>

<h2>TCP and UDP — the two main transport protocols</h2>

<p><strong>TCP (Transmission Control Protocol)</strong> provides reliable, ordered delivery. Before sending data, TCP establishes a connection through a three-way handshake:</p>
<ol>
<li>Client sends SYN (synchronise) — "I want to connect"</li>
<li>Server responds with SYN-ACK (synchronise-acknowledge) — "I received your request, here are my parameters"</li>
<li>Client sends ACK (acknowledge) — "Connection established"</li>
</ol>

<p>Once established, TCP ensures that all data arrives, in order, without errors. If packets are lost, TCP requests retransmission. This reliability comes at the cost of overhead and latency.</p>

<p>TCP is used where accuracy matters: web browsing, email, file transfer, SSH. Most application-layer attacks exploit TCP connections.</p>

<p><strong>SYN flood attacks</strong> exploit the TCP handshake — attackers send enormous numbers of SYN packets without completing the handshake, consuming server resources waiting for connections that never complete.</p>

<p><strong>UDP (User Datagram Protocol)</strong> is connectionless — it sends data without establishing a connection first and without guaranteeing delivery or order. There is no handshake, no confirmation of receipt, no retransmission if packets are lost.</p>

<p>UDP is used where speed matters more than perfect accuracy: DNS lookups, video streaming, online gaming, VoIP. A dropped frame in a video call is preferable to the delay that would result from waiting for TCP retransmission.</p>

<p>UDP is also used in some DDoS amplification attacks — attackers send small requests to services that respond with much larger replies, directing those replies at the victim. DNS amplification attacks work this way: a small spoofed DNS query triggers a large DNS response sent to the victim.</p>

<h2>ICMP — the diagnostic protocol</h2>

<p>ICMP (Internet Control Message Protocol) is used for network diagnostics and error reporting. The ping command uses ICMP to check whether a host is reachable and measure round-trip time. Traceroute uses ICMP to map the path packets take through the network.</p>

<p>ICMP can also be abused — ICMP tunnelling encodes data inside ICMP packets to exfiltrate information or create covert communication channels. Some organisations block ICMP at their perimeter, though this can make troubleshooting network problems more difficult.</p>

<h2>How to read an IP address in a security context</h2>

<p>When you encounter an IP address during an investigation, several tools help you understand what it is:</p>

<ul>
<li><strong>Whois lookup</strong> — identifies who owns an IP address range and what organisation it is assigned to</li>
<li><strong>Geolocation</strong> — provides an approximate geographic location (useful but not precise — VPNs and Tor make this unreliable)</li>
<li><strong>AbuseIPDB</strong> — a database of IP addresses reported for malicious activity</li>
<li><strong>VirusTotal</strong> — checks an IP address against multiple threat intelligence sources</li>
<li><strong>Shodan</strong> — shows what services are running on an IP address and what it looks like to the internet</li>
</ul>

<h2>Real-world example: investigating a suspicious connection</h2>

<p>Imagine you are reviewing firewall logs and notice repeated connection attempts from 185.220.101.42 to your server on port 22 (SSH). Here is how you would investigate:</p>

<ol>
<li>Look up 185.220.101.42 on AbuseIPDB — it shows hundreds of reports for SSH brute-force attacks</li>
<li>Check the whois record — the IP is in a range associated with a Tor exit node, commonly used to anonymise attack traffic</li>
<li>Review your SSH logs — you see thousands of failed authentication attempts trying common usernames (root, admin, ubuntu)</li>
<li>Conclusion: this is an automated SSH brute-force attack, almost certainly not targeted at you specifically</li>
<li>Response: block the IP at the firewall, review whether SSH should be exposed to the internet at all, ensure password authentication is disabled and only key-based authentication is permitted</li>
</ol>

<h2>Common misconceptions</h2>

<p><strong>"My IP address reveals my exact location."</strong> IP geolocation is approximate — typically accurate to the city or region level, not the street. VPNs, proxies, and Tor route your traffic through other servers, making your traffic appear to originate from a different IP address entirely.</p>

<p><strong>"Using a non-standard port improves security."</strong> Running SSH on port 2222 instead of 22 reduces the volume of automated scanning because most scanners check port 22 by default. But any attacker doing a proper port scan will find it immediately. This is "security through obscurity" — it adds minor friction but is not a meaningful security control.</p>

<p><strong>"Firewalls block based on IP addresses, so blocking an attacker's IP stops them."</strong> Attackers trivially change their IP addresses — they use botnets (thousands of compromised computers), VPNs, proxies, or cloud services. Blocking a specific IP is useful for immediate noise reduction but rarely stops a determined attacker.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-b3",
        "section": "B",
        "lesson_number": 8,
        "order": 8,
        "title": "DNS, Domains, and Web Traffic",
        "body": """<h2>What DNS is and why it matters for security</h2>

<p>The Domain Name System is the internet's phone book. When you type bliztechacademy.com into your browser, your computer does not know where to find that site. DNS translates the human-readable domain name into an IP address — say, 104.21.35.67 — that your computer can use to make a connection.</p>

<p>DNS is fundamental to almost everything that happens on the internet. It is also fundamental to many attacks. Attackers abuse DNS to direct users to malicious servers, to communicate with malware covertly, and to steal credentials. Understanding DNS — how it works and how it can be abused — is essential for a security professional.</p>

<h2>How DNS resolution works — step by step</h2>

<p>When you type a domain name into your browser, a multi-step process resolves it to an IP address:</p>

<ol>
<li><strong>Local cache check</strong> — Your computer first checks its own DNS cache. If it recently looked up the same domain, it uses the cached result without querying anything.</li>
<li><strong>Recursive resolver query</strong> — If not cached, your computer contacts a recursive DNS resolver — typically provided by your ISP or a public service like 8.8.8.8 (Google) or 1.1.1.1 (Cloudflare).</li>
<li><strong>Root nameserver query</strong> — The resolver contacts one of 13 root nameservers that know where to find authoritative information for each top-level domain (.com, .uk, .org).</li>
<li><strong>TLD nameserver query</strong> — The root server directs the resolver to the TLD nameserver for .com, which knows where to find authoritative information for bliztechacademy.com specifically.</li>
<li><strong>Authoritative nameserver query</strong> — The resolver contacts the authoritative nameserver for bliztechacademy.com, which returns the actual IP address.</li>
<li><strong>Response and caching</strong> — The resolver returns the IP address to your computer and caches it for a period defined by the TTL (Time to Live) value in the DNS record.</li>
</ol>

<p>This entire process typically completes in milliseconds. Understanding it helps you understand where DNS attacks occur and what they can achieve.</p>

<h2>DNS record types</h2>

<table>
<thead>
<tr><th>Record type</th><th>Purpose</th><th>Security relevance</th></tr>
</thead>
<tbody>
<tr><td>A</td><td>Maps domain to IPv4 address</td><td>Primary record for finding servers; target of DNS hijacking</td></tr>
<tr><td>AAAA</td><td>Maps domain to IPv6 address</td><td>Same as A record for IPv6</td></tr>
<tr><td>MX</td><td>Identifies mail servers for the domain</td><td>Used to verify email routing; target of business email compromise</td></tr>
<tr><td>CNAME</td><td>Alias pointing one domain to another</td><td>Subdomain takeover attacks target orphaned CNAME records</td></tr>
<tr><td>TXT</td><td>Text information</td><td>Used for SPF, DKIM, DMARC email authentication; domain verification</td></tr>
<tr><td>NS</td><td>Identifies authoritative nameservers</td><td>Compromising these gives control over all DNS for the domain</td></tr>
<tr><td>PTR</td><td>Reverse DNS — IP to domain name</td><td>Used to verify that an IP matches the claimed domain</td></tr>
</tbody>
</table>

<h2>DNS attacks — the major categories</h2>

<p><strong>DNS cache poisoning (DNS spoofing)</strong> — An attacker inserts false DNS records into a resolver's cache. When users query that resolver, they receive the attacker's IP address instead of the legitimate one and are directed to a malicious server. The attack is particularly dangerous because it affects every user of the poisoned resolver, not just those who clicked a malicious link.</p>

<p>The Kaminsky Attack (2008) demonstrated that DNS cache poisoning was far easier than previously believed, affecting virtually all DNS resolvers. The disclosure led to emergency patching of DNS software worldwide — a reminder that infrastructure everyone relies on can have fundamental flaws.</p>

<p><strong>DNS hijacking</strong> — Rather than poisoning a cache, an attacker compromises the domain registrar account or the authoritative DNS server directly, changing the legitimate DNS records. When victims look up the domain, they get the attacker's IP address — and this response is authoritative, so caches propagate the malicious record everywhere.</p>

<p>In 2019, a series of DNS hijacking attacks attributed to Iranian threat actors targeted government and telecommunications organisations across the Middle East, redirecting traffic to attacker-controlled servers that intercepted credentials.</p>

<p><strong>DNS tunnelling</strong> — DNS queries are allowed through most firewalls because DNS is essential for internet connectivity. Attackers exploit this by encoding data inside DNS queries and responses, creating a covert communication channel that can bypass security controls.</p>

<p>Malware that uses DNS tunnelling can communicate with command-and-control infrastructure even in heavily restricted environments. Data exfiltration via DNS tunnelling is slow but hard to detect without specific DNS monitoring in place.</p>

<p><strong>Typosquatting and homograph attacks</strong> — Registering domains that look similar to legitimate ones to catch users who mistype or are deceived by visual similarity. Examples: g00gle.com, paypa1.com, rnicrosoft.com (using 'rn' to look like 'm'). Homograph attacks use Unicode characters that are visually identical to Latin characters — аpple.com using a Cyrillic 'а' instead of a Latin 'a' looks identical in many browsers.</p>

<h2>How web traffic works — the full journey of a request</h2>

<p>Understanding exactly what happens when you load a webpage helps you understand where attacks can occur and what controls can intercept them.</p>

<ol>
<li><strong>DNS resolution</strong> — Your browser resolves the domain name to an IP address (as described above).</li>
<li><strong>TCP connection</strong> — Your browser initiates a TCP connection to the server's IP address on port 80 (HTTP) or 443 (HTTPS), completing the three-way handshake.</li>
<li><strong>TLS handshake (for HTTPS)</strong> — If connecting over HTTPS, your browser and the server negotiate encryption parameters, the server presents its TLS certificate (which your browser verifies), and an encrypted session is established.</li>
<li><strong>HTTP request</strong> — Your browser sends an HTTP GET request for the page: "GET /index.html HTTP/1.1, Host: bliztechacademy.com"</li>
<li><strong>Server processing</strong> — The server processes the request, potentially querying a database, executing application code, and assembling a response.</li>
<li><strong>HTTP response</strong> — The server sends back the HTML, CSS, and JavaScript that make up the page, along with HTTP headers that tell the browser how to handle the content.</li>
<li><strong>Browser rendering</strong> — The browser parses the HTML and makes additional requests for images, stylesheets, scripts, and other resources, potentially from multiple different domains.</li>
</ol>

<p>Attacks can occur at each stage: DNS poisoning before the connection is made, man-in-the-middle interception during the TLS handshake, injection attacks during server processing, and content-security policy violations when loading external resources.</p>

<h2>HTTP status codes — what they tell you</h2>

<table>
<thead>
<tr><th>Code</th><th>Meaning</th><th>Security relevance</th></tr>
</thead>
<tbody>
<tr><td>200</td><td>OK — success</td><td>Normal response</td></tr>
<tr><td>301/302</td><td>Redirect</td><td>Open redirects can be used in phishing</td></tr>
<tr><td>400</td><td>Bad request</td><td>May indicate injection attempts or fuzzing</td></tr>
<tr><td>401</td><td>Unauthorised</td><td>Authentication required — large numbers may indicate brute force</td></tr>
<tr><td>403</td><td>Forbidden</td><td>Authenticated but not authorised — access control working</td></tr>
<tr><td>404</td><td>Not found</td><td>Large numbers of 404s may indicate scanning or directory traversal</td></tr>
<tr><td>500</td><td>Server error</td><td>May indicate successful injection or application crash</td></tr>
<tr><td>503</td><td>Service unavailable</td><td>May indicate DDoS or overload</td></tr>
</tbody>
</table>

<h2>TLS certificates — what they prove and what they do not</h2>

<p>A TLS certificate serves two purposes: it enables encryption of traffic between your browser and the server, and it provides verification of the server's identity. When you see the padlock in your browser, it means both of these things are happening.</p>

<p>However, a TLS certificate does not mean the website is safe. It means:</p>
<ul>
<li>Your traffic to the site is encrypted (no one between you and the server can read it)</li>
<li>The server controls the domain the certificate was issued for</li>
</ul>

<p>It does not mean:</p>
<ul>
<li>The site is legitimate or trustworthy</li>
<li>The site is not malicious</li>
<li>The organisation behind the site is who they claim to be (for DV certificates)</li>
</ul>

<p>Phishing sites routinely obtain valid TLS certificates — they are free and automated. The padlock has been severely misused as a trust indicator in user awareness training. The accurate message is: "The connection is encrypted" not "This site is safe."</p>

<h2>Common misconceptions</h2>

<p><strong>"The padlock means the site is safe."</strong> As described above — the padlock means encrypted, not trustworthy. Over half of phishing sites now use HTTPS. Train users to look at the full domain name, not just the padlock.</p>

<p><strong>"Changing my DNS server to 8.8.8.8 improves security."</strong> Using a well-known resolver like Google (8.8.8.8) or Cloudflare (1.1.1.1) can improve reliability and provide some protection against misconfigured ISP resolvers. But it also means your DNS queries are visible to those companies. For enterprise environments, a dedicated internal DNS resolver with monitoring provides more security value.</p>

<p><strong>"HTTPS protects against all web-based attacks."</strong> HTTPS encrypts the channel, not the content. A website serving malware over HTTPS is just as dangerous as one serving it over HTTP. SQL injection, cross-site scripting, and other web application attacks work just as well over HTTPS.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-b4",
        "section": "B",
        "lesson_number": 9,
        "order": 9,
        "title": "Windows and Linux Basics",
        "body": """<h2>Why operating systems matter in security</h2>

<p>Almost every attack ultimately targets or interacts with an operating system. Malware executes within an OS. Attackers use OS tools to move laterally through networks. Defenders use OS logs to detect and investigate incidents. Misconfigurations in the OS create vulnerabilities. Understanding the fundamentals of both Windows and Linux is not optional for a security professional — it is foundational.</p>

<p>Windows dominates corporate desktop environments and is the most common target for attacks against end users and business systems. Linux dominates servers, cloud infrastructure, and security tools. A security professional who cannot navigate both is limited in what they can do.</p>

<h2>Windows fundamentals</h2>

<p><strong>The file system structure</strong></p>

<p>Windows organises files in a hierarchical structure starting from drive letters (C:\, D:\ etc). Key locations to know:</p>

<ul>
<li><code>C:\Windows\System32</code> — core operating system files. Attackers frequently place malicious files here to blend in with legitimate system files (a technique called masquerading).</li>
<li><code>C:\Users\[username]</code> — each user's profile directory, containing their documents, desktop, downloads, and application data</li>
<li><code>C:\Users\[username]\AppData</code> — hidden folder containing application settings and data. Malware frequently uses AppData\Roaming or AppData\Local to store files because users have write access here without administrator privileges</li>
<li><code>C:\Program Files</code> — installed applications (requires administrator rights to write)</li>
<li><code>C:\Temp</code> and <code>%TEMP%</code> — temporary files. Malware frequently drops files here during execution</li>
</ul>

<p><strong>The Windows Registry</strong></p>

<p>The registry is a hierarchical database that stores configuration settings for Windows and installed applications. It is one of the most important places to understand for security because it is heavily used by both legitimate software and malware.</p>

<p>Key registry locations for security:</p>
<ul>
<li><code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> — programs that start automatically when the current user logs in. Malware frequently creates entries here to establish persistence.</li>
<li><code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code> — programs that start for all users. Requires administrator access to modify.</li>
<li><code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</code> — installed Windows services. Malware installed as a service will appear here.</li>
</ul>

<p><strong>Windows Event Logs</strong></p>

<p>Windows logs security-relevant events in the Event Viewer. The Security log is the most important for security monitoring. Key event IDs:</p>

<table>
<thead>
<tr><th>Event ID</th><th>Description</th><th>Why it matters</th></tr>
</thead>
<tbody>
<tr><td>4624</td><td>Successful logon</td><td>Who logged in, when, from where, and how (interactive, network, remote)</td></tr>
<tr><td>4625</td><td>Failed logon</td><td>Multiple failures indicate brute-force; single failure may be mistyped password</td></tr>
<tr><td>4648</td><td>Logon using explicit credentials</td><td>Common during lateral movement — attacker using stolen credentials</td></tr>
<tr><td>4688</td><td>New process created</td><td>What commands are being run — essential for detecting malicious activity</td></tr>
<tr><td>4698</td><td>Scheduled task created</td><td>Common persistence mechanism for malware</td></tr>
<tr><td>4720</td><td>User account created</td><td>Attackers often create backdoor accounts</td></tr>
<tr><td>4740</td><td>Account locked out</td><td>May indicate brute-force or password spraying</td></tr>
<tr><td>7045</td><td>New service installed</td><td>Malware installed as a service</td></tr>
</tbody>
</table>

<p><strong>PowerShell</strong></p>

<p>PowerShell is Windows' powerful scripting and automation tool. It is also one of the most abused tools by attackers because it is built into Windows, trusted by default, and extremely capable.</p>

<p>Attackers use PowerShell to: download and execute malware, move laterally through networks, dump credentials from memory, disable security tools, and exfiltrate data. This is called "living off the land" — using legitimate system tools for malicious purposes, making detection harder.</p>

<p>PowerShell logging (specifically Script Block Logging and Module Logging) captures what PowerShell commands are being run. Enabling these logs is one of the most valuable things you can do for Windows security visibility. The logs capture the actual commands executed, even if they were obfuscated.</p>

<p><strong>Example of malicious PowerShell (for recognition purposes):</strong></p>

<pre><code>powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand [base64 encoded command]</code></pre>

<p>The flags here are warning signs: -ExecutionPolicy Bypass (circumventing security policy), -WindowStyle Hidden (running without a visible window), -EncodedCommand (the actual command is base64 encoded to evade detection). Seeing these in logs is a significant indicator of suspicious activity.</p>

<h2>Linux fundamentals</h2>

<p><strong>The file system structure</strong></p>

<p>Linux uses a single hierarchical structure starting from the root directory (/). Unlike Windows, everything in Linux — including hardware devices — is represented as a file.</p>

<ul>
<li><code>/etc</code> — system configuration files. Contains critical files like /etc/passwd (user accounts), /etc/shadow (password hashes), /etc/ssh/sshd_config (SSH configuration)</li>
<li><code>/var/log</code> — log files. The most important location for security investigation on Linux systems</li>
<li><code>/home/[username]</code> — user home directories</li>
<li><code>/root</code> — the root user's home directory</li>
<li><code>/tmp</code> — temporary files, world-writable. Attackers frequently use /tmp to store malicious files because any user can write here</li>
<li><code>/proc</code> — virtual filesystem representing running processes. Useful for investigating what is currently running</li>
<li><code>/bin</code>, <code>/sbin</code>, <code>/usr/bin</code> — system executables and commands</li>
</ul>

<p><strong>Essential Linux commands for security</strong></p>

<table>
<thead>
<tr><th>Command</th><th>Purpose</th><th>Security use</th></tr>
</thead>
<tbody>
<tr><td><code>ls -la</code></td><td>List files including hidden files with permissions</td><td>Spot unusual files, check permissions</td></tr>
<tr><td><code>ps aux</code></td><td>List all running processes</td><td>Identify suspicious processes</td></tr>
<tr><td><code>netstat -tulpn</code></td><td>Show network connections and listening ports</td><td>Identify unexpected connections or services</td></tr>
<tr><td><code>ss -tulpn</code></td><td>Modern replacement for netstat</td><td>Same as above, preferred on modern systems</td></tr>
<tr><td><code>who</code> / <code>w</code></td><td>Show logged-in users</td><td>Identify unexpected active sessions</td></tr>
<tr><td><code>last</code></td><td>Show recent login history</td><td>Identify unusual login patterns</td></tr>
<tr><td><code>find / -mtime -1</code></td><td>Find files modified in last 24 hours</td><td>Identify recently changed or created files</td></tr>
<tr><td><code>grep -r "search" /path</code></td><td>Search for text recursively</td><td>Search logs for specific events or indicators</td></tr>
<tr><td><code>cat /etc/passwd</code></td><td>View user accounts</td><td>Check for unexpected accounts</td></tr>
<tr><td><code>crontab -l</code></td><td>List scheduled tasks for current user</td><td>Check for malicious persistence via cron</td></tr>
<tr><td><code>sudo -l</code></td><td>List sudo permissions</td><td>Identify privilege escalation opportunities</td></tr>
</tbody>
</table>

<p><strong>Linux file permissions</strong></p>

<p>Linux uses a permissions model that assigns three types of access (read, write, execute) to three categories of users (owner, group, others). When you run <code>ls -la</code>, you see permissions displayed like this:</p>

<pre><code>-rwxr-xr-- 1 alice developers 4096 Mar 15 14:23 script.sh</code></pre>

<p>Breaking this down:</p>
<ul>
<li><code>-</code> — file type (- for file, d for directory, l for symlink)</li>
<li><code>rwx</code> — owner (alice) has read, write, and execute permissions</li>
<li><code>r-x</code> — group (developers) has read and execute, but not write</li>
<li><code>r--</code> — others have read only</li>
</ul>

<p>Security implications of permissions:</p>
<ul>
<li>World-writable files (<code>-rwxrwxrwx</code> or mode 777) are dangerous — any user can modify them</li>
<li>SUID files (permission bit that runs the file as the file owner, not the current user) can be exploited for privilege escalation</li>
<li>Sensitive files like /etc/shadow should be readable only by root</li>
</ul>

<p><strong>Key Linux log files</strong></p>

<table>
<thead>
<tr><th>Log file</th><th>Contents</th></tr>
</thead>
<tbody>
<tr><td><code>/var/log/auth.log</code> (Debian/Ubuntu)</td><td>Authentication events — logins, sudo use, SSH connections</td></tr>
<tr><td><code>/var/log/secure</code> (RHEL/CentOS)</td><td>Same as auth.log on Red Hat-based systems</td></tr>
<tr><td><code>/var/log/syslog</code></td><td>General system messages</td></tr>
<tr><td><code>/var/log/apache2/access.log</code></td><td>Web server access log — every HTTP request</td></tr>
<tr><td><code>/var/log/apache2/error.log</code></td><td>Web server errors — may reveal attack attempts</td></tr>
<tr><td><code>/var/log/cron</code></td><td>Scheduled task execution</td></tr>
</tbody>
</table>

<h2>Real-world example: investigating a compromised Linux server</h2>

<p>A web server is suspected of being compromised. Here is the investigation process using basic Linux commands:</p>

<ol>
<li><code>w</code> — check for active sessions. An unfamiliar IP address with an active session is an immediate indicator.</li>
<li><code>last | head -20</code> — review recent logins. Look for logins from unusual IP addresses, at unusual hours, or from users who should not have SSH access.</li>
<li><code>ps aux --sort=-%cpu</code> — check running processes. Look for processes with unusual names, running as root when they should not be, or consuming significant resources unexpectedly.</li>
<li><code>netstat -tulpn</code> — check network connections. Look for outbound connections to unfamiliar addresses or unexpected listening services.</li>
<li><code>find /tmp /var/tmp -type f -mtime -7</code> — look for recently created files in temp directories. Attackers frequently use these locations.</li>
<li><code>grep "Failed password" /var/log/auth.log | tail -50</code> — check for brute-force attempts. If there are thousands of failed attempts followed by a successful login, the account was likely compromised through brute force.</li>
</ol>

<h2>Common misconceptions</h2>

<p><strong>"Linux is inherently more secure than Windows."</strong> Linux has a better security track record in some respects — a more granular permissions model, generally faster patching, and a smaller attack surface in server configurations. But Linux systems are absolutely attacked and compromised. Poorly configured Linux servers are among the most common attack targets. Security depends on configuration and maintenance, not the choice of OS.</p>

<p><strong>"Macs don't get viruses."</strong> macOS (which is Unix-based, similar to Linux) has historically had fewer malware infections, largely due to smaller market share making it a less attractive target. As Mac adoption has grown in enterprises, so has targeted malware. Several sophisticated malware families specifically target macOS, including state-sponsored tools.</p>

<p><strong>"I don't need to understand the command line — there are GUI tools for everything."</strong> GUI tools are convenient, but the command line provides capabilities that GUIs often lack: scripting and automation, remote access over SSH, handling large volumes of data, and access to low-level system information. Security investigations frequently require command-line work, and many security tools are command-line only.</p>""",
        "lab": None,
    },
    {
        "slug": "gic-b5",
        "section": "B",
        "lesson_number": 10,
        "order": 10,
        "title": "Users, Permissions, and Access Control",
        "body": """<h2>Why access control is at the heart of security</h2>

<p>The majority of security controls ultimately come down to one question: who is allowed to do what? Access control is the discipline of answering that question correctly and enforcing the answer consistently.</p>

<p>When access control fails — when someone can do something they should not be able to do, or when someone who should have access cannot get it — security fails. The Target breach happened partly because a third-party vendor had more access than it needed. The Snowden case happened partly because a contractor could access and copy data that should have been more restricted. The majority of insider threat incidents involve excessive access that was never revoked.</p>

<p>Getting access control right is not exciting work, but it is some of the most impactful security work an organisation can do.</p>

<h2>Authentication vs authorisation — a critical distinction</h2>

<p><strong>Authentication</strong> answers the question: "Who are you?" It is the process of verifying that someone is who they claim to be. When you enter a username and password, you are authenticating — proving your identity to the system.</p>

<p><strong>Authorisation</strong> answers the question: "What are you allowed to do?" It is the process of determining what an authenticated user can access. After you authenticate, the system checks what you are permitted to do and allows or denies your requests accordingly.</p>

<p>Both must work correctly. Authentication without proper authorisation means that once logged in, a user can access anything — including things they have no business seeing. Authorisation without proper authentication means that if someone can impersonate another user, they get all that user's permissions.</p>

<p>A common security mistake is treating authentication as the entire solution. "They logged in with valid credentials, so they must be authorised" is flawed thinking — credentials can be stolen, and even legitimate users should not have access to everything.</p>

<h2>Authentication factors</h2>

<p>Authentication factors are categorised into three types. Each type has different strengths and weaknesses.</p>

<p><strong>Something you know</strong> — Passwords, PINs, security questions. The most common factor. Weaknesses: can be guessed, phished, leaked in breaches, or captured by keyloggers. The vulnerability is that knowledge can be shared or stolen without the legitimate user knowing.</p>

<p><strong>Something you have</strong> — A physical or logical object: a hardware security key (YubiKey), a smartphone running an authenticator app, or a smart card. Significantly harder to steal remotely than a password. An attacker who phishes your password still cannot authenticate without your physical device.</p>

<p><strong>Something you are</strong> — Biometrics: fingerprint, face recognition, iris scan. Convenient and cannot be forgotten. Significant weaknesses: biometrics cannot be changed if compromised (you cannot reset your fingerprint), biometric data is sensitive and valuable if leaked, and biometric systems can be spoofed with sufficient sophistication.</p>

<p><strong>Multi-factor authentication (MFA)</strong> combines two or more factors. Even if an attacker steals your password (something you know), they cannot authenticate without your phone (something you have). MFA is one of the most effective controls available against credential-based attacks. Microsoft has stated that MFA blocks over 99.9% of account compromise attacks on their platform.</p>

<h2>MFA types — not all are equal</h2>

<p><strong>SMS one-time codes</strong> — A code sent via text message. Better than no MFA, but vulnerable to SIM swapping (convincing a mobile carrier to transfer your number to an attacker's SIM), SS7 attacks (exploiting vulnerabilities in the mobile network protocol), and real-time phishing (attackers relay the code before it expires).</p>

<p><strong>Authenticator apps (TOTP)</strong> — Time-based one-time passwords generated by apps like Google Authenticator or Authy. Change every 30 seconds based on a shared secret and the current time. More secure than SMS because the code is generated locally and not transmitted over the mobile network. Still vulnerable to real-time phishing relay attacks.</p>

<p><strong>Hardware security keys</strong> — Physical devices (YubiKey, Google Titan) that implement FIDO2/WebAuthn. The strongest form of MFA for most users. Cryptographically bound to the specific website — a key registered for accounts.google.com will not respond to a phishing site at accounts-google-security.com. This property makes hardware keys completely resistant to phishing.</p>

<p><strong>Push notifications</strong> — An app on your phone receives a push notification asking you to approve a login attempt. Convenient, but vulnerable to MFA fatigue attacks: attackers flood a user with push notifications hoping they approve one out of frustration or confusion. Several high-profile breaches (including the 2022 Uber breach) used this technique.</p>

<h2>Access control models</h2>

<p><strong>DAC (Discretionary Access Control)</strong> — The resource owner decides who can access their resources and what they can do with them. Standard file system permissions work this way — when you create a file, you control who can read, write, or execute it. Flexible but difficult to enforce consistently at scale, because control is distributed across every resource owner.</p>

<p><strong>MAC (Mandatory Access Control)</strong> — Access decisions are made by the system based on security classifications, not by resource owners. A document classified as "Top Secret" can only be accessed by users with "Top Secret" clearance, regardless of who created it. Used in high-security government and military systems. Inflexible but extremely consistent.</p>

<p><strong>RBAC (Role-Based Access Control)</strong> — The dominant model in enterprise environments. Permissions are assigned to roles, and users are assigned to roles. A user who is a "Finance Analyst" gets all the permissions associated with that role — read access to financial reports, write access to expense claims, no access to HR records. When the user changes jobs, you change their role rather than auditing every individual permission.</p>

<p><strong>ABAC (Attribute-Based Access Control)</strong> — Decisions are based on attributes of the user, the resource, the action, and the environment. A doctor can access patient records (user attribute: doctor) for patients they are treating (relationship attribute) during business hours (time attribute) from a hospital network (location attribute). More flexible than RBAC but significantly more complex to implement and manage.</p>

<h2>Least privilege — in practice</h2>

<p>The principle of least privilege says every user, system, and process should have the minimum access needed to perform its function. In practice, applying this principle requires ongoing effort because there is a natural tendency toward accumulation of permissions over time.</p>

<p>Common least privilege failures:</p>

<ul>
<li><strong>Privilege creep</strong> — users accumulate permissions over time as they change roles, work on special projects, or request access for specific tasks that is never revoked. An employee who has been with a company for five years may have accumulated access appropriate for five different roles they have held.</li>
<li><strong>Excessive default permissions</strong> — new accounts are created with broad access "to make it easier to start work" rather than with access scoped to their actual needs.</li>
<li><strong>Shared accounts</strong> — multiple people share a single account, making attribution of actions impossible and creating a situation where access cannot be revoked for one person without affecting all.</li>
<li><strong>Standing administrator access</strong> — users perform day-to-day work with full administrator privileges rather than using elevated access only when needed.</li>
</ul>

<p>Addressing least privilege requires:</p>
<ul>
<li><strong>Access reviews</strong> — periodic audits of who has access to what, confirming that access is still appropriate and revoking what is not needed</li>
<li><strong>Just-in-time access</strong> — granting elevated privileges for specific tasks and specific time periods, automatically revoking them afterward</li>
<li><strong>Separation of duties</strong> — ensuring that no single user has all the permissions needed to complete a sensitive action alone</li>
</ul>

<h2>The identity lifecycle</h2>

<p><strong>Provisioning</strong> — creating accounts and granting appropriate initial access. This should be based on the user's role and follow the principle of least privilege from the start. Provisioning should be a formal process — access should not be granted based on informal requests.</p>

<p><strong>Access changes</strong> — when a user changes roles, access should be adjusted: previous role's access revoked, new role's access granted. In practice, organisations often grant new access without revoking old access, leading to privilege creep.</p>

<p><strong>De-provisioning</strong> — revoking access when a user leaves the organisation or no longer needs specific access. This is one of the most consistently failed processes in access management. Inactive accounts — especially those of former employees — are prime targets for attackers because they may not be actively monitored, may have significant access, and the legitimate user is no longer around to notice suspicious activity on their account.</p>

<p><strong>Real-world example:</strong> In 2020, a former employee of a water treatment facility in the United States accessed the facility's systems six months after leaving the organisation, using credentials that had never been revoked. The incident highlighted the critical importance of timely de-provisioning — a failure that is surprisingly common across industries.</p>

<h2>Common misconceptions</h2>

<p><strong>"MFA makes accounts unbreachable."</strong> MFA dramatically reduces the risk of account compromise but does not eliminate it. Real-time phishing attacks (adversary-in-the-middle) can relay both passwords and MFA codes before they expire. Push notification fatigue attacks can bypass app-based MFA. Session cookie theft bypasses MFA entirely because the authentication already happened. MFA is essential but not sufficient.</p>

<p><strong>"Strong passwords eliminate the need for MFA."</strong> Passwords, however strong, can be phished. A 30-character random password is still captured if you type it into a convincing fake login page. MFA provides protection that password strength cannot — an additional factor that cannot be captured through a phishing page (especially hardware keys).</p>

<p><strong>"We can trust users with administrator access because they are senior employees."</strong> Seniority is not a security control. Senior employees' credentials are valuable targets precisely because they have significant access. Senior employees click phishing links. Senior employees' accounts are compromised. Administrator access should be restricted to those who genuinely need it, regardless of seniority, and should be used only when elevated access is actually required.</p>""",
        "lab": """<h2>Practical Lab: Network Commands</h2>

<p>This lab applies the networking concepts from Section B using real tools on your own machine. Work through each part and record your findings.</p>

<h3>Part 1: View your network configuration</h3>

<p><strong>Windows:</strong> Open Command Prompt (cmd) and run:</p>
<pre><code>ipconfig /all</code></pre>

<p><strong>Linux/macOS:</strong> Open Terminal and run:</p>
<pre><code>ip addr show</code></pre>
<p>or on macOS:</p>
<pre><code>ifconfig</code></pre>

<p>Record the following from the output:</p>
<ul>
<li>Your device's IP address — is it a private address (10.x.x.x, 172.16-31.x.x, or 192.168.x.x)?</li>
<li>Your subnet mask — what range of addresses are on your local network?</li>
<li>Your default gateway — this is your router's IP address</li>
<li>Your DNS server address — what is resolving your domain names?</li>
<li>Your MAC address — the physical address of your network interface</li>
</ul>

<h3>Part 2: Trace a route to a remote server</h3>

<p><strong>Windows:</strong></p>
<pre><code>tracert google.com</code></pre>

<p><strong>Linux/macOS:</strong></p>
<pre><code>traceroute google.com</code></pre>

<p>Record:</p>
<ul>
<li>How many hops does traffic take to reach google.com?</li>
<li>What is the IP address of the first hop? (This is your router)</li>
<li>Are there any hops where the response time increases significantly?</li>
<li>Are there any hops that time out (shown as * * *)? What might explain this?</li>
</ul>

<h3>Part 3: DNS lookups</h3>

<p>Run the following commands and record the results:</p>

<pre><code>nslookup bliztechacademy.com</code></pre>

<p>What IP address does bliztechacademy.com resolve to?</p>

<pre><code>nslookup -type=MX gmail.com</code></pre>

<p>What mail servers handle email for gmail.com? Note the priority numbers — lower numbers indicate higher priority.</p>

<pre><code>nslookup -type=TXT google.com</code></pre>

<p>What TXT records exist for google.com? Can you identify the SPF record?</p>

<h3>Part 4: Check active network connections</h3>

<p><strong>Windows:</strong></p>
<pre><code>netstat -an</code></pre>

<p><strong>Linux/macOS:</strong></p>
<pre><code>ss -tulpn</code></pre>

<p>Record:</p>
<ul>
<li>Which ports is your device listening on? (LISTEN or LISTENING state)</li>
<li>Are there any ESTABLISHED connections? Where are they going?</li>
<li>Are there any connections or listening services you cannot identify?</li>
</ul>

<h3>Part 5: Check your public IP and DNS</h3>

<p>Visit these sites in your browser:</p>
<ul>
<li>whatismyip.com — what is your public IP address? Is it different from your private IP address from Part 1?</li>
<li>dnsleaktest.com — what DNS servers are actually being used? Do they match what you found in Part 1?</li>
<li>haveibeenpwned.com — enter your email address to check whether it has appeared in any known data breaches</li>
</ul>

<h3>Part 6: Reflection questions</h3>

<ol>
<li>Why is your device's private IP address different from your public IP address?</li>
<li>What is the significance of the first hop in your traceroute being your router's IP address?</li>
<li>If you were investigating a suspicious outbound connection from your device, what command would you run first and what would you look for?</li>
<li>Why would an attacker want to know what DNS server you are using?</li>
<li>If haveibeenpwned.com showed your email in a breach, what should you do, and why is the specific breach information important?</li>
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
            from app.models import CourseTopic
            topic = CourseTopic(**lesson)
            db.session.add(topic)
            updated += 1

    db.session.commit()
    print(f"Done — {updated} Section B lessons updated.")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()