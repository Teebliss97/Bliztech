"""
seed_lesson_diagrams.py  (v2)
------------------------------
PYTHONPATH=/opt/render/project/src .venv/bin/python seed_lesson_diagrams.py

IMPORTANT: Run this AFTER the expanded content seeds so the h2 markers exist.
This script is safe to re-run — it checks for markers before inserting.
To reset diagrams, re-run the expanded content seeds first, then this script.
"""

ARROW_DEFS = '<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>'

def d(inner, h, caption):
    return (
        '<div style="margin:28px 0;border:1px solid rgba(255,255,255,0.07);'
        'border-radius:8px;overflow:hidden;background:rgba(255,255,255,0.02);max-width:100%;">'
        f'<svg width="100%" viewBox="0 0 680 {h}" xmlns="http://www.w3.org/2000/svg" '
        'preserveAspectRatio="xMidYMid meet" overflow="hidden" '
        'style="display:block;font-family:ui-monospace,JetBrains Mono,monospace;max-width:100%;">'
        f'{ARROW_DEFS}{inner}</svg>'
        '<div style="font-family:ui-monospace,monospace;font-size:10px;text-transform:uppercase;'
        'letter-spacing:0.6px;color:#555;padding:7px 14px;border-top:1px solid rgba(255,255,255,0.05)">'
        f'{caption}</div></div>'
    )

# ── Risk formula ─────────────────────────────────────────────────────────────
RISK_FORMULA = d(
    '<text x="340" y="26" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">RISK FORMULA</text>'
    '<rect x="30" y="40" width="96" height="50" rx="5" fill="none" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="78" y="60" text-anchor="middle" font-size="13" font-weight="600" fill="#00d97e">RISK</text>'
    '<text x="78" y="78" text-anchor="middle" font-size="9" fill="#555">total exposure</text>'
    '<text x="146" y="69" text-anchor="middle" font-size="18" fill="#333">=</text>'
    '<rect x="162" y="40" width="130" height="50" rx="5" fill="none" stroke="#333" stroke-width="1"/>'
    '<text x="227" y="60" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">Threat</text>'
    '<text x="227" y="78" text-anchor="middle" font-size="9" fill="#555">who might attack</text>'
    '<text x="312" y="69" text-anchor="middle" font-size="18" fill="#333">x</text>'
    '<rect x="328" y="40" width="148" height="50" rx="5" fill="none" stroke="#333" stroke-width="1"/>'
    '<text x="402" y="60" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">Vulnerability</text>'
    '<text x="402" y="78" text-anchor="middle" font-size="9" fill="#555">what weakness exists</text>'
    '<text x="496" y="69" text-anchor="middle" font-size="18" fill="#333">x</text>'
    '<rect x="512" y="40" width="130" height="50" rx="5" fill="none" stroke="#333" stroke-width="1"/>'
    '<text x="577" y="60" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">Impact</text>'
    '<text x="577" y="78" text-anchor="middle" font-size="9" fill="#555">consequence if it happens</text>'
    '<text x="340" y="116" text-anchor="middle" font-size="10" fill="#444">'
    'If any single factor equals zero, the total risk is zero — use this to prioritise controls</text>',
    130, 'Risk = Threat x Vulnerability x Impact')

# ── CIA Triad ─────────────────────────────────────────────────────────────────
CIA_TRIAD = d(
    '<text x="340" y="26" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">CIA TRIAD</text>'
    '<rect x="230" y="36" width="220" height="66" rx="5" fill="rgba(0,217,126,0.05)" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="340" y="60" text-anchor="middle" font-size="13" font-weight="600" fill="#00d97e">Confidentiality</text>'
    '<text x="340" y="78" text-anchor="middle" font-size="10" fill="#888">Authorised access only</text>'
    '<text x="340" y="94" text-anchor="middle" font-size="9" fill="#555">Encryption · Access controls · Classification</text>'
    '<rect x="50" y="142" width="220" height="66" rx="5" fill="rgba(255,255,255,0.02)" stroke="#333" stroke-width="1"/>'
    '<text x="160" y="166" text-anchor="middle" font-size="13" font-weight="600" fill="#ccc">Integrity</text>'
    '<text x="160" y="184" text-anchor="middle" font-size="10" fill="#888">Data is accurate and unmodified</text>'
    '<text x="160" y="200" text-anchor="middle" font-size="9" fill="#555">Hashing · Digital signatures · Audit logs</text>'
    '<rect x="410" y="142" width="220" height="66" rx="5" fill="rgba(255,255,255,0.02)" stroke="#333" stroke-width="1"/>'
    '<text x="520" y="166" text-anchor="middle" font-size="13" font-weight="600" fill="#ccc">Availability</text>'
    '<text x="520" y="184" text-anchor="middle" font-size="10" fill="#888">Systems accessible when needed</text>'
    '<text x="520" y="200" text-anchor="middle" font-size="9" fill="#555">Redundancy · Backups · DDoS mitigation</text>'
    '<line x1="290" y1="102" x2="200" y2="142" stroke="#2a2a2a" stroke-width="1" marker-end="url(#arrow)"/>'
    '<line x1="390" y1="102" x2="460" y2="142" stroke="#2a2a2a" stroke-width="1" marker-end="url(#arrow)"/>'
    '<line x1="270" y1="175" x2="409" y2="175" stroke="#2a2a2a" stroke-width="1" marker-end="url(#arrow)"/>',
    232, 'The three core properties of information security — every security decision balances these three')

# ── Kill Chain ────────────────────────────────────────────────────────────────
KILL_CHAIN = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">CYBER KILL CHAIN — 7 STAGES</text>'
    + ''.join([
        f'<rect x="{10+i*95}" y="36" width="84" height="64" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
        f'<text x="{52+i*95}" y="57" text-anchor="middle" font-size="10" font-weight="600" fill="{["#888","#888","#888","#888","#888","#888","#00d97e"][i]}">{["Recon","Weaponise","Deliver","Exploit","Install","C2","Objectives"][i]}</text>'
        f'<text x="{52+i*95}" y="73" text-anchor="middle" font-size="9" fill="#555">{["Gather info","Build payload","Email or USB","Trigger flaw","Persistence","Remote control","Data theft"][i]}</text>'
        f'<text x="{52+i*95}" y="88" text-anchor="middle" font-size="9" fill="#444">{["on target","or purchase","or exploit","in software","reg key/task","or ransom","or disruption"][i]}</text>'
        + (f'<line x1="{96+i*95}" y1="68" x2="{103+i*95}" y2="68" stroke="#333" stroke-width="1" marker-end="url(#arrow)"/>' if i < 6 else '')
        for i in range(7)
    ])
    + '<text x="340" y="124" text-anchor="middle" font-size="10" fill="#444">'
      'Defenders can interrupt the chain at any stage — email filtering stops Deliver, EDR stops Install, monitoring detects C2</text>',
    138, 'The 7-stage cyber kill chain — interrupting any stage stops or limits the attack')

# ── Defence in depth ─────────────────────────────────────────────────────────
DEFENCE_DEPTH = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">DEFENCE IN DEPTH — LAYERED CONTROLS</text>'
    '<rect x="30" y="36" width="620" height="48" rx="5" fill="rgba(255,255,255,0.015)" stroke="#222" stroke-width="1"/>'
    '<text x="340" y="56" text-anchor="middle" font-size="11" font-weight="500" fill="#555">Perimeter</text>'
    '<text x="340" y="74" text-anchor="middle" font-size="9" fill="#3a3a3a">Firewall · IDS/IPS · Email filtering · Web application firewall · DDoS mitigation</text>'
    '<rect x="70" y="94" width="540" height="46" rx="5" fill="rgba(255,255,255,0.015)" stroke="#252525" stroke-width="1"/>'
    '<text x="340" y="113" text-anchor="middle" font-size="11" font-weight="500" fill="#555">Network</text>'
    '<text x="340" y="129" text-anchor="middle" font-size="9" fill="#3a3a3a">Segmentation · DMZ · VPN · Traffic monitoring · Network access control</text>'
    '<rect x="110" y="150" width="460" height="46" rx="5" fill="rgba(255,255,255,0.015)" stroke="#2a2a2a" stroke-width="1"/>'
    '<text x="340" y="169" text-anchor="middle" font-size="11" font-weight="500" fill="#666">Endpoint</text>'
    '<text x="340" y="185" text-anchor="middle" font-size="9" fill="#3a3a3a">EDR · Antivirus · Patch management · Device encryption · Application control</text>'
    '<rect x="150" y="206" width="380" height="46" rx="5" fill="rgba(255,255,255,0.015)" stroke="#2f2f2f" stroke-width="1"/>'
    '<text x="340" y="225" text-anchor="middle" font-size="11" font-weight="500" fill="#777">Application</text>'
    '<text x="340" y="241" text-anchor="middle" font-size="9" fill="#3a3a3a">Authentication · Authorisation · Input validation · Logging</text>'
    '<rect x="190" y="262" width="300" height="46" rx="5" fill="rgba(0,217,126,0.04)" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="340" y="281" text-anchor="middle" font-size="11" font-weight="600" fill="#00d97e">Data</text>'
    '<text x="340" y="297" text-anchor="middle" font-size="9" fill="#888">Encryption at rest and in transit · DLP · Access controls</text>'
    '<text x="340" y="334" text-anchor="middle" font-size="10" fill="#444">'
    'Each layer operates independently — a breach at the perimeter is contained by the layers inside</text>',
    348, 'Defence in depth — independent layers so one failure does not expose everything')

# ── MITM ─────────────────────────────────────────────────────────────────────
MITM = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">MAN-IN-THE-MIDDLE ATTACK</text>'
    '<rect x="20" y="44" width="120" height="58" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
    '<text x="80" y="67" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">User</text>'
    '<text x="80" y="84" text-anchor="middle" font-size="9" fill="#555">Sends message</text>'
    '<text x="80" y="97" text-anchor="middle" font-size="9" fill="#555">or credentials</text>'
    '<rect x="270" y="30" width="140" height="86" rx="5" fill="rgba(180,40,40,0.07)" stroke="#903030" stroke-width="1.5"/>'
    '<text x="340" y="54" text-anchor="middle" font-size="11" font-weight="600" fill="#b04040">Attacker</text>'
    '<text x="340" y="72" text-anchor="middle" font-size="9" fill="#888">Intercepts all traffic</text>'
    '<text x="340" y="87" text-anchor="middle" font-size="9" fill="#888">Reads and modifies</text>'
    '<text x="340" y="102" text-anchor="middle" font-size="9" fill="#888">before forwarding</text>'
    '<rect x="540" y="44" width="120" height="58" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
    '<text x="600" y="67" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">Server</text>'
    '<text x="600" y="84" text-anchor="middle" font-size="9" fill="#555">Receives modified</text>'
    '<text x="600" y="97" text-anchor="middle" font-size="9" fill="#555">or copied traffic</text>'
    '<line x1="142" y1="73" x2="268" y2="73" stroke="#903030" stroke-width="1.5" stroke-dasharray="6,3" marker-end="url(#arrow)"/>'
    '<text x="205" y="65" text-anchor="middle" font-size="9" fill="#903030">intercepted</text>'
    '<line x1="412" y1="73" x2="538" y2="73" stroke="#903030" stroke-width="1.5" stroke-dasharray="6,3" marker-end="url(#arrow)"/>'
    '<text x="476" y="65" text-anchor="middle" font-size="9" fill="#903030">forwarded</text>'
    '<line x1="142" y1="152" x2="538" y2="152" stroke="#00d97e" stroke-width="1" stroke-dasharray="4,4" marker-end="url(#arrow)"/>'
    '<text x="340" y="145" text-anchor="middle" font-size="9" fill="#00d97e">What the user believes — a direct encrypted connection</text>'
    '<rect x="20" y="166" width="640" height="26" rx="4" fill="rgba(0,217,126,0.04)" stroke="rgba(0,217,126,0.15)" stroke-width="1"/>'
    '<text x="340" y="183" text-anchor="middle" font-size="10" fill="#00d97e">'
    'Defence: TLS with certificate validation · HSTS preloading · VPN on untrusted networks</text>',
    208, 'Man-in-the-middle — attacker silently reads and modifies all traffic between two parties')

# ── Network segmentation ──────────────────────────────────────────────────────
NETWORK_SEG = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">NETWORK SEGMENTATION</text>'
    '<rect x="10" y="40" width="80" height="96" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2a2a2a" stroke-width="1"/>'
    '<text x="50" y="62" text-anchor="middle" font-size="10" font-weight="500" fill="#666">Internet</text>'
    '<text x="50" y="80" text-anchor="middle" font-size="9" fill="#444">Untrusted</text>'
    '<text x="50" y="95" text-anchor="middle" font-size="9" fill="#444">external</text>'
    '<text x="50" y="110" text-anchor="middle" font-size="9" fill="#444">traffic</text>'
    '<line x1="92" y1="88" x2="106" y2="88" stroke="#333" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="108" y="58" width="52" height="60" rx="4" fill="rgba(0,217,126,0.05)" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="134" y="82" text-anchor="middle" font-size="10" font-weight="600" fill="#00d97e">FW 1</text>'
    '<text x="134" y="98" text-anchor="middle" font-size="8" fill="#666">Outer</text>'
    '<text x="134" y="111" text-anchor="middle" font-size="8" fill="#666">firewall</text>'
    '<line x1="162" y1="88" x2="176" y2="88" stroke="#333" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="178" y="30" width="156" height="126" rx="5" fill="rgba(255,255,255,0.01)" stroke="#252525" stroke-dasharray="5,3" stroke-width="1"/>'
    '<text x="256" y="48" text-anchor="middle" font-size="9" fill="#444">DMZ</text>'
    '<rect x="188" y="54" width="136" height="36" rx="4" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="256" y="68" text-anchor="middle" font-size="10" font-weight="500" fill="#999">Web server</text>'
    '<text x="256" y="82" text-anchor="middle" font-size="9" fill="#555">Public-facing</text>'
    '<rect x="188" y="98" width="136" height="36" rx="4" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="256" y="112" text-anchor="middle" font-size="10" font-weight="500" fill="#999">Mail server</text>'
    '<text x="256" y="126" text-anchor="middle" font-size="9" fill="#555">Email gateway</text>'
    '<line x1="336" y1="88" x2="350" y2="88" stroke="#333" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="352" y="58" width="52" height="60" rx="4" fill="rgba(0,217,126,0.05)" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="378" y="82" text-anchor="middle" font-size="10" font-weight="600" fill="#00d97e">FW 2</text>'
    '<text x="378" y="98" text-anchor="middle" font-size="8" fill="#666">Inner</text>'
    '<text x="378" y="111" text-anchor="middle" font-size="8" fill="#666">firewall</text>'
    '<line x1="406" y1="88" x2="420" y2="88" stroke="#333" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="422" y="30" width="248" height="126" rx="5" fill="rgba(0,217,126,0.02)" stroke="rgba(0,217,126,0.18)" stroke-width="1"/>'
    '<text x="546" y="48" text-anchor="middle" font-size="9" fill="#00d97e">Internal network</text>'
    '<rect x="432" y="54" width="106" height="36" rx="4" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="485" y="68" text-anchor="middle" font-size="10" font-weight="500" fill="#999">Workstations</text>'
    '<text x="485" y="82" text-anchor="middle" font-size="9" fill="#555">User devices</text>'
    '<rect x="554" y="54" width="106" height="36" rx="4" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="607" y="68" text-anchor="middle" font-size="10" font-weight="500" fill="#999">Database</text>'
    '<text x="607" y="82" text-anchor="middle" font-size="9" fill="#00d97e">Protected zone</text>'
    '<rect x="432" y="98" width="228" height="36" rx="4" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="546" y="112" text-anchor="middle" font-size="10" font-weight="500" fill="#999">Finance and HR systems</text>'
    '<text x="546" y="126" text-anchor="middle" font-size="9" fill="#555">No direct path from DMZ</text>'
    '<text x="340" y="182" text-anchor="middle" font-size="10" fill="#444">'
    'A compromised web server in the DMZ cannot reach the database directly — the second firewall blocks it</text>',
    198, 'Network segmentation — zones separated by firewalls limit how far an attacker can move after a breach')

# ── TCP handshake ─────────────────────────────────────────────────────────────
TCP_HANDSHAKE = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">TCP THREE-WAY HANDSHAKE</text>'
    '<rect x="60" y="36" width="130" height="38" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
    '<text x="125" y="60" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">Client</text>'
    '<line x1="125" y1="74" x2="125" y2="196" stroke="#222" stroke-width="1" stroke-dasharray="4,3"/>'
    '<rect x="490" y="36" width="130" height="38" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
    '<text x="555" y="60" text-anchor="middle" font-size="12" font-weight="500" fill="#bbb">Server</text>'
    '<line x1="555" y1="74" x2="555" y2="196" stroke="#222" stroke-width="1" stroke-dasharray="4,3"/>'
    '<line x1="125" y1="92" x2="555" y2="112" stroke="#00d97e" stroke-width="1.5" marker-end="url(#arrow)"/>'
    '<rect x="270" y="80" width="140" height="20" rx="3" fill="#050f08"/>'
    '<text x="340" y="95" text-anchor="middle" font-size="11" font-weight="600" fill="#00d97e">SYN</text>'
    '<text x="340" y="110" text-anchor="middle" font-size="9" fill="#444">"I want to connect"</text>'
    '<line x1="555" y1="136" x2="125" y2="154" stroke="#00d97e" stroke-width="1.5" marker-end="url(#arrow)"/>'
    '<rect x="270" y="124" width="140" height="20" rx="3" fill="#050f08"/>'
    '<text x="340" y="139" text-anchor="middle" font-size="11" font-weight="600" fill="#00d97e">SYN-ACK</text>'
    '<text x="340" y="154" text-anchor="middle" font-size="9" fill="#444">"Acknowledged, ready"</text>'
    '<line x1="125" y1="172" x2="555" y2="188" stroke="#00d97e" stroke-width="1.5" marker-end="url(#arrow)"/>'
    '<rect x="270" y="162" width="140" height="20" rx="3" fill="#050f08"/>'
    '<text x="340" y="177" text-anchor="middle" font-size="11" font-weight="600" fill="#00d97e">ACK</text>'
    '<text x="340" y="192" text-anchor="middle" font-size="9" fill="#00d97e">Connection established</text>'
    '<text x="340" y="220" text-anchor="middle" font-size="10" fill="#444">'
    'SYN floods exploit this — sending millions of SYNs without completing step 3 exhausts server memory</text>',
    234, 'TCP three-way handshake — reliable connection established before any data is transmitted')

# ── DNS resolution ────────────────────────────────────────────────────────────
DNS_RESOLUTION = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">DNS RESOLUTION — 5 STEPS</text>'
    '<rect x="20" y="62" width="110" height="48" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
    '<text x="75" y="82" text-anchor="middle" font-size="11" font-weight="500" fill="#bbb">Browser</text>'
    '<text x="75" y="98" text-anchor="middle" font-size="9" fill="#555">Types domain name</text>'
    '<line x1="132" y1="86" x2="148" y2="86" stroke="#00d97e" stroke-width="1.5" marker-end="url(#arrow)"/>'
    '<text x="140" y="78" text-anchor="middle" font-size="9" fill="#444">1</text>'
    '<rect x="150" y="62" width="120" height="48" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2d2d2d" stroke-width="1"/>'
    '<text x="210" y="82" text-anchor="middle" font-size="11" font-weight="500" fill="#bbb">Resolver</text>'
    '<text x="210" y="98" text-anchor="middle" font-size="9" fill="#555">8.8.8.8 or 1.1.1.1</text>'
    '<line x1="272" y1="74" x2="336" y2="42" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<text x="300" y="50" text-anchor="middle" font-size="9" fill="#444">2</text>'
    '<rect x="338" y="24" width="120" height="44" rx="5" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="398" y="42" text-anchor="middle" font-size="11" font-weight="500" fill="#888">Root server</text>'
    '<text x="398" y="58" text-anchor="middle" font-size="9" fill="#555">Knows .com TLD</text>'
    '<line x1="398" y1="68" x2="398" y2="102" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<text x="412" y="90" font-size="9" fill="#444">3</text>'
    '<rect x="338" y="104" width="120" height="44" rx="5" fill="rgba(255,255,255,0.02)" stroke="#222" stroke-width="1"/>'
    '<text x="398" y="122" text-anchor="middle" font-size="11" font-weight="500" fill="#888">TLD server</text>'
    '<text x="398" y="138" text-anchor="middle" font-size="9" fill="#555">.com nameserver</text>'
    '<line x1="460" y1="126" x2="528" y2="96" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<text x="498" y="104" text-anchor="middle" font-size="9" fill="#444">4</text>'
    '<rect x="530" y="62" width="130" height="48" rx="5" fill="rgba(0,217,126,0.05)" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="595" y="82" text-anchor="middle" font-size="11" font-weight="500" fill="#00d97e">Auth. server</text>'
    '<text x="595" y="98" text-anchor="middle" font-size="9" fill="#888">Returns IP address</text>'
    '<line x1="528" y1="86" x2="272" y2="86" stroke="#00d97e" stroke-width="1.5" stroke-dasharray="4,3" marker-end="url(#arrow)"/>'
    '<text x="400" y="168" text-anchor="middle" font-size="9" fill="#00d97e">5  IP address returned to browser — connection made</text>'
    '<text x="340" y="192" text-anchor="middle" font-size="10" fill="#444">'
    'DNS cache poisoning inserts false records at the resolver — users are silently sent to attacker servers</text>',
    208, 'DNS resolution — every domain name lookup follows these 5 steps taking roughly 10 milliseconds')

# ── Auth factors ──────────────────────────────────────────────────────────────
AUTH_FACTORS = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">THREE AUTHENTICATION FACTORS</text>'
    '<rect x="30" y="36" width="186" height="102" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2a2a2a" stroke-width="1"/>'
    '<text x="123" y="58" text-anchor="middle" font-size="12" font-weight="600" fill="#aaa">Something you know</text>'
    '<line x1="48" y1="68" x2="198" y2="68" stroke="#1e1e1e" stroke-width="1"/>'
    '<text x="123" y="84" text-anchor="middle" font-size="10" fill="#888">Password · PIN</text>'
    '<text x="123" y="100" text-anchor="middle" font-size="10" fill="#666">Security question</text>'
    '<text x="123" y="128" text-anchor="middle" font-size="9" fill="#803030">Can be phished or guessed</text>'
    '<rect x="247" y="36" width="186" height="102" rx="5" fill="rgba(0,217,126,0.05)" stroke="#00d97e" stroke-width="1.5"/>'
    '<text x="340" y="58" text-anchor="middle" font-size="12" font-weight="600" fill="#00d97e">Something you have</text>'
    '<line x1="263" y1="68" x2="415" y2="68" stroke="rgba(0,217,126,0.2)" stroke-width="1"/>'
    '<text x="340" y="84" text-anchor="middle" font-size="10" fill="#888">Authenticator app · Hardware key</text>'
    '<text x="340" y="100" text-anchor="middle" font-size="10" fill="#888">Smart card · Phone</text>'
    '<text x="340" y="128" text-anchor="middle" font-size="9" fill="#00d97e">Hardware key = phishing-proof</text>'
    '<rect x="464" y="36" width="186" height="102" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2a2a2a" stroke-width="1"/>'
    '<text x="557" y="58" text-anchor="middle" font-size="12" font-weight="600" fill="#aaa">Something you are</text>'
    '<line x1="480" y1="68" x2="632" y2="68" stroke="#1e1e1e" stroke-width="1"/>'
    '<text x="557" y="84" text-anchor="middle" font-size="10" fill="#888">Fingerprint · Face ID</text>'
    '<text x="557" y="100" text-anchor="middle" font-size="10" fill="#666">Iris scan · Voice</text>'
    '<text x="557" y="128" text-anchor="middle" font-size="9" fill="#666">Cannot be changed if stolen</text>'
    '<rect x="30" y="156" width="620" height="30" rx="4" fill="rgba(0,217,126,0.04)" stroke="rgba(0,217,126,0.18)" stroke-width="1"/>'
    '<text x="340" y="176" text-anchor="middle" font-size="11" font-weight="500" fill="#00d97e">'
    'MFA = any two factors combined — blocks over 99% of credential-based account attacks</text>',
    204, 'Three authentication factors — MFA combines two or more so stolen passwords alone are insufficient')

# ── Phishing flow ─────────────────────────────────────────────────────────────
PHISHING_FLOW = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">PHISHING ATTACK FLOW</text>'
    '<rect x="14" y="40" width="106" height="64" rx="5" fill="rgba(160,40,40,0.07)" stroke="#803030" stroke-width="1.5"/>'
    '<text x="67" y="62" text-anchor="middle" font-size="11" font-weight="600" fill="#aa4040">Attacker</text>'
    '<text x="67" y="78" text-anchor="middle" font-size="9" fill="#888">Crafts convincing</text>'
    '<text x="67" y="93" text-anchor="middle" font-size="9" fill="#888">spoofed email</text>'
    '<line x1="122" y1="72" x2="138" y2="72" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="140" y="40" width="116" height="64" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2a2a2a" stroke-width="1"/>'
    '<text x="198" y="62" text-anchor="middle" font-size="11" font-weight="500" fill="#bbb">Fake email</text>'
    '<text x="198" y="78" text-anchor="middle" font-size="9" fill="#666">Spoofed sender</text>'
    '<text x="198" y="93" text-anchor="middle" font-size="9" fill="#666">Urgent message</text>'
    '<line x1="258" y1="72" x2="274" y2="72" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="276" y="40" width="116" height="64" rx="5" fill="rgba(255,255,255,0.02)" stroke="#2a2a2a" stroke-width="1"/>'
    '<text x="334" y="62" text-anchor="middle" font-size="11" font-weight="500" fill="#bbb">Victim</text>'
    '<text x="334" y="78" text-anchor="middle" font-size="9" fill="#666">Clicks the link</text>'
    '<text x="334" y="93" text-anchor="middle" font-size="9" fill="#666">or opens file</text>'
    '<line x1="394" y1="72" x2="410" y2="72" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="412" y="40" width="116" height="64" rx="5" fill="rgba(160,40,40,0.07)" stroke="#803030" stroke-width="1"/>'
    '<text x="470" y="62" text-anchor="middle" font-size="11" font-weight="500" fill="#aa4040">Fake site</text>'
    '<text x="470" y="78" text-anchor="middle" font-size="9" fill="#888">Identical to real login</text>'
    '<text x="470" y="93" text-anchor="middle" font-size="9" fill="#888">Valid HTTPS certificate</text>'
    '<line x1="530" y1="72" x2="546" y2="72" stroke="#444" stroke-width="1" marker-end="url(#arrow)"/>'
    '<rect x="548" y="40" width="118" height="64" rx="5" fill="rgba(160,40,40,0.09)" stroke="#903030" stroke-width="1.5"/>'
    '<text x="607" y="62" text-anchor="middle" font-size="11" font-weight="600" fill="#aa4040">Credentials</text>'
    '<text x="607" y="78" text-anchor="middle" font-size="9" fill="#888">Sent to attacker</text>'
    '<text x="607" y="93" text-anchor="middle" font-size="9" fill="#888">Account compromised</text>'
    '<rect x="14" y="120" width="652" height="26" rx="4" fill="rgba(0,217,126,0.04)" stroke="rgba(0,217,126,0.14)" stroke-width="1"/>'
    '<text x="340" y="137" text-anchor="middle" font-size="10" fill="#00d97e">'
    'Defence: Check actual sender domain · Verify SPF/DKIM/DMARC · Hardware keys are phishing-proof</text>',
    164, 'Phishing — password strength is irrelevant because the victim types it directly into the attacker form')

# ── Ransomware chain ──────────────────────────────────────────────────────────
RANSOMWARE = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">RANSOMWARE INFECTION CHAIN</text>'
    + ''.join([
        f'<rect x="{10+i*108}" y="36" width="96" height="66" rx="5" fill="rgba(255,255,255,0.02)" '
        f'stroke="{"#903030" if i==5 else "#2a2a2a"}" stroke-width="{"1.5" if i==5 else "1"}"/>'
        f'<text x="{58+i*108}" y="58" text-anchor="middle" font-size="11" font-weight="{"600" if i==5 else "500"}" '
        f'fill="{"#aa4040" if i==5 else "#bbb"}">{["Phishing","Execute","Persist","Exfiltrate","Encrypt","Ransom"][i]}</text>'
        f'<text x="{58+i*108}" y="74" text-anchor="middle" font-size="9" fill="{"#888" if i>=4 else "#666"}">'
        f'{["Email with attachment","User opens — macro runs","Registry key / task","Copy data out first","Lock all files","Pay or lose data"][i]}</text>'
        f'<text x="{58+i*108}" y="89" text-anchor="middle" font-size="9" fill="#444">'
        f'{["Convincing pretext","Payload downloads","Survives reboots","Double extortion","Key withheld","Avg $1.5M demand"][i]}</text>'
        + (f'<line x1="{108+i*108}" y1="69" x2="{116+i*108}" y2="69" stroke="#333" stroke-width="1" marker-end="url(#arrow)"/>' if i<5 else '')
        for i in range(6)
    ])
    + '<rect x="10" y="118" width="660" height="26" rx="4" fill="rgba(0,217,126,0.04)" stroke="rgba(0,217,126,0.14)" stroke-width="1"/>'
    '<text x="340" y="135" text-anchor="middle" font-size="10" fill="#00d97e">'
    'Defence: Offline backups that cannot be encrypted · Email filtering · Disable macros · EDR · Patching</text>',
    150, 'Ransomware — modern groups steal data before encrypting for double extortion leverage')

# ── IR lifecycle ──────────────────────────────────────────────────────────────
IR_LIFECYCLE = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">INCIDENT RESPONSE LIFECYCLE</text>'
    + ''.join([
        f'<rect x="{10+i*108}" y="36" width="96" height="64" rx="5" fill="rgba(255,255,255,0.02)" '
        f'stroke="{"#00d97e" if i==5 else "#903030" if i==2 else "#2a2a2a"}" '
        f'stroke-width="{"1.5" if i in [2,5] else "1"}"/>'
        f'<text x="{58+i*108}" y="57" text-anchor="middle" font-size="11" font-weight="{"600" if i in [2,5] else "500"}" '
        f'fill="{"#00d97e" if i==5 else "#aa4040" if i==2 else "#bbb"}">'
        f'{["Prepare","Detect","Contain","Eradicate","Recover","Learn"][i]}</text>'
        f'<text x="{58+i*108}" y="73" text-anchor="middle" font-size="9" fill="{"#888" if i in [2,5] else "#666"}">'
        f'{["Policies & tools","SIEM & alerts","Isolate systems","Remove attacker","Restore systems","Post-incident"][i]}</text>'
        f'<text x="{58+i*108}" y="88" text-anchor="middle" font-size="9" fill="#444">'
        f'{["Training & plans","User reports","Stop the spread","Close entry point","Verify clean","Review & improve"][i]}</text>'
        + (f'<line x1="{108+i*108}" y1="68" x2="{116+i*108}" y2="68" stroke="#2a2a2a" stroke-width="1" marker-end="url(#arrow)"/>' if i<5 else '')
        for i in range(6)
    ])
    + '<text x="340" y="126" text-anchor="middle" font-size="10" fill="#444">'
    'GDPR 72-hour notification clock starts at containment — not when the full investigation is complete</text>',
    140, 'Incident response — six phases from preparation through to lessons learned and improved defences')

# ── Shared responsibility ──────────────────────────────────────────────────────
SHARED_RESP = d(
    '<text x="340" y="24" text-anchor="middle" font-size="10" fill="#444" letter-spacing="1">CLOUD SHARED RESPONSIBILITY</text>'
    '<rect x="20" y="36" width="170" height="26" rx="0" fill="rgba(255,255,255,0.02)" stroke="#1e1e1e"/>'
    '<text x="105" y="54" text-anchor="middle" font-size="10" fill="#444">Layer</text>'
    '<rect x="200" y="36" width="140" height="26" rx="0" fill="rgba(255,255,255,0.02)" stroke="#1e1e1e"/>'
    '<text x="270" y="54" text-anchor="middle" font-size="10" fill="#888">IaaS (e.g. EC2)</text>'
    '<rect x="350" y="36" width="140" height="26" rx="0" fill="rgba(255,255,255,0.02)" stroke="#1e1e1e"/>'
    '<text x="420" y="54" text-anchor="middle" font-size="10" fill="#888">PaaS</text>'
    '<rect x="500" y="36" width="160" height="26" rx="0" fill="rgba(255,255,255,0.02)" stroke="#1e1e1e"/>'
    '<text x="580" y="54" text-anchor="middle" font-size="10" fill="#888">SaaS (e.g. M365)</text>'
    + ''.join([
        f'<rect x="20" y="{68+i*30}" width="170" height="30" rx="0" fill="rgba(255,255,255,0.015)" stroke="#1a1a1a"/>'
        f'<text x="105" y="{87+i*30}" text-anchor="middle" font-size="10" fill="#888">'
        f'{["Data and access","Applications","OS and runtime","Infrastructure","Physical security"][i]}</text>'
        + ''.join([
            f'<rect x="{200+j*150}" y="{68+i*30}" width="{140 if j<2 else 160}" height="30" rx="0" '
            f'fill="{"rgba(0,217,126,0.07)" if [True,True,True,False,False][i] and j==0 or [True,True,False,False,False][i] and j==1 or [True,False,False,False,False][i] and j==2 else "rgba(255,255,255,0.01)"}" '
            f'stroke="#1a1a1a"/>'
            f'<text x="{270+j*150}" y="{87+i*30}" text-anchor="middle" font-size="10" '
            f'font-weight="{"600" if [True,True,True,False,False][i] and j==0 or [True,True,False,False,False][i] and j==1 or [True,False,False,False,False][i] and j==2 else "400"}" '
            f'fill="{"#00d97e" if [True,True,True,False,False][i] and j==0 or [True,True,False,False,False][i] and j==1 or [True,False,False,False,False][i] and j==2 else "#444"}">'
            f'{"Customer" if [True,True,True,False,False][i] and j==0 or [True,True,False,False,False][i] and j==1 or [True,False,False,False,False][i] and j==2 else "Provider"}</text>'
            for j in range(3)
        ])
        for i in range(5)
    ])
    + '<text x="340" y="242" text-anchor="middle" font-size="10" fill="#444">'
    'Most cloud breaches exploit customer responsibility — misconfigured buckets and overly permissive IAM roles</text>',
    256, 'Cloud shared responsibility — your security boundary depends on which service model you are using')


PATCHES = [
    ("gic-a2", "<h2>The attack lifecycle</h2>",                           KILL_CHAIN),
    ("gic-a3", "<h2>The foundation of security thinking</h2>",            CIA_TRIAD),
    ("gic-a4", "<h2>How security professionals think about risk</h2>",    RISK_FORMULA),
    ("gic-a5", "<h2>Why no single control is enough</h2>",                DEFENCE_DEPTH),
    ("gic-b1", "<h2>What a network is</h2>",                              MITM),
    ("gic-b1", "<h2>Network security concepts</h2>",                      NETWORK_SEG),
    ("gic-b2", "<h2>TCP and UDP — the two main transport protocols</h2>", TCP_HANDSHAKE),
    ("gic-b3", "<h2>How DNS resolution works — step by step</h2>",       DNS_RESOLUTION),
    ("gic-b5", "<h2>Authentication factors</h2>",                         AUTH_FACTORS),
    ("gic-c2", "<h2>Why email is the primary attack vector</h2>",         PHISHING_FLOW),
    ("gic-c4", "<h2>How infections happen — delivery mechanisms</h2>",    RANSOMWARE),
    ("gic-c5", "<h2>Incident response — the lifecycle</h2>",              IR_LIFECYCLE),
    ("gic-d1", "<h2>The shared responsibility model</h2>",                SHARED_RESP),
]


def seed():
    from app.models import CourseTopic
    from app.extensions import db

    updated = set()
    for slug, marker, diagram in PATCHES:
        topic = CourseTopic.query.filter_by(slug=slug).first()
        if not topic:
            print(f"  SKIP {slug} — not found")
            continue
        if marker not in topic.body:
            print(f"  WARN {slug} — marker not found: {marker[:50]}")
            continue
        idx = topic.body.find(marker)
        end = topic.body.find('>', idx) + 1
        topic.body = topic.body[:end] + diagram + topic.body[end:]
        updated.add(slug)
        print(f"  patched {slug}")

    db.session.commit()
    print(f"\nDone — {len(updated)} lessons updated.")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()