"""
seed_lesson_diagrams.py
-----------------------
Embeds SVG diagrams into lesson content at the appropriate points.
Run from project root:
    PYTHONPATH=/opt/render/project/src .venv/bin/python seed_lesson_diagrams.py
"""

# ── SVG Diagrams ────────────────────────────────────────────────────────────

# Shared style for all diagrams
SVG_STYLE = """
<style>
.diagram-wrap {
  margin: 28px 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: var(--bg-3);
}
.diagram-caption {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  color: var(--text-3);
  padding: 8px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg-2);
}
</style>
"""

def diagram(svg_content, caption):
    return f"""
{SVG_STYLE}
<div class="diagram-wrap">
{svg_content}
<div class="diagram-caption">{caption}</div>
</div>
"""

# ── Attack Lifecycle (Lesson A2) ─────────────────────────────────────────────
ATTACK_LIFECYCLE_SVG = diagram("""
<svg viewBox="0 0 760 120" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#00d97e" opacity="0.7"/>
    </marker>
  </defs>
  <!-- Steps -->
  <g font-family="JetBrains Mono, monospace" font-size="9" fill="#aaa" text-anchor="middle">
    <!-- 1 Recon -->
    <rect x="10" y="30" width="88" height="60" rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="54" y="55" fill="#00d97e" font-size="16">🔍</text>
    <text x="54" y="72" fill="#fff" font-size="9" font-weight="600">Recon</text>
    <text x="54" y="84">Gather info</text>
    <!-- arrow -->
    <line x1="100" y1="60" x2="112" y2="60" stroke="#00d97e" stroke-width="1.5" opacity="0.5" marker-end="url(#arr)"/>
    <!-- 2 Weaponise -->
    <rect x="114" y="30" width="88" height="60" rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="158" y="55" fill="#00d97e" font-size="16">⚙️</text>
    <text x="158" y="72" fill="#fff" font-size="9" font-weight="600">Weaponise</text>
    <text x="158" y="84">Build payload</text>
    <!-- arrow -->
    <line x1="204" y1="60" x2="216" y2="60" stroke="#00d97e" stroke-width="1.5" opacity="0.5" marker-end="url(#arr)"/>
    <!-- 3 Delivery -->
    <rect x="218" y="30" width="88" height="60" rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="262" y="55" fill="#00d97e" font-size="16">📧</text>
    <text x="262" y="72" fill="#fff" font-size="9" font-weight="600">Delivery</text>
    <text x="262" y="84">Send attack</text>
    <!-- arrow -->
    <line x1="308" y1="60" x2="320" y2="60" stroke="#00d97e" stroke-width="1.5" opacity="0.5" marker-end="url(#arr)"/>
    <!-- 4 Exploit -->
    <rect x="322" y="30" width="88" height="60" rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="366" y="55" fill="#00d97e" font-size="16">💥</text>
    <text x="366" y="72" fill="#fff" font-size="9" font-weight="600">Exploit</text>
    <text x="366" y="84">Trigger flaw</text>
    <!-- arrow -->
    <line x1="412" y1="60" x2="424" y2="60" stroke="#00d97e" stroke-width="1.5" opacity="0.5" marker-end="url(#arr)"/>
    <!-- 5 Install -->
    <rect x="426" y="30" width="88" height="60" rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="470" y="55" fill="#00d97e" font-size="16">🔧</text>
    <text x="470" y="72" fill="#fff" font-size="9" font-weight="600">Install</text>
    <text x="470" y="84">Persistence</text>
    <!-- arrow -->
    <line x1="516" y1="60" x2="528" y2="60" stroke="#00d97e" stroke-width="1.5" opacity="0.5" marker-end="url(#arr)"/>
    <!-- 6 C2 -->
    <rect x="530" y="30" width="88" height="60" rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="574" y="55" fill="#00d97e" font-size="16">📡</text>
    <text x="574" y="72" fill="#fff" font-size="9" font-weight="600">C2</text>
    <text x="574" y="84">Take control</text>
    <!-- arrow -->
    <line x1="620" y1="60" x2="632" y2="60" stroke="#00d97e" stroke-width="1.5" opacity="0.5" marker-end="url(#arr)"/>
    <!-- 7 Actions -->
    <rect x="634" y="30" width="116" height="60" rx="6" fill="#1a1a1a" stroke="#00d97e" stroke-width="1.5"/>
    <text x="692" y="55" fill="#00d97e" font-size="16">🎯</text>
    <text x="692" y="72" fill="#fff" font-size="9" font-weight="600">Objectives</text>
    <text x="692" y="84">Data theft / damage</text>
  </g>
</svg>
""", "The Cyber Kill Chain — 7 stages of a typical attack")

# ── CIA Triad (Lesson A3) ────────────────────────────────────────────────────
CIA_TRIAD_SVG = diagram("""
<svg viewBox="0 0 600 260" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <!-- Triangle -->
  <polygon points="300,30 80,220 520,220" fill="none" stroke="#333" stroke-width="1.5"/>
  <!-- C -->
  <rect x="60" y="228" width="170" height="70" rx="8" fill="#111" stroke="#00d97e" stroke-width="1.5"/>
  <text x="145" y="252" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e" text-transform="uppercase" letter-spacing="2">CONFIDENTIALITY</text>
  <text x="145" y="272" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#888">Only authorised access</text>
  <text x="145" y="289" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#888">Encryption · Access controls</text>
  <!-- I -->
  <rect x="370" y="228" width="170" height="70" rx="8" fill="#111" stroke="#00d97e" stroke-width="1.5"/>
  <text x="455" y="252" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e" letter-spacing="2">INTEGRITY</text>
  <text x="455" y="272" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#888">Data is accurate &amp; unmodified</text>
  <text x="455" y="289" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#888">Hashing · Digital signatures</text>
  <!-- A -->
  <rect x="215" y="5" width="170" height="70" rx="8" fill="#111" stroke="#00d97e" stroke-width="1.5"/>
  <text x="300" y="29" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e" letter-spacing="2">AVAILABILITY</text>
  <text x="300" y="49" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#888">Systems accessible when needed</text>
  <text x="300" y="66" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#888">Redundancy · Backups · DDoS mitigation</text>
  <!-- Centre label -->
  <text x="300" y="168" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="11" fill="#444" font-weight="600">CIA TRIAD</text>
</svg>
""", "The CIA Triad — the three core properties of information security")

# ── Man-in-the-Middle / Sniffing (Lesson B1 / B2) ───────────────────────────
MITM_SVG = diagram("""
<svg viewBox="0 0 680 160" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="arr2" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#00d97e" opacity="0.8"/>
    </marker>
    <marker id="arr3" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#e05c5c" opacity="0.9"/>
    </marker>
  </defs>
  <!-- User -->
  <rect x="20" y="50" width="110" height="60" rx="8" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <text x="75" y="76" text-anchor="middle" font-size="20">👤</text>
  <text x="75" y="96" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#fff">User</text>
  <text x="75" y="110" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#666">Sends data</text>
  <!-- Server -->
  <rect x="550" y="50" width="110" height="60" rx="8" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <text x="605" y="76" text-anchor="middle" font-size="20">🖥</text>
  <text x="605" y="96" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#fff">Server</text>
  <text x="605" y="110" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#666">Receives data</text>
  <!-- Attacker in middle -->
  <rect x="275" y="30" width="130" height="100" rx="8" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
  <text x="340" y="62" text-anchor="middle" font-size="20">🕵️</text>
  <text x="340" y="84" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#e05c5c">Attacker</text>
  <text x="340" y="100" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#888">Intercepts &amp;</text>
  <text x="340" y="113" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#888">reads all traffic</text>
  <!-- Normal path (top, greyed) -->
  <line x1="130" y1="58" x2="275" y2="68" stroke="#e05c5c" stroke-width="1.5" stroke-dasharray="5,3" marker-end="url(#arr3)"/>
  <line x1="405" y1="68" x2="550" y2="58" stroke="#e05c5c" stroke-width="1.5" stroke-dasharray="5,3" marker-end="url(#arr3)"/>
  <!-- Labels -->
  <text x="200" y="52" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">intercepted</text>
  <text x="480" y="52" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">forwarded</text>
  <!-- What user thinks -->
  <line x1="130" y1="132" x2="550" y2="132" stroke="#00d97e" stroke-width="1" stroke-dasharray="4,3" marker-end="url(#arr2)"/>
  <text x="340" y="148" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">What the user thinks is happening (direct connection)</text>
</svg>
""", "Man-in-the-middle attack — attacker intercepts and reads all traffic between user and server")

# ── DNS Resolution (Lesson B3) ───────────────────────────────────────────────
DNS_RESOLUTION_SVG = diagram("""
<svg viewBox="0 0 720 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="da" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#00d97e" opacity="0.8"/>
    </marker>
  </defs>
  <!-- Browser -->
  <rect x="10" y="70" width="110" height="60" rx="7" fill="#1a1a1a" stroke="#333"/>
  <text x="65" y="96" text-anchor="middle" font-size="18">🌐</text>
  <text x="65" y="113" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">Your Browser</text>
  <text x="65" y="126" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">bliztechacademy.com</text>
  <!-- Resolver -->
  <rect x="165" y="70" width="110" height="60" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="220" y="96" text-anchor="middle" font-size="18">🔄</text>
  <text x="220" y="113" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">DNS Resolver</text>
  <text x="220" y="126" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">8.8.8.8 (Google)</text>
  <!-- Root NS -->
  <rect x="320" y="20" width="110" height="60" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="375" y="46" text-anchor="middle" font-size="18">🌍</text>
  <text x="375" y="63" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">Root Server</text>
  <text x="375" y="76" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">Knows .com TLD</text>
  <!-- TLD NS -->
  <rect x="320" y="120" width="110" height="60" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="375" y="146" text-anchor="middle" font-size="18">📂</text>
  <text x="375" y="163" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">TLD Server</text>
  <text x="375" y="176" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">.com nameserver</text>
  <!-- Auth NS -->
  <rect x="480" y="70" width="120" height="60" rx="7" fill="#1a1a1a" stroke="#00d97e" stroke-width="1.5"/>
  <text x="540" y="96" text-anchor="middle" font-size="18">✅</text>
  <text x="540" y="113" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">Auth. Server</text>
  <text x="540" y="126" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Returns IP: 104.21.35.67</text>
  <!-- Final server -->
  <rect x="620" y="70" width="90" height="60" rx="7" fill="#1a1a1a" stroke="#333"/>
  <text x="665" y="96" text-anchor="middle" font-size="18">🖥</text>
  <text x="665" y="113" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">Web Server</text>
  <text x="665" y="126" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">104.21.35.67</text>
  <!-- Arrows: numbered steps -->
  <line x1="120" y1="100" x2="163" y2="100" stroke="#00d97e" stroke-width="1.5" marker-end="url(#da)"/>
  <text x="141" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#00d97e">①</text>
  <line x1="220" y1="70" x2="340" y2="55" stroke="#00d97e" stroke-width="1.5" marker-end="url(#da)"/>
  <text x="275" y="55" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#00d97e">②</text>
  <line x1="375" y1="80" x2="375" y2="122" stroke="#00d97e" stroke-width="1.5" marker-end="url(#da)"/>
  <text x="388" y="108" font-family="JetBrains Mono,monospace" font-size="8" fill="#00d97e">③</text>
  <line x1="430" y1="150" x2="478" y2="120" stroke="#00d97e" stroke-width="1.5" marker-end="url(#da)"/>
  <text x="460" y="130" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#00d97e">④</text>
  <line x1="540" y1="70" x2="540" y2="50" stroke="none"/>
  <line x1="540" y1="100" x2="618" y2="100" stroke="#00d97e" stroke-width="2" marker-end="url(#da)"/>
  <text x="578" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#00d97e">⑤ IP</text>
</svg>
""", "DNS resolution — how a domain name is translated to an IP address (5-step process)")

# ── TCP Three-Way Handshake (Lesson B2) ─────────────────────────────────────
TCP_HANDSHAKE_SVG = diagram("""
<svg viewBox="0 0 500 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="ta" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#00d97e" opacity="0.9"/>
    </marker>
  </defs>
  <!-- Client -->
  <rect x="30" y="10" width="100" height="40" rx="6" fill="#1a1a1a" stroke="#333"/>
  <text x="80" y="35" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="11" fill="#fff">CLIENT</text>
  <line x1="80" y1="50" x2="80" y2="185" stroke="#444" stroke-width="1" stroke-dasharray="4,3"/>
  <!-- Server -->
  <rect x="370" y="10" width="100" height="40" rx="6" fill="#1a1a1a" stroke="#333"/>
  <text x="420" y="35" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="11" fill="#fff">SERVER</text>
  <line x1="420" y1="50" x2="420" y2="185" stroke="#444" stroke-width="1" stroke-dasharray="4,3"/>
  <!-- Step 1: SYN -->
  <line x1="80" y1="75" x2="420" y2="95" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ta)"/>
  <rect x="175" y="62" width="100" height="22" rx="4" fill="#0a1a12"/>
  <text x="225" y="77" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e">① SYN</text>
  <text x="225" y="89" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">"I want to connect"</text>
  <!-- Step 2: SYN-ACK -->
  <line x1="420" y1="115" x2="80" y2="135" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ta)"/>
  <rect x="175" y="110" width="100" height="22" rx="4" fill="#0a1a12"/>
  <text x="225" y="125" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e">② SYN-ACK</text>
  <text x="225" y="137" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">"OK, ready"</text>
  <!-- Step 3: ACK -->
  <line x1="80" y1="155" x2="420" y2="170" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ta)"/>
  <rect x="175" y="155" width="100" height="22" rx="4" fill="#0a1a12"/>
  <text x="225" y="170" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e">③ ACK</text>
  <text x="225" y="182" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">"Connected ✓"</text>
</svg>
""", "TCP three-way handshake — how a reliable connection is established before data is sent")

# ── Defence in Depth (Lesson A5) ─────────────────────────────────────────────
DEFENCE_DEPTH_SVG = diagram("""
<svg viewBox="0 0 500 300" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <!-- Concentric rings -->
  <circle cx="250" cy="150" r="220" fill="none" stroke="#1e1e1e" stroke-width="40"/>
  <circle cx="250" cy="150" r="175" fill="none" stroke="#1a2a1a" stroke-width="40"/>
  <circle cx="250" cy="150" r="130" fill="none" stroke="#162216" stroke-width="40"/>
  <circle cx="250" cy="150" r="85" fill="none" stroke="#122012" stroke-width="40"/>
  <circle cx="250" cy="150" r="42" fill="#0a1a0a"/>
  <!-- Ring outlines -->
  <circle cx="250" cy="150" r="240" fill="none" stroke="#2a2a2a" stroke-width="1"/>
  <circle cx="250" cy="150" r="195" fill="none" stroke="#2a2a2a" stroke-width="1"/>
  <circle cx="250" cy="150" r="150" fill="none" stroke="#2a2a2a" stroke-width="1"/>
  <circle cx="250" cy="150" r="107" fill="none" stroke="#2a2a2a" stroke-width="1"/>
  <circle cx="250" cy="150" r="62" fill="none" stroke="#00d97e" stroke-width="1.5" stroke-dasharray="4,3"/>
  <!-- Labels on rings -->
  <text x="250" y="17" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#555">PERIMETER · Firewall · Email filtering · IDS</text>
  <text x="250" y="64" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#666">NETWORK · Segmentation · VPN · DMZ</text>
  <text x="250" y="112" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#777">ENDPOINT · EDR · Patching · Encryption</text>
  <text x="250" y="148" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#888">APPLICATION · Auth · Input validation</text>
  <!-- Centre -->
  <text x="250" y="146" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">DATA</text>
  <text x="250" y="158" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#00d97e">Encrypted</text>
  <!-- Attacker arrow -->
  <line x1="10" y1="150" x2="188" y2="150" stroke="#e05c5c" stroke-width="2" stroke-dasharray="6,3" marker-end="url(#arr_red)"/>
  <text x="90" y="140" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">Attacker</text>
  <defs>
    <marker id="arr_red" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#e05c5c"/>
    </marker>
  </defs>
  <text x="10" y="278" font-family="sans-serif" font-size="9" fill="#444">Each layer independently blocks the attacker</text>
</svg>
""", "Defence in depth — multiple independent security layers protect the core data asset")

# ── Phishing Attack Flow (Lesson C2) ─────────────────────────────────────────
PHISHING_FLOW_SVG = diagram("""
<svg viewBox="0 0 700 160" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="pa" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#e05c5c" opacity="0.9"/>
    </marker>
    <marker id="ga" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#00d97e" opacity="0.9"/>
    </marker>
  </defs>
  <!-- Attacker -->
  <rect x="10" y="50" width="95" height="60" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
  <text x="57" y="76" text-anchor="middle" font-size="18">🕵️</text>
  <text x="57" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">Attacker</text>
  <!-- Email -->
  <rect x="145" y="50" width="100" height="60" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="195" y="76" text-anchor="middle" font-size="18">📧</text>
  <text x="195" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">Fake Email</text>
  <text x="195" y="107" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">"Your account..."</text>
  <!-- Victim -->
  <rect x="285" y="50" width="100" height="60" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="335" y="76" text-anchor="middle" font-size="18">👤</text>
  <text x="335" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">Victim</text>
  <text x="335" y="107" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">Clicks link</text>
  <!-- Fake site -->
  <rect x="425" y="50" width="115" height="60" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
  <text x="482" y="76" text-anchor="middle" font-size="18">🎣</text>
  <text x="482" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">Fake Site</text>
  <text x="482" y="107" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Looks legitimate</text>
  <!-- Attacker gets creds -->
  <rect x="580" y="50" width="110" height="60" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
  <text x="635" y="76" text-anchor="middle" font-size="18">🔑</text>
  <text x="635" y="95" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">Stolen Creds</text>
  <text x="635" y="107" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Sent to attacker</text>
  <!-- Arrows -->
  <line x1="107" y1="80" x2="143" y2="80" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#pa)"/>
  <line x1="247" y1="80" x2="283" y2="80" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#pa)"/>
  <line x1="387" y1="80" x2="423" y2="80" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#pa)"/>
  <line x1="542" y1="80" x2="578" y2="80" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#pa)"/>
  <!-- Defence note -->
  <text x="335" y="140" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">Defence: Check actual domain · SPF/DKIM · Hardware security keys</text>
</svg>
""", "Phishing attack flow — how credentials are stolen through a fake login page")

# ── Network Segmentation (Lesson B1) ─────────────────────────────────────────
NETWORK_SEG_SVG = diagram("""
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="na" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto">
      <path d="M0,0 L0,5 L5,2.5 z" fill="#555"/>
    </marker>
    <marker id="na2" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto">
      <path d="M0,0 L0,5 L5,2.5 z" fill="#00d97e"/>
    </marker>
  </defs>
  <!-- Internet -->
  <rect x="10" y="70" width="90" height="60" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="55" y="97" text-anchor="middle" font-size="18">🌐</text>
  <text x="55" y="116" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#aaa">Internet</text>
  <!-- Firewall -->
  <rect x="130" y="70" width="80" height="60" rx="7" fill="#1a1a1a" stroke="#00d97e" stroke-width="1.5"/>
  <text x="170" y="97" text-anchor="middle" font-size="18">🛡</text>
  <text x="170" y="116" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">Firewall</text>
  <!-- DMZ -->
  <rect x="245" y="40" width="110" height="120" rx="7" fill="#111" stroke="#555" stroke-dasharray="4,3"/>
  <text x="300" y="60" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#666">DMZ</text>
  <rect x="260" y="68" width="80" height="38" rx="5" fill="#1a1a1a" stroke="#333"/>
  <text x="300" y="88" text-anchor="middle" font-size="13">🌐</text>
  <text x="300" y="100" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Web Server</text>
  <rect x="260" y="112" width="80" height="38" rx="5" fill="#1a1a1a" stroke="#333"/>
  <text x="300" y="132" text-anchor="middle" font-size="13">📧</text>
  <text x="300" y="144" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Mail Server</text>
  <!-- Internal FW -->
  <rect x="387" y="70" width="80" height="60" rx="7" fill="#1a1a1a" stroke="#00d97e" stroke-width="1.5"/>
  <text x="427" y="97" text-anchor="middle" font-size="18">🛡</text>
  <text x="427" y="116" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">Int. FW</text>
  <!-- Internal zone -->
  <rect x="498" y="20" width="170" height="160" rx="7" fill="#111" stroke="#00d97e" stroke-width="1" stroke-dasharray="4,3"/>
  <text x="583" y="42" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">Internal Network</text>
  <rect x="513" y="52" width="65" height="36" rx="5" fill="#1a1a1a" stroke="#333"/>
  <text x="545" y="73" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Workstations</text>
  <rect x="590" y="52" width="65" height="36" rx="5" fill="#1a1a1a" stroke="#333"/>
  <text x="622" y="73" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">HR Systems</text>
  <rect x="513" y="100" width="65" height="36" rx="5" fill="#1a1a1a" stroke="#00d97e" stroke-width="1"/>
  <text x="545" y="121" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#00d97e">Database</text>
  <rect x="590" y="100" width="65" height="36" rx="5" fill="#1a1a1a" stroke="#333"/>
  <text x="622" y="121" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">Finance</text>
  <text x="583" y="158" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#444">Protected from DMZ</text>
  <!-- Arrows -->
  <line x1="102" y1="100" x2="128" y2="100" stroke="#555" stroke-width="1.5" marker-end="url(#na)"/>
  <line x1="212" y1="100" x2="243" y2="100" stroke="#555" stroke-width="1.5" marker-end="url(#na)"/>
  <line x1="357" y1="100" x2="385" y2="100" stroke="#555" stroke-width="1.5" marker-end="url(#na)"/>
  <line x1="469" y1="100" x2="496" y2="100" stroke="#00d97e" stroke-width="1.5" marker-end="url(#na2)"/>
</svg>
""", "Network segmentation — firewall zones isolate public-facing servers from internal systems")

# ── Ransomware Infection Chain (Lesson C4) ───────────────────────────────────
RANSOMWARE_SVG = diagram("""
<svg viewBox="0 0 720 130" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="ra" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#e05c5c" opacity="0.9"/>
    </marker>
  </defs>
  <!-- Steps -->
  <g font-family="JetBrains Mono, monospace" font-size="9" text-anchor="middle">
    <rect x="10" y="25" width="95" height="70" rx="7" fill="#1a1a1a" stroke="#444"/>
    <text x="57" y="52" font-size="16">📧</text>
    <text x="57" y="70" fill="#fff" font-size="9" font-weight="600">Phishing</text>
    <text x="57" y="83" fill="#666">Email arrives</text>
    <line x1="107" y1="60" x2="118" y2="60" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#ra)"/>

    <rect x="120" y="25" width="95" height="70" rx="7" fill="#1a1a1a" stroke="#444"/>
    <text x="167" y="52" font-size="16">📎</text>
    <text x="167" y="70" fill="#fff" font-size="9" font-weight="600">Attachment</text>
    <text x="167" y="83" fill="#666">User opens it</text>
    <line x1="217" y1="60" x2="228" y2="60" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#ra)"/>

    <rect x="230" y="25" width="95" height="70" rx="7" fill="#1a1a1a" stroke="#444"/>
    <text x="277" y="52" font-size="16">⚙️</text>
    <text x="277" y="70" fill="#fff" font-size="9" font-weight="600">Macro runs</text>
    <text x="277" y="83" fill="#666">Downloads payload</text>
    <line x1="327" y1="60" x2="338" y2="60" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#ra)"/>

    <rect x="340" y="25" width="95" height="70" rx="7" fill="#1a1a1a" stroke="#444"/>
    <text x="387" y="52" font-size="16">🔐</text>
    <text x="387" y="70" fill="#fff" font-size="9" font-weight="600">Encrypt</text>
    <text x="387" y="83" fill="#666">Files locked</text>
    <line x1="437" y1="60" x2="448" y2="60" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#ra)"/>

    <rect x="450" y="25" width="95" height="70" rx="7" fill="#1a1a1a" stroke="#444"/>
    <text x="497" y="52" font-size="16">📡</text>
    <text x="497" y="70" fill="#fff" font-size="9" font-weight="600">Exfiltrate</text>
    <text x="497" y="83" fill="#666">Data stolen too</text>
    <line x1="547" y1="60" x2="558" y2="60" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#ra)"/>

    <rect x="560" y="25" width="150" height="70" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
    <text x="635" y="52" font-size="16">💰</text>
    <text x="635" y="70" fill="#e05c5c" font-size="9" font-weight="600">Ransom Demand</text>
    <text x="635" y="83" fill="#888">Pay or lose data</text>
  </g>
</svg>
""", "Ransomware infection chain — from phishing email to ransom demand")

# ── Authentication Factors (Lesson B5 / C1) ──────────────────────────────────
AUTH_FACTORS_SVG = diagram("""
<svg viewBox="0 0 600 140" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <!-- Factor 1 -->
  <rect x="20" y="20" width="170" height="100" rx="8" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <text x="105" y="50" text-anchor="middle" font-size="24">🧠</text>
  <text x="105" y="73" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e">Something you KNOW</text>
  <text x="105" y="90" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#888">Password · PIN</text>
  <text x="105" y="106" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#555">Can be phished or stolen</text>
  <!-- Factor 2 -->
  <rect x="215" y="20" width="170" height="100" rx="8" fill="#1a1a1a" stroke="#00d97e" stroke-width="1.5"/>
  <text x="300" y="50" text-anchor="middle" font-size="24">📱</text>
  <text x="300" y="73" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e">Something you HAVE</text>
  <text x="300" y="90" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#888">Phone · Hardware key</text>
  <text x="300" y="106" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#00d97e">Strongest with FIDO2 key</text>
  <!-- Factor 3 -->
  <rect x="410" y="20" width="170" height="100" rx="8" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <text x="495" y="50" text-anchor="middle" font-size="24">👆</text>
  <text x="495" y="73" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#00d97e">Something you ARE</text>
  <text x="495" y="90" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#888">Fingerprint · Face ID</text>
  <text x="495" y="106" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#555">Can't be reset if stolen</text>
  <!-- MFA = combine any 2 -->
  <text x="300" y="133" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">MFA = any 2 factors combined → blocks 99.9% of account attacks</text>
</svg>
""", "The three authentication factors — MFA combines two or more for strong identity verification")

# ── Shared Responsibility Model (Lesson D1) ──────────────────────────────────
SHARED_RESP_SVG = diagram("""
<svg viewBox="0 0 660 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <!-- Header row -->
  <rect x="10" y="10" width="180" height="35" rx="5" fill="#111" stroke="#333"/>
  <text x="100" y="32" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#666">RESPONSIBILITY</text>
  <rect x="200" y="10" width="140" height="35" rx="5" fill="#111" stroke="#444"/>
  <text x="270" y="32" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#aaa">IaaS (EC2)</text>
  <rect x="350" y="10" width="140" height="35" rx="5" fill="#111" stroke="#444"/>
  <text x="420" y="32" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#aaa">PaaS</text>
  <rect x="500" y="10" width="150" height="35" rx="5" fill="#111" stroke="#444"/>
  <text x="575" y="32" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#aaa">SaaS (M365)</text>

  <!-- Rows -->
  <g font-family="sans-serif" font-size="10" text-anchor="middle">
    <!-- Data -->
    <rect x="10" y="50" width="180" height="28" rx="0" fill="#1a1a1a" stroke="#222"/>
    <text x="100" y="68" fill="#ccc">Data &amp; Access</text>
    <rect x="200" y="50" width="140" height="28" fill="#0a2a0a" stroke="#222"/>
    <text x="270" y="68" fill="#00d97e">Customer</text>
    <rect x="350" y="50" width="140" height="28" fill="#0a2a0a" stroke="#222"/>
    <text x="420" y="68" fill="#00d97e">Customer</text>
    <rect x="500" y="50" width="150" height="28" fill="#0a2a0a" stroke="#222"/>
    <text x="575" y="68" fill="#00d97e">Customer</text>
    <!-- App -->
    <rect x="10" y="80" width="180" height="28" rx="0" fill="#1a1a1a" stroke="#222"/>
    <text x="100" y="98" fill="#ccc">Application</text>
    <rect x="200" y="80" width="140" height="28" fill="#0a2a0a" stroke="#222"/>
    <text x="270" y="98" fill="#00d97e">Customer</text>
    <rect x="350" y="80" width="140" height="28" fill="#0a2a0a" stroke="#222"/>
    <text x="420" y="98" fill="#00d97e">Customer</text>
    <rect x="500" y="80" width="150" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="575" y="98" fill="#888">Provider</text>
    <!-- OS -->
    <rect x="10" y="110" width="180" height="28" rx="0" fill="#1a1a1a" stroke="#222"/>
    <text x="100" y="128" fill="#ccc">OS &amp; Runtime</text>
    <rect x="200" y="110" width="140" height="28" fill="#0a2a0a" stroke="#222"/>
    <text x="270" y="128" fill="#00d97e">Customer</text>
    <rect x="350" y="110" width="140" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="420" y="128" fill="#888">Provider</text>
    <rect x="500" y="110" width="150" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="575" y="128" fill="#888">Provider</text>
    <!-- Infra -->
    <rect x="10" y="140" width="180" height="28" rx="0" fill="#1a1a1a" stroke="#222"/>
    <text x="100" y="158" fill="#ccc">Infrastructure</text>
    <rect x="200" y="140" width="140" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="270" y="158" fill="#888">Provider</text>
    <rect x="350" y="140" width="140" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="420" y="158" fill="#888">Provider</text>
    <rect x="500" y="140" width="150" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="575" y="158" fill="#888">Provider</text>
    <!-- Physical -->
    <rect x="10" y="170" width="180" height="28" rx="0" fill="#1a1a1a" stroke="#222"/>
    <text x="100" y="188" fill="#ccc">Physical Security</text>
    <rect x="200" y="170" width="140" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="270" y="188" fill="#888">Provider</text>
    <rect x="350" y="170" width="140" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="420" y="188" fill="#888">Provider</text>
    <rect x="500" y="170" width="150" height="28" fill="#1a2a1a" stroke="#222"/>
    <text x="575" y="188" fill="#888">Provider</text>
  </g>
</svg>
""", "Cloud shared responsibility model — what you secure vs what your cloud provider secures")

# ── Risk Formula (Lesson A4) ──────────────────────────────────────────────────
RISK_FORMULA_SVG = diagram("""
<svg viewBox="0 0 600 100" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <!-- Risk = -->
  <rect x="20" y="20" width="100" height="60" rx="8" fill="#1a1a1a" stroke="#00d97e" stroke-width="2"/>
  <text x="70" y="48" text-anchor="middle" font-family="Syne, sans-serif" font-size="13" fill="#00d97e" font-weight="700">RISK</text>
  <text x="70" y="66" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#555">= T × V × I</text>
  <text x="140" y="55" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="20" fill="#444">=</text>
  <!-- Threat -->
  <rect x="158" y="20" width="120" height="60" rx="8" fill="#1a1a1a" stroke="#333"/>
  <text x="218" y="45" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#fff" font-weight="600">THREAT</text>
  <text x="218" y="62" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#666">Who might attack?</text>
  <text x="288" y="55" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="20" fill="#444">×</text>
  <!-- Vulnerability -->
  <rect x="302" y="20" width="140" height="60" rx="8" fill="#1a1a1a" stroke="#333"/>
  <text x="372" y="45" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#fff" font-weight="600">VULNERABILITY</text>
  <text x="372" y="62" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#666">What weakness exists?</text>
  <text x="452" y="55" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="20" fill="#444">×</text>
  <!-- Impact -->
  <rect x="466" y="20" width="114" height="60" rx="8" fill="#1a1a1a" stroke="#333"/>
  <text x="523" y="45" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="10" fill="#fff" font-weight="600">IMPACT</text>
  <text x="523" y="62" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#666">How bad if it happens?</text>
</svg>
""", "Risk formula — Risk = Threat × Vulnerability × Impact. If any factor is zero, risk is zero")

# ── MITM / Sniffing on open WiFi (Lesson B2) ─────────────────────────────────
WIFI_SNIFF_SVG = diagram("""
<svg viewBox="0 0 600 160" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="wa" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#e05c5c" opacity="0.8"/>
    </marker>
  </defs>
  <!-- User on laptop -->
  <rect x="20" y="55" width="110" height="65" rx="7" fill="#1a1a1a" stroke="#333"/>
  <text x="75" y="82" text-anchor="middle" font-size="20">💻</text>
  <text x="75" y="100" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#fff">User</text>
  <text x="75" y="114" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">Coffee shop WiFi</text>
  <!-- WiFi signal waves -->
  <path d="M145,88 Q165,70 185,88" fill="none" stroke="#444" stroke-width="1.5"/>
  <path d="M145,78 Q172,55 200,78" fill="none" stroke="#444" stroke-width="1" opacity="0.5"/>
  <!-- Rogue AP -->
  <rect x="205" y="35" width="110" height="65" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
  <text x="260" y="62" text-anchor="middle" font-size="20">📡</text>
  <text x="260" y="82" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#e05c5c">Rogue AP</text>
  <text x="260" y="96" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#888">"Free WiFi"</text>
  <!-- Attacker reads -->
  <rect x="205" y="110" width="110" height="45" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1"/>
  <text x="260" y="130" text-anchor="middle" font-size="14">🕵️</text>
  <text x="260" y="148" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="8" fill="#e05c5c">Reads all traffic</text>
  <line x1="260" y1="102" x2="260" y2="108" stroke="#e05c5c" stroke-width="1.5" marker-end="url(#wa)"/>
  <!-- Real AP -->
  <rect x="380" y="55" width="110" height="65" rx="7" fill="#1a1a1a" stroke="#444"/>
  <text x="435" y="82" text-anchor="middle" font-size="20">🌐</text>
  <text x="435" y="100" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#aaa">Internet</text>
  <text x="435" y="114" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#666">Traffic forwarded</text>
  <!-- Arrows -->
  <line x1="318" y1="70" x2="378" y2="80" stroke="#555" stroke-width="1.5" stroke-dasharray="4,3" marker-end="url(#wa)"/>
  <!-- VPN defence -->
  <rect x="490" y="55" width="100" height="65" rx="7" fill="#0a1a0a" stroke="#00d97e" stroke-width="1.5"/>
  <text x="540" y="82" text-anchor="middle" font-size="20">🔒</text>
  <text x="540" y="100" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">VPN</text>
  <text x="540" y="114" text-anchor="middle" font-family="sans-serif" font-size="8" fill="#00d97e">Encrypts all traffic</text>
  <text x="300" y="155" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#00d97e">Defence: Use VPN on public Wi-Fi · HTTPS only · Avoid sensitive activity</text>
</svg>
""", "Evil twin / WiFi sniffing — attacker intercepts all traffic on an unsecured network")

# ── Incident Response Lifecycle (Lesson C5) ──────────────────────────────────
IR_LIFECYCLE_SVG = diagram("""
<svg viewBox="0 0 640 140" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;">
  <defs>
    <marker id="ira" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="#00d97e" opacity="0.8"/>
    </marker>
  </defs>
  <g font-family="JetBrains Mono,monospace" font-size="9" text-anchor="middle">
    <!-- Prepare -->
    <rect x="10" y="30" width="95" height="75" rx="7" fill="#1a1a1a" stroke="#333"/>
    <text x="57" y="57" font-size="16">📋</text>
    <text x="57" y="75" fill="#fff" font-weight="600">Prepare</text>
    <text x="57" y="89" fill="#666">Policies</text>
    <text x="57" y="100" fill="#666">Training</text>
    <line x1="107" y1="67" x2="118" y2="67" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ira)"/>
    <!-- Detect -->
    <rect x="120" y="30" width="95" height="75" rx="7" fill="#1a1a1a" stroke="#333"/>
    <text x="167" y="57" font-size="16">🔍</text>
    <text x="167" y="75" fill="#fff" font-weight="600">Detect</text>
    <text x="167" y="89" fill="#666">SIEM alerts</text>
    <text x="167" y="100" fill="#666">User reports</text>
    <line x1="217" y1="67" x2="228" y2="67" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ira)"/>
    <!-- Contain -->
    <rect x="230" y="30" width="95" height="75" rx="7" fill="#1a1a1a" stroke="#e05c5c" stroke-width="1.5"/>
    <text x="277" y="57" font-size="16">🛑</text>
    <text x="277" y="75" fill="#e05c5c" font-weight="600">Contain</text>
    <text x="277" y="89" fill="#888">Isolate systems</text>
    <text x="277" y="100" fill="#888">Stop spread</text>
    <line x1="327" y1="67" x2="338" y2="67" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ira)"/>
    <!-- Eradicate -->
    <rect x="340" y="30" width="95" height="75" rx="7" fill="#1a1a1a" stroke="#333"/>
    <text x="387" y="57" font-size="16">🧹</text>
    <text x="387" y="75" fill="#fff" font-weight="600">Eradicate</text>
    <text x="387" y="89" fill="#666">Remove malware</text>
    <text x="387" y="100" fill="#666">Close entry point</text>
    <line x1="437" y1="67" x2="448" y2="67" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ira)"/>
    <!-- Recover -->
    <rect x="450" y="30" width="95" height="75" rx="7" fill="#1a1a1a" stroke="#333"/>
    <text x="497" y="57" font-size="16">🔄</text>
    <text x="497" y="75" fill="#fff" font-weight="600">Recover</text>
    <text x="497" y="89" fill="#666">Restore systems</text>
    <text x="497" y="100" fill="#666">Verify clean</text>
    <line x1="547" y1="67" x2="558" y2="67" stroke="#00d97e" stroke-width="1.5" marker-end="url(#ira)"/>
    <!-- Lessons -->
    <rect x="560" y="30" width="70" height="75" rx="7" fill="#1a1a1a" stroke="#00d97e" stroke-width="1.5"/>
    <text x="595" y="57" font-size="16">📝</text>
    <text x="595" y="75" fill="#00d97e" font-weight="600">Learn</text>
    <text x="595" y="89" fill="#888">Post-incident</text>
    <text x="595" y="100" fill="#888">review</text>
  </g>
</svg>
""", "Incident response lifecycle — the six phases from preparation through to lessons learned")


# ── Lesson content patches ───────────────────────────────────────────────────

PATCHES = {
    "gic-a2": {
        "insert_after": "<h2>The attack lifecycle</h2>",
        "insert": ATTACK_LIFECYCLE_SVG,
    },
    "gic-a3": {
        "insert_after": "<h2>The foundation of security thinking</h2>",
        "insert": CIA_TRIAD_SVG,
    },
    "gic-a4": {
        "insert_after": "<h2>How security professionals think about risk</h2>",
        "insert": RISK_FORMULA_SVG,
    },
    "gic-a5": {
        "insert_after": "<h2>Why no single control is enough</h2>",
        "insert": DEFENCE_DEPTH_SVG,
    },
    "gic-b1": {
        "insert_after": "<h2>Network security concepts</h2>",
        "insert": NETWORK_SEG_SVG,
    },
    "gic-b2": {
        "insert_after": "<h2>TCP and UDP — the two main transport protocols</h2>",
        "insert": TCP_HANDSHAKE_SVG,
    },
    "gic-b3": {
        "insert_after": "<h2>How DNS resolution works — step by step</h2>",
        "insert": DNS_RESOLUTION_SVG,
    },
    "gic-b5": {
        "insert_after": "<h2>Authentication factors</h2>",
        "insert": AUTH_FACTORS_SVG,
    },
    "gic-c2": {
        "insert_after": "<h2>Why email is the primary attack vector</h2>",
        "insert": PHISHING_FLOW_SVG,
    },
    "gic-c4": {
        "insert_after": "<h2>How infections happen — delivery mechanisms</h2>",
        "insert": RANSOMWARE_SVG,
    },
    "gic-c5": {
        "insert_after": "<h2>Incident response — the lifecycle</h2>",
        "insert": IR_LIFECYCLE_SVG,
    },
    "gic-d1": {
        "insert_after": "<h2>The shared responsibility model</h2>",
        "insert": SHARED_RESP_SVG,
    },
}

# Also add WiFi sniffing to B2 (second diagram)
WIFI_PATCH = {
    "gic-b2": {
        "insert_after": "<h2>How to read an IP address in a security context</h2>",
        "insert": WIFI_SNIFF_SVG,
    }
}

# MITM diagram into B1
MITM_PATCH = {
    "gic-b1": {
        "insert_after": "<h2>What a network is</h2>",
        "insert": MITM_SVG,
    }
}


def apply_patches(body, patches_list):
    for patch in patches_list:
        marker = patch["insert_after"]
        insert = patch["insert"]
        if marker in body:
            # Insert after the closing </p> or </h2> that follows the marker
            idx = body.find(marker)
            # Find end of the heading tag
            end_tag_idx = body.find('>', idx) + 1
            body = body[:end_tag_idx] + insert + body[end_tag_idx:]
    return body


def seed():
    from app.models import CourseTopic
    from app.extensions import db

    all_patches = {}

    # Merge all patch dicts
    for slug, patch in PATCHES.items():
        all_patches.setdefault(slug, []).append(patch)
    for slug, patch in WIFI_PATCH.items():
        all_patches.setdefault(slug, []).append(patch)
    for slug, patch in MITM_PATCH.items():
        all_patches.setdefault(slug, []).append(patch)

    updated = 0
    for slug, patches in all_patches.items():
        topic = CourseTopic.query.filter_by(slug=slug).first()
        if not topic:
            print(f"  SKIP {slug} — not found")
            continue
        topic.body = apply_patches(topic.body, patches)
        updated += 1
        print(f"  patched {slug} — {len(patches)} diagram(s)")

    db.session.commit()
    print(f"\nDone — {updated} lessons updated with SVG diagrams.")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import create_app
    app = create_app()
    with app.app_context():
        seed()