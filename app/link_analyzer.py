import re
import math
import urllib.parse
from typing import Optional

# ---------------------------------------------------------------------------
# INJECTION / MALICIOUS INPUT PROTECTION
# ---------------------------------------------------------------------------

# Hard limit on raw input length
MAX_URL_LENGTH = 2048

# Patterns that indicate someone is trying to inject code or commands
_INJECTION_PATTERNS = [
    r"<script",
    r"javascript:",
    r"vbscript:",
    r"data:text/html",
    r"on\w+\s*=",           # onerror=, onload=, etc.
    r"(\.\./){2,}",         # path traversal
    r"(;|\||\$\(|`)",       # shell injection
    r"(union\s+select|drop\s+table|insert\s+into|delete\s+from)",  # SQLi
    r"(\bexec\b|\beval\b|\bsystem\b|\bpassthru\b)",  # code exec
    r"(%00|%0d%0a|%3cscript)",  # encoded attacks
    r"\x00",                # null bytes
]

_INJECTION_RE = re.compile(
    "|".join(_INJECTION_PATTERNS),
    re.IGNORECASE
)


def _sanitize_input(raw: str) -> Optional[str]:
    """
    Validate and sanitize raw input. Returns cleaned URL string or None
    if the input is malicious/invalid and should be rejected outright.
    """
    if not raw or not isinstance(raw, str):
        return None

    # Strip leading/trailing whitespace and null bytes
    cleaned = raw.strip().replace("\x00", "")

    # Reject if too long
    if len(cleaned) > MAX_URL_LENGTH:
        return None

    # Reject if injection patterns found
    if _INJECTION_RE.search(cleaned):
        return None

    # Reject if it contains newlines (header injection)
    if "\n" in cleaned or "\r" in cleaned:
        return None

    return cleaned


# ---------------------------------------------------------------------------
# KNOWN GOOD / TRUSTED DOMAINS (whitelist)
# ---------------------------------------------------------------------------

TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "github.com", "www.github.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "wikipedia.org", "en.wikipedia.org",
    "reddit.com", "www.reddit.com",
    "netflix.com", "www.netflix.com",
    "dropbox.com", "www.dropbox.com",
    "paypal.com", "www.paypal.com",
    "bbc.co.uk", "www.bbc.co.uk", "bbc.com",
    "gov.uk", "nhs.uk",
    "ilovepdf.com", "www.ilovepdf.com",
    "canva.com", "www.canva.com",
    "notion.so", "www.notion.so",
    "cloudflare.com", "www.cloudflare.com",
    "stripe.com", "www.stripe.com",
}

# ---------------------------------------------------------------------------
# DETECTION DATA
# ---------------------------------------------------------------------------

TRUSTED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "netflix", "instagram", "twitter", "whatsapp", "barclays", "hsbc",
    "lloyds", "natwest", "halifax", "santander", "ebay", "dropbox",
    "linkedin", "yahoo", "outlook", "chase", "wellsfargo", "citibank",
    "dhl", "fedex", "ups", "usps", "royalmail", "hmrc", "irs",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".info", ".biz",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".ws", ".cc",
    ".ru", ".cn", ".su", ".icu", ".vip", ".work", ".loan",
    ".download", ".stream", ".racing", ".review", ".win",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "tiny.cc", "is.gd", "rb.gy", "cutt.ly", "bl.ink",
    "rebrand.ly", "shorturl.at", "clck.ru", "s.id", "v.gd",
}

PHISHING_KEYWORDS = [
    "verify", "confirm", "update", "suspended", "unusual-activity",
    "account-locked", "login-required", "reset-password", "validate",
    "authenticate", "unlock", "restore", "limited", "urgent",
    "winner", "prize", "claim", "free-gift", "congratulations",
    "billing", "invoice", "payment-failed", "card-declined",
]

# Homograph / lookalike character mappings
HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g", "@": "a",
}

# Brand typosquatting variants (common misspellings)
TYPOSQUAT_PATTERNS = {
    "paypal":     ["paypa1", "paypai", "paypa-l", "paypall", "paypaI"],
    "google":     ["g00gle", "gooogle", "googel", "g0ogle"],
    "microsoft":  ["micros0ft", "microsofl", "mlcrosoft"],
    "amazon":     ["amaz0n", "amazzon", "arnazon"],
    "apple":      ["app1e", "appie", "appl3"],
    "facebook":   ["faceb00k", "faceb0ok", "facebok"],
    "netflix":    ["netfl1x", "netfix", "netf1ix"],
    "paystack":   ["payst4ck", "paystaek"],
    "instagram":  ["inst4gram", "instagr4m"],
    "whatsapp":   ["whatsap", "whatsapp-web", "whatsap-web"],
    "barclays":   ["barc1ays", "barclays-bank"],
    "hsbc":       ["h5bc", "hsbcbank"],
    "hmrc":       ["hmrc-gov", "hmrc-refund", "hmrc-tax"],
    "irs":        ["irs-gov", "irs-refund"],
    "dhl":        ["dhl-delivery", "dh1"],
    "fedex":      ["fedex-delivery", "f3dex"],
}


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _url_entropy(s: str) -> float:
    """Shannon entropy — high entropy strings often indicate encoded payloads."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _normalize_domain(domain: str) -> str:
    """Lowercase, strip www., strip port."""
    d = domain.lower().split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def _homograph_decode(text: str) -> str:
    """Replace lookalike digits/chars with their letter equivalents."""
    result = []
    for ch in text.lower():
        result.append(HOMOGRAPH_MAP.get(ch, ch))
    return "".join(result)


def _levenshtein(a: str, b: str) -> int:
    """Basic Levenshtein distance for typosquat detection."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[len(b)]


# ---------------------------------------------------------------------------
# MAIN ANALYZER
# ---------------------------------------------------------------------------

def analyze_url(raw: str) -> dict:

    # ── Step 1: Sanitize input ───────────────────────────────────────────
    cleaned = _sanitize_input(raw)
    if cleaned is None:
        return {
            "risk": "Blocked",
            "risk_level": 3,
            "flags": ["Input contains malicious or invalid characters and was rejected"],
            "explanation": "This input looks like an injection attempt or is otherwise invalid. It has been blocked.",
            "advice": ["Do not submit scripts, HTML, or shell commands into this tool"],
            "domain": "—",
        }

    url = cleaned
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    flags = []
    score = 0

    # ── Step 2: Parse ────────────────────────────────────────────────────
    try:
        parsed = urllib.parse.urlparse(url)
        domain_raw = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()
        domain = _normalize_domain(domain_raw)
        domain_base = domain.split(".")[0] if domain else ""
    except Exception:
        return {
            "risk": "Invalid",
            "risk_level": 3,
            "flags": ["Could not parse this URL — it appears to be malformed"],
            "explanation": "We could not analyse this link. Make sure it is a valid URL.",
            "advice": ["Double-check the URL format before submitting"],
            "domain": "—",
        }

    # ── Step 3: Whitelist check ──────────────────────────────────────────
    if domain in TRUSTED_DOMAINS or _normalize_domain(domain_raw) in TRUSTED_DOMAINS:
        # Still flag HTTP even for trusted domains
        if parsed.scheme == "http":
            flags.append("No HTTPS — connection is not encrypted even on this known domain")
            score += 15
        if not flags:
            flags.append("No suspicious indicators detected")
        return {
            "risk": "Looks Safe",
            "risk_level": 1,
            "flags": flags,
            "explanation": "This domain is a well-known, trusted website. No major red flags were found.",
            "advice": [
                "Always verify you are on the correct domain before logging in",
                "Look for the padlock icon in your browser address bar",
                "Avoid clicking links in unsolicited emails even to trusted sites",
            ],
            "domain": domain,
        }

    # ── Step 4: Individual checks ────────────────────────────────────────

    # 4a. HTTP (no encryption)
    if parsed.scheme == "http":
        flags.append("No HTTPS — your data would be transmitted unencrypted")
        score += 30

    # 4b. IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        flags.append("Uses a raw IP address instead of a domain name — a major phishing indicator")
        score += 45

    # 4c. Private/reserved IP ranges
    private_ip = re.match(r"^(192\.168|10\.|172\.(1[6-9]|2\d|3[01]))\.", domain)
    if private_ip:
        flags.append("Points to a private/internal IP address — should never appear in a public link")
        score += 50

    # 4d. URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            flags.append(f"Uses a URL shortener ({shortener}) — the real destination is hidden")
            score += 30
            break

    # 4e. Brand spoofing — exact known typosquats
    for brand, variants in TYPOSQUAT_PATTERNS.items():
        for variant in variants:
            if variant in domain:
                flags.append(f'Domain uses "{variant}" which impersonates "{brand}"')
                score += 55
                break

    # 4f. Brand in domain but not the real domain
    for brand in TRUSTED_BRANDS:
        if brand in domain:
            real_domains = [f"{brand}.com", f"{brand}.co.uk", f"{brand}.org"]
            is_real = any(domain == rd or domain.endswith("." + rd) for rd in real_domains)
            if not is_real:
                flags.append(f'Contains "{brand}" but is not the official {brand} domain')
                score += 45
            break

    # 4g. Homograph attack — decode digits to letters then check brands
    decoded = _homograph_decode(domain_base)
    if decoded != domain_base:
        for brand in TRUSTED_BRANDS:
            if brand in decoded and brand not in domain_base:
                flags.append(f'Uses character substitution (e.g. numbers for letters) to impersonate "{brand}"')
                score += 55
                break

    # 4h. Levenshtein typosquatting (edit distance 1–2 from a trusted brand)
    for brand in TRUSTED_BRANDS:
        if len(brand) >= 5 and brand not in domain_base:
            dist = _levenshtein(domain_base, brand)
            if 0 < dist <= 2:
                flags.append(f'Domain name is suspiciously close to "{brand}" — possible typosquatting')
                score += 40
                break

    # 4i. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f'Uses a high-risk top-level domain ({tld}) commonly associated with scam sites')
            score += 30
            break

    # 4j. Excessive subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        flags.append("Has an unusual number of subdomains — often used to make fake sites look legitimate")
        score += 25

    # 4k. Multiple hyphens in domain
    if domain.count("-") >= 2:
        flags.append("Domain contains multiple hyphens — a common pattern in phishing domains")
        score += 20

    # 4l. Very long URL
    if len(url) > 150:
        flags.append("Unusually long URL — often used to bury the real destination in noise")
        score += 15

    # 4m. Phishing keywords in path/query
    full_path = (path + "?" + query).lower()
    kw_hits = [kw for kw in PHISHING_KEYWORDS if kw in full_path]
    if len(kw_hits) >= 2:
        flags.append(f'Path contains multiple phishing keywords: {", ".join(kw_hits[:4])}')
        score += 25
    elif len(kw_hits) == 1:
        flags.append(f'Path contains a phishing-associated keyword: "{kw_hits[0]}"')
        score += 12

    # 4n. Encoded characters in domain (obfuscation)
    if "%" in domain_raw:
        flags.append("Domain contains URL-encoded characters — a common obfuscation technique")
        score += 35

    # 4o. High entropy path (randomised/obfuscated paths)
    if path and len(path) > 20:
        entropy = _url_entropy(path)
        if entropy > 4.2:
            flags.append("URL path has high randomness — may be an obfuscated tracking or phishing link")
            score += 15

    # 4p. Misleading auth credentials in URL (http://paypal.com@evil.com)
    if "@" in domain_raw:
        flags.append("URL contains an @ symbol in the domain — a classic trick to hide the real destination")
        score += 60

    # 4q. Double extension tricks (e.g. invoice.pdf.exe, login.html.php)
    suspicious_double_ext = re.search(r"\.(pdf|doc|xls|jpg|png)\.(exe|php|js|sh|bat|cmd)", path)
    if suspicious_double_ext:
        flags.append("URL path uses a double file extension — commonly used to disguise malware")
        score += 50

    # ── Step 5: Determine risk level ────────────────────────────────────
    if score >= 55:
        risk = "High Risk"
        risk_level = 3
        explanation = (
            "This link has multiple strong indicators of a phishing or scam attempt. "
            "It should not be visited or shared."
        )
        advice = [
            "Do not click or visit this link under any circumstances",
            "Do not enter passwords, card details, or personal information",
            "If received by email or text, report it as phishing",
            "If you already visited it, change your passwords immediately and monitor your accounts",
        ]
    elif score >= 25:
        risk = "Suspicious"
        risk_level = 2
        explanation = (
            "This link has warning signs that suggest it may not be safe. "
            "It could be legitimate, but treat it with caution."
        )
        advice = [
            "Do not enter sensitive information unless you are 100% certain it is safe",
            "Navigate to the official website by typing it directly in your browser instead",
            "Inspect the full URL carefully — look for misspellings or unusual characters",
            "If in doubt, contact the organisation directly through their official channels",
        ]
    else:
        risk = "Looks Safe"
        risk_level = 1
        explanation = (
            "No significant red flags were detected. However, no automated tool can guarantee "
            "a link is completely safe — always apply your own judgement."
        )
        advice = [
            "Always verify the sender before clicking links in emails or messages",
            "Check for the padlock icon and correct domain in your browser",
            "Trust your instincts — if something feels off, it probably is",
        ]

    if not flags:
        flags.append("No suspicious indicators detected")

    return {
        "risk": risk,
        "risk_level": risk_level,
        "score": score,
        "flags": flags,
        "explanation": explanation,
        "advice": advice,
        "domain": domain or domain_raw,
    }