import re
import urllib.parse

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
    'banking', 'password', 'credential', 'alert', 'urgent', 'suspended',
    'limited', 'unusual', 'activity', 'click', 'winner', 'prize', 'free',
    'offer', 'claim', 'validate', 'authenticate', 'unlock', 'restore'
]

TRUSTED_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix',
    'instagram', 'twitter', 'whatsapp', 'barclays', 'hsbc', 'lloyds', 'natwest',
    'halifax', 'santander', 'ebay', 'dropbox', 'linkedin', 'yahoo', 'outlook'
]

SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.online', '.site', '.info', '.biz', '.tk',
    '.ml', '.ga', '.cf', '.gq', '.pw', '.ws', '.cc', '.ru', '.cn'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'short.link', 'tiny.cc', 'is.gd', 'rb.gy', 'cutt.ly'
]


def analyze_url(url: str) -> dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    flags = []
    score = 0  # higher = more risky

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()
    except Exception:
        return {
            'risk': 'Unknown',
            'risk_level': 0,
            'flags': ['Could not parse this URL — it may be malformed'],
            'explanation': 'We could not analyse this link. Make sure it is a valid URL.',
            'advice': ['Double-check the URL before visiting it']
        }

    # 1. HTTP not HTTPS
    if parsed.scheme == 'http':
        flags.append('No HTTPS — connection is not encrypted')
        score += 20

    # 2. IP address instead of domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}', domain):
        flags.append('Uses an IP address instead of a domain name')
        score += 35

    # 3. URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            flags.append(f'Uses a URL shortener ({shortener}) — hides the real destination')
            score += 25
            break

    # 4. Misspelled brand name in domain
    for brand in TRUSTED_BRANDS:
        if brand in full:
            # Check if it's actually the real domain
            real_domains = [f'{brand}.com', f'{brand}.co.uk', f'www.{brand}.com']
            is_real = any(rd in domain for rd in real_domains)
            if not is_real:
                flags.append(f'Appears to impersonate "{brand}" but is not the official domain')
                score += 40
                break

    # 5. Suspicious keywords
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if len(keyword_hits) >= 3:
        flags.append(f'Contains multiple urgency/security keywords: {", ".join(keyword_hits[:4])}')
        score += 20
    elif len(keyword_hits) >= 1:
        flags.append(f'Contains suspicious keyword(s): {", ".join(keyword_hits[:3])}')
        score += 10

    # 6. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f'Uses a suspicious top-level domain ({tld})')
            score += 25
            break

    # 7. Very long URL
    if len(url) > 100:
        flags.append('Unusually long URL — often used to hide the real destination')
        score += 10

    # 8. Excessive subdomains
    parts = domain.split('.')
    if len(parts) > 4:
        flags.append('Has many subdomains — a common trick to make fake sites look real')
        score += 20

    # 9. Hyphens in domain (e.g. paypal-secure-login.com)
    domain_base = parts[0] if parts else ''
    if domain.count('-') >= 2:
        flags.append('Domain contains multiple hyphens — common in phishing domains')
        score += 15

    # 10. Numbers replacing letters (paypa1, g00gle)
    if re.search(r'[a-z][0-9]|[0-9][a-z]', domain.split('.')[0]):
        flags.append('Domain mixes letters and numbers — may be imitating a real brand')
        score += 30

    # Determine risk level
    if score >= 50:
        risk = 'High Risk'
        risk_level = 3
        explanation = 'This link has multiple signs of a phishing or scam attempt. Do not visit it, enter any details, or share it.'
        advice = [
            'Do not click or visit this link',
            'Do not enter any passwords, card details, or personal information',
            'Report it as phishing if received via email or text',
            'If you already clicked, change your passwords immediately'
        ]
    elif score >= 25:
        risk = 'Suspicious'
        risk_level = 2
        explanation = 'This link has some warning signs. It may be legitimate, but treat it with caution.'
        advice = [
            'Do not enter sensitive information unless you are certain it is safe',
            'Try visiting the official website directly by typing it in your browser',
            'Check the full URL carefully before proceeding',
            'If in doubt, contact the company directly'
        ]
    else:
        risk = 'Looks Safe'
        risk_level = 1
        explanation = 'No major red flags were found. However, no automated tool can guarantee a link is 100% safe.'
        advice = [
            'Always verify the sender before clicking links in emails or texts',
            'Look for HTTPS and a padlock in your browser',
            'Trust your instincts — if something feels off, it probably is'
        ]

    if not flags:
        flags.append('No obvious red flags detected')

    return {
        'risk': risk,
        'risk_level': risk_level,
        'score': score,
        'flags': flags,
        'explanation': explanation,
        'advice': advice,
        'domain': domain
    }