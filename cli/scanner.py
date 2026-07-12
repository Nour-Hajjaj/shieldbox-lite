from urllib.parse import urlparse
from difflib import SequenceMatcher

def check_https(url):
    if not url.startswith("https://"):
        return 15, "This link does not use a secure HTTPS connection, which is common in phishing attempts."
    return 0, None

def check_length(url):
    if len(url) > 75:
        return 10, "This link is unusually long, which scammers often use to hide the real destination."
    return 0, None

def check_at_symbol(url):
    if "@" in url:
        return 20, "This link contains an '@' symbol, a known trick used to disguise the real destination website."
    return 0, None

def check_dots(url):
    dot_count = url.count(".")
    if dot_count > 3:
        return 15, "This link has an unusually high number of subdomains, often used to make fake sites look legitimate."
    return 0, None

def check_hyphens(url):
    hyphen_count = url.count("-")
    if hyphen_count > 3:
        return 10, "This link contains an excessive number of hyphens, a pattern common in scam websites."
    return 0, None

def check_suspicious_words(url):
    suspicious_words = ["verify", "urgent", "account", "suspended", "login",
                         "update", "confirm", "deactivate", "security", "unlock"]

    found_words = []

    for i in suspicious_words:
        if i in url.lower():
            found_words.append(i)

    if found_words:
        points = len(found_words) * 5
        return points, f"This link contains urgency-related keywords often used in phishing attempts: {', '.join(found_words)}."
    return 0, None

def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    domain = domain.replace("www.", "")
    return domain

def check_lookalike_brands(url):
    real_brands = ["rbc.com", "td.com", "cibc.com", "cra-arc.gc.ca", "ucalgary.ca", "d2l.ucalgary.ca"]

    domain = extract_domain(url)

    if domain in real_brands:
        return 0, None

    for real in real_brands:
        similarity = SequenceMatcher(None, domain, real).ratio()
        if similarity > 0.7:
            return 30, f"The domain '{domain}' closely resembles the official domain '{real}', suggesting possible brand impersonation."

    return 0, None

def calculate_score(url):
    checks = [
        check_https,
        check_length,
        check_at_symbol,
        check_dots,
        check_hyphens,
        check_suspicious_words,
        check_lookalike_brands,
    ]

    total_score = 0
    reasons = []

    for check_function in checks:
        points, reason = check_function(url)
        total_score += points
        if reason:
            reasons.append(reason)

    total_score = min(total_score, 100)

    if total_score >= 60:
        risk_level = "High"
    elif total_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "score": total_score,
        "risk_level": risk_level,
        "reasons": reasons
    }


# ---- test prints ----
test_urls = [
    "https://www.royalbank.com",
    "http://fake-bank-login.com",
    "https://rbc-secure-login-verify.com",
    "https://ucalgary-verify-account-urgent.com",
    "https://www.google.com",
]

for url in test_urls:
    result = calculate_score(url)
    print(f"\nURL: {url}")
    print(f"Score: {result['score']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons: {result['reasons']}")