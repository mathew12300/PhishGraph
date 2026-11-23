"""
Brand impersonation and typosquatting detection engine for PhishGraph.
Detects targeted spoofing of high-value brands using Jaro-Winkler and Levenshtein metrics.
"""

import re
import urllib.parse
from typing import Dict, List, Any, Optional


TOP_TARGETED_BRANDS = [
    {"name": "PayPal", "domain": "paypal.com", "keywords": ["paypal"], "category": "Fintech / Payment"},
    {"name": "Microsoft", "domain": "microsoft.com", "keywords": ["microsoft", "office365", "outlook", "azure", "onedrive"], "category": "Enterprise / Cloud"},
    {"name": "Google", "domain": "google.com", "keywords": ["google", "gmail", "googlemail", "gsuite"], "category": "Cloud / Identity"},
    {"name": "Apple", "domain": "apple.com", "keywords": ["apple", "icloud", "appleid", "itunes"], "category": "Ecosystem / Hardware"},
    {"name": "Amazon", "domain": "amazon.com", "keywords": ["amazon", "prime", "aws", "amazonpay"], "category": "E-Commerce / Cloud"},
    {"name": "Netflix", "domain": "netflix.com", "keywords": ["netflix", "nflx"], "category": "Streaming Media"},
    {"name": "Chase Bank", "domain": "chase.com", "keywords": ["chase", "chasebank"], "category": "Banking / Finance"},
    {"name": "Bank of America", "domain": "bankofamerica.com", "keywords": ["bankofamerica", "bofa"], "category": "Banking / Finance"},
    {"name": "Wells Fargo", "domain": "wellsfargo.com", "keywords": ["wellsfargo"], "category": "Banking / Finance"},
    {"name": "Meta / Facebook", "domain": "facebook.com", "keywords": ["facebook", "instagram", "whatsapp"], "category": "Social Media"},
    {"name": "Binance", "domain": "binance.com", "keywords": ["binance"], "category": "Cryptocurrency"},
    {"name": "Coinbase", "domain": "coinbase.com", "keywords": ["coinbase"], "category": "Cryptocurrency"},
    {"name": "Steam / Valve", "domain": "steampowered.com", "keywords": ["steam", "steampowered", "steamcommunity"], "category": "Gaming"},
    {"name": "DHL Express", "domain": "dhl.com", "keywords": ["dhl"], "category": "Logistics / Shipping"},
    {"name": "FedEx", "domain": "fedex.com", "keywords": ["fedex"], "category": "Logistics / Shipping"},
    {"name": "Dropbox", "domain": "dropbox.com", "keywords": ["dropbox"], "category": "Cloud Storage"},
    {"name": "Adobe", "domain": "adobe.com", "keywords": ["adobe", "adobesign", "acrobat"], "category": "Enterprise Software"},
    {"name": "LinkedIn", "domain": "linkedin.com", "keywords": ["linkedin"], "category": "Social / Professional"},
    {"name": "eBay", "domain": "ebay.com", "keywords": ["ebay"], "category": "E-Commerce"},
    {"name": "Spotify", "domain": "spotify.com", "keywords": ["spotify"], "category": "Media / Music"}
]

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '8': 'b', '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm', 'cl': 'd'
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates classic Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Computes Jaro-Winkler similarity giving weight to common prefixes."""
    if s1 == s2:
        return 1.0

    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    max_dist = (max(len1, len2) // 2) - 1
    match1 = [False] * len1
    match2 = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - max_dist)
        end = min(i + max_dist + 1, len2)
        for j in range(start, end):
            if match2[j] or s1[i] != s2[j]:
                continue
            match1[i] = True
            match2[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    t = 0
    k = 0
    for i in range(len1):
        if not match1[i]:
            continue
        while not match2[k]:
            k += 1
        if s1[i] != s2[k]:
            t += 1
        k += 1
    transpositions = t / 2

    jaro = (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0

    # Winkler prefix bonus (up to 4 characters)
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return round(jaro + prefix * 0.1 * (1.0 - jaro), 4)


def normalize_leet(text: str) -> str:
    """Replaces common leet / homoglyph characters with their standard ASCII letters."""
    norm = text.lower()
    for k, v in HOMOGLYPH_MAP.items():
        norm = norm.replace(k, v)
    return norm


def analyze_brand_impersonation(raw_url: str) -> Dict[str, Any]:
    """
    Examines an input URL against top targeted brands to identify typosquatting,
    homoglyphs, and unauthorized brand token containment.
    """
    raw = raw_url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw):
        raw = 'https://' + raw
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or parsed.netloc or '').lower()
    path = parsed.path.lower()
    full_str = f"{host}{path}"

    host_parts = host.split('.')
    # Collect all tokens from host labels and hyphen splits
    tokens_to_test = set(host_parts)
    for part in host_parts:
        for subtoken in part.split('-'):
            if len(subtoken) >= 3:
                tokens_to_test.add(subtoken)
    if len(host_parts) >= 2:
        tokens_to_test.add(host_parts[-2])

    matches = []
    for brand in TOP_TARGETED_BRANDS:
        b_name = brand['name']
        official_domain = brand['domain']

        # Is this the actual official domain?
        is_legitimate = (host == official_domain or host.endswith(f".{official_domain}"))

        # Check each keyword
        for kw in brand['keywords']:
            # Exact containment in subdomains or path when host is NOT legitimate
            if not is_legitimate and kw in full_str:
                containment_location = "Host / Subdomain" if kw in host else "URL Path"
                matches.append({
                    "brand": b_name,
                    "official_domain": official_domain,
                    "category": brand['category'],
                    "tactic": f"Unauthorized Keyword Containment ({containment_location})",
                    "similarity": 0.95,
                    "target_token": kw,
                    "severity": "Critical",
                    "explanation": f"The brand keyword '{kw}' appears on an unauthorized non-{official_domain} host."
                })
                break

            # Test typosquatting / Jaro-Winkler similarity on all candidate tokens
            if not is_legitimate:
                token_matched = False
                for token in tokens_to_test:
                    norm_token = normalize_leet(token)
                    sim = jaro_winkler_similarity(norm_token, kw)
                    lev = levenshtein_distance(token, kw)

                    if (sim >= 0.82 or (lev <= 2 and len(kw) >= 4)) and token != kw:
                        matches.append({
                            "brand": b_name,
                            "official_domain": official_domain,
                            "category": brand['category'],
                            "tactic": "Typosquatting / Visual Distance",
                            "similarity": round(sim, 3),
                            "target_token": kw,
                            "severity": "Critical" if sim >= 0.88 else "Suspicious",
                            "explanation": f"Host token '{token}' has a Jaro-Winkler similarity of {sim*100:.1f}% to official brand token '{kw}' (Edit distance: {lev})."
                        })
                        token_matched = True
                        break
                if token_matched:
                    break

    # Deduplicate matches by brand
    unique_matches = {}
    for m in matches:
        b = m['brand']
        if b not in unique_matches or m['similarity'] > unique_matches[b]['similarity']:
            unique_matches[b] = m

    ranked = sorted(unique_matches.values(), key=lambda x: x['similarity'], reverse=True)

    is_impersonating = len(ranked) > 0
    top_match = ranked[0] if ranked else None

    return {
        "url": raw_url,
        "host": host,
        "is_impersonating": is_impersonating,
        "impersonation_score": round(top_match['similarity'] * 100, 1) if top_match else 0.0,
        "top_brand": top_match['brand'] if top_match else None,
        "top_category": top_match['category'] if top_match else None,
        "official_domain": top_match['official_domain'] if top_match else None,
        "risk_rating": top_match['severity'] if top_match else "No Brand Threat Detected",
        "matches_count": len(ranked),
        "matches": ranked
    }
