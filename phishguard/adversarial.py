"""
Adversarial attack simulation and robustness evaluation engine for PhishGraph.
Evaluates graph ML and fuzzy logic resilience against evasion mutations.
"""

import re
import urllib.parse
from typing import Dict, List, Any


EVASION_TACTICS = [
    {
        "id": "subdomain_padding",
        "name": "Subdomain Camouflage",
        "description": "Prepends trust tokens as subdomains (e.g. login.secure.verify.cdn)",
        "category": "Structural Obfuscation"
    },
    {
        "id": "hyphen_fragmentation",
        "name": "Hyphen Fragmentation",
        "description": "Splits brand tokens using hyphens to evade exact string matching (e.g. ac-count-re-set)",
        "category": "Lexical Evasion"
    },
    {
        "id": "homoglyph_typo",
        "name": "Typosquatting & Leet Mutation",
        "description": "Replaces standard ASCII characters with lookalike visual digits (e.g. o->0, l->1, e->3)",
        "category": "Visual Deception"
    },
    {
        "id": "userinfo_spoofing",
        "name": "RFC Userinfo Confusion",
        "description": "Embeds a reputable brand before an @ symbol so casual readers overlook the true host",
        "category": "Protocol Misdirection"
    },
    {
        "id": "path_padding",
        "name": "Deep Deceptive Path Chaining",
        "description": "Appends legitimate-looking API / OAuth verification paths to skew path length heuristics",
        "category": "Path Camouflage"
    },
    {
        "id": "suspicious_tld_swap",
        "name": "Abusive TLD Substitution",
        "description": "Swaps benign TLDs for high-abuse top-level domains (e.g. .top, .xyz, .click, .tk)",
        "category": "Infrastructure Repositioning"
    }
]


def mutate_url(raw_url: str, tactic_id: str) -> str:
    """Applies an adversarial perturbation tactic to an input URL."""
    raw = raw_url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw):
        raw = 'https://' + raw
    parsed = urllib.parse.urlsplit(raw)
    host = parsed.hostname or parsed.netloc or 'example.test'
    scheme = parsed.scheme or 'https'
    path = parsed.path or '/'
    query = f"?{parsed.query}" if parsed.query else ""

    if tactic_id == "subdomain_padding":
        mutated_host = f"login.secure-auth.cdn.{host}"
        return f"{scheme}://{mutated_host}{path}{query}"

    elif tactic_id == "hyphen_fragmentation":
        parts = host.split('.')
        if len(parts) >= 2:
            domain_name = parts[-2]
            # Insert hyphens
            if len(domain_name) > 4:
                domain_name = domain_name[:2] + '-' + domain_name[2:4] + '-' + domain_name[4:]
            else:
                domain_name = '-'.join(list(domain_name))
            parts[-2] = domain_name
            mutated_host = '.'.join(parts)
        else:
            mutated_host = f"{host}-secure-verify"
        return f"{scheme}://{mutated_host}{path}{query}"

    elif tactic_id == "homoglyph_typo":
        table = {'o': '0', 'l': '1', 'e': '3', 'i': '1', 'a': '4'}
        parts = host.split('.')
        if len(parts) >= 2:
            target = list(parts[-2])
            for idx, ch in enumerate(target):
                if ch.lower() in table:
                    target[idx] = table[ch.lower()]
                    break  # Replace first match
            parts[-2] = "".join(target)
            mutated_host = '.'.join(parts)
        else:
            mutated_host = host.replace('o', '0').replace('l', '1')
        return f"{scheme}://{mutated_host}{path}{query}"

    elif tactic_id == "userinfo_spoofing":
        return f"{scheme}://trusted-security-portal.account.verify@{host}{path}{query}"

    elif tactic_id == "path_padding":
        extended_path = "/oauth2/v1/authorize/session/token/identity-challenge/confirm"
        return f"{scheme}://{host}{extended_path}{query}"

    elif tactic_id == "suspicious_tld_swap":
        parts = host.split('.')
        if len(parts) >= 2:
            parts[-1] = "top"  # Swap to high abuse TLD
            mutated_host = '.'.join(parts)
        else:
            mutated_host = f"{host}.xyz"
        return f"{scheme}://{mutated_host}{path}{query}"

    return raw


def evaluate_adversarial_robustness(detector, original_url: str) -> Dict[str, Any]:
    """
    Evaluates detector performance across 6 adversarial mutations.
    Calculates perturbation resilience, delta shifts, and evasion detection status.
    """
    baseline = detector.predict(original_url)
    baseline_risk = baseline['risk_score']

    simulations = []
    shifts = []

    for tactic in EVASION_TACTICS:
        mutated = mutate_url(original_url, tactic['id'])
        pred = detector.predict(mutated)
        mutated_risk = pred['risk_score']
        delta = round(mutated_risk - baseline_risk, 2)
        shifts.append(abs(delta))

        # Check evasion status
        # If baseline was phishing (High risk) and mutated drops to Low, evasion succeeded
        # If baseline was Benign and mutated increases, detector successfully caught added warning signals
        if baseline['verdict'] == 'High risk':
            if pred['verdict'] == 'Low risk':
                resilience_status = 'Evasion Succeeded (Model Fooled)'
                caught = False
            elif pred['verdict'] == 'Review needed':
                resilience_status = 'Partial Evasion (Degraded to Review)'
                caught = True
            else:
                resilience_status = 'Defense Upheld (Threat Blocked)'
                caught = True
        else:
            if mutated_risk > baseline_risk + 15:
                resilience_status = 'Anomaly Detected (Flagged Mutation)'
                caught = True
            else:
                resilience_status = 'Robust Invariance (Stable Baseline)'
                caught = True

        simulations.append({
            'tactic_id': tactic['id'],
            'tactic_name': tactic['name'],
            'category': tactic['category'],
            'description': tactic['description'],
            'mutated_url': mutated,
            'mutated_host': pred['host'],
            'original_risk': baseline_risk,
            'mutated_risk': mutated_risk,
            'delta_shift': delta,
            'original_verdict': baseline['verdict'],
            'mutated_verdict': pred['verdict'],
            'caught': caught,
            'resilience_status': resilience_status,
            'graph_score': pred['graph_score'],
            'lexical_score': pred['lexical_score']
        })

    mean_shift = sum(shifts) / max(1, len(shifts))
    caught_count = sum(1 for s in simulations if s['caught'])
    # Resilience index: higher when defenses uphold verdict without erratic swings
    resilience_score = round(max(0, min(100, 100 - (mean_shift * 0.75) + (caught_count / len(simulations) * 25))), 1)

    return {
        'original_url': original_url,
        'baseline_risk': baseline_risk,
        'baseline_verdict': baseline['verdict'],
        'resilience_score': resilience_score,
        'defense_rating': 'High Resilience' if resilience_score >= 80 else ('Moderate Resilience' if resilience_score >= 55 else 'Vulnerable to Evasion'),
        'evasion_caught_ratio': f"{caught_count}/{len(simulations)}",
        'mean_absolute_shift': round(mean_shift, 2),
        'simulations': simulations
    }
