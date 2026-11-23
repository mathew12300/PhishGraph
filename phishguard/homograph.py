"""
Internationalized Domain Name (IDN) homograph and Punycode confusable detector for PhishGraph.
Analyzes cross-script character substitutions (e.g., Cyrillic/Greek lookalikes).
"""

import unicodedata
import urllib.parse
from typing import Dict, List, Any


# Common confusable characters mapped to Latin equivalent
CONFUSABLE_UNICODE_MAP = {
    # Cyrillic small letters
    '\u0430': {'latin': 'a', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER A'},
    '\u0441': {'latin': 'c', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER ES'},
    '\u0435': {'latin': 'e', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER IE'},
    '\u0456': {'latin': 'i', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I'},
    '\u0458': {'latin': 'j', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER JE'},
    '\u043e': {'latin': 'o', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER O'},
    '\u0440': {'latin': 'p', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER ER'},
    '\u0455': {'latin': 's', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER DZE'},
    '\u0443': {'latin': 'y', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER U'},
    '\u0445': {'latin': 'x', 'script': 'Cyrillic', 'name': 'CYRILLIC SMALL LETTER HA'},
    # Greek letters
    '\u03bf': {'latin': 'o', 'script': 'Greek', 'name': 'GREEK SMALL LETTER OMICRON'},
    '\u03bd': {'latin': 'v', 'script': 'Greek', 'name': 'GREEK SMALL LETTER NU'},
    '\u03b1': {'latin': 'a', 'script': 'Greek', 'name': 'GREEK SMALL LETTER ALPHA'},
    '\u03c1': {'latin': 'p', 'script': 'Greek', 'name': 'GREEK SMALL LETTER RHO'},
    # Mathematical / special lookalikes
    '\u2010': {'latin': '-', 'script': 'Punctuation', 'name': 'HYPHEN'},
    '\u2011': {'latin': '-', 'script': 'Punctuation', 'name': 'NON-BREAKING HYPHEN'},
    '\u2044': {'latin': '/', 'script': 'Symbol', 'name': 'FRACTION SLASH'},
}


def get_character_script(char: str) -> str:
    """Returns primary script name for a Unicode character."""
    name = unicodedata.name(char, "")
    if "CYRILLIC" in name:
        return "Cyrillic"
    elif "GREEK" in name:
        return "Greek"
    elif "LATIN" in name:
        return "Latin"
    elif "ARABIC" in name:
        return "Arabic"
    elif "HEBREW" in name:
        return "Hebrew"
    elif char.isascii() and (char.isalnum() or char in ".-_"):
        return "Latin"
    return "Other / Symbol"


def analyze_homograph_spoofing(raw_url: str) -> Dict[str, Any]:
    """
    Analyzes an input URL or domain for Punycode encoding, mixed-script labels,
    and confusable visual homoglyphs.
    """
    raw = raw_url.strip()
    if not (raw.startswith("http://") or raw.startswith("https://")):
        raw = "https://" + raw

    parsed = urllib.parse.urlsplit(raw)
    host = parsed.hostname or parsed.netloc or ""

    is_punycode = "xn--" in host.lower()
    decoded_host = host
    if is_punycode:
        try:
            # Decode Punycode to native Unicode
            decoded_host = host.encode('ascii').decode('idna')
        except Exception:
            decoded_host = host

    labels = decoded_host.split('.')
    flagged_chars = []
    scripts_observed = set()
    canonical_latin = []

    for label_idx, label in enumerate(labels):
        label_scripts = set()
        for char_idx, ch in enumerate(label):
            script = get_character_script(ch)
            scripts_observed.add(script)
            label_scripts.add(script)

            code_point = f"U+{ord(ch):04X}"
            if ch in CONFUSABLE_UNICODE_MAP:
                conf_info = CONFUSABLE_UNICODE_MAP[ch]
                flagged_chars.append({
                    "char": ch,
                    "code_point": code_point,
                    "script": conf_info['script'],
                    "unicode_name": conf_info['name'],
                    "confusable_with": conf_info['latin'],
                    "label": label,
                    "position": char_idx
                })
                canonical_latin.append(conf_info['latin'])
            else:
                canonical_latin.append(ch)
        if label_idx < len(labels) - 1:
            canonical_latin.append('.')

    canonical_domain = "".join(canonical_latin)

    # Mixed script detection: when a label mixes Latin with non-Latin scripts
    has_mixed_script = len(scripts_observed.intersection({'Cyrillic', 'Greek', 'Arabic', 'Hebrew'})) > 0 and 'Latin' in scripts_observed
    has_homoglyphs = len(flagged_chars) > 0

    if has_homoglyphs or (is_punycode and has_mixed_script):
        threat_level = "High Threat (Homograph Spoof Confirmed)"
    elif is_punycode:
        threat_level = "Suspicious (IDN Punycode Encoding)"
    else:
        threat_level = "Clean (Pure ASCII / Standard Script)"

    return {
        "original_host": host,
        "is_punycode": is_punycode,
        "decoded_host": decoded_host,
        "canonical_latin_target": canonical_domain,
        "has_mixed_script": has_mixed_script,
        "scripts_observed": sorted(list(scripts_observed)),
        "has_homoglyphs": has_homoglyphs,
        "homoglyph_count": len(flagged_chars),
        "threat_level": threat_level,
        "flagged_characters": flagged_chars,
        "summary": (
            f"Detected {len(flagged_chars)} confusable characters mimicking '{canonical_domain}'."
            if has_homoglyphs else
            ("Standard Latin domain without cross-script homoglyphs." if not is_punycode else "Punycode encoded international domain.")
        )
    }
