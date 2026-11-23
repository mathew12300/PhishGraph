"""Deterministic URL features. No network requests or DNS lookups."""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit, unquote

NAMES = ['url_length', 'host_length', 'dots', 'hyphens', 'digit_ratio',
         'path_depth', 'query_length', 'at_sign', 'ip_host', 'http',
         'punycode', 'keywords', 'percent_count', 'host_entropy', 'nonstandard_port']
KEYWORDS = ('login', 'verify', 'secure', 'account', 'update', 'password', 'wallet', 'bank')

FEATURE_INFO = {
    'url_length': {
        'title': 'URL Length',
        'desc': 'Total character count of the full canonical URL string.',
        'rationale': 'Phishing URLs frequently use obfuscated paths, subdomains, and embedded tracking parameters that lengthen the overall URL.'
    },
    'host_length': {
        'title': 'Host Length',
        'desc': 'Character count of the normalized fully-qualified hostname.',
        'rationale': 'Long hostnames often conceal suspicious subdomains or multiple concatenated brand names.'
    },
    'dots': {
        'title': 'Subdomain Dots Count',
        'desc': 'Number of period delimiters contained in the hostname.',
        'rationale': 'Excessive subdomains (e.g., login.bank.secure.example.com) are commonly used to mimic legitimate organization domains.'
    },
    'hyphens': {
        'title': 'Hostname Hyphens',
        'desc': 'Count of hyphen characters in the hostname.',
        'rationale': 'Attackers use hyphenated brand names (e.g., paypal-verification) to evade domain uniqueness checks while misleading users.'
    },
    'digit_ratio': {
        'title': 'Digit Ratio',
        'desc': 'Proportion of numeric digits relative to total URL length.',
        'rationale': 'High numeric content is typical of auto-generated phishing kits, IP hexes, and session tokens.'
    },
    'path_depth': {
        'title': 'Path Depth',
        'desc': 'Number of hierarchical path segments separated by slashes.',
        'rationale': 'Deep directory nesting can indicate embedded phishing landing kits or disguised redirects.'
    },
    'query_length': {
        'title': 'Query Length',
        'desc': 'Character length of the query string parameter section.',
        'rationale': 'Phishing lures often encode targeted victim email addresses or base64 redirects in the URL query.'
    },
    'at_sign': {
        'title': 'Userinfo @ Delimiter',
        'desc': 'Binary indicator of credential/userinfo syntax before the actual hostname.',
        'rationale': 'The @ character instructs the browser to treat preceding text as userinfo, directing traffic to the host following the @ sign.'
    },
    'ip_host': {
        'title': 'IP Address Hostname',
        'desc': 'Binary flag: whether host is an IPv4 or IPv6 address instead of a domain.',
        'rationale': 'Legitimate public services rarely present bare IP addresses to consumers due to lack of trusted TLS and branding.'
    },
    'http': {
        'title': 'Plain HTTP Scheme',
        'desc': 'Binary flag indicating unencrypted HTTP transport.',
        'rationale': 'Modern legitimate websites enforce HTTPS/TLS; however, HTTPS alone does not guarantee that a site is safe.'
    },
    'punycode': {
        'title': 'Punycode / IDN Domain',
        'desc': 'Detection of xn-- internationalized domain name prefix.',
        'rationale': 'Homograph attacks exploit lookalike Unicode characters (e.g., Cyrillic "а" instead of Latin "a") mapped via Punycode.'
    },
    'keywords': {
        'title': 'Security & Auth Keywords',
        'desc': 'Count of sensitive account and credential keywords found in URL.',
        'rationale': 'Phishing lures disproportionately target authentication workflows using words like login, verify, wallet, and update.'
    },
    'percent_count': {
        'title': 'Percent Encoding Count',
        'desc': 'Frequency of % hex-encoding sequences in the URL.',
        'rationale': 'Frequent percent-encoding is used to mask executable characters, keywords, and malicious redirect targets.'
    },
    'host_entropy': {
        'title': 'Hostname Shannon Entropy',
        'desc': 'Information-theoretic randomness of characters within the host.',
        'rationale': 'Domain Generation Algorithms (DGA) and randomized subdomains exhibit significantly higher entropy than dictionary domain names.'
    },
    'nonstandard_port': {
        'title': 'Non-standard Port',
        'desc': 'Binary flag indicating a port other than 80 (HTTP) or 443 (HTTPS).',
        'rationale': 'Phishing or rogue testing hosts often operate on unconventional listener ports (e.g. 8080, 8443, 2082).'
    }
}

def parse_url(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Enter a non-empty URL.')
    value = value.strip()
    if len(value) > 2048 or re.search(r'[\s\x00-\x1f\x7f\\]', value):
        raise ValueError('URL must be at most 2048 characters, without whitespace or backslashes.')
    if '://' not in value:
        value = 'https://' + value
    try:
        p = urlsplit(value)
        if p.scheme not in ('http', 'https') or not p.hostname:
            raise ValueError()
        host = p.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        port = p.port
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or '.' not in host or any(
                not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                for part in host.split('.')
            ):
                raise ValueError()
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ValueError('Enter a valid HTTP(S) URL with a domain or IP address.') from None
    # Retain userinfo for risk extraction, but never store it in result/history.
    netloc = ('[' + host + ']' if ':' in host else host)
    if port:
        netloc += ':' + str(port)
    if p.username is not None:
        netloc = p.netloc.rsplit('@', 1)[0] + '@' + netloc
    canonical = urlunsplit((p.scheme, netloc, p.path or '/', p.query, ''))
    return canonical, host

def extract(value):
    url, host = parse_url(value)
    p = urlsplit(url)
    try:
        ipaddress.ip_address(host)
        ip = 1
    except ValueError:
        ip = 0
    counts = Counter(host)
    entropy = -sum((n / len(host)) * math.log2(n / len(host)) for n in counts.values())
    decoded = unquote(url).lower()
    values = [len(url), len(host), host.count('.'), host.count('-'),
              sum(c.isdigit() for c in url) / len(url),
              len([x for x in p.path.split('/') if x]), len(p.query),
              int('@' in p.netloc), ip, int(p.scheme == 'http'),
              int('xn--' in host), sum(k in decoded for k in KEYWORDS),
              url.count('%'), entropy, int(p.port is not None and p.port not in (80, 443))]
    return dict(zip(NAMES, values))

def lexical_risk(features):
    """Transparent heuristics, not individually conclusive indicators."""
    f = features
    indicators = [
        ('Credentials/userinfo in URL', .30 * f['at_sign']),
        ('IP address used as host', .25 * f['ip_host']),
        ('HTTP scheme (TLS not verified)', .10 * f['http']),
        ('Internationalized/punycode hostname', .10 * f['punycode']),
        ('Many hostname separators', .15 * min(1, max(0, f['dots'] - 2) / 3)),
        ('Multiple hostname hyphens', .10 * min(1, f['hyphens'] / 3)),
        ('Account/security terms', .20 * min(1, f['keywords'] / 3)),
        ('Long URL', .10 * min(1, max(0, f['url_length'] - 75) / 150)),
        ('Nonstandard port', .10 * f['nonstandard_port']),
    ]
    return min(1., sum(v for _, v in indicators)), [
        {'signal': label, 'weight': round(v, 3)} for label, v in indicators if v > 0
    ]
