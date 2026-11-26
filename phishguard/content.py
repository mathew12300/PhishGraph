"""Safe, static Website Content Analyzer (HTML/DOM phishing indicator extraction).

Supports both offline pasted HTML inspection and optional SSRF-guarded passive
HTML fetching (no JavaScript execution, strict private-IP blocking, size & timeout caps).
"""
import ipaddress
import re
import socket
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

CONTENT_BRANDS = (
    'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix',
    'instagram', 'facebook', 'whatsapp', 'chase', 'wellsfargo',
    'bankofamerica', 'linkedin', 'dropbox', 'adobe', 'coinbase', 'binance'
)

OBFUSCATION_PATTERNS = (
    r'\beval\s*\(',
    r'\bunescape\s*\(',
    r'\batob\s*\(',
    r'String\.fromCharCode\s*\(',
    r'document\.write\s*\(\s*unescape',
)


class _PhishingHTMLParser(HTMLParser):
    """Deterministic HTML parser extracting structural phishing signals without executing scripts."""

    def __init__(self, page_host: str = ''):
        super().__init__(convert_charrefs=True)
        self.page_host = (page_host or '').lower()
        self.in_title = False
        self.title_chunks: List[str] = []
        self.in_script = False
        self.script_chunks: List[str] = []

        self.password_inputs = 0
        self.forms_count = 0
        self.external_form_actions: List[str] = []
        self.hidden_iframes = 0
        self.meta_refresh = 0
        self.total_scripts = 0
        self.external_scripts = 0
        self.right_click_disabled = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag = tag.lower()
        attr_map = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'title':
            self.in_title = True

        elif tag == 'input':
            if attr_map.get('type', '').strip().lower() == 'password':
                self.password_inputs += 1

        elif tag == 'form':
            self.forms_count += 1
            action = attr_map.get('action', '').strip()
            if action and (action.startswith('http://') or action.startswith('https://') or action.startswith('//')):
                action_url = ('https:' + action) if action.startswith('//') else action
                action_host = (urlsplit(action_url).hostname or '').lower()
                if action_host and self.page_host and not _same_registrable_domain(action_host, self.page_host):
                    self.external_form_actions.append(action_host)

        elif tag == 'iframe':
            style = attr_map.get('style', '').lower().replace(' ', '')
            width = attr_map.get('width', '').strip()
            height = attr_map.get('height', '').strip()
            if (
                'display:none' in style
                or 'visibility:hidden' in style
                or width in ('0', '0px')
                or height in ('0', '0px')
            ):
                self.hidden_iframes += 1

        elif tag == 'meta':
            if attr_map.get('http-equiv', '').strip().lower() == 'refresh':
                self.meta_refresh += 1

        elif tag == 'script':
            self.total_scripts += 1
            src = attr_map.get('src', '').strip()
            if src and (src.startswith('http://') or src.startswith('https://') or src.startswith('//')):
                src_url = ('https:' + src) if src.startswith('//') else src
                src_host = (urlsplit(src_url).hostname or '').lower()
                if src_host and self.page_host and not _same_registrable_domain(src_host, self.page_host):
                    self.external_scripts += 1
            elif not src:
                self.in_script = True

        if 'oncontextmenu' in attr_map and 'return false' in attr_map['oncontextmenu'].lower():
            self.right_click_disabled = True

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag == 'title':
            self.in_title = False
        elif tag == 'script':
            self.in_script = False

    def handle_data(self, data: str):
        if self.in_title:
            self.title_chunks.append(data)
        elif self.in_script:
            self.script_chunks.append(data)


def _same_registrable_domain(host_a: str, host_b: str) -> bool:
    """Compare approximate registrable domains (last 2 labels) for static DOM checks."""
    a_parts = host_a.strip('.').split('.')
    b_parts = host_b.strip('.').split('.')
    reg_a = '.'.join(a_parts[-2:]) if len(a_parts) >= 2 else host_a
    reg_b = '.'.join(b_parts[-2:]) if len(b_parts) >= 2 else host_b
    return reg_a == reg_b


def _is_public_ip(ip_str: str) -> bool:
    """Return True only if ip_str is a globally routable public IP address (SSRF guard)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_safe_fetch_target(url: str) -> str:
    """Validate URL scheme and resolve DNS to block SSRF against local/private networks."""
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Only public HTTP(S) URLs can be fetched for content inspection.')

    hostname = parsed.hostname.strip('.')
    if hostname.lower() in ('localhost', 'localhost.localdomain') or hostname.lower().endswith('.test') or hostname.lower().endswith('.local'):
        raise ValueError(f'Blocked non-public or reserved host "{hostname}" for SSRF protection.')

    try:
        # If literal IP, validate directly
        ipaddress.ip_address(hostname)
        if not _is_public_ip(hostname):
            raise ValueError(f'Blocked non-public IP address "{hostname}" for SSRF protection.')
    except ValueError as err:
        if 'SSRF protection' in str(err):
            raise
        # Resolve DNS and verify all returned A/AAAA records are public
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as dns_err:
            raise ValueError(f'DNS resolution failed for "{hostname}": {dns_err}') from dns_err
        if not addr_info:
            raise ValueError(f'No IP addresses resolved for "{hostname}".')
        for info in addr_info:
            resolved_ip = info[4][0]
            if not _is_public_ip(resolved_ip):
                raise ValueError(f'Blocked host "{hostname}" resolving to non-public IP {resolved_ip}.')

    return url


def fetch_html_safely(url: str, timeout: float = 5.0, max_bytes: int = 512 * 1024) -> Tuple[str, Dict[str, Any]]:
    """Fetch static HTML safely with SSRF checks, bounded timeout, and max byte cap."""
    safe_url = validate_safe_fetch_target(url)
    req = Request(
        safe_url,
        headers={
            'User-Agent': 'PhishGraph-StaticInspector/1.0 (+passive-html-only)',
            'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
        },
        method='GET'
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            validate_safe_fetch_target(final_url)
            content_type = resp.headers.get('Content-Type', '')
            raw_bytes = resp.read(max_bytes + 1)
            truncated = len(raw_bytes) > max_bytes
            if truncated:
                raw_bytes = raw_bytes[:max_bytes]
            html_text = raw_bytes.decode('utf-8', errors='replace')
            meta = {
                'status_code': getattr(resp, 'status', 200),
                'final_url': final_url,
                'content_type': content_type,
                'bytes_read': len(raw_bytes),
                'truncated': truncated,
            }
            return html_text, meta
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ValueError(f'Unable to fetch page content safely: {exc}') from exc


def analyze_html_content(html_text: str, url: str = '') -> Dict[str, Any]:
    """Extract deterministic phishing indicators from static HTML without executing JavaScript."""
    if not isinstance(html_text, str) or not html_text.strip():
        raise ValueError('Provide non-empty HTML content to analyze.')

    host = (urlsplit(url).hostname or '').lower() if url else ''
    parser = _PhishingHTMLParser(page_host=host)
    parser.feed(html_text[:512 * 1024])
    parser.close()

    title_text = ' '.join(parser.title_chunks).strip()
    title_lower = title_text.lower()
    inline_js = '\n'.join(parser.script_chunks)

    obfuscation_hits = sum(1 for pat in OBFUSCATION_PATTERNS if re.search(pat, inline_js, re.IGNORECASE))
    if re.search(r'oncontextmenu\s*=\s*["\']?\s*return\s+false', html_text, re.IGNORECASE):
        parser.right_click_disabled = True

    # Title-domain brand mismatch check
    matched_title_brands = [b for b in CONTENT_BRANDS if b in title_lower]
    title_brand_mismatch = False
    if matched_title_brands and host:
        if not any(b in host for b in matched_title_brands):
            title_brand_mismatch = True

    ext_script_ratio = (
        round(parser.external_scripts / parser.total_scripts, 3)
        if parser.total_scripts > 0 else 0.0
    )

    features = {
        'password_inputs': parser.password_inputs,
        'forms_count': parser.forms_count,
        'external_form_action': len(parser.external_form_actions),
        'hidden_iframes': parser.hidden_iframes,
        'meta_refresh': parser.meta_refresh,
        'title_brand_mismatch': int(title_brand_mismatch),
        'external_script_ratio': ext_script_ratio,
        'obfuscated_js_hits': obfuscation_hits,
        'right_click_disabled': int(parser.right_click_disabled),
    }

    signals: List[Dict[str, Any]] = []
    if parser.external_form_actions:
        signals.append({
            'signal': f'External form submission target ({", ".join(parser.external_form_actions[:2])})',
            'weight': 0.35
        })
    if title_brand_mismatch:
        signals.append({
            'signal': f'Page title mentions brand ({", ".join(matched_title_brands)}) not matching host "{host}"',
            'weight': 0.30
        })
    if parser.password_inputs > 0:
        signals.append({
            'signal': f'Credential password input field detected ({parser.password_inputs})',
            'weight': 0.15
        })
    if parser.hidden_iframes > 0:
        signals.append({
            'signal': f'Hidden iframe element detected ({parser.hidden_iframes})',
            'weight': 0.25
        })
    if parser.meta_refresh > 0:
        signals.append({
            'signal': 'HTML meta-refresh redirect detected',
            'weight': 0.15
        })
    if obfuscation_hits > 0:
        signals.append({
            'signal': f'Suspicious JS obfuscation patterns ({obfuscation_hits})',
            'weight': 0.20
        })
    if ext_script_ratio >= 0.7 and parser.total_scripts >= 2:
        signals.append({
            'signal': f'High external script ratio ({ext_script_ratio:.0%})',
            'weight': 0.10
        })
    if parser.right_click_disabled:
        signals.append({
            'signal': 'Right-click context menu disabled',
            'weight': 0.10
        })

    content_risk = min(1.0, sum(s['weight'] for s in signals))
    verdict_label = 'High risk' if content_risk >= 0.65 else ('Review needed' if content_risk >= 0.35 else 'Low risk')

    return {
        'host': host or 'pasted-html',
        'page_title': title_text[:120] or '(No <title> found)',
        'content_risk_score': round(content_risk * 100, 2),
        'content_verdict': verdict_label,
        'features': features,
        'signals': signals,
        'matched_title_brands': matched_title_brands,
    }
