"""
Security Operations Center (SOC) alert triage and incident response playbook engine for PhishGraph.
Provides MITRE ATT&CK mapping, analyst disposition tracking, and perimeter firewall ACL generation.
"""

from typing import Dict, List, Any


MITRE_TACTICS_MAP = {
    "High risk": [
        {
            "technique_id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "mitigation": "Block domain at Secure Email Gateway (SEG) and DNS sinkhole."
        },
        {
            "technique_id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "mitigation": "Flag newly observed domain (NOD) in web proxy threat feeds."
        },
        {
            "technique_id": "T1056.003",
            "name": "Input Capture: Web Portal Credential Harvesting",
            "tactic": "Credential Access",
            "mitigation": "Enforce FIDO2 / WebAuthn phishing-resistant MFA across user accounts."
        }
    ],
    "Review needed": [
        {
            "technique_id": "T1584.004",
            "name": "Compromise Infrastructure: Server",
            "tactic": "Resource Development",
            "mitigation": "Sandbox URL and inspect SSL/TLS leaf certificate chain."
        },
        {
            "technique_id": "T1071.001",
            "name": "Web Protocols (HTTP/HTTPS Evasion)",
            "tactic": "Command and Control",
            "mitigation": "Isolate user browser via Remote Browser Isolation (RBI)."
        }
    ],
    "Low risk": [
        {
            "technique_id": "T1592",
            "name": "Gather Victim Host Information",
            "tactic": "Reconnaissance",
            "mitigation": "Passive telemetry logging; no active containment required."
        }
    ]
}


def generate_firewall_rules(host: str) -> Dict[str, str]:
    """Generates multi-vendor perimeter defense rules for blocking a threat domain."""
    safe_host = host.strip().lower()

    # 1. Suricata / Snort IDS Rule
    suricata_rule = (
        f'alert dns any any -> any any (msg:"PHISHGRAPH Suspicious Domain Lookup - {safe_host}"; '
        f'dns.query; content:"{safe_host}"; nocase; classtype:trojan-activity; sid:9000001; rev:1;)'
    )

    # 2. Linux iptables String Matching
    iptables_rule = (
        f'iptables -A FORWARD -p tcp --dport 80 -m string --string "{safe_host}" --algo bm -j DROP\n'
        f'iptables -A FORWARD -p tcp --dport 443 -m string --string "{safe_host}" --algo bm -j DROP'
    )

    # 3. Cisco IOS / ASA ACL
    cisco_rule = (
        f'access-list 101 deny tcp any host {safe_host} eq www\n'
        f'access-list 101 deny tcp any host {safe_host} eq 443\n'
        f'access-list 101 permit ip any any'
    )

    # 4. Pi-hole / DNS Sinkhole Domain format
    dns_sinkhole = f"0.0.0.0 {safe_host}"

    return {
        "suricata": suricata_rule,
        "iptables": iptables_rule,
        "cisco": cisco_rule,
        "dns_sinkhole": dns_sinkhole
    }


def get_incident_triage_pack(scan_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synthesizes an incident investigation pack for SOC analysts,
    including severity level, MITRE mappings, firewall rules, and containment checklist.
    """
    host = scan_record.get('host', 'unknown.test')
    verdict = scan_record.get('verdict', 'Low risk')
    risk_score = scan_record.get('risk_score', 0)

    mitre_list = MITRE_TACTICS_MAP.get(verdict, MITRE_TACTICS_MAP['Low risk'])
    firewall_rules = generate_firewall_rules(host)

    if verdict == 'High risk':
        priority = "P1 - Critical Containment"
        actions = [
            "Immediately apply DNS sinkhole rule across internal resolvers.",
            "Search EDR telemetry for outbound HTTP connections to this host in the last 72 hours.",
            "Reset credentials for any user who submitted authentication tokens.",
            "Submit IOC to Threat Intelligence platform (STIX/TAXII)."
        ]
    elif verdict == 'Review needed':
        priority = "P2 - Elevated Investigation"
        actions = [
            "Route traffic through Remote Browser Isolation (RBI).",
            "Inspect WHOIS registration age and passive DNS infrastructure.",
            "Verify presence of brand impersonation or homoglyphs.",
            "Escalate to tier-2 analyst if corporate login was requested."
        ]
    else:
        priority = "P4 - Informational Telemetry"
        actions = [
            "No containment needed; retain passive audit record.",
            "Monitor for reputation score degradation over 14-day window."
        ]

    return {
        "host": host,
        "priority": priority,
        "risk_score": risk_score,
        "verdict": verdict,
        "mitre_mappings": mitre_list,
        "containment_checklist": actions,
        "firewall_rules": firewall_rules
    }
