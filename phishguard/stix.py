"""
OASIS STIX 2.1 and OpenIOC threat intelligence exporter for PhishGraph.
Produces standardized cyber threat intelligence (CTI) packages for enterprise SOC ingestion.
"""

import datetime
import json
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, List, Any


def generate_stix21_bundle(scan_records: List[Dict[str, Any]], bundle_title: str = "PhishGraph Threat Intelligence Feed") -> Dict[str, Any]:
    """
    Generates a valid OASIS STIX 2.1 JSON bundle representing phishing indicators,
    cyber observables, and MITRE ATT&CK kill chain mappings.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    objects = []

    # 1. Identity Object (PhishGraph Research Engine)
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'phishgraph.security.local')}"
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "PhishGraph Graph-ML Threat Intelligence Engine",
        "identity_class": "system",
        "sectors": ["technology", "cybersecurity"]
    }
    objects.append(identity_obj)

    # 2. Indicators & Observables for High & Review items
    for item in scan_records:
        host = item.get('host', 'unknown.test')
        risk = item.get('risk_score', 0)
        verdict = item.get('verdict', 'Review needed')

        indicator_id = f"indicator--{uuid.uuid4()}"
        confidence = int(min(100, max(10, risk)))

        pattern = f"[url:value LIKE '%{host}%']"

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Phishing Domain Indicator: {host}",
            "description": f"PhishGraph composite risk index of {risk:.1f}/100. Graph proximity: {item.get('graph_score', 0):.1f}%, Lexical warning score: {item.get('lexical_score', 0):.1f}%.",
            "indicator_types": ["malicious-activity", "attribution"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now_iso,
            "confidence": confidence,
            "created_by_ref": identity_id,
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                },
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "reconnaissance"
                }
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1566.002",
                    "description": "Phishing: Spearphishing Link"
                },
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1583.001",
                    "description": "Acquire Infrastructure: Domains"
                }
            ]
        }
        objects.append(indicator_obj)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
    return bundle


def generate_openioc_xml(scan_records: List[Dict[str, Any]]) -> str:
    """
    Generates standard Mandiant OpenIOC 1.1 XML package for firewall and EDR import.
    """
    ioc_id = str(uuid.uuid4())
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    root = ET.Element("ioc", {
        "id": ioc_id,
        "last-modified": now_iso,
        "xmlns": "http://schemas.mandiant.com/2010/ioc"
    })

    short_desc = ET.SubElement(root, "short_description")
    short_desc.text = "PhishGraph Phishing Domain IOC Blocklist"

    desc = ET.SubElement(root, "description")
    desc.text = "Automated OpenIOC feed synthesized by PhishGraph Graph ML & Fuzzy Logic Detection Engine."

    authored_by = ET.SubElement(root, "authored_by")
    authored_by.text = "PhishGraph Cybersecurity Lab"

    definition = ET.SubElement(root, "definition")
    indicator = ET.SubElement(definition, "Indicator", {"operator": "OR", "id": str(uuid.uuid4())})

    for item in scan_records:
        host = item.get('host', '')
        if not host:
            continue
        ind_item = ET.SubElement(indicator, "IndicatorItem", {"id": str(uuid.uuid4()), "condition": "contains"})
        context = ET.SubElement(ind_item, "Context", {"document": "UrlHistory", "search": "UrlHistory/URI"})
        content = ET.SubElement(ind_item, "Content", {"type": "string"})
        content.text = host
        comment = ET.SubElement(ind_item, "Comment")
        comment.text = f"Risk Score: {item.get('risk_score', 0):.1f}/100, Verdict: {item.get('verdict', 'Unknown')}"

    return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode('utf-8')
