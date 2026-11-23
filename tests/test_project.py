import csv
import io
import tempfile
import unittest
from pathlib import Path
import numpy as np
from app import create_app
from generate_demo import generate
from train import load_rows, train
from phishguard.database import init_db, insert_scan, query_history
from phishguard.datasets import validate_and_register_dataset
from phishguard.features import extract, parse_url
from phishguard.fuzzy import infer, membership, get_fuzzy_curves
from phishguard.model import Detector
from phishguard.reports import sanitize_csv_cell, export_batch_csv, generate_single_pdf_report, generate_batch_pdf_report
from phishguard.trainer import ExperimentManager

class ProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.csv = generate(cls.root / 'demo.csv')
        cls.report = train(cls.csv, cls.root / 'models', demo=True)
        cls.model = Detector.load(cls.root / 'models/detector.joblib')
        cls.db_path = cls.root / 'history.db'
        cls.client = create_app(cls.model, cls.db_path).test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_validation(self):
        for value in [None, '', 'javascript:alert(1)', 'ftp://example.com', 'https://',
                      'https://bad host.test', 'https://x.test:99999', 'https://-bad.test',
                      'https://example.test\\@evil.test', 'a'*2049]:
            with self.subTest(value=value), self.assertRaises(ValueError): parse_url(value)
        self.assertEqual(parse_url('EXAMPLE.com')[1], 'example.com')
        self.assertEqual(parse_url('https://[::1]/')[1], '::1')
        self.assertEqual(extract('https://trusted.test@evil.test')['at_sign'], 1)
        self.assertEqual(extract('http://192.0.2.1')['ip_host'], 1)
        self.assertEqual(extract('https://xn--bcher-kva.test')['punycode'], 1)

    def test_fuzzy_coverage_and_monotonicity(self):
        for x in np.linspace(0, 1, 21):
            self.assertAlmostEqual(sum(membership(x)), 1)
            scores = [infer(x, y)[0] for y in np.linspace(0, 1, 21)]
            self.assertTrue(all(0 <= s <= 1 for s in scores))
            self.assertTrue(all(a <= b + 1e-10 for a,b in zip(scores, scores[1:])))
        self.assertLess(infer(0, 0)[0], infer(1, 1)[0])

    def test_split_and_artifact(self):
        from sklearn.model_selection import GroupShuffleSplit
        urls, labels, groups = load_rows(self.csv)
        a,b = next(GroupShuffleSplit(n_splits=1,test_size=.25,random_state=42).split(urls,labels,groups))
        self.assertFalse(set(groups[i] for i in a) & set(groups[i] for i in b))
        self.assertEqual(self.model.x.shape[0], len(a))
        self.assertEqual(set(self.model.visible_y), {-1,0,1})
        self.assertEqual(set(self.model.hosts), set(groups[i] for i in a))
        r = self.model.predict('https://example.test')
        self.assertTrue(0 <= r['risk_score'] <= 100)
        self.assertTrue(r['demo'])

    def test_input_conflicts(self):
        path = self.root / 'bad.csv'
        path.write_text('url,label\nhttps://x.test,0\nhttps://x.test,1\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Conflicting'): load_rows(path)

    def test_api_and_privacy(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        with self.client.get('/static/app.js') as response:
            self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/predict', json={'url':'https://user:secret@privacy.test/private?token=secret'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('risk_score', response.json)
        self.assertNotIn('secret', response.get_data(as_text=True))
        history = self.client.get('/api/history').get_data(as_text=True)
        self.assertNotIn('secret', history)
        self.assertNotIn('/private', history)
        self.assertIn('privacy.test', history)
        self.assertEqual(self.client.post('/api/predict', json=[]).status_code, 400)
        self.assertEqual(self.client.post('/api/predict', json={'url':None}).status_code, 400)
        self.assertEqual(self.client.post('/api/predict', json={'url':'x'*40000}).status_code, 413)
        self.assertEqual(self.client.delete('/api/history').status_code, 415)
        self.assertEqual(self.client.delete('/api/history', json={}).status_code, 200)
        self.assertEqual(self.client.get('/api/history').json, [])

    # =========================================================================
    # UPGRADE FEATURE TESTS
    # =========================================================================

    def test_batch_prediction_api(self):
        urls = [
            'https://cedar1.test/catalog/item/1',
            'http://secure-verify-1.wallet.account.test/login',
            'ftp://invalid.test/url',
            'https://cedar1.test/catalog/item/1' # Duplicate
        ]
        res = self.client.post('/api/predict/batch', json={'urls': urls})
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertEqual(data['total_valid'], 2) # 2 unique valid URLs
        self.assertEqual(data['total_errors'], 1) # 1 ftp error
        self.assertEqual(len(data['items']), 2)

    def test_formula_injection_and_csv_export(self):
        # Formula injection mitigation
        self.assertEqual(sanitize_csv_cell('=1+1'), "'=1+1")
        self.assertEqual(sanitize_csv_cell('@SUM(1,2)'), "'@SUM(1,2)")
        self.assertEqual(sanitize_csv_cell('-cmd|'), "'-cmd|")
        self.assertEqual(sanitize_csv_cell('+123'), "'+123")
        self.assertEqual(sanitize_csv_cell('https://example.com'), 'https://example.com')

        # Batch CSV export endpoint
        items = [{
            'url': '=cmd',
            'host': 'evil.test',
            'risk_score': 85.5,
            'verdict': 'High risk',
            'graph_score': 80.0,
            'lexical_score': 90.0,
            'signals': [{'signal': 'Keywords', 'weight': 0.2}]
        }]
        res = self.client.post('/api/export/batch/csv', json={'items': items})
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment; filename=", res.headers['Content-Disposition'])
        text = res.data.decode('utf-8-sig')
        self.assertIn("'=cmd", text)

    def test_pure_python_pdf_generation(self):
        sample = {
            'host': 'secure-bank.test',
            'risk_score': 78.5,
            'verdict': 'High risk',
            'graph_score': 75.0,
            'lexical_score': 82.0,
            'signals': [{'signal': 'Keywords', 'weight': 0.2}],
            'model_version': 'v1-demo',
            'demo': True,
            'neighbors': [{'host': 'seed.test', 'distance': 2.1, 'similarity': 0.7, 'seed_status': 'Phishing Seed', 'spread_score': 0.9}]
        }
        single_pdf = generate_single_pdf_report(sample)
        self.assertTrue(single_pdf.startswith(b'%PDF-1.4'))
        self.assertTrue(b'%%EOF' in single_pdf)

        batch_pdf = generate_batch_pdf_report({}, [sample])
        self.assertTrue(batch_pdf.startswith(b'%PDF-1.4'))
        self.assertTrue(b'%%EOF' in batch_pdf)

    def test_fuzzy_playground_endpoints(self):
        res = self.client.get('/api/fuzzy/playground')
        self.assertEqual(res.status_code, 200)
        self.assertIn('curves', res.json)
        self.assertEqual(len(res.json['curves']['x']), 50)

        # Simulation
        res2 = self.client.get('/api/fuzzy/simulate?graph=0.8&lexical=0.8')
        self.assertEqual(res2.status_code, 200)
        self.assertGreaterEqual(res2.json['risk_score'], 65.0)
        self.assertEqual(res2.json['verdict'], 'High risk')

    def test_dataset_validation(self):
        datasets_dir = self.root / 'datasets'
        # Valid CSV
        valid_csv = 'url,label\n' + '\n'.join([f'https://host{i}.test/page,0' for i in range(25)]) + '\n' + \
                    '\n'.join([f'https://phish{i}.test/login,1' for i in range(25)])
        meta = validate_and_register_dataset(valid_csv.encode('utf-8'), 'test.csv', datasets_dir)
        self.assertEqual(meta['unique_valid_urls'], 50)
        self.assertEqual(meta['class_distribution']['benign_count'], 25)

        # Empty / malformed CSV
        with self.assertRaises(ValueError):
            validate_and_register_dataset(b'invalid,columns\n1,2', 'bad.csv', datasets_dir)

    def test_searchable_history_and_pagination(self):
        from phishguard.database import clear_all_history
        clear_all_history(self.db_path)
        # Insert test records
        insert_scan(self.db_path, host='test-alpha.com', risk=20.0, verdict='Low risk')
        insert_scan(self.db_path, host='test-beta.com', risk=85.0, verdict='High risk')

        # Query with filter
        q_res = query_history(self.db_path, query='alpha', page=1, per_page=10)
        self.assertEqual(q_res['total'], 1)
        self.assertEqual(q_res['items'][0]['host'], 'test-alpha.com')

        # Verdict filter
        v_res = query_history(self.db_path, verdict_filter='High risk')
        self.assertEqual(v_res['total'], 1)
        self.assertEqual(v_res['items'][0]['host'], 'test-beta.com')

if __name__ == '__main__':
    unittest.main()
