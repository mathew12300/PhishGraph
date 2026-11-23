import hashlib
import hmac
import io
import json
import time
from pathlib import Path
from flask import Flask, abort, jsonify, render_template, request, Response, send_file
from werkzeug.exceptions import HTTPException

from phishguard.adversarial import evaluate_adversarial_robustness
from phishguard.brand import analyze_brand_impersonation
from phishguard.homograph import analyze_homograph_spoofing
from phishguard.graph_analytics import compute_spectral_graph_metrics
from phishguard.clustering import cluster_campaign_urls
from phishguard.stix import generate_stix21_bundle, generate_openioc_xml
from phishguard.soc import get_incident_triage_pack, generate_firewall_rules
from phishguard.database import (
    init_db, insert_scan, query_history, get_scan_by_id,
    clear_all_history, delete_scan_record, update_scan_triage, get_triage_queue
)
from phishguard.datasets import validate_and_register_dataset, list_datasets
from phishguard.features import FEATURE_INFO, parse_url
from phishguard.fuzzy import (
    infer, get_fuzzy_curves, verdict, get_active_profile, set_active_consequents, PRESET_PROFILES
)
from phishguard.model import Detector
from phishguard.reports import export_batch_csv, generate_single_pdf_report, generate_batch_pdf_report
from phishguard.trainer import ExperimentManager

ROOT = Path(__file__).resolve().parent

class AppState:
    def __init__(self, model=None, root=ROOT):
        self.root = root
        self.detector = model
        self.exp_mgr = ExperimentManager(root)
        if self.detector is None and (self.root / 'artifacts/detector.joblib').exists():
            try:
                self.detector = Detector.load(self.root / 'artifacts/detector.joblib')
            except Exception:
                self.detector = None

def create_app(model=None, database=None):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max for dataset uploads
    
    db_path = Path(database) if database else ROOT / 'instance/history.sqlite3'
    init_db(db_path)
    state = AppState(model=model, root=ROOT)

    @app.after_request
    def headers(response):
        # Local, strict CSP headers
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    # -------------------------------------------------------------
    # WEB UI PAGES
    # -------------------------------------------------------------
    @app.get('/')
    def home():
        return render_template('index.html')

    @app.get('/report/single/<int:scan_id>')
    def report_view(scan_id):
        scan = get_scan_by_id(db_path, scan_id)
        if not scan:
            abort(404, description='Scan record not found.')
        return render_template('report.html', scan=scan, is_batch=False)

    # -------------------------------------------------------------
    # SYSTEM STATUS & METRICS
    # -------------------------------------------------------------
    @app.get('/api/health')
    def health():
        det = state.detector
        active_info = state.exp_mgr.get_active_model_info()
        return jsonify({
            'status': 'ready' if det else 'model_missing',
            'demo': det.demo if det else None,
            'model_version': getattr(det, 'version', 'v1-demo') if det else 'None',
            'active_info': active_info
        })

    @app.get('/api/metrics')
    def metrics():
        path = ROOT / 'artifacts/metrics.json'
        if not path.exists():
            return jsonify(error='Train a model to generate evaluation metrics.'), 404
        return jsonify(json.loads(path.read_text(encoding='utf-8')))

    # -------------------------------------------------------------
    # SINGLE & BATCH PREDICTION
    # -------------------------------------------------------------
    @app.post('/api/predict')
    def predict():
        # Enforce 32KB limit on single predict endpoint
        if request.content_length and request.content_length > 32 * 1024:
            abort(413, description='Request payload exceeds 32KB limit.')

        if state.detector is None:
            return jsonify(error='Model missing. Run python train.py --demo, then restart the app.'), 503
        
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error='Send a JSON object with a url field.'), 400
        
        url_val = body.get('url')
        try:
            result = state.detector.predict(url_val)
        except ValueError as error:
            return jsonify(error=str(error)), 400

        # Save to SQLite (sanitized: only host, scores, verdict, signals, features - no creds/query/path)
        scan_id = insert_scan(
            db_path=db_path,
            host=result['host'],
            risk=result['risk_score'],
            verdict=result['verdict'],
            graph_score=result['graph_score'],
            lexical_score=result['lexical_score'],
            model_version=result['model_version'],
            scan_type='single',
            signals=result.get('signals', []),
            features=result.get('features', {})
        )
        result['scan_id'] = scan_id
        return jsonify(result)

    @app.post('/api/predict/batch')
    def predict_batch():
        if state.detector is None:
            return jsonify(error='Model missing. Run python train.py --demo, then restart the app.'), 503

        body = request.get_json(silent=True)
        if not isinstance(body, dict) or 'urls' not in body:
            return jsonify(error='Provide a JSON object with a "urls" array of strings.'), 400

        urls = body.get('urls', [])
        if not isinstance(urls, list):
            return jsonify(error='"urls" field must be a list of URL strings.'), 400

        max_limit = min(200, int(body.get('max_batch', 200)))
        batch_out = state.detector.batch_predict(urls, max_batch=max_limit)

        save_history = bool(body.get('save_history', True))
        if save_history and batch_out['items']:
            for it in batch_out['items']:
                insert_scan(
                    db_path=db_path,
                    host=it['host'],
                    risk=it['risk_score'],
                    verdict=it['verdict'],
                    graph_score=it['graph_score'],
                    lexical_score=it['lexical_score'],
                    model_version=it['model_version'],
                    scan_type='batch',
                    signals=it.get('signals', []),
                    features=it.get('features', {})
                )

        return jsonify(batch_out)

    # -------------------------------------------------------------
    # EXPORT ENDPOINTS (CSV & PDF)
    # -------------------------------------------------------------
    @app.post('/api/export/batch/csv')
    def export_csv_endpoint():
        body = request.get_json(silent=True) or {}
        items = body.get('items', [])
        if not items:
            return jsonify(error='No items provided for export.'), 400
        csv_bytes = export_batch_csv(items)
        return Response(
            csv_bytes,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename="phishgraph_batch_analysis.csv"'}
        )

    @app.post('/api/export/batch/pdf')
    def export_batch_pdf_endpoint():
        body = request.get_json(silent=True) or {}
        items = body.get('items', [])
        summary = body.get('summary', {})
        if not items:
            return jsonify(error='No items provided for PDF generation.'), 400
        pdf_bytes = generate_batch_pdf_report(summary, items)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename="phishgraph_batch_report.pdf"'}
        )

    @app.get('/api/export/single/pdf/<int:scan_id>')
    def export_single_pdf_endpoint(scan_id):
        scan = get_scan_by_id(db_path, scan_id)
        if not scan:
            abort(404, description='Scan record not found.')
        
        # Build mock result dict matching generate_single_pdf_report
        res = {
            'host': scan['host'],
            'risk_score': scan['risk'],
            'verdict': scan['verdict'],
            'graph_score': scan.get('graph_score', 0),
            'lexical_score': scan.get('lexical_score', 0),
            'signals': scan.get('signals', []),
            'model_version': scan.get('model_version', 'v1-demo'),
            'demo': True,
            'limited_support': False,
            'neighbors': []
        }
        pdf_bytes = generate_single_pdf_report(res)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="phishgraph_scan_{scan["host"]}.pdf"'}
        )

    @app.post('/api/export/current/pdf')
    def export_current_pdf_endpoint():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error='Invalid analysis payload.'), 400
        pdf_bytes = generate_single_pdf_report(body)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename="phishgraph_analysis.pdf"'}
        )

    # -------------------------------------------------------------
    # HISTORY & AUDIT LOG
    # -------------------------------------------------------------
    @app.get('/api/history')
    def history():
        # Check if caller asks for pagination or filtered search
        has_params = any(k in request.args for k in ('page', 'per_page', 'q', 'verdict', 'scan_type', 'sort_by'))
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        query = request.args.get('q', '')
        verdict_f = request.args.get('verdict', '')
        scan_type_f = request.args.get('scan_type', '')
        sort_by = request.args.get('sort_by', 'id')
        sort_dir = request.args.get('sort_dir', 'desc')

        res = query_history(
            db_path=db_path,
            query=query,
            verdict_filter=verdict_f,
            scan_type=scan_type_f,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page,
            per_page=per_page
        )
        if not has_params:
            # Backward compatibility with existing tests
            return jsonify(res['items'])
        return jsonify(res)

    @app.get('/api/history/<int:scan_id>')
    def history_item(scan_id):
        item = get_scan_by_id(db_path, scan_id)
        if not item:
            abort(404, description='Scan record not found.')
        return jsonify(item)

    @app.delete('/api/history')
    def clear_history():
        if not request.is_json:
            return jsonify(error='Use application/json.'), 415
        clear_all_history(db_path)
        return jsonify(deleted=True)

    @app.delete('/api/history/<int:scan_id>')
    def delete_single_history(scan_id):
        if not request.is_json:
            return jsonify(error='Use application/json.'), 415
        delete_scan_record(db_path, scan_id)
        return jsonify(deleted=True, id=scan_id)

    # -------------------------------------------------------------
    # FUZZY LOGIC PLAYGROUND
    # -------------------------------------------------------------
    @app.get('/api/fuzzy/playground')
    def fuzzy_playground_data():
        curves = get_fuzzy_curves(num_points=50)
        return jsonify({
            'curves': curves,
            'levels': ['low', 'medium', 'high'],
            'consequents_matrix': [[0.05, 0.25, 0.55], [0.30, 0.50, 0.75], [0.65, 0.85, 0.95]]
        })

    @app.get('/api/fuzzy/simulate')
    def fuzzy_simulate():
        try:
            g = float(request.args.get('graph', 0.5))
            l = float(request.args.get('lexical', 0.5))
            g = max(0.0, min(1.0, g))
            l = max(0.0, min(1.0, l))
            score, rules = infer(g, l)
            return jsonify({
                'graph_score': g,
                'lexical_score': l,
                'risk_score': round(score * 100, 2),
                'verdict': verdict(score),
                'rules': rules
            })
        except Exception as e:
            return jsonify(error=str(e)), 400

    # -------------------------------------------------------------
    # DATASET MANAGEMENT
    # -------------------------------------------------------------
    @app.get('/api/datasets')
    def get_datasets():
        datasets_dir = ROOT / 'data/datasets'
        items = list_datasets(datasets_dir, default_csv=ROOT / 'data/demo.csv')
        return jsonify(items)

    @app.post('/api/datasets/upload')
    def upload_dataset():
        if 'file' not in request.files:
            return jsonify(error='No file part provided in multipart request.'), 400
        file = request.files['file']
        if not file.filename:
            return jsonify(error='No file selected.'), 400
        if not file.filename.lower().endswith('.csv'):
            return jsonify(error='Dataset must be a CSV file (.csv).'), 400

        source_note = request.form.get('source_note', 'User uploaded CSV')
        try:
            meta = validate_and_register_dataset(
                file_stream_or_path=file.stream,
                filename=file.filename,
                datasets_dir=ROOT / 'data/datasets',
                source_note=source_note
            )
            return jsonify(meta), 201
        except Exception as err:
            return jsonify(error=str(err)), 400

    # -------------------------------------------------------------
    # TRAINING & EXPERIMENT MANAGEMENT
    # -------------------------------------------------------------
    @app.get('/api/training/status')
    def training_status():
        return jsonify(state.exp_mgr.get_job_status())

    @app.post('/api/training/start')
    def start_training():
        body = request.get_json(silent=True) or {}
        is_demo = bool(body.get('demo', False))
        dataset_id = body.get('dataset_id', 'demo_synthetic')
        gamma = float(body.get('gamma', 0.08))
        alpha = float(body.get('alpha', 0.2))
        unlabel_ratio = float(body.get('unlabel_ratio', 0.3))
        seed = int(body.get('seed', 42))
        custom_version = body.get('version')

        if is_demo or dataset_id == 'demo_synthetic':
            csv_path = ROOT / 'data/demo.csv'
            if not csv_path.exists():
                from generate_demo import generate
                generate(csv_path)
            is_demo = True
        else:
            csv_path = ROOT / f'data/datasets/{dataset_id}.csv'
            if not csv_path.exists():
                return jsonify(error=f"Dataset '{dataset_id}' does not exist on server."), 404
            is_demo = False

        try:
            res = state.exp_mgr.start_training_job(
                dataset_csv_path=csv_path,
                is_demo=is_demo,
                gamma=gamma,
                alpha=alpha,
                unlabel_ratio=unlabel_ratio,
                seed=seed,
                custom_version=custom_version
            )
            return jsonify(res), 202
        except Exception as e:
            return jsonify(error=str(e)), 400

    @app.get('/api/experiments')
    def list_experiments():
        return jsonify(state.exp_mgr.list_experiments())

    @app.post('/api/experiments/activate')
    def activate_experiment():
        body = request.get_json(silent=True) or {}
        exp_id = body.get('experiment_id')
        if not exp_id:
            return jsonify(error='Provide an experiment_id to activate.'), 400
        try:
            model_obj, metrics_obj = state.exp_mgr.activate_experiment(exp_id)
            state.detector = model_obj
            return jsonify({
                'activated': True,
                'experiment_id': exp_id,
                'version': getattr(model_obj, 'version', exp_id),
                'demo': getattr(model_obj, 'demo', True)
            })
        except Exception as e:
            return jsonify(error=str(e)), 400

    # -------------------------------------------------------------
    # GUIDED DEMO SAMPLES & GLOSSARY
    # -------------------------------------------------------------
    @app.get('/api/demo/samples')
    def demo_samples():
        return jsonify({
            'samples': [
                {
                    'category': 'Low risk',
                    'title': 'Legitimate E-commerce Catalog',
                    'url': 'https://cedar12.test/catalog/item/12',
                    'description': 'Standard hierarchical path structure without authentication keywords, no userinfo credentials, and single-level subdomain. Graph clustering places it near benign training nodes.',
                    'expected_band': 'Low risk (< 35/100)'
                },
                {
                    'category': 'Review needed',
                    'title': 'Ambiguous Query on Unencrypted HTTP',
                    'url': 'http://archive1.test/articles/1?page=2',
                    'description': 'Lacks malicious tokens but uses unencrypted plain HTTP transport and multiple query segments. The graph ML component reports moderate distance, triggering a manual review recommendation.',
                    'expected_band': 'Review needed (35 - 64/100)'
                },
                {
                    'category': 'High risk',
                    'title': 'Subdomain Brand Impersonation Kit',
                    'url': 'http://secure-verify-9.wallet.account.test/login/password?update=9',
                    'description': 'Features four suspicious keywords (secure, verify, wallet, account, login, password), high dot count, multiple hyphens, and high proximity to phishing seed cluster.',
                    'expected_band': 'High risk (>= 65/100)'
                },
                {
                    'category': 'High risk',
                    'title': 'Credential / Userinfo Delimiter Attack',
                    'url': 'https://trusted.test@verify-wallet-0.test/secure/login',
                    'description': 'Exploits the RFC userinfo @ delimiter syntax. Unwary users perceive "trusted.test" as the destination, while traffic is routed to "verify-wallet-0.test". Flagged with heavy heuristic weight.',
                    'expected_band': 'High risk (>= 65/100)'
                }
            ],
            'glossary': [
                {
                    'term': 'Label Spreading (Graph ML)',
                    'definition': 'A semi-supervised algorithm that constructs an affinity graph via an RBF kernel. Known labels propagate smoothly through high-density data manifolds to identify cluster boundaries.'
                },
                {
                    'term': 'Graph Neural Network (GNN) Distinction',
                    'definition': 'PhishGraph uses classical graph-based label spreading, NOT deep graph neural networks (GCN/GAT). It operates deterministically without gradient backpropagation.'
                },
                {
                    'term': 'Sugeno Fuzzy Inference',
                    'definition': 'A zero-order Takagi-Sugeno fuzzy model that translates continuous graph and lexical degrees into membership functions and calculates a weighted average of crisp consequents.'
                },
                {
                    'term': 'Host-Disjoint Holdout',
                    'definition': 'A validation split where exact hostnames are never shared between training and testing partitions, preventing the model from trivial lookup memorization.'
                },
                {
                    'term': 'Uncalibrated Scores',
                    'definition': 'The output index (0–100) conveys synthesized severity based on expert fuzzy rules, not a frequentist or Bayesian probability percentage.'
                }
            ]
        })

    @app.get('/presentation')
    def presentation_view():
        return render_template('presentation.html')

    # -------------------------------------------------------------
    # FEATURE UPGRADE: ADVERSARIAL EVASION SIMULATOR
    # -------------------------------------------------------------
    @app.post('/api/adversarial/simulate')
    def adversarial_simulate_endpoint():
        body = request.get_json(silent=True) or {}
        raw_url = body.get('url', '').strip()
        if not raw_url:
            return jsonify(error='Please provide a valid URL to simulate evasion attacks.'), 400
        if state.detector is None:
            return jsonify(error='Model not loaded. Train a model first.'), 503
        result = evaluate_adversarial_robustness(state.detector, raw_url)
        return jsonify(result)

    # -------------------------------------------------------------
    # FEATURE UPGRADE: BRAND IMPERSONATION & TYPOSQUATTING RADAR
    # -------------------------------------------------------------
    @app.route('/api/brand/analyze', methods=['GET', 'POST'])
    def brand_analyze_endpoint():
        if request.method == 'POST':
            body = request.get_json(silent=True) or {}
            raw_url = body.get('url', '').strip()
        else:
            raw_url = request.args.get('url', '').strip()
        if not raw_url:
            return jsonify(error='Target URL parameter is required.'), 400
        result = analyze_brand_impersonation(raw_url)
        return jsonify(result)

    # -------------------------------------------------------------
    # FEATURE UPGRADE: IDN HOMOGRAPH & PUNYCODE ANALYZER
    # -------------------------------------------------------------
    @app.route('/api/homograph/analyze', methods=['GET', 'POST'])
    def homograph_analyze_endpoint():
        if request.method == 'POST':
            body = request.get_json(silent=True) or {}
            raw_url = body.get('url', '').strip()
        else:
            raw_url = request.args.get('url', '').strip()
        if not raw_url:
            return jsonify(error='Target URL parameter is required.'), 400
        result = analyze_homograph_spoofing(raw_url)
        return jsonify(result)

    # -------------------------------------------------------------
    # FEATURE UPGRADE: SPECTRAL GRAPH & HOMOPHILY ANALYTICS
    # -------------------------------------------------------------
    @app.get('/api/graph/spectral')
    def spectral_graph_endpoint():
        if state.detector is None:
            return jsonify(error='Model not loaded.'), 503
        metrics = compute_spectral_graph_metrics(state.detector)
        return jsonify(metrics)

    # -------------------------------------------------------------
    # FEATURE UPGRADE: CAMPAIGN CLUSTERING ON BATCH THREATS
    # -------------------------------------------------------------
    @app.post('/api/campaigns/cluster')
    def campaign_cluster_endpoint():
        body = request.get_json(silent=True) or {}
        items = body.get('items', [])
        # If no items supplied, fetch last 100 historical scans
        if not items:
            history_data = query_history(db_path, per_page=100)
            items = history_data.get('items', [])
        if not items:
            return jsonify(error='No scan records available to cluster.'), 400
        clustering_result = cluster_campaign_urls(items)
        return jsonify(clustering_result)

    # -------------------------------------------------------------
    # FEATURE UPGRADE: OASIS STIX 2.1 & OPENIOC CTI EXPORTS
    # -------------------------------------------------------------
    @app.post('/api/export/stix')
    def export_stix_endpoint():
        body = request.get_json(silent=True) or {}
        items = body.get('items', [])
        if not items:
            history_data = query_history(db_path, per_page=50)
            items = history_data.get('items', [])
        bundle = generate_stix21_bundle(items)
        return Response(
            json.dumps(bundle, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename="phishgraph_threat_intel_stix21.json"'}
        )

    @app.post('/api/export/openioc')
    def export_openioc_endpoint():
        body = request.get_json(silent=True) or {}
        items = body.get('items', [])
        if not items:
            history_data = query_history(db_path, per_page=50)
            items = history_data.get('items', [])
        xml_content = generate_openioc_xml(items)
        return Response(
            xml_content,
            mimetype='application/xml',
            headers={'Content-Disposition': 'attachment; filename="phishgraph_ioc.xml"'}
        )

    # -------------------------------------------------------------
    # FEATURE UPGRADE: SOC ALERT TRIAGE & INCIDENT PACKS
    # -------------------------------------------------------------
    @app.get('/api/soc/triage')
    def soc_triage_queue_endpoint():
        status = request.args.get('status', 'all')
        queue = get_triage_queue(db_path, status=status)
        return jsonify(queue)

    @app.post('/api/soc/triage')
    def soc_triage_update_endpoint():
        body = request.get_json(silent=True) or {}
        scan_id = body.get('scan_id')
        status = body.get('status', 'Confirmed Phishing')
        notes = body.get('notes', '')
        if not scan_id:
            return jsonify(error='scan_id is required.'), 400
        ok = update_scan_triage(db_path, int(scan_id), status, notes)
        return jsonify(success=ok, scan_id=scan_id, status=status)

    @app.get('/api/soc/pack/<int:scan_id>')
    def soc_incident_pack_endpoint(scan_id):
        scan = get_scan_by_id(db_path, scan_id)
        if not scan:
            abort(404, description='Scan record not found.')
        pack = get_incident_triage_pack(scan)
        return jsonify(pack)

    # -------------------------------------------------------------
    # FEATURE UPGRADE: TUNABLE SUGENO FUZZY RULE PROFILES
    # -------------------------------------------------------------
    @app.get('/api/fuzzy/profile')
    def fuzzy_profile_get():
        return jsonify(get_active_profile())

    @app.post('/api/fuzzy/profile')
    def fuzzy_profile_post():
        body = request.get_json(silent=True) or {}
        matrix = body.get('matrix')
        profile_name = body.get('profile_name', 'custom')
        if not matrix or len(matrix) != 3 or any(len(r) != 3 for r in matrix):
            return jsonify(error='Matrix must be 3x3 with values between 0.0 and 1.0.'), 400
        try:
            set_active_consequents(matrix, profile_name)
            return jsonify(success=True, profile=get_active_profile())
        except Exception as e:
            return jsonify(error=str(e)), 400

    # -------------------------------------------------------------
    # FEATURE UPGRADE: DEVELOPER API & WEBHOOK SIMULATOR
    # -------------------------------------------------------------
    @app.post('/api/api-console/simulate-webhook')
    def simulate_webhook_endpoint():
        body = request.get_json(silent=True) or {}
        webhook_url = body.get('webhook_url', 'https://siem.enterprise.local/api/v1/alerts')
        secret_key = body.get('secret_key', 'pg_sec_prod_live_8f92b7c4a1e5')
        scan_data = body.get('scan_data') or {
            "event_type": "phishing.detected",
            "host": "secure-verify.wallet.account.test",
            "risk_score": 88.5,
            "verdict": "High risk",
            "timestamp": int(time.time()),
            "engine": "PhishGraph Graph ML + Sugeno Fuzzy"
        }

        payload_bytes = json.dumps(scan_data, sort_keys=True).encode('utf-8')
        signature = hmac.new(secret_key.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()

        simulated_headers = {
            "Content-Type": "application/json",
            "User-Agent": "PhishGraph-Webhook-Agent/2.0",
            "X-PhishGraph-Event": "phishing.detected",
            "X-PhishGraph-Signature-256": f"sha256={signature}",
            "X-PhishGraph-Timestamp": str(int(time.time()))
        }

        return jsonify({
            "target_webhook_url": webhook_url,
            "dispatch_status": "Simulated Delivery Successful (HTTP 200 OK)",
            "hmac_sha256_signature": f"sha256={signature}",
            "headers": simulated_headers,
            "payload": scan_data
        })

    return app

if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=False)
