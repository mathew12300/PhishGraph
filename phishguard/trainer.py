"""Asynchronous background training runner, model versioning, and experiment registry."""
import hashlib
import json
import logging
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from .features import NAMES, extract
from .model import Detector
from .datasets import validate_and_register_dataset

logger = logging.getLogger(__name__)

class ExperimentManager:
    def __init__(self, root_dir):
        self.root = Path(root_dir)
        self.artifacts_dir = self.root / 'artifacts'
        self.experiments_dir = self.artifacts_dir / 'experiments'
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.experiments_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.active_job = None  # { id, thread, status, start_time, logs, result, error }

    def get_active_model_info(self):
        metrics_file = self.artifacts_dir / 'metrics.json'
        if not metrics_file.exists():
            return {'status': 'missing', 'version': 'None', 'demo': True}
        try:
            report = json.loads(metrics_file.read_text(encoding='utf-8'))
            return {
                'status': 'ready',
                'version': report.get('model_version', 'v1-demo'),
                'demo': report.get('synthetic_demo', True),
                'dataset': report.get('dataset', 'demo.csv'),
                'accuracy': report.get('models', {}).get('graph_plus_fuzzy', {}).get('accuracy', 0.0),
                'train_rows': report.get('train_rows', 0),
                'test_rows': report.get('test_rows', 0)
            }
        except Exception:
            return {'status': 'error', 'version': 'Unknown', 'demo': True}

    def list_experiments(self):
        items = []
        for exp_folder in sorted(self.experiments_dir.glob('*'), reverse=True):
            if not exp_folder.is_dir():
                continue
            meta_path = exp_folder / 'experiment.json'
            if meta_path.exists():
                try:
                    info = json.loads(meta_path.read_text(encoding='utf-8'))
                    items.append(info)
                except Exception:
                    continue
        return items

    def get_job_status(self):
        with self.lock:
            if not self.active_job:
                return {'status': 'idle', 'message': 'No training job currently running.'}
            return {
                'id': self.active_job['id'],
                'status': self.active_job['status'],
                'start_time': self.active_job['start_time'],
                'duration': round(time.time() - self.active_job['start_time'], 1) if self.active_job['status'] == 'running' else self.active_job.get('duration', 0),
                'logs': list(self.active_job['logs']),
                'error': self.active_job.get('error'),
                'result': self.active_job.get('result')
            }

    def start_training_job(self, dataset_csv_path, is_demo=False, gamma=0.08, alpha=0.2,
                           unlabel_ratio=0.3, seed=42, custom_version=None, on_complete_callback=None):
        with self.lock:
            if self.active_job and self.active_job['status'] == 'running':
                raise RuntimeError('A training job is already in progress. Please wait for it to complete.')

            exp_id = f"exp_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            version_tag = custom_version or (f"demo_{exp_id[-6:]}" if is_demo else f"custom_{exp_id[-6:]}")
            
            job = {
                'id': exp_id,
                'version': version_tag,
                'status': 'running',
                'start_time': time.time(),
                'logs': [f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Training job {exp_id} queued..."],
                'error': None,
                'result': None,
                'duration': 0
            }
            self.active_job = job

            thread = threading.Thread(
                target=self._run_training_worker,
                args=(job, dataset_csv_path, is_demo, gamma, alpha, unlabel_ratio, seed, version_tag, on_complete_callback),
                daemon=True
            )
            thread.start()
            return {'job_id': exp_id, 'version': version_tag, 'status': 'running'}

    def _run_training_worker(self, job, dataset_csv_path, is_demo, gamma, alpha, unlabel_ratio, seed, version_tag, on_complete_callback):
        def log(msg):
            ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
            line = f"[{ts}] {msg}"
            job['logs'].append(line)
            logger.info(line)

        try:
            exp_dir = self.experiments_dir / job['id']
            exp_dir.mkdir(parents=True, exist_ok=True)
            log(f"Starting training run with dataset: {Path(dataset_csv_path).name}")
            log(f"Hyperparameters: gamma={gamma}, alpha={alpha}, unlabel_ratio={unlabel_ratio}, seed={seed}")

            # Import helper here to avoid circular imports
            from train import load_rows, metrics

            urls, labels, groups = load_rows(dataset_csv_path)
            log(f"Loaded {len(urls)} unique URLs across {len(set(groups))} hostnames.")

            # Host-disjoint stratified holdout
            log("Computing 25% host-disjoint holdout split (GroupShuffleSplit)...")
            train_ids, test_ids = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed).split(urls, labels, groups))
            
            if any(len(np.unique(labels[idx])) != 2 for idx in (train_ids, test_ids)):
                raise ValueError('Host split resulted in one class missing from train or test set. Please supply more distinct hostnames per class.')

            log(f"Partitioned into {len(train_ids)} training nodes and {len(test_ids)} test nodes.")

            # Train detector
            detector = Detector(version=version_tag)
            log("Fitting feature scaler and building RBF similarity graph...")
            detector.fit([urls[i] for i in train_ids], labels[train_ids], seed=seed,
                         gamma=gamma, alpha=alpha, unlabel_ratio=unlabel_ratio, version=version_tag)
            detector.demo = is_demo

            log(f"Label spreading converged. Visible labels: {int(sum(detector.visible_y != -1))}/{len(train_ids)} (hidden: {int(sum(detector.visible_y == -1))}).")

            # Evaluation on untouched test set
            log("Evaluating against untouched held-out test hosts...")
            test_urls = [urls[i] for i in test_ids]
            results = [detector.predict(u) for u in test_urls]
            xt = detector.scaler.transform([[extract(u)[n] for n in NAMES] for u in test_urls])
            baseline_probs = detector.baseline.predict_proba(xt)[:, 1]

            metrics_report = {
                'experiment_id': job['id'],
                'model_version': version_tag,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'dataset': Path(dataset_csv_path).name,
                'sha256': hashlib.sha256(Path(dataset_csv_path).read_bytes()).hexdigest(),
                'synthetic_demo': is_demo,
                'seed': seed,
                'hyperparameters': {
                    'gamma': gamma,
                    'alpha': alpha,
                    'unlabel_ratio': unlabel_ratio,
                    'kernel': 'rbf'
                },
                'train_rows': len(train_ids),
                'test_rows': len(test_ids),
                'labeled_train_rows': int(sum(detector.visible_y != -1)),
                'split': '25% holdout grouped by exact hostname; holdout excluded from scaler and training graph',
                'limitations': [
                    'Host grouping does not isolate registrable domains, campaigns, or time.',
                    'Demo templates are repetitive; demo metrics do not estimate real-world performance.',
                    'Fuzzy rules and thresholds are hand-set, not tuned or calibrated.'
                ],
                'binary_evaluation_threshold': 0.5,
                'ui_thresholds': {'low_below': 0.35, 'high_at_or_above': 0.65},
                'models': {
                    'logistic_baseline': metrics(labels[test_ids], baseline_probs),
                    'graph_ml': metrics(labels[test_ids], [r['graph_score'] / 100 for r in results]),
                    'graph_plus_fuzzy': metrics(labels[test_ids], [r['risk_score'] / 100 for r in results])
                }
            }

            # Save experiment artifacts
            log("Saving experiment artifacts...")
            detector.save(exp_dir / 'detector.joblib')
            (exp_dir / 'metrics.json').write_text(json.dumps(metrics_report, indent=2), encoding='utf-8')

            duration = round(time.time() - job['start_time'], 2)
            meta = {
                'id': job['id'],
                'version': version_tag,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': duration,
                'status': 'completed',
                'dataset': Path(dataset_csv_path).name,
                'synthetic_demo': is_demo,
                'metrics': metrics_report['models'],
                'hyperparameters': metrics_report['hyperparameters'],
                'train_rows': len(train_ids),
                'test_rows': len(test_ids)
            }
            (exp_dir / 'experiment.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            job['status'] = 'completed'
            job['duration'] = duration
            job['result'] = meta
            log(f"Training successfully completed in {duration}s! Accuracy: {metrics_report['models']['graph_plus_fuzzy']['accuracy'] * 100:.1f}%.")

            if on_complete_callback:
                on_complete_callback(job['id'], exp_dir)

        except Exception as e:
            err_msg = str(e)
            tb = traceback.format_exc()
            job['status'] = 'failed'
            job['error'] = err_msg
            job['duration'] = round(time.time() - job['start_time'], 2)
            log(f"ERROR: Training failed: {err_msg}")
            logger.error(f"Training failed:\n{tb}")

    def activate_experiment(self, exp_id):
        """
        Safely activate a completed experiment without risking model corruption.
        """
        exp_dir = self.experiments_dir / exp_id
        model_path = exp_dir / 'detector.joblib'
        metrics_path = exp_dir / 'metrics.json'

        if not model_path.exists() or not metrics_path.exists():
            raise FileNotFoundError(f"Experiment '{exp_id}' lacks required model artifacts.")

        # Read and verify before overwriting active model
        test_model = Detector.load(model_path)
        metrics_data = json.loads(metrics_path.read_text(encoding='utf-8'))

        # Copy to active artifacts directory
        active_model_path = self.artifacts_dir / 'detector.joblib'
        active_metrics_path = self.artifacts_dir / 'metrics.json'

        test_model.save(active_model_path)
        active_metrics_path.write_text(json.dumps(metrics_data, indent=2), encoding='utf-8')
        return test_model, metrics_data
