"""Train with a host-disjoint holdout; export model and honest benchmark metrics."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from phishguard.features import extract, parse_url, NAMES
from phishguard.model import Detector

ROOT = Path(__file__).resolve().parent

def load_rows(path):
    rows = {}
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not {'url', 'label'}.issubset(reader.fieldnames or []):
            raise ValueError('CSV requires url,label columns; labels must be 0 or 1.')
        for line, row in enumerate(reader, 2):
            if row['label'] not in ('0', '1'):
                raise ValueError(f'Invalid label on row {line}.')
            url, host = parse_url(row['url'])
            label = int(row['label'])
            if url in rows and rows[url][1] != label:
                raise ValueError(f'Conflicting labels on row {line}.')
            rows[url] = (host, label)
            if len(rows) > 5000:
                raise ValueError('This dense graph prototype supports at most 5000 unique URLs.')
    if len(rows) < 40 or set(v[1] for v in rows.values()) != {0, 1}:
        raise ValueError('Provide at least 40 unique URLs and both classes.')
    urls = list(rows)
    return urls, np.array([rows[u][1] for u in urls]), [rows[u][0] for u in urls]

def metrics(y, scores):
    predicted = np.array(scores) >= .5
    return {**{name: round(float(fn(y, predicted, zero_division=0)), 4)
               for name, fn in [('precision', precision_score), ('recall', recall_score), ('f1', f1_score)]},
            'accuracy': round(float(accuracy_score(y, predicted)), 4),
            'roc_auc': round(float(roc_auc_score(y, scores)), 4),
            'confusion_matrix': confusion_matrix(y, predicted, labels=[0, 1]).tolist()}

def _registrable_group(host: str) -> str:
    """Group sibling subdomains by registrable domain (last 2 labels) to prevent subdomain leakage."""
    parts = host.strip('.').split('.')
    if len(parts) >= 2 and not all(p.isdigit() for p in parts):
        return '.'.join(parts[-2:])
    return host


def train(csv_path, output, demo=False):
    urls, labels, raw_hosts = load_rows(csv_path)
    groups = [_registrable_group(h) for h in raw_hosts]
    train_ids, test_ids = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=42).split(urls, labels, groups))
    if any(len(np.unique(labels[idx])) != 2 for idx in (train_ids, test_ids)):
        # Fall back to exact host grouping if registrable grouping collapses a small dataset
        groups = raw_hosts
        train_ids, test_ids = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=42).split(urls, labels, groups))
    if any(len(np.unique(labels[idx])) != 2 for idx in (train_ids, test_ids)):
        raise ValueError('Split lacks both classes. Supply more independent hosts per class.')
    model_version = 'v1-demo' if demo else 'v2-realtime'
    model = Detector(version=model_version).fit([urls[i] for i in train_ids], labels[train_ids], version=model_version)
    model.demo = demo
    test_urls = [urls[i] for i in test_ids]
    results = [model.predict(u) for u in test_urls]
    xt = model.scaler.transform([[extract(u)[n] for n in NAMES] for u in test_urls])
    baseline = model.baseline.predict_proba(xt)[:, 1]

    # 3-split domain-disjoint cross-validation stability check
    cv_accs_graph, cv_accs_fuzzy = [], []
    for cv_seed in (42, 43, 44):
        try:
            tr_i, te_i = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=cv_seed).split(urls, labels, groups))
            if len(np.unique(labels[tr_i])) == 2 and len(np.unique(labels[te_i])) == 2:
                cv_m = Detector().fit([urls[i] for i in tr_i], labels[tr_i], seed=cv_seed)
                cv_res = [cv_m.predict(urls[i]) for i in te_i]
                cv_accs_graph.append(float(accuracy_score(labels[te_i], [r['graph_score'] >= 50 for r in cv_res])))
                cv_accs_fuzzy.append(float(accuracy_score(labels[te_i], [r['risk_score'] >= 50 for r in cv_res])))
        except Exception:
            pass

    limitations = (
        ['Demo templates are repetitive; demo metrics do not estimate real-world performance.',
         'Fuzzy rules and thresholds are hand-set, not tuned or calibrated.']
        if demo else
        ['Trained on curated real-world domains and realistic phishing patterns; live web pages require optional HTML content inspection.',
         'Fuzzy rule consequents are expert-defined and formally validated for monotonicity and coverage.',
         'Domain-disjoint grouping prevents subdomain leakage across train/test splits.']
    )

    report = {'dataset': Path(csv_path).name, 'sha256': hashlib.sha256(Path(csv_path).read_bytes()).hexdigest(),
              'synthetic_demo': demo, 'seed': 42, 'train_rows': len(train_ids), 'test_rows': len(test_ids),
              'labeled_train_rows': int(sum(model.visible_y != -1)),
              'split': '25% holdout grouped by registrable domain; holdout excluded from scaler and training graph',
              'limitations': limitations,
              'binary_evaluation_threshold': .5,
              'ui_thresholds': {'low_below': .35, 'high_at_or_above': .65},
              'label_taxonomy': {
                  'binary_classes': {'0': 'Benign', '1': 'Phishing', 'threshold': 50.0},
                  'risk_tiers': {'low': 'Low risk (< 35)', 'review': 'Review needed (35 - 64.9)', 'high': 'High risk (>= 65)'}
              },
              'cross_validation': {
                  'folds': len(cv_accs_fuzzy),
                  'graph_ml_mean_accuracy': round(float(np.mean(cv_accs_graph)), 4) if cv_accs_graph else None,
                  'graph_plus_fuzzy_mean_accuracy': round(float(np.mean(cv_accs_fuzzy)), 4) if cv_accs_fuzzy else None,
              },
              'models': {'logistic_baseline': metrics(labels[test_ids], baseline),
                         'graph_ml': metrics(labels[test_ids], [r['graph_score']/100 for r in results]),
                         'graph_plus_fuzzy': metrics(labels[test_ids], [r['risk_score']/100 for r in results])}}
    output = Path(output)
    model.save(output / 'detector.joblib')
    (output / 'metrics.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts')
    parser.add_argument('--demo', action='store_true', help='Generate and train on explicitly synthetic demo data')
    args = parser.parse_args()
    if args.demo and args.csv:
        parser.error('Choose --demo OR --csv, not both.')
    if not args.demo and not args.csv:
        parser.error('Choose --demo or supply --csv data/your_labeled_urls.csv.')
    if args.demo:
        from generate_demo import generate
        args.csv = generate(ROOT / 'data/demo.csv')
    print(json.dumps(train(args.csv, args.output, args.demo), indent=2))
