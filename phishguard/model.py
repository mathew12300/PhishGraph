from pathlib import Path
import joblib
import numpy as np
from sklearn.semi_supervised import LabelSpreading
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from .features import NAMES, extract, parse_url, lexical_risk
from .fuzzy import infer, verdict

import math
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
from sklearn.semi_supervised import LabelSpreading
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from .features import NAMES, FEATURE_INFO, extract, parse_url, lexical_risk
from .fuzzy import infer, verdict

class Detector:
    def __init__(self, version='v1-demo'):
        self.version = version
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.demo = True
        self.gamma = 0.08
        self.alpha = 0.2

    def fit(self, urls, labels, seed=42, gamma=0.08, alpha=0.2, unlabel_ratio=0.3, version=None):
        if version:
            self.version = version
        self.gamma = float(gamma)
        self.alpha = float(alpha)
        self.hosts = [parse_url(u)[1] for u in urls]
        x = np.array([[extract(u)[n] for n in NAMES] for u in urls], dtype=float)
        self.scaler = StandardScaler().fit(x)
        self.x = self.scaler.transform(x)
        self.y = np.array(labels, dtype=int)
        
        # Hide unlabel_ratio of each class to demonstrate semi-supervised learning.
        self.visible_y = self.y.copy()
        rng = np.random.default_rng(seed)
        for label in (0, 1):
            ids = np.flatnonzero(self.y == label)
            rng.shuffle(ids)
            cutoff = int(len(ids) * max(0.0, min(0.9, float(unlabel_ratio))))
            self.visible_y[ids[:cutoff]] = -1

        self.graph = LabelSpreading(kernel='rbf', gamma=self.gamma, alpha=self.alpha, max_iter=200)
        self.graph.fit(self.x, self.visible_y)
        
        # Fair labeled-data budget for baseline; graph also sees unlabeled features.
        known = self.visible_y != -1
        self.baseline = LogisticRegression(max_iter=1000, random_state=seed).fit(self.x[known], self.y[known])
        return self

    def predict(self, url, k_neighbors=6):
        canonical, host = parse_url(url)
        f = extract(canonical)
        x = self.scaler.transform([[f[n] for n in NAMES]])
        p = float(self.graph.predict_proba(x)[0, list(self.graph.classes_).index(1)])
        if not np.isfinite(p):
            raise ValueError('URL is outside model support; no reliable graph score is available.')
        
        lexical, signals = lexical_risk(f)
        score, rules = infer(p, lexical)
        
        # Compute distances across all training nodes in standardized feature space
        distances = np.linalg.norm(self.x - x[0], axis=1)
        k = min(len(self.hosts), max(3, int(k_neighbors)))
        ids = np.argsort(distances)[:k]
        
        neighbors = []
        graph_nodes = [{
            'id': 'query',
            'label': host,
            'type': 'query',
            'verdict': verdict(score),
            'risk_score': round(score * 100, 2),
            'x': 240,
            'y': 160
        }]
        graph_edges = []

        angle_step = 2 * math.pi / k
        gamma = getattr(self, 'gamma', 0.08)
        for idx_rank, i in enumerate(ids):
            dist = float(distances[i])
            rbf_sim = float(np.exp(-gamma * (dist ** 2)))
            seed_lbl = int(self.visible_y[i])
            spread = float(self.graph.label_distributions_[i, 1])
            
            # Seed label status text
            status = 'Unlabeled (Hidden in SSL)' if seed_lbl == -1 else ('Phishing Seed' if seed_lbl == 1 else 'Benign Seed')
            n_info = {
                'id': f'node_{i}',
                'host': self.hosts[i],
                'distance': round(dist, 3),
                'similarity': round(rbf_sim, 4),
                'seed_label': seed_lbl,
                'seed_status': status,
                'spread_score': round(spread, 4)
            }
            neighbors.append(n_info)

            # Node coordinates in radial layout
            nx = round(240 + 140 * math.cos(idx_rank * angle_step), 1)
            ny = round(160 + 95 * math.sin(idx_rank * angle_step), 1)
            graph_nodes.append({
                'id': f'node_{i}',
                'label': self.hosts[i],
                'type': 'seed_phish' if seed_lbl == 1 else ('seed_benign' if seed_lbl == 0 else 'unlabeled'),
                'seed_label': seed_lbl,
                'status': status,
                'similarity': round(rbf_sim, 4),
                'distance': round(dist, 3),
                'spread_score': round(spread, 4),
                'x': nx,
                'y': ny
            })
            graph_edges.append({
                'source': 'query',
                'target': f'node_{i}',
                'similarity': round(rbf_sim, 4),
                'weight': round(rbf_sim, 3)
            })

        min_dist = float(distances[ids[0]])
        is_limited_support = bool(min_dist > 5.0)

        # Enriched feature details with plain-English rationales
        feature_breakdown = {}
        for k_name in NAMES:
            val = f[k_name]
            meta = FEATURE_INFO.get(k_name, {'title': k_name, 'desc': '', 'rationale': ''})
            feature_breakdown[k_name] = {
                'value': val,
                'title': meta['title'],
                'desc': meta['desc'],
                'rationale': meta['rationale']
            }

        return {
            'host': host,
            'risk_score': round(score * 100, 2),
            'verdict': verdict(score),
            'graph_score': round(p * 100, 2),
            'lexical_score': round(lexical * 100, 2),
            'features': f,
            'feature_breakdown': feature_breakdown,
            'signals': signals,
            'rules': rules,
            'neighbors': neighbors,
            'graph_view': {
                'nodes': graph_nodes,
                'edges': graph_edges,
                'total_training_nodes': len(self.hosts),
                'displayed_subgraph': k
            },
            'demo': getattr(self, 'demo', True),
            'model_version': getattr(self, 'version', 'v1-demo'),
            'limited_support': is_limited_support,
            'min_distance': round(min_dist, 3),
            'notice': ('Synthetic demo model; scores are not calibrated probabilities. URL text only; low risk does not establish safety.'
                       if getattr(self, 'demo', True) else
                       'Experimental model; scores are not calibrated probabilities. URL text only; low risk does not establish safety.')
        }

    def batch_predict(self, urls, max_batch=200):
        results = []
        errors = []
        seen = set()

        for idx, raw in enumerate(urls, 1):
            if idx > max_batch:
                errors.append({'row': idx, 'input': str(raw)[:100], 'error': f'Exceeded maximum batch limit of {max_batch} URLs.'})
                break
            raw_str = (raw or '').strip()
            if not raw_str:
                continue
            try:
                canonical, _ = parse_url(raw_str)
                if canonical in seen:
                    continue
                seen.add(canonical)
                res = self.predict(canonical)
                results.append(res)
            except Exception as err:
                errors.append({'row': idx, 'input': raw_str[:120], 'error': str(err)})

        return {
            'items': results,
            'errors': errors,
            'total_submitted': len(urls),
            'total_valid': len(results),
            'total_errors': len(errors)
        }

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        # Only load your own locally trained artifact. Pickle/joblib files can execute code.
        return joblib.load(path)
