"""
Campaign clustering and phishing kit fingerprinting engine for PhishGraph.
Groups analyzed URLs into synchronized infrastructure and attack families.
"""

import math
from typing import Dict, List, Any
import numpy as np
from phishguard.features import extract, NAMES


def cluster_campaign_urls(batch_items: List[Dict[str, Any]], similarity_threshold: float = 0.65) -> Dict[str, Any]:
    """
    Performs agglomerative single-linkage / connected component clustering
    on a set of analyzed URLs using normalized feature vectors.
    """
    if not batch_items:
        return {"clusters": [], "cluster_count": 0, "total_items": 0}

    # Extract feature matrices
    feature_matrix = []
    valid_items = []
    for item in batch_items:
        if 'features' in item:
            feats = [item['features'].get(k, 0.0) for k in NAMES]
            feature_matrix.append(feats)
            valid_items.append(item)

    if not feature_matrix:
        return {"clusters": [], "cluster_count": 0, "total_items": len(batch_items)}

    X = np.array(feature_matrix, dtype=float)
    # Standardize
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)
    stds[stds == 0] = 1.0
    X_scaled = (X - means) / stds

    n = len(valid_items)
    # Pairwise RBF similarity matrix
    gamma = 0.08
    dists = np.sum((X_scaled[:, np.newaxis, :] - X_scaled[np.newaxis, :, :]) ** 2, axis=-1)
    sim_matrix = np.exp(-gamma * dists)

    # Connected components for clusters
    adj = (sim_matrix >= similarity_threshold).astype(int)
    visited = [False] * n
    clusters = []

    for i in range(n):
        if visited[i]:
            continue
        # BFS
        component = []
        queue = [i]
        visited[i] = True

        while queue:
            curr = queue.pop(0)
            component.append(curr)
            for neighbor in range(n):
                if adj[curr, neighbor] == 1 and not visited[neighbor]:
                    visited[neighbor] = True
                    queue.append(neighbor)

        cluster_items = [valid_items[idx] for idx in component]
        avg_risk = sum(item.get('risk_score', 0) for item in cluster_items) / len(cluster_items)
        phish_count = sum(1 for item in cluster_items if item.get('verdict') == 'High risk')

        # Determine dominant characteristics
        cluster_hosts = [item.get('host', '') for item in cluster_items]
        dominant_tld = 'unknown'
        tlds = [h.split('.')[-1] for h in cluster_hosts if '.' in h]
        if tlds:
            dominant_tld = max(set(tlds), key=tlds.count)

        clusters.append({
            "cluster_id": f"CAMPAIGN-KIT-{len(clusters)+1:02d}",
            "size": len(cluster_items),
            "average_risk": round(avg_risk, 1),
            "threat_density": f"{phish_count}/{len(cluster_items)} High Risk",
            "dominant_tld": dominant_tld,
            "representative_host": cluster_hosts[0],
            "members": [
                {
                    "host": it.get('host'),
                    "risk_score": it.get('risk_score'),
                    "verdict": it.get('verdict'),
                    "graph_score": it.get('graph_score'),
                    "lexical_score": it.get('lexical_score')
                } for it in cluster_items
            ]
        })

    # Sort clusters by size and risk
    clusters.sort(key=lambda c: (c['size'], c['average_risk']), reverse=True)

    return {
        "cluster_count": len(clusters),
        "total_items": n,
        "similarity_threshold": similarity_threshold,
        "clusters": clusters
    }
