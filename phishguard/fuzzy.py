"""Zero-order Sugeno fuzzy inference; product AND and weighted average."""
import math
from typing import Tuple, List, Dict, Any, Optional

LEVELS = ('low', 'medium', 'high')
# Default expert-defined monotonic Sugeno consequents
DEFAULT_CONSEQUENTS = ((.05, .25, .55), (.30, .50, .75), (.65, .85, .95))
CONSEQUENTS = DEFAULT_CONSEQUENTS

PRESET_PROFILES = {
    "balanced": {
        "name": "Standard Balanced (Default)",
        "description": "Monotonic 9-rule matrix balancing detection with low false alarms.",
        "matrix": [[0.05, 0.25, 0.55], [0.30, 0.50, 0.75], [0.65, 0.85, 0.95]]
    },
    "aggressive": {
        "name": "Aggressive / Zero-Trust Defense",
        "description": "Amplified consequent penalties for any graph or lexical anomaly.",
        "matrix": [[0.10, 0.40, 0.70], [0.45, 0.70, 0.90], [0.80, 0.95, 0.99]]
    },
    "conservative": {
        "name": "High-Assurance / Low False-Positive",
        "description": "Requires both high graph proximity AND high lexical risk to trigger high alerts.",
        "matrix": [[0.02, 0.15, 0.45], [0.15, 0.40, 0.65], [0.50, 0.75, 0.90]]
    }
}

ACTIVE_PROFILE_NAME = "balanced"
CURRENT_CONSEQUENTS = [list(r) for r in DEFAULT_CONSEQUENTS]


def set_active_consequents(matrix, profile_name: str = "custom"):
    global CURRENT_CONSEQUENTS, ACTIVE_PROFILE_NAME
    # Validate monotonicity and bounds
    for i in range(3):
        for j in range(3):
            val = float(matrix[i][j])
            if not (0.0 <= val <= 1.0):
                raise ValueError("Consequent values must be between 0.0 and 1.0.")
    CURRENT_CONSEQUENTS = [list(r) for r in matrix]
    ACTIVE_PROFILE_NAME = profile_name


def get_active_profile() -> Dict[str, Any]:
    return {
        "active_profile": ACTIVE_PROFILE_NAME,
        "consequents": CURRENT_CONSEQUENTS,
        "presets": PRESET_PROFILES
    }


def membership(x):
    x = float(x)
    if not math.isfinite(x) or not 0 <= x <= 1:
        raise ValueError('Fuzzy inputs must be finite values between 0 and 1.')
    return (max(0., 1 - 2*x), max(0., 1 - abs(2*x - 1)), max(0., 2*x - 1))


def infer(graph_score, lexical_score, custom_consequents=None):
    c_matrix = custom_consequents or CURRENT_CONSEQUENTS
    g, l = membership(graph_score), membership(lexical_score)
    rules = []
    for i in range(3):
        for j in range(3):
            weight = g[i] * l[j]
            if weight > 0:
                c_val = float(c_matrix[i][j])
                rules.append({'rule': f'Graph {LEVELS[i]} AND lexical {LEVELS[j]}',
                              'activation': round(weight, 4),
                              'consequent': c_val,
                              'graph_level': LEVELS[i],
                              'lexical_level': LEVELS[j],
                              'weighted_consequent': round(weight * c_val, 4)})
    denom = sum(r['activation'] for r in rules)
    score = (sum(r['activation'] * r['consequent'] for r in rules) / denom) if denom > 0 else 0.0
    return float(score), rules


def get_fuzzy_curves(num_points=50):
    """Generate curve points for visual graphing of low, medium, and high fuzzy sets."""
    xs = [round(i / (num_points - 1), 3) for i in range(num_points)]
    curves = {'x': xs, 'low': [], 'medium': [], 'high': []}
    for x in xs:
        low, med, high = membership(x)
        curves['low'].append(round(low, 4))
        curves['medium'].append(round(med, 4))
        curves['high'].append(round(high, 4))
    return curves


def verdict(score):
    return 'High risk' if score >= .65 else 'Review needed' if score >= .35 else 'Low risk'
