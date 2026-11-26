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


def validate_sugeno_rules(matrix=None) -> Dict[str, Any]:
    """Formally validate Sugeno fuzzy membership partition, coverage, bounds, and monotonicity."""
    c_matrix = matrix if matrix is not None else CURRENT_CONSEQUENTS
    errors: List[str] = []

    if not isinstance(c_matrix, (list, tuple)) or len(c_matrix) != 3 or any(
        not isinstance(row, (list, tuple)) or len(row) != 3 for row in c_matrix
    ):
        return {
            'valid': False,
            'errors': ['Rule matrix must be a 3x3 grid.'],
            'checks': {}
        }

    parsed = []
    for i in range(3):
        row_vals = []
        for j in range(3):
            try:
                val = float(c_matrix[i][j])
            except (TypeError, ValueError):
                errors.append(f'Rule ({LEVELS[i]}, {LEVELS[j]}) consequent is not numeric.')
                val = -1.0
            if not math.isfinite(val) or not (0.0 <= val <= 1.0):
                errors.append(f'Rule ({LEVELS[i]}, {LEVELS[j]}) consequent {val} must be in [0.0, 1.0].')
            row_vals.append(val)
        parsed.append(row_vals)

    bounds_ok = len(errors) == 0

    # Row monotonicity: increasing lexical risk must not decrease consequent
    row_mono_ok = True
    for i in range(3):
        if not (parsed[i][0] <= parsed[i][1] <= parsed[i][2]):
            row_mono_ok = False
            errors.append(f'Row monotonicity violated for Graph={LEVELS[i]}: {parsed[i]}.')

    # Column monotonicity: increasing graph risk must not decrease consequent
    col_mono_ok = True
    for j in range(3):
        if not (parsed[0][j] <= parsed[1][j] <= parsed[2][j]):
            col_mono_ok = False
            errors.append(f'Column monotonicity violated for Lexical={LEVELS[j]}: {[parsed[0][j], parsed[1][j], parsed[2][j]]}.')

    # Boundary alignment with 3-tier UI verdicts
    boundary_ok = bool(parsed[0][0] < 0.35 and parsed[2][2] >= 0.65)
    if not boundary_ok:
        errors.append('Boundary check failed: (low, low) must be < 0.35 and (high, high) must be >= 0.65.')

    # Partition of unity & surface coverage over [0, 1]^2
    partition_ok = True
    coverage_ok = True
    surface_mono_ok = True
    grid = [k / 20.0 for k in range(21)]
    for x in grid:
        if abs(sum(membership(x)) - 1.0) > 1e-9:
            partition_ok = False
            break
    for g_val in grid:
        prev_out = -1.0
        for l_val in grid:
            out, rules = infer(g_val, l_val, custom_consequents=parsed if bounds_ok else DEFAULT_CONSEQUENTS)
            if sum(r['activation'] for r in rules) <= 0.0:
                coverage_ok = False
            if bounds_ok and row_mono_ok and col_mono_ok and out + 1e-9 < prev_out:
                surface_mono_ok = False
            prev_out = out

    if not partition_ok:
        errors.append('Membership functions failed partition-of-unity check.')
    if not coverage_ok:
        errors.append('Rule base has uncovered regions in [0, 1]^2.')

    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'checks': {
            'bounds_in_unit_interval': bounds_ok,
            'row_monotonicity': row_mono_ok,
            'column_monotonicity': col_mono_ok,
            'boundary_verdict_alignment': boundary_ok,
            'partition_of_unity': partition_ok,
            'full_domain_coverage': coverage_ok,
            'surface_monotonicity': surface_mono_ok,
        },
        'matrix': parsed,
    }


def set_active_consequents(matrix, profile_name: str = "custom"):
    global CURRENT_CONSEQUENTS, ACTIVE_PROFILE_NAME
    validation = validate_sugeno_rules(matrix)
    if not validation['valid']:
        raise ValueError('; '.join(validation['errors']))
    CURRENT_CONSEQUENTS = [list(r) for r in validation['matrix']]
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


def binary_class(score, threshold: float = 0.50) -> str:
    """Consistent binary classification label aligned with evaluation metrics."""
    return 'Phishing' if float(score) >= threshold else 'Benign'
