"""Dataset validation, schema enforcement, class distribution analysis, and metadata persistence."""
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from .features import parse_url

MAX_DATASET_ROWS = 5000
MIN_DATASET_ROWS = 40

def validate_and_register_dataset(file_stream_or_path, filename, datasets_dir, source_note='User upload'):
    """
    Validate a labeled CSV file.
    Does NOT make network calls, DNS lookups, or fetch URLs.
    """
    datasets_dir = Path(datasets_dir)
    datasets_dir.mkdir(parents=True, exist_ok=True)

    if isinstance(file_stream_or_path, (str, Path)):
        content_bytes = Path(file_stream_or_path).read_bytes()
    elif isinstance(file_stream_or_path, (bytes, bytearray)):
        content_bytes = bytes(file_stream_or_path)
    else:
        content_bytes = file_stream_or_path.read()

    if len(content_bytes) > 10 * 1024 * 1024:
        raise ValueError('Dataset file exceeds maximum allowed size of 10 MB.')

    sha256 = hashlib.sha256(content_bytes).hexdigest()
    text = content_bytes.decode('utf-8-sig', errors='replace')
    lines = text.splitlines()

    if not lines:
        raise ValueError('Uploaded CSV file is completely empty.')

    reader = csv.DictReader(lines)
    fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
    if not {'url', 'label'}.issubset(set(fieldnames)):
        raise ValueError("CSV header must contain 'url' and 'label' columns (comma-separated).")

    valid_rows = {}
    errors = []
    seen_urls = {}
    class_0_hosts = set()
    class_1_hosts = set()

    for line_num, row in enumerate(reader, 2):
        raw_url = (row.get('url') or row.get('URL') or '').strip()
        raw_lbl = (row.get('label') or row.get('LABEL') or '').strip()

        if not raw_url:
            errors.append({'line': line_num, 'error': 'Missing URL value'})
            continue
        if raw_lbl not in ('0', '1'):
            errors.append({'line': line_num, 'error': f"Invalid label '{raw_lbl}'; expected 0 (benign) or 1 (phishing)"})
            continue

        lbl = int(raw_lbl)
        try:
            canonical, host = parse_url(raw_url)
        except Exception as e:
            errors.append({'line': line_num, 'error': f"Malformed URL syntax: {str(e)}"})
            continue

        if canonical in seen_urls and seen_urls[canonical] != lbl:
            raise ValueError(f"Conflicting labels detected on row {line_num} for URL '{canonical}'.")

        seen_urls[canonical] = lbl
        valid_rows[canonical] = (host, lbl)
        if lbl == 0:
            class_0_hosts.add(host)
        else:
            class_1_hosts.add(host)

        if len(valid_rows) > MAX_DATASET_ROWS:
            raise ValueError(f"Dataset exceeds the dense RBF prototype limit of {MAX_DATASET_ROWS} unique URLs.")

    if len(valid_rows) < MIN_DATASET_ROWS:
        raise ValueError(f"Dataset must have at least {MIN_DATASET_ROWS} unique valid URLs (found {len(valid_rows)}).")

    n_benign = sum(1 for _, l in valid_rows.values() if l == 0)
    n_phish = sum(1 for _, l in valid_rows.values() if l == 1)

    if n_benign == 0 or n_phish == 0:
        raise ValueError('Dataset must contain samples from both classes (0 = benign, 1 = phishing).')

    if len(class_0_hosts) < 3 or len(class_1_hosts) < 3:
        raise ValueError('Dataset must include at least 3 distinct hostnames per class for valid cross-validation.')

    # Check for domain overlap between classes (e.g., compromised legitimate host vs benign)
    overlap_hosts = sorted(list(class_0_hosts.intersection(class_1_hosts)))

    clean_stem = Path(filename).stem.replace(' ', '_').lower()
    dataset_id = f"{clean_stem}_{sha256[:8]}"
    save_csv_path = datasets_dir / f"{dataset_id}.csv"
    save_meta_path = datasets_dir / f"{dataset_id}.json"

    # Write normalized, sanitized CSV
    with save_csv_path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for u, (_, lbl) in sorted(valid_rows.items()):
            writer.writerow([u, lbl])

    metadata = {
        'id': dataset_id,
        'filename': filename,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'sha256': sha256,
        'size_bytes': len(content_bytes),
        'source_note': source_note,
        'total_rows_submitted': len(lines) - 1,
        'unique_valid_urls': len(valid_rows),
        'validation_errors_count': len(errors),
        'validation_errors_sample': errors[:10],
        'class_distribution': {
            'benign_count': n_benign,
            'phishing_count': n_phish,
            'phishing_ratio': round(n_phish / len(valid_rows), 4)
        },
        'hosts_summary': {
            'unique_benign_hosts': len(class_0_hosts),
            'unique_phishing_hosts': len(class_1_hosts),
            'cross_class_host_overlap_count': len(overlap_hosts),
            'overlap_hosts_sample': overlap_hosts[:5]
        },
        'warnings': [
            'URLs were validated purely as text strings; no outbound HTTP, DNS, or socket calls were performed.',
            'Holdout splits grouped by exact hostname may still have data leakage if sibling subdomains or shared campaigns exist.',
            'Heuristic thresholds in fuzzy inference are not tuned to this specific dataset.'
        ]
    }

    save_meta_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return metadata

def list_datasets(datasets_dir, default_csv=None):
    datasets_dir = Path(datasets_dir)
    datasets_dir.mkdir(parents=True, exist_ok=True)
    items = []

    # Include default demo dataset if present
    if default_csv and Path(default_csv).exists():
        p = Path(default_csv)
        items.append({
            'id': 'demo_synthetic',
            'filename': p.name,
            'created_at': 'System default',
            'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
            'source_note': 'Synthetic demo data on reserved .test domains',
            'unique_valid_urls': 480,
            'class_distribution': {'benign_count': 240, 'phishing_count': 240, 'phishing_ratio': 0.5},
            'is_synthetic': True
        })

    for meta_file in sorted(datasets_dir.glob('*.json'), reverse=True):
        try:
            info = json.loads(meta_file.read_text(encoding='utf-8'))
            info['is_synthetic'] = False
            items.append(info)
        except Exception:
            continue
    return items
