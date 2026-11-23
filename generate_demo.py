"""Generate synthetic examples on reserved .test domains; not real threat data."""
import csv
from pathlib import Path

def generate(path='data/demo.csv'):
    rows = []
    for i in range(80):
        name = f'cedar{i}'
        rows.extend([
            (f'https://{name}.test/catalog/item/{i}', 0),
            (f'https://{name}.test/account/login', 0),
            (f'http://archive{i}.test/articles/{i}?page=2', 0),
            (f'http://secure-verify-{i}.wallet.account.test/login/password?update={i}', 1),
            (f'https://bank-update-{i}.test/verify/account?session={i}abc123', 1),
            (f'https://trusted.test@verify-wallet-{i}.test/secure/login', 1),
        ])
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        writer.writerows(rows)
    return path

if __name__ == '__main__':
    print(generate())
