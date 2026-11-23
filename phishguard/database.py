"""Persistent SQLite storage with migrations, search, pagination, and privacy safeguards."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 2

def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn, conn:
        cursor = conn.cursor()
        # Ensure schema_version table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schema_info (
                key TEXT PRIMARY KEY,
                val TEXT
            )
        ''')
        # Base table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                risk REAL NOT NULL,
                verdict TEXT NOT NULL,
                graph_score REAL DEFAULT 0,
                lexical_score REAL DEFAULT 0,
                model_version TEXT DEFAULT 'v1-demo',
                scan_type TEXT DEFAULT 'single',
                signals_json TEXT DEFAULT '[]',
                features_json TEXT DEFAULT '{}',
                created TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Check existing columns in scans table to migrate smoothly if created by older version
        cursor.execute("PRAGMA table_info(scans)")
        cols = {row[1] for row in cursor.fetchall()}
        add_cols = {
            'graph_score': 'REAL DEFAULT 0',
            'lexical_score': 'REAL DEFAULT 0',
            'model_version': "TEXT DEFAULT 'v1-demo'",
            'scan_type': "TEXT DEFAULT 'single'",
            'signals_json': "TEXT DEFAULT '[]'",
            'features_json': "TEXT DEFAULT '{}'",
            'triage_status': "TEXT DEFAULT 'Unreviewed'",
            'triage_notes': "TEXT DEFAULT ''"
        }
        for col_name, col_type in add_cols.items():
            if col_name not in cols:
                cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")

        # Indices for efficient querying
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)")
        cursor.execute("INSERT OR REPLACE INTO schema_info (key, val) VALUES ('version', ?)", (str(SCHEMA_VERSION),))

def insert_scan(db_path, host, risk, verdict, graph_score=0, lexical_score=0,
                model_version='v1-demo', scan_type='single', signals=None, features=None):
    """
    Record scan summary. Sensitive credentials, query parameters, and URL paths
    are NEVER persisted here to guarantee user privacy.
    """
    signals_str = json.dumps(signals or [])
    features_str = json.dumps(features or {})
    created_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    with closing(sqlite3.connect(db_path)) as conn, conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (host, risk, verdict, graph_score, lexical_score,
                               model_version, scan_type, signals_json, features_json, created)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (host, float(risk), verdict, float(graph_score), float(lexical_score),
              model_version, scan_type, signals_str, features_str, created_utc))
        scan_id = cursor.lastrowid
        # Bound retained history to 1000 items
        cursor.execute('''
            DELETE FROM scans WHERE id NOT IN (
                SELECT id FROM scans ORDER BY id DESC LIMIT 1000
            )
        ''')
        return scan_id

def query_history(db_path, query=None, verdict_filter=None, scan_type=None,
                  sort_by='id', sort_dir='desc', page=1, per_page=20):
    page = max(1, int(page))
    per_page = min(100, max(1, int(per_page)))
    offset = (page - 1) * per_page

    where_clauses = []
    params = []

    if query and query.strip():
        where_clauses.append("host LIKE ?")
        params.append(f"%{query.strip().lower()}%")

    if verdict_filter and verdict_filter.strip() and verdict_filter.lower() != 'all':
        where_clauses.append("LOWER(verdict) = ?")
        params.append(verdict_filter.strip().lower())

    if scan_type and scan_type.strip() and scan_type.lower() != 'all':
        where_clauses.append("LOWER(scan_type) = ?")
        params.append(scan_type.strip().lower())

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    allowed_sort_cols = {'id', 'created', 'risk', 'host', 'graph_score', 'lexical_score'}
    sort_col = sort_by if sort_by in allowed_sort_cols else 'id'
    sort_direction = 'ASC' if str(sort_dir).lower() == 'asc' else 'DESC'

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Count total
        count_sql = f"SELECT COUNT(*) as total FROM scans{where_sql}"
        cursor.execute(count_sql, params)
        total_rows = cursor.fetchone()['total']

        # Select rows
        select_sql = f'''
            SELECT id, host, risk, verdict, graph_score, lexical_score,
                   model_version, scan_type, signals_json, features_json, created
            FROM scans{where_sql}
            ORDER BY {sort_col} {sort_direction}
            LIMIT ? OFFSET ?
        '''
        cursor.execute(select_sql, params + [per_page, offset])
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            try:
                d['signals'] = json.loads(d['signals_json'])
            except Exception:
                d['signals'] = []
            try:
                d['features'] = json.loads(d['features_json'])
            except Exception:
                d['features'] = {}
            rows.append(d)

    total_pages = max(1, (total_rows + per_page - 1) // per_page)
    return {
        'items': rows,
        'total': total_rows,
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages
    }

def get_scan_by_id(db_path, scan_id):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d['signals'] = json.loads(d['signals_json'])
        except Exception:
            d['signals'] = []
        try:
            d['features'] = json.loads(d['features_json'])
        except Exception:
            d['features'] = {}
        return d

def clear_all_history(db_path):
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute('DELETE FROM scans')
    return True

def delete_scan_record(db_path, scan_id):
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    return True

def update_scan_triage(db_path, scan_id, status='Confirmed Phishing', notes=''):
    """Updates the analyst triage disposition and investigation notes for a scan."""
    with closing(sqlite3.connect(db_path)) as conn, conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scans
            SET triage_status = ?, triage_notes = ?
            WHERE id = ?
        ''', (status, notes, scan_id))
        return cursor.rowcount > 0

def get_triage_queue(db_path, status=None, limit=50):
    """Fetches high priority scans for the SOC alert triage queue."""
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if status and status != 'all':
            cursor.execute('''
                SELECT * FROM scans WHERE triage_status = ? ORDER BY id DESC LIMIT ?
            ''', (status, limit))
        else:
            cursor.execute('''
                SELECT * FROM scans ORDER BY risk DESC, id DESC LIMIT ?
            ''', (limit,))
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            try:
                d['signals'] = json.loads(d['signals_json'])
            except Exception:
                d['signals'] = []
            rows.append(d)
        return rows
