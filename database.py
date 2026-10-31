import sqlite3, threading, json, os, time

DB_FILE = os.environ.get("DB_PATH", "agents_v4.db")
db_lock = threading.RLock()
_locks, _master = {}, threading.Lock()

def lock_for(key):
    with _master:
        if key not in _locks:
            _locks[key] = threading.Lock()
        return _locks[key]

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

conn = get_db()
with db_lock:
    conn.executescript('''
    -- Task 2: A2A Invoice Storage
    CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, principal TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS msgs (
        principal TEXT,
        mid TEXT,
        hash TEXT,
        task_id TEXT,
        created_at REAL,
        PRIMARY KEY(principal, mid)
    );
    CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT);

    -- Task 3: Mailroom Storage
    CREATE TABLE IF NOT EXISTS mailroom_evals (
        eval_id TEXT PRIMARY KEY,
        req_hash TEXT,
        verifier_jwk TEXT,
        input_digest TEXT,
        proposals_json TEXT,
        response_json TEXT
    );

    -- Task 4: Incident Triage Storage
    CREATE TABLE IF NOT EXISTS incident_runs (
        run_id TEXT PRIMARY KEY,
        request_hash TEXT,
        state_json TEXT
    );
    CREATE TABLE IF NOT EXISTS incident_receipts (
        receipt_key TEXT PRIMARY KEY,
        receipt_hash TEXT,
        response_json TEXT
    );
    ''')
    conn.commit()

def q(sql, args=()):
    with db_lock:
        c = conn.cursor()
        c.execute(sql, args)
        conn.commit()
        return c.fetchall()

def tx(statements):
    with db_lock:
        try:
            c = conn.cursor()
            for sql, args in statements:
                c.execute(sql, args)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
