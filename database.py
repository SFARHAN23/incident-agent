import sqlite3, threading, json, os

DB_FILE = os.environ.get("DB_PATH", "agents_v2.db")
db_lock = threading.RLock()

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

conn = get_db()
with db_lock:
    conn.executescript('''
    -- A2A Invoice Storage
    CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, principal TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS msgs (principal TEXT, mid TEXT, hash TEXT, task_id TEXT, PRIMARY KEY(principal, mid));
    CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT);

    -- Incident Agent v2 Storage
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

    -- Mailroom Storage
    CREATE TABLE IF NOT EXISTS mailroom_cases (
        case_id TEXT PRIMARY KEY,
        principal TEXT,
        decision TEXT,
        status TEXT,
        receipt_token TEXT,
        executed INTEGER DEFAULT 0
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
