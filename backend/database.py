"""
database.py Ã¢â‚¬â€œ MySQL connection manager & schema initializer.
Primary: MySQL via PyMySQL (pure-Python, no C extensions needed).
Fallback: SQLite for local dev when DB_TYPE=sqlite.
"""

import os
import sqlite3
import logging
from datetime import datetime, timedelta
import random
from dotenv import load_dotenv

_backend_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_backend_dir, '../config/.env'), override=True)

logger = logging.getLogger(__name__)

DB_TYPE = os.getenv('DB_TYPE', 'sqlite')      # 'mysql' | 'postgres' | 'sqlite'
DB_PATH = os.getenv('DB_PATH', 'secureauth.db')

_backend_dir = os.path.dirname(os.path.abspath(__file__))


def _resolve_db_path(db_path: str) -> str:
    if os.path.isabs(db_path):
        return db_path

    # Only use /tmp/ in actual Vercel cloud environments.
    # Avoid VERCEL=1 since `vercel dev` locally will cause disappearing data.
    if os.getenv('VERCEL_ENV') in ['production', 'preview']:
        return os.path.join('/tmp', os.path.basename(db_path))

    return os.path.join(_backend_dir, db_path)


DB_PATH = _resolve_db_path(DB_PATH)


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# Connection
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------

def get_connection():
    """Return a database connection."""
    if DB_TYPE == 'mysql':
        return _mysql_connection()
    if DB_TYPE == 'postgres':
        return _postgres_connection()
    return _sqlite_connection()


def _mysql_connection():
    """Open a PyMySQL connection with DictCursor for dict-style row access."""
    try:
        import pymysql
        import pymysql.cursors
        conn = pymysql.connect(
            host     = os.getenv('DB_HOST', 'localhost'),
            port     = int(os.getenv('DB_PORT', 3306)),
            database = os.getenv('DB_NAME', 'secureauth_db'),
            user     = os.getenv('DB_USER', 'secureauth_user'),
            password = os.getenv('DB_PASSWORD', ''),
            charset  = 'utf8mb4',
            autocommit = False,
            cursorclass = pymysql.cursors.DictCursor,
            connect_timeout = 10,
        )
        logger.debug("MySQL connection established.")
        return conn
    except ImportError:
        logger.error("PyMySQL not installed. Run: pip install PyMySQL")
        raise
    except Exception as exc:
        logger.error("MySQL connection failed: %s", exc)
        raise

def _postgres_connection():
    """Open a Psycopg2 connection with RealDictCursor."""
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(
            host     = os.getenv('PG_HOST', 'localhost'),
            port     = int(os.getenv('PG_PORT', 5432)),
            dbname   = os.getenv('PG_NAME', 'postgres'),
            user     = os.getenv('PG_USER', 'postgres'),
            password = os.getenv('PG_PASSWORD', ''),
            connect_timeout = 10,
            cursor_factory = psycopg2.extras.RealDictCursor
        )
        logger.debug("PostgreSQL connection established.")
        return conn
    except ImportError:
        logger.error("psycopg2-binary not installed. Run: pip install psycopg2-binary")
        raise
    except Exception as exc:
        logger.error("PostgreSQL connection failed: %s", exc)
        raise


def _sqlite_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# Schema – MySQL dialect (also valid for SQLite with minor notes)
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------

# MySQL DDL statements (executed one at a time)
MYSQL_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id              INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username        VARCHAR(80)     NOT NULL UNIQUE,
        email           VARCHAR(255)    NOT NULL UNIQUE,
        password_hash   VARCHAR(255)    NOT NULL,
        role            VARCHAR(20)     NOT NULL DEFAULT 'user',
        is_locked       TINYINT(1)      NOT NULL DEFAULT 0,
        failed_attempts INT             NOT NULL DEFAULT 0,
        locked_until    DATETIME        NULL,
        created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS login_history (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id     INT             NOT NULL,
        ip_address  VARCHAR(45)     NULL,
        device_hash VARCHAR(64)     NULL,
        location    VARCHAR(255)    NULL,
        risk_score  FLOAT           NULL,
        risk_level  VARCHAR(10)     NULL,
        status      VARCHAR(20)     NULL,
        explanation TEXT            NULL,
        timestamp   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS mfa_tokens (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id     INT             NOT NULL,
        otp_hash    VARCHAR(255)    NOT NULL,
        mfa_token   VARCHAR(64)     NOT NULL UNIQUE,
        expires_at  DATETIME        NOT NULL,
        used        TINYINT(1)      NOT NULL DEFAULT 0,
        created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id     INT             NOT NULL,
        token_hash  VARCHAR(64)     NOT NULL UNIQUE,
        expires_at  DATETIME        NOT NULL,
        revoked     TINYINT(1)      NOT NULL DEFAULT 0,
        created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ai_metrics (
        id              INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id         INT             NOT NULL,
        feature_vector  MEDIUMTEXT      NULL,
        model_votes     TEXT            NULL,
        risk_score      FLOAT           NULL,
        risk_level      VARCHAR(10)     NULL,
        confidence      FLOAT           NULL,
        explanation     TEXT            NULL,
        timestamp       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS rate_limit_log (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        ip_address  VARCHAR(45)     NOT NULL,
        endpoint    VARCHAR(100)    NULL,
        timestamp   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]

# PostgreSQL DDL statements
POSTGRES_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id              SERIAL          PRIMARY KEY,
        username        VARCHAR(80)     NOT NULL UNIQUE,
        email           VARCHAR(255)    NOT NULL UNIQUE,
        password_hash   VARCHAR(255)    NOT NULL,
        role            VARCHAR(20)     NOT NULL DEFAULT 'user',
        is_locked       BOOLEAN         NOT NULL DEFAULT FALSE,
        failed_attempts INT             NOT NULL DEFAULT 0,
        locked_until    TIMESTAMP       NULL,
        created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS login_history (
        id          SERIAL          PRIMARY KEY,
        user_id     INT             NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ip_address  VARCHAR(45)     NULL,
        device_hash VARCHAR(64)     NULL,
        location    VARCHAR(255)    NULL,
        risk_score  FLOAT           NULL,
        risk_level  VARCHAR(10)     NULL,
        status      VARCHAR(20)     NULL,
        explanation TEXT            NULL,
        timestamp   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS mfa_tokens (
        id          SERIAL          PRIMARY KEY,
        user_id     INT             NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        otp_hash    VARCHAR(255)    NOT NULL,
        mfa_token   VARCHAR(64)     NOT NULL UNIQUE,
        expires_at  TIMESTAMP       NOT NULL,
        used        BOOLEAN         NOT NULL DEFAULT FALSE,
        created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id          SERIAL          PRIMARY KEY,
        user_id     INT             NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash  VARCHAR(64)     NOT NULL UNIQUE,
        expires_at  TIMESTAMP       NOT NULL,
        revoked     BOOLEAN         NOT NULL DEFAULT FALSE,
        created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ai_metrics (
        id              SERIAL          PRIMARY KEY,
        user_id         INT             NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        feature_vector  TEXT            NULL,
        model_votes     TEXT            NULL,
        risk_score      FLOAT           NULL,
        risk_level      VARCHAR(10)     NULL,
        confidence      FLOAT           NULL,
        explanation     TEXT            NULL,
        timestamp       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS rate_limit_log (
        id          SERIAL          PRIMARY KEY,
        ip_address  VARCHAR(45)     NOT NULL,
        endpoint    VARCHAR(100)    NULL,
        timestamp   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
]

# SQLite fallback schema (single executescript call)
SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'user',
    is_locked       INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS login_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    ip_address  TEXT,
    device_hash TEXT,
    location    TEXT,
    risk_score  REAL,
    risk_level  TEXT,
    status      TEXT,
    explanation TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS mfa_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    otp_hash    TEXT    NOT NULL,
    mfa_token   TEXT    NOT NULL UNIQUE,
    expires_at  TEXT    NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    token_hash  TEXT    NOT NULL UNIQUE,
    expires_at  TEXT    NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ai_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    feature_vector  TEXT,
    model_votes     TEXT,
    risk_score      REAL,
    risk_level      TEXT,
    confidence      REAL,
    explanation     TEXT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS rate_limit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT    NOT NULL,
    endpoint    TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# init_db
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------

def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    try:
        if DB_TYPE == 'mysql':
            cur = conn.cursor()
            for stmt in MYSQL_SCHEMA:
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            conn.commit()
            logger.info("MySQL schema initialised.")
        elif DB_TYPE == 'postgres':
            cur = conn.cursor()
            for stmt in POSTGRES_SCHEMA:
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            conn.commit()
            logger.info("PostgreSQL schema initialised.")
        else:
            conn.executescript(SQLITE_SCHEMA)
            conn.commit()
            logger.info("SQLite database initialised at %s", DB_PATH)
    finally:
        conn.close()


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# Placeholder / query helpers
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------

def ph():
    """Return the correct placeholder for the active DB driver.
    MySQL uses %s, SQLite uses ?.
    """
    return '%s' if DB_TYPE in ('mysql', 'postgres') else '?'


def execute(conn, query, params=()):
    try:
        # Simple placeholder translation for PyMySQL and PostgreSQL compatibility
        if DB_TYPE in ('mysql', 'postgres') and '?' in query:
            query = query.replace('?', '%s')
        
        cur = conn.cursor()
        cur.execute(query, params)
        return cur
    except Exception as exc:
        logger.error("Query execution failed: %s", exc)
        raise


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# Row – dict helper
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------

def dict_from_row(row) -> dict | None:
    """Normalise a row to a plain dict regardless of driver."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    if isinstance(row, sqlite3.Row):
        return dict(row)
    # Fallback (e.g. tuple): shouldn't happen with DictCursor
    return dict(row)


def hash_token(token: str) -> str:
    """SHA-256 hash for token storage."""
    return hashlib.sha256(token.encode()).hexdigest()


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
# Seed demo data
# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

def seed_demo_data():
    """Insert demo users + calibrated per-user login history if the DB is empty."""
    import bcrypt
    import random
    import hashlib as _hl
    from datetime import timedelta

    conn = get_connection()
    try:
        cur = execute(conn, "SELECT COUNT(*) AS cnt FROM users")
        row = cur.fetchone()
        count = dict_from_row(row).get('cnt', 0) if row else 0
        if count > 0:
            logger.info("Demo data already present Ã¢â‚¬â€œ skipping seed.")
            return

        users = [
            ('alice',   'alice@demo.com',   'SecurePass123!', 'user', 240),
            ('bob',     'bob@demo.com',     'Pass@2024',       'user', 90),
            ('charlie', 'charlie@demo.com', 'Admin@999',       'user', 400),
            ('admin',   'admin@demo.com',   'AdminSecure1!',   'admin', 365),
        ]

        now = datetime.utcnow()
        for uname, email, pwd, role, age_days in users:
            pw_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            created_at = (now - timedelta(days=age_days)).strftime('%Y-%m-%d %H:%M:%S')
            execute(
                conn,
                "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                (uname, email, pw_hash, role, created_at)
            )
        conn.commit()

        cur = execute(conn, "SELECT id, username FROM users")
        db_users = cur.fetchall()

        # Ã¢â€â‚¬Ã¢â€â‚¬ Per-user seed profiles Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #
        # device_hash:
        #   LOW users  Ã¢â€ â€™ '' (empty) so device_change = 0 on any real login
        #              (condition: current != last AND last != '' Ã¢â€ â€™ False when last == '')
        #   HIGH user  Ã¢â€ â€™ random 8-char hex so device_change = 1 (always new device)
        #
        # location:
        #   LOW users  Ã¢â€ â€™ 'Unknown, IN' matches the frontend default
        #              Ã¢â€ â€™ location_change = 0 on login
        #   HIGH user  Ã¢â€ â€™ foreign cities Ã¢â€ â€™ location_change = 1
        #
        # status / scores calibrated so fail_ratio drives differentiation:
        #   alice  Ã¢â€ â€™ all 'allowed' (fail_ratio Ã¢â€°Ë† 0.00) Ã¢â€ â€™ LOW
        #   bob    Ã¢â€ â€™ mix of mfa/allowed (fail_ratio Ã¢â€°Ë† 0.0Ã¢â‚¬â€œ0.10) Ã¢â€ â€™ MEDIUM context
        #   charlieÃ¢â€ â€™ mostly 'blocked' (fail_ratio Ã¢â€°Ë† 0.65+) Ã¢â€ â€™ HIGH
        #   admin  Ã¢â€ â€™ all 'allowed' like alice Ã¢â€ â€™ LOW

        def _rnd_hex8():
            return _hl.md5(str(random.random()).encode()).hexdigest()[:8]

        _profiles = {
            'alice': {
                'location_pool': ['Unknown, IN'],
                'device_pool':   [''],
                'score_lo': 5, 'score_hi': 28,
                'recent_hours': (4, 8),
                'history_hours': (24, 720),
            },
            'bob': {
                'location_pool': ['Unknown, IN'],
                'device_pool':   [''],
                'score_lo': 35, 'score_hi': 75,
                'recent_hours': (18, 32),
                'history_hours': (48, 720),
            },
            'charlie': {
                'location_pool': ['London, UK', 'Moscow, RU', 'Sao Paulo, BR',
                                   'Lagos, NG', 'Frankfurt, DE'],
                'device_pool':   [_rnd_hex8() for _ in range(6)],
                'score_lo': 68, 'score_hi': 94,
                'recent_hours': (96, 144),
                'history_hours': (120, 720),
            },
            'admin': {
                'location_pool': ['Unknown, IN'],
                'device_pool':   [''],
                'score_lo': 4, 'score_hi': 22,
                'recent_hours': (4, 8),
                'history_hours': (24, 720),
            },
        }

        local_ips = ['192.168.1.{}'.format(i) for i in range(10, 50)]

        for row in db_users:
            row_d = dict_from_row(row)
            uid   = row_d['id']
            uname = row_d['username']
            prof  = _profiles.get(uname, _profiles['alice'])

            lo = prof['score_lo']
            hi = prof['score_hi']

            # Seed 24 historical logins spread over the past 30 days
            for i in range(24):
                hist_lo, hist_hi = prof['history_hours']
                hours_ago = random.randint(hist_lo, hist_hi)
                ts    = now - timedelta(hours=hours_ago)
                score = random.uniform(lo, hi)
                rlvl  = 'LOW' if score < 40 else ('MEDIUM' if score < 70 else 'HIGH')
                status = 'allowed' if score < 40 else ('mfa_required' if score < 70 else 'blocked')
                execute(
                    conn,
                    """INSERT INTO login_history
                       (user_id, ip_address, device_hash, location,
                        risk_score, risk_level, status, timestamp)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (uid,
                     random.choice(local_ips),
                     random.choice(prof['device_pool']),
                     random.choice(prof['location_pool']),
                     round(score, 1),
                     rlvl,
                     status,
                     ts.strftime('%Y-%m-%d %H:%M:%S'))
                )

            # Seed 1 very-recent login that will be history[0]
            # This is the critical entry compared against the live login
            recent_h_lo, recent_h_hi = prof['recent_hours']
            recent_ts = now - timedelta(hours=random.uniform(recent_h_lo, recent_h_hi))
            recent_score = random.uniform(lo, hi)
            recent_rlvl  = 'LOW' if recent_score < 40 else ('MEDIUM' if recent_score < 70 else 'HIGH')
            recent_status = 'allowed' if recent_score < 40 else ('mfa_required' if recent_score < 70 else 'blocked')
            execute(
                conn,
                """INSERT INTO login_history
                   (user_id, ip_address, device_hash, location,
                    risk_score, risk_level, status, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (uid,
                 '127.0.0.1',
                 # LOW users: empty device_hash Ã¢â€ â€™ device_change = 0 on any login
                 # HIGH/MED users: real hex Ã¢â€ â€™ device_change = 1
                 '' if prof['device_pool'][0] == '' else _rnd_hex8(),
                 # LOW users: 'Unknown, IN' matches frontend default Ã¢â€ â€™ location_change = 0
                 # HIGH users: foreign city Ã¢â€ â€™ location_change = 1
                 prof['location_pool'][0],
                 round(recent_score, 1),
                 recent_rlvl,
                 recent_status,
                 recent_ts.strftime('%Y-%m-%d %H:%M:%S'))
            )

        conn.commit()
        logger.info("Demo data seeded successfully.")
    finally:
        conn.close()



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    init_db()
    seed_demo_data()
    print("Database ready.")
