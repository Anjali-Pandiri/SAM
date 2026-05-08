"""
app.py  —  CfA Software Health Monitor
=======================================
This is the MAIN APPLICATION — a Flask web server that acts as
a simulated enterprise software system (like the kind a SysAdmin manages).

WHAT IS FLASK?
Flask is a Python web framework. A "web framework" is a library
that lets you build web servers — programs that listen for HTTP
requests (like when you visit a website) and send back responses.

WHAT IS AN HTTP REQUEST?
When you type a URL in your browser, your browser sends an HTTP request
to a server. The server runs code and sends back HTML, JSON, or data.

WHY FLASK?
- Lightweight: easy to understand, not much boilerplate
- Industry standard for Python web apps
- Used by NASA, Netflix, LinkedIn
- Perfect for REST APIs (Application Programming Interfaces)
"""

# ── IMPORTS ────────────────────────────────────────────────────────────────────
# Each "import" line loads a module (a library of pre-written code).
# Without imports, you'd have to write everything from scratch.

from flask import Flask, jsonify, request  
# Flask    = the web framework class itself
# jsonify  = converts Python dicts to JSON responses (the language of APIs)
# request  = lets us read data from incoming HTTP requests

import sqlite3    
# sqlite3 = Python's built-in module for SQLite databases
# SQLite is a file-based database — no separate database server needed
# Perfect for learning and small production apps

import datetime   
# datetime = module for working with dates and times
# We use this to record WHEN events happen (timestamps)

import platform   
# platform = module that reads information about the OS/system we're running on
# e.g., Linux vs Windows, Python version, CPU info

import psutil     
# psutil = "process utilities" — reads real CPU, memory, disk usage
# This is a THIRD-PARTY library (must be installed via pip install psutil)
# It talks directly to the operating system to get hardware metrics

import os         
# os = operating system module
# Lets Python interact with the OS: read env variables, file paths, etc.

import hashlib    
# hashlib = cryptographic hashing library
# A hash is a one-way fingerprint of data — you can't reverse it
# Used for storing passwords SAFELY (never store plain text passwords!)

import secrets    
# secrets = cryptographically secure random number generator
# Used for generating API tokens and session keys
# More secure than the regular "random" module

import logging    
# logging = Python's built-in logging system
# Instead of print() statements, professional code uses logging
# Logs can go to files, databases, monitoring systems

# ── LOGGING SETUP ──────────────────────────────────────────────────────────────
# Configure logging BEFORE anything else runs
# This is industry standard practice — always set up logging first

logging.basicConfig(
    # basicConfig() sets the global logging configuration
    
    level=logging.INFO,
    # level=INFO means: record INFO, WARNING, ERROR, CRITICAL messages
    # DEBUG < INFO < WARNING < ERROR < CRITICAL  (left=least severe)
    # We skip DEBUG for cleaner output in production
    
    format='%(asctime)s | %(levelname)s | %(message)s',
    # format= defines how each log line looks
    # %(asctime)s   = current date/time  →  2026-01-15 10:30:45,123
    # %(levelname)s = severity level     →  INFO
    # %(message)s   = the actual message →  Server started
    
    handlers=[
        logging.FileHandler('/app/logs/app.log'),
        # FileHandler = writes logs to a FILE
        # /app/logs/app.log is the path inside our Docker container
        
        logging.StreamHandler()
        # StreamHandler = also prints logs to the terminal (stdout)
        # Having BOTH is best practice: file for permanent record, terminal for live watching
    ]
)

logger = logging.getLogger(__name__)
# getLogger(__name__) creates a logger named after this file
# __name__ is a Python special variable containing the module name
# "app" in this case — helps identify which file produced a log message


# ── FLASK APP INITIALIZATION ───────────────────────────────────────────────────
app = Flask(__name__)
# Flask(__name__) creates the Flask application instance
# __name__ tells Flask where to find templates and static files
# "app" is the conventional variable name — this object handles ALL requests


# ── DATABASE INITIALIZATION ────────────────────────────────────────────────────
DB_PATH = '/app/db/monitor.db'
# This is the file path for our SQLite database
# In Docker, /app/ is inside the container (mapped to our host directory)

def init_db():
    """
    Creates the database tables if they don't exist yet.
    
    WHAT IS A DATABASE?
    A database is organized storage for data that persists (survives restarts).
    Unlike variables in memory, database data survives when the program stops.
    
    WHAT IS SQL?
    SQL = Structured Query Language
    It's the language used to talk to relational databases.
    "Relational" means data is organized in tables (rows and columns).
    
    WHAT IS SQLite?
    SQLite stores the entire database in ONE file (monitor.db).
    No server needed — Python talks to the file directly.
    Perfect for: development, small apps, embedded systems.
    
    WHAT IS A CONTEXT MANAGER (with statement)?
    "with sqlite3.connect(...) as conn:" is a context manager.
    It AUTOMATICALLY closes the database connection when done,
    even if an error occurs. This prevents resource leaks.
    """
    
    with sqlite3.connect(DB_PATH) as conn:
        # sqlite3.connect(DB_PATH) opens (or creates) the database file
        # conn = "connection" object — our pipeline to the database
        
        cursor = conn.cursor()
        # cursor() creates a cursor — an object that executes SQL commands
        # Think of a cursor like a "pen" that writes SQL to the database
        
        # ── TABLE 1: SOFTWARE INVENTORY ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS software_inventory (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                version     TEXT    NOT NULL,
                status      TEXT    DEFAULT 'active',
                installed   TEXT    NOT NULL,
                last_patch  TEXT,
                notes       TEXT
            )
        ''')
        # CREATE TABLE IF NOT EXISTS = only create if it doesn't already exist
        # This prevents errors when running the app multiple times
        # 
        # Column definitions:
        # id INTEGER PRIMARY KEY AUTOINCREMENT  = unique auto-numbered ID
        # TEXT NOT NULL = text field that cannot be empty
        # TEXT DEFAULT 'active' = text field, defaults to 'active' if not given
        #
        # This table tracks enterprise software installed on systems
        # (like Oracle ERP, Google Workspace, MS Teams, Slack)
        
        # ── TABLE 2: HEALTH LOGS ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS health_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                cpu_percent REAL,
                mem_percent REAL,
                disk_percent REAL,
                status      TEXT
            )
        ''')
        # REAL = floating point number (like 45.7 for CPU %)
        # This table stores snapshots of system health over time
        # Used for trending and identifying performance degradation
        
        # ── TABLE 3: AUDIT LOG ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                action    TEXT    NOT NULL,
                user      TEXT,
                details   TEXT,
                ip_addr   TEXT
            )
        ''')
        # ITIL PRINCIPLE: Every action on enterprise systems must be logged
        # This is the CHANGE LOG — required for security audits
        # Who did what, when, from where
        
        # ── TABLE 4: API TOKENS (SECURITY) ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT    NOT NULL UNIQUE,
                username   TEXT    NOT NULL,
                created    TEXT    NOT NULL,
                expires    TEXT,
                active     INTEGER DEFAULT 1
            )
        ''')
        # We store the HASH of the token, never the token itself
        # UNIQUE = no two rows can have the same token_hash
        # active INTEGER = 0 (false) or 1 (true) — SQLite has no boolean type
        
        conn.commit()
        # commit() = SAVES all the CREATE TABLE commands
        # In SQL, changes aren't permanent until you commit()
        # This is called a "transaction" — all or nothing
        
        # Seed initial data
        _seed_initial_data(cursor, conn)
    
    logger.info("Database initialized successfully")


def _seed_initial_data(cursor, conn):
    """
    Adds sample data if the software_inventory table is empty.
    
    "Seeding" a database means populating it with initial/example data.
    This simulates an enterprise environment with real software names.
    """
    
    cursor.execute("SELECT COUNT(*) FROM software_inventory")
    # SELECT COUNT(*) = count how many rows exist
    # This returns a tuple like (5,) meaning 5 rows exist
    
    count = cursor.fetchone()[0]
    # fetchone() = get the first (and only) result row
    # [0] = get the first element of that tuple (the number)
    
    if count == 0:
        # Only add seed data if the table is empty
        
        software_list = [
            # Each tuple = one row of data
            # Format: (name, version, status, installed_date, last_patch, notes)
            ('Oracle ERP',         '19c',    'active',   '2024-01-15', '2026-01-01', 'Financial and HR system'),
            ('Google Workspace',   '2024.1', 'active',   '2023-06-01', '2026-01-10', 'Email, Docs, Drive, Meet'),
            ('Microsoft Teams',    '24.12',  'active',   '2023-06-01', '2026-01-08', 'Video conferencing'),
            ('Slack',              '4.35',   'active',   '2022-03-15', '2025-12-15', 'Team messaging'),
            ('JIRA',               '9.4',    'active',   '2023-01-10', '2025-11-20', 'Project tracking'),
            ('Legacy FITS System', '2.1',    'legacy',   '2018-05-01', '2023-06-01', 'Astronomy data format — EOL'),
            ('Zabbix Monitor',     '6.4',    'active',   '2024-02-01', '2026-01-05', 'Infrastructure monitoring'),
        ]
        
        cursor.executemany(
            "INSERT INTO software_inventory (name, version, status, installed, last_patch, notes) VALUES (?,?,?,?,?,?)",
            software_list
        )
        # executemany() = runs the same INSERT command for each item in software_list
        # ? marks are PLACEHOLDERS — they get replaced safely with actual values
        # WHY PLACEHOLDERS? They prevent SQL Injection attacks
        # SQL Injection = when malicious data can modify the SQL query itself
        # Placeholders ensure data is treated as DATA not as SQL code
        
        conn.commit()
        logger.info("Seeded initial software inventory data")


# ── HELPER: AUTHENTICATION MIDDLEWARE ─────────────────────────────────────────
def require_api_key(func):
    """
    A DECORATOR that protects API endpoints with token authentication.
    
    WHAT IS A DECORATOR?
    A decorator is a function that WRAPS another function, adding behavior
    before or after the original function runs.
    
    Syntax: @require_api_key above a function means:
    "run this function THROUGH require_api_key first"
    
    WHAT IS API KEY AUTHENTICATION?
    Instead of username/password for every request, the client sends
    a secret token in the request header.
    The server checks if the token is valid before proceeding.
    
    This is how most real APIs work (GitHub, AWS, Snowflake all use tokens).
    """
    
    from functools import wraps
    # functools.wraps preserves the original function's name and docstring
    # Without it, all decorated functions would appear to be named "wrapper"
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        # *args    = any positional arguments (passed through to original func)
        # **kwargs = any keyword arguments (passed through to original func)
        
        token = request.headers.get('X-API-Key')
        # request.headers is a dict-like object of HTTP headers
        # HTTP headers are metadata sent with every request
        # X-API-Key is a custom header — the "X-" prefix means "custom/extended"
        # .get() returns None if the header doesn't exist (safer than ['key'])
        
        if not token:
            return jsonify({'error': 'API key required', 'status': 401}), 401
            # If no token provided, return 401 Unauthorized
            # HTTP status codes: 200=OK, 401=Unauthorized, 403=Forbidden, 404=Not Found
        
        # Hash the provided token and check if it exists in the database
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        # hashlib.sha256() = SHA-256 cryptographic hash function
        # SHA-256 always produces a 64-character hex string from any input
        # .encode() = converts the string to bytes (sha256 requires bytes)
        # .hexdigest() = returns the hash as a readable hex string
        # 
        # WHY HASH? If someone steals our database, they get hashes, not real tokens
        # SHA-256 is a ONE-WAY function — impossible to reverse-engineer the token
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username FROM api_tokens WHERE token_hash=? AND active=1",
                (token_hash,)
                # (token_hash,) is a tuple with one element
                # The trailing comma makes it a tuple — Python quirk
            )
            row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'Invalid or expired token', 'status': 401}), 401
        
        return func(*args, **kwargs)
        # Token is valid — proceed to the actual function
    
    return wrapper


# ── ROUTE: HOME ────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    """
    WHAT IS A ROUTE?
    A route maps a URL path to a Python function.
    
    @app.route('/') means: "when someone visits http://localhost:5000/,
    run the home() function and return its result"
    
    The @app.route decorator registers this function with Flask's URL router.
    """
    return jsonify({
        'service': 'CfA Software Health Monitor',
        'version': '1.0.0',
        'status': 'operational',
        'description': 'Enterprise software administration and monitoring system',
        'docs': '/api/docs',
        'endpoints': {
            'health':    'GET /api/health',
            'inventory': 'GET /api/software',
            'metrics':   'GET /api/metrics',
            'audit':     'GET /api/audit',
            'token':     'POST /api/token'
        }
    })


# ── ROUTE: HEALTH CHECK ────────────────────────────────────────────────────────
@app.route('/api/health')
def health_check():
    """
    Returns real-time system health metrics using psutil.
    
    HEALTH CHECKS are standard in enterprise software management.
    Load balancers and monitoring tools (like Zabbix, Prometheus, Nagios)
    ping this endpoint regularly to check if the service is alive.
    
    WHAT IS AN API?
    API = Application Programming Interface
    It's a contract: "send me data in THIS format, I'll respond in THAT format"
    REST APIs use HTTP verbs: GET (read), POST (create), PUT (update), DELETE (remove)
    """
    
    # psutil calls — these talk directly to the operating system kernel
    cpu    = psutil.cpu_percent(interval=0.1)
    # cpu_percent() measures CPU usage percentage over the given interval
    # interval=0.1 means: measure for 0.1 seconds, return the average
    
    memory = psutil.virtual_memory()
    # virtual_memory() returns an object with:
    # .total, .available, .used, .percent, etc.
    
    disk   = psutil.disk_usage('/')
    # disk_usage('/') checks the root filesystem
    # In Docker on Linux, '/' is the root of the container filesystem
    
    now    = datetime.datetime.utcnow().isoformat()
    # utcnow() = current UTC time (Coordinated Universal Time)
    # WHY UTC? Enterprise systems ALWAYS use UTC to avoid timezone confusion
    # isoformat() = "2026-01-15T10:30:45.123456" — ISO 8601 standard format
    
    # Determine overall status
    status = 'healthy'
    if cpu > 90 or memory.percent > 90 or disk.percent > 90:
        status = 'critical'
    elif cpu > 75 or memory.percent > 75 or disk.percent > 80:
        status = 'warning'
    
    metrics = {
        'timestamp': now,
        'status': status,
        'system': {
            'os':       platform.system(),    # e.g., "Linux"
            'python':   platform.python_version(),  # e.g., "3.11.5"
            'hostname': platform.node(),      # container hostname
        },
        'cpu': {
            'percent': cpu,
            'cores':   psutil.cpu_count()     # logical CPU cores
        },
        'memory': {
            'total_gb':   round(memory.total   / (1024**3), 2),
            # 1024**3 = 1,073,741,824 bytes = 1 GB
            # Dividing bytes by 1024^3 converts to gigabytes
            'used_gb':    round(memory.used    / (1024**3), 2),
            'percent':    memory.percent
        },
        'disk': {
            'total_gb':  round(disk.total / (1024**3), 2),
            'used_gb':   round(disk.used  / (1024**3), 2),
            'percent':   disk.percent
        }
    }
    
    # Log this health check to the database for trending
    _log_health(metrics)
    
    return jsonify(metrics)


def _log_health(metrics):
    """Persists health snapshot to database for historical trending."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO health_logs (timestamp, cpu_percent, mem_percent, disk_percent, status) VALUES (?,?,?,?,?)",
                (
                    metrics['timestamp'],
                    metrics['cpu']['percent'],
                    metrics['memory']['percent'],
                    metrics['disk']['percent'],
                    metrics['status']
                )
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log health metrics: {e}")
        # f-string = f"..." allows embedding variables with {curly_braces}
        # We catch the exception so a logging failure doesn't crash the app


# ── ROUTE: SOFTWARE INVENTORY ──────────────────────────────────────────────────
@app.route('/api/software', methods=['GET'])
def get_software():
    """
    Returns the software inventory — all enterprise applications managed.
    
    methods=['GET'] restricts this endpoint to only accept GET requests.
    GET = read-only, no side effects (doesn't change data).
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        # row_factory = sqlite3.Row makes each result row behave like a dict
        # Instead of row[0], row[1]... you can write row['name'], row['version']
        # Much more readable and less error-prone
        
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM software_inventory ORDER BY name")
        # SELECT * = select ALL columns
        # ORDER BY name = sort alphabetically by the 'name' column
        
        rows = cursor.fetchall()
        # fetchall() returns ALL matching rows as a list
        
        software = [dict(row) for row in rows]
        # List comprehension: create a new list by applying dict() to each row
        # dict(row) converts a sqlite3.Row object to a plain Python dictionary
        # We need plain dicts because jsonify() doesn't know sqlite3.Row
    
    return jsonify({'software': software, 'count': len(software)})


# ── ROUTE: PATCH SIMULATION (SECURITY OPERATION) ──────────────────────────────
@app.route('/api/software/<int:software_id>/patch', methods=['POST'])
@require_api_key
def patch_software(software_id):
    """
    Simulates applying a security patch to a specific piece of software.
    
    WHAT IS /api/software/<int:software_id>/patch ?
    <int:software_id> is a URL parameter — a variable in the URL path.
    int: means Flask will convert it to an integer automatically.
    e.g., GET /api/software/3/patch → software_id = 3
    
    WHAT IS PATCHING?
    Security patches fix vulnerabilities in software.
    SysAdmins must track which software has been patched and when.
    Unpatched software is one of the top security risks.
    
    methods=['POST'] = this endpoint CREATES/MODIFIES data.
    @require_api_key = protected — must have a valid token.
    """
    
    data = request.get_json()
    # get_json() parses the request body as JSON
    # The client sends: {"version": "19c.1", "notes": "CVE-2025-1234 patch"}
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    new_version = data.get('version', 'patched')
    notes       = data.get('notes', 'Security patch applied')
    patch_date  = datetime.datetime.utcnow().isoformat()
    
    with sqlite3.connect(DB_PATH) as conn:
        # First, check the software exists
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM software_inventory WHERE id=?", (software_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': f'Software ID {software_id} not found'}), 404
        
        software_name = row[0]
        
        # Update the record
        conn.execute(
            "UPDATE software_inventory SET version=?, last_patch=?, notes=? WHERE id=?",
            (new_version, patch_date, notes, software_id)
        )
        # UPDATE changes existing rows
        # SET column=value, column=value...
        # WHERE id=? limits the update to ONE specific row
        
        # AUDIT LOG — ITIL requirement: every change must be recorded
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, user, details, ip_addr) VALUES (?,?,?,?,?)",
            (
                patch_date,
                'PATCH_APPLIED',
                request.headers.get('X-Username', 'api_user'),
                f"Patched {software_name} to version {new_version}: {notes}",
                request.remote_addr  # The IP address making the request
            )
        )
        conn.commit()
    
    logger.info(f"Patch applied to software ID {software_id}: {software_name} → {new_version}")
    
    return jsonify({
        'success':     True,
        'software_id': software_id,
        'name':        software_name,
        'new_version': new_version,
        'patched_at':  patch_date,
        'message':     f'Security patch applied to {software_name}'
    })


# ── ROUTE: GENERATE API TOKEN (AUTHENTICATION) ────────────────────────────────
@app.route('/api/token', methods=['POST'])
def generate_token():
    """
    Creates a new API token for authenticated access.
    
    WHY TOKENS INSTEAD OF PASSWORDS?
    1. Tokens can expire automatically
    2. Tokens can be revoked without changing user passwords
    3. Tokens can have limited scope (read-only, write, admin)
    4. More secure for API calls than sending password every time
    
    This simulates what AWS, GitHub, Snowflake all do.
    """
    
    data     = request.get_json()
    username = data.get('username', 'anonymous') if data else 'anonymous'
    
    # Generate a cryptographically secure random token
    raw_token = secrets.token_hex(32)
    # secrets.token_hex(32) generates 32 random bytes encoded as hex
    # Result is a 64-character string like: "a3f8e2b1c9d7..."
    # "cryptographically secure" means truly unpredictable — not guessable
    
    # Store only the HASH in the database
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    created  = datetime.datetime.utcnow().isoformat()
    expires  = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat()
    # timedelta(days=30) creates a "duration" of 30 days
    # Adding it to utcnow() gives us the expiry timestamp
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO api_tokens (token_hash, username, created, expires) VALUES (?,?,?,?)",
            (token_hash, username, created, expires)
        )
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, user, details, ip_addr) VALUES (?,?,?,?,?)",
            (created, 'TOKEN_CREATED', username, f'New API token generated (expires {expires})', request.remote_addr)
        )
        conn.commit()
    
    logger.info(f"New API token generated for user: {username}")
    
    return jsonify({
        'token':   raw_token,      # Return the REAL token to the user ONCE
        'username': username,
        'created': created,
        'expires': expires,
        'warning': 'Save this token — it cannot be retrieved again'
        # We only ever show the real token ONCE (like AWS secret keys)
        # After this, only the hash is stored
    }), 201
    # 201 = Created (resource was successfully created)


# ── ROUTE: AUDIT LOG ──────────────────────────────────────────────────────────
@app.route('/api/audit')
@require_api_key
def get_audit_log():
    """
    Returns the audit trail — every administrative action taken.
    
    WHAT IS AN AUDIT LOG?
    An audit log (also called audit trail) is a chronological record of
    every significant action taken on a system.
    
    WHY IS IT REQUIRED?
    - Security: detect unauthorized access or changes
    - Compliance: many regulations (FISMA, NIST) require audit trails
    - Troubleshooting: "what changed before this broke?"
    - Accountability: who did what, when
    
    ITIL (IT Infrastructure Library) mandates audit trails for:
    - Changes to production systems
    - Access to sensitive data
    - Security events
    """
    
    limit = request.args.get('limit', 50, type=int)
    # request.args = query parameters from the URL
    # e.g., GET /api/audit?limit=20 → limit = 20
    # type=int automatically converts the string "20" to integer 20
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        # ORDER BY timestamp DESC = newest first (descending order)
        # LIMIT ? = only return the most recent N records
        
        logs = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({'audit_log': logs, 'count': len(logs)})


# ── ROUTE: METRICS HISTORY ────────────────────────────────────────────────────
@app.route('/api/metrics/history')
def metrics_history():
    """Returns historical health metrics for trending analysis."""
    
    hours = request.args.get('hours', 24, type=int)
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat()
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM health_logs WHERE timestamp > ? ORDER BY timestamp DESC",
            (since,)
        )
        history = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({
        'period_hours': hours,
        'data_points': len(history),
        'history': history
    })


# ── ROUTE: VULNERABILITY SCAN SIMULATION ──────────────────────────────────────
@app.route('/api/security/scan')
@require_api_key
def vulnerability_scan():
    """
    Simulates a vulnerability scan — a core SysAdmin security task.
    
    WHAT IS A VULNERABILITY SCAN?
    A vulnerability scanner checks software versions against databases of
    known security flaws (CVEs — Common Vulnerabilities and Exposures).
    
    Real tools: Nessus, OpenVAS, Qualys, AWS Inspector
    
    This simulation checks our inventory for:
    - Legacy software (past end-of-life)
    - Software not patched in > 90 days
    - Simulated CVE findings
    """
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM software_inventory")
        inventory = [dict(row) for row in cursor.fetchall()]
    
    findings = []
    now = datetime.datetime.utcnow()
    
    # Simulated CVE database — in reality this would query NVD (nvd.nist.gov)
    simulated_cves = {
        'Oracle ERP':         [{'cve': 'CVE-2025-0001', 'severity': 'HIGH',   'desc': 'SQL injection in HR module'}],
        'Legacy FITS System': [{'cve': 'CVE-2023-9999', 'severity': 'CRITICAL','desc': 'Remote code execution'}],
        'Slack':              [{'cve': 'CVE-2025-1234', 'severity': 'MEDIUM',  'desc': 'XSS in message renderer'}],
    }
    
    for sw in inventory:
        issues = []
        
        # Check 1: Is this legacy software?
        if sw['status'] == 'legacy':
            issues.append({
                'type':    'EOL_SOFTWARE',
                'severity':'CRITICAL',
                'message': f"{sw['name']} is end-of-life and no longer receives security patches"
            })
        
        # Check 2: Is it overdue for patching? (> 90 days)
        if sw['last_patch']:
            last_patch = datetime.datetime.fromisoformat(sw['last_patch'])
            days_since = (now - last_patch).days
            # timedelta arithmetic: subtracting two datetimes gives a timedelta
            # .days extracts just the number of days from the timedelta
            
            if days_since > 90:
                issues.append({
                    'type':     'OVERDUE_PATCH',
                    'severity': 'HIGH',
                    'message':  f"Last patched {days_since} days ago — policy requires ≤90 days"
                })
        
        # Check 3: Known CVEs
        if sw['name'] in simulated_cves:
            for cve in simulated_cves[sw['name']]:
                issues.append({'type': 'CVE_FOUND', **cve})
                # **cve "unpacks" the dict — spreads its key:value pairs into this dict
        
        if issues:
            findings.append({
                'software_id': sw['id'],
                'software':    sw['name'],
                'version':     sw['version'],
                'issues':      issues,
                'issue_count': len(issues)
            })
    
    # Log the scan in the audit trail
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, user, details, ip_addr) VALUES (?,?,?,?,?)",
            (
                now.isoformat(),
                'VULNERABILITY_SCAN',
                'system',
                f"Scan complete: {len(findings)} software items with findings",
                request.remote_addr
            )
        )
        conn.commit()
    
    severity_counts = {}
    for f in findings:
        for issue in f['issues']:
            sev = issue.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return jsonify({
        'scan_time':       now.isoformat(),
        'total_software':  len(inventory),
        'findings':        findings,
        'findings_count':  len(findings),
        'severity_summary': severity_counts
    })


# ── ENTRYPOINT ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    """
    WHAT IS if __name__ == '__main__'?
    When Python runs a file directly (python app.py), __name__ = '__main__'
    When a file is imported by another file, __name__ = the file's name.
    
    This pattern ensures that the code inside only runs when we DIRECTLY
    execute this file, not when it's imported as a module.
    """
    
    # Create log directory if it doesn't exist
    os.makedirs('/app/logs', exist_ok=True)
    os.makedirs('/app/db',   exist_ok=True)
    # exist_ok=True: don't raise an error if the directory already exists
    
    init_db()
    logger.info("Starting CfA Software Health Monitor...")
    
    app.run(
        host  ='0.0.0.0',
        # 0.0.0.0 means "listen on ALL network interfaces"
        # If we used 127.0.0.1 (localhost), only the container could reach it
        # 0.0.0.0 allows the Docker host to connect to the container
        
        port  =5000,
        # Port 5000 is Flask's default development port
        # Ports are like "channels" — different services use different ports
        # e.g., HTTP=80, HTTPS=443, SSH=22, Flask=5000
        
        debug =False
        # debug=False for production-like behavior
        # debug=True enables auto-reload and detailed error pages (DEV ONLY)
    )
