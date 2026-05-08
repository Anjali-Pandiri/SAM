"""
========================================================
 CfA Software Asset Manager — app.py
 A mini enterprise SysAdmin demo project covering:
   - Flask (web framework / REST API)
   - SQLAlchemy (ORM — database layer)
   - SQLite (relational database)
   - psutil (system monitoring)
   - python-dotenv (.env config / secrets management)
   - RBAC (Role-Based Access Control)
   - Patch/vulnerability management workflow
   - ITIL-style change management states
   - API design with JSON responses
   - Security headers + hardening
========================================================
"""

# ── IMPORTS ──────────────────────────────────────────────────────────────────

# os — built-in Python module to read environment variables and file paths
import os

# datetime — built-in module for date/time objects
from datetime import datetime, timedelta

# json — built-in module to convert Python dicts ↔ JSON strings
import json

# secrets — built-in module for cryptographically strong random tokens
import secrets

# hashlib — built-in module for hashing (SHA-256 etc.)
import hashlib

# Flask — the web framework. Handles HTTP requests and routing.
# Flask       = the main app class
# render_template = renders HTML Jinja2 templates from /templates/
# request     = gives access to incoming HTTP request data (body, headers, args)
# jsonify     = converts a Python dict into a proper JSON HTTP response
# session     = server-side session dict tied to a browser cookie
# redirect    = returns an HTTP 302 redirect response
# url_for     = builds URLs from function names (avoids hardcoding)
# g           = per-request global storage (used for current_user)
# abort       = immediately returns an HTTP error (e.g., 403 Forbidden)
from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, g, abort
)

# flask_sqlalchemy — SQLAlchemy ORM integration for Flask.
# db.Model   = base class for all database table models
# db.Column  = defines a column in a table
# db.Integer, db.String, db.DateTime, db.Boolean = column data types
# db.relationship = defines a foreign-key relationship between tables
from flask_sqlalchemy import SQLAlchemy

# psutil — "process and system utilities"
# Reads live CPU, memory, disk, network stats from the OS
import psutil

# python-dotenv — loads KEY=VALUE pairs from a .env file into os.environ
from dotenv import load_dotenv

# functools.wraps — used when writing decorators to preserve the wrapped
# function's name and docstring (important for Flask routing)
from functools import wraps

# ── LOAD .env FILE ───────────────────────────────────────────────────────────
# load_dotenv() reads .env and sets each line as an environment variable.
# This is how we keep secrets (API keys, DB passwords) OUT of source code.
# .env is listed in .gitignore so it never gets committed.
load_dotenv()

# ── CREATE FLASK APP ─────────────────────────────────────────────────────────
# Flask(__name__) creates the app.
#   __name__ tells Flask where to look for templates/ and static/ folders.
#   It evaluates to the Python module name, e.g. "app" when running app.py.
app = Flask(__name__)

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# app.config is a dict Flask reads for settings.
# We read from environment variables (set in .env) with os.environ.get().
# The second argument is the DEFAULT if the variable isn't set.

# SECRET_KEY — Flask uses this to cryptographically sign session cookies.
# If an attacker doesn't know this key, they can't forge a session.
# In production this MUST be a long random string stored in .env, NOT hardcoded.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# SQLALCHEMY_DATABASE_URI — tells SQLAlchemy which database to connect to.
# "sqlite:///sam.db" means: SQLite file named sam.db in the instance folder.
# SQLite = serverless, file-based relational database. Perfect for demos.
# In production you'd use: postgresql://user:password@host/dbname
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///sam.db'
)

# SQLALCHEMY_TRACK_MODIFICATIONS — SQLAlchemy can fire events every time
# a model object changes. We don't need that, and it uses extra memory.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── DATABASE OBJECT ───────────────────────────────────────────────────────────
# db is the SQLAlchemy extension instance.
# db.init_app(app) would be the pattern for larger apps (application factory).
# For simplicity we pass app directly here.
db = SQLAlchemy(app)

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE MODELS (Tables)
# Each class = one table. Each class attribute with db.Column = one column.
# SQLAlchemy automatically maps Python objects ↔ database rows.
# ══════════════════════════════════════════════════════════════════════════════

class User(db.Model):
    """
    Users table — represents a staff member who can log in.
    Demonstrates: authentication, password hashing, RBAC roles.
    """
    # __tablename__ = the actual SQL table name. If omitted, Flask uses the class name.
    __tablename__ = 'users'

    # db.Column(type, primary_key=True) — integer auto-increment primary key.
    # Every table needs a primary key — a unique identifier for each row.
    id = db.Column(db.Integer, primary_key=True)

    # db.String(80) — VARCHAR(80) in SQL. nullable=False = NOT NULL constraint.
    # unique=True = UNIQUE constraint (no two users can share a username).
    username = db.Column(db.String(80), unique=True, nullable=False)

    # password_hash — we NEVER store plaintext passwords.
    # We store a SHA-256 hash. On login we hash what the user typed and compare.
    password_hash = db.Column(db.String(256), nullable=False)

    # role — implements RBAC (Role-Based Access Control).
    # Possible values: 'admin', 'engineer', 'viewer'
    # This controls what actions each user can perform.
    role = db.Column(db.String(20), nullable=False, default='viewer')

    # db.DateTime — stores a Python datetime object as SQL DATETIME.
    # default=datetime.utcnow means "set to current UTC time when row is created".
    # Note: datetime.utcnow (no parentheses) — we pass the FUNCTION, not the result,
    # so it's called fresh for each new row, not once at app startup.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # db.relationship — tells SQLAlchemy "a User has many ChangeTickets".
    # backref='requester' adds a .requester attribute to ChangeTicket pointing back.
    # lazy=True means the related objects are loaded on first access (not eagerly).
    change_tickets = db.relationship('ChangeTicket', backref='requester', lazy=True)

    def set_password(self, password):
        """Hash a plaintext password and store the hash."""
        # hashlib.sha256() creates a SHA-256 hash object.
        # .encode() converts string → bytes (required by hashlib).
        # .hexdigest() returns the hash as a 64-character hex string.
        # In production: use bcrypt or argon2 which add salt automatically.
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Return True if the given password matches the stored hash."""
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def to_dict(self):
        """Serialize this User to a Python dict (for JSON API responses)."""
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }


class SoftwareAsset(db.Model):
    """
    Software assets table — represents an installed enterprise application.
    Demonstrates: software lifecycle, patch status, ITIL asset management.
    """
    __tablename__ = 'software_assets'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)        # e.g. "Oracle ERP 19c"
    vendor = db.Column(db.String(80))                       # e.g. "Oracle"
    version = db.Column(db.String(40))                      # e.g. "19.3.0.0"
    latest_version = db.Column(db.String(40))               # e.g. "19.4.0.0"
    category = db.Column(db.String(40))                     # ERP, CRM, Collab, etc.
    environment = db.Column(db.String(20), default='production')  # prod/dev/staging
    server_host = db.Column(db.String(120))                 # hostname where installed
    install_date = db.Column(db.DateTime)
    last_patched = db.Column(db.DateTime)
    patch_status = db.Column(db.String(20), default='current')
    # patch_status values: 'current' | 'patch_available' | 'critical_update' | 'eol'

    # security_score — 0-100. Calculated from patch status, age, config findings.
    security_score = db.Column(db.Integer, default=100)

    # notes — free-text field for admin comments
    notes = db.Column(db.Text)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # One asset can have many vulnerability findings
    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy=True,
                                       cascade='all, delete-orphan')
    # cascade='all, delete-orphan' means: when we delete an asset, automatically
    # delete all its associated Vulnerability rows too.

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'vendor': self.vendor,
            'version': self.version,
            'latest_version': self.latest_version,
            'category': self.category,
            'environment': self.environment,
            'server_host': self.server_host,
            'patch_status': self.patch_status,
            'security_score': self.security_score,
            'last_patched': self.last_patched.isoformat() if self.last_patched else None,
            'vuln_count': len(self.vulnerabilities)
        }


class Vulnerability(db.Model):
    """
    Vulnerabilities (findings) linked to a software asset.
    Demonstrates: POA&M (Plan of Action & Milestones), patch management,
    CVE tracking, NIST-style risk management.
    """
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)

    # ForeignKey links this row to a specific SoftwareAsset row.
    # 'software_assets.id' = table_name.column_name
    asset_id = db.Column(db.Integer, db.ForeignKey('software_assets.id'), nullable=False)

    # CVE = Common Vulnerabilities and Exposures — the industry-standard ID system
    # for publicly known security vulnerabilities. Format: CVE-YEAR-NUMBER
    cve_id = db.Column(db.String(20))                       # e.g. "CVE-2024-1234"

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    # severity: Critical / High / Medium / Low — based on CVSS score
    # CVSS = Common Vulnerability Scoring System (0.0 - 10.0)
    severity = db.Column(db.String(20), default='Medium')
    cvss_score = db.Column(db.Float, default=5.0)           # 0.0 – 10.0

    # status — ITIL/POA&M lifecycle:
    # 'open' → newly discovered
    # 'in_remediation' → a change ticket has been created, work in progress
    # 'resolved' → patch applied / mitigated
    # 'accepted_risk' → risk acknowledged, won't fix (with justification)
    status = db.Column(db.String(20), default='open')

    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    remediation_notes = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'cve_id': self.cve_id,
            'title': self.title,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'status': self.status,
            'discovered_at': self.discovered_at.isoformat()
        }


class ChangeTicket(db.Model):
    """
    Change management tickets — ITIL Change Management in code.
    Every modification to a production system must go through a change ticket.
    States: draft → submitted → approved → in_progress → completed / rejected
    Demonstrates: ITIL change management, workflow state machines, audit trails.
    """
    __tablename__ = 'change_tickets'

    id = db.Column(db.Integer, primary_key=True)

    # ticket_number — human-readable ID like "CHG-0001"
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    change_type = db.Column(db.String(30))  # 'patch', 'upgrade', 'config', 'install'
    priority = db.Column(db.String(20), default='normal')   # 'critical', 'high', 'normal', 'low'

    # State machine: the valid states a ticket can be in
    status = db.Column(db.String(20), default='draft')
    # draft → submitted → approved → in_progress → completed
    #                  ↘ rejected

    # Foreign key to the User who submitted this ticket
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Which asset is this change for?
    asset_id = db.Column(db.Integer, db.ForeignKey('software_assets.id'))

    # Scheduled maintenance window
    scheduled_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'ticket_number': self.ticket_number,
            'title': self.title,
            'change_type': self.change_type,
            'priority': self.priority,
            'status': self.status,
            'asset_id': self.asset_id,
            'requester': self.requester.username if self.requester else None,
            'scheduled_at': self.scheduled_at.isoformat() if self.scheduled_at else None,
            'created_at': self.created_at.isoformat()
        }


# ══════════════════════════════════════════════════════════════════════════════
# DECORATORS (Middleware-like functions)
# A decorator is a function that wraps another function to add behavior.
# In Flask, we use decorators for: auth checks, role checks, security headers.
# ══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    """
    Decorator: redirect to login if the user is not authenticated.
    Usage: @login_required above any route function.

    How it works:
    1. Flask calls our wrapper() instead of the original route function f().
    2. wrapper() checks session['user_id'].
    3. If no user_id in session → redirect to /login.
    4. If user_id found → load the user from DB and store in g.user, then call f().

    session is Flask's encrypted cookie dict. It persists across requests
    for the same browser.
    g is Flask's per-request context object — resets each request.
    """
    @wraps(f)  # @wraps preserves the original function's __name__ (required for Flask routing)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        g.user = db.session.get(User, user_id)
        if not g.user:
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles):
    """
    Decorator factory: only allow users whose role is in the allowed roles list.
    Usage: @role_required('admin', 'engineer')

    This is RBAC (Role-Based Access Control) in action:
    - Viewer can read dashboards
    - Engineer can create/edit assets and tickets
    - Admin can approve tickets, manage users
    """
    def decorator(f):
        @wraps(f)
        @login_required  # Must be logged in first
        def wrapper(*args, **kwargs):
            if g.user.role not in roles:
                # 403 Forbidden — you are authenticated but not authorized
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── SECURITY HEADERS ─────────────────────────────────────────────────────────
# after_request runs after EVERY response before it's sent to the browser.
# We use it to add security headers — these are a core system hardening technique.
@app.after_request
def add_security_headers(response):
    """
    Add HTTP security headers to every response.
    These are standard NIST/CIS hardening controls for web applications.
    """
    # X-Content-Type-Options: nosniff
    # Prevents the browser from guessing (sniffing) the content type.
    # Without this, a browser might execute a text file as JavaScript.
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # X-Frame-Options: DENY
    # Prevents the page from being embedded in an iframe.
    # Protects against clickjacking attacks.
    response.headers['X-Frame-Options'] = 'DENY'

    # X-XSS-Protection: 1; mode=block
    # Tells older browsers to block pages if they detect a reflected XSS attack.
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Referrer-Policy: strict-origin-when-cross-origin
    # Controls how much URL info is sent in the Referer header when clicking links.
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Cache-Control: no-store
    # Prevents caching of potentially sensitive API responses.
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'

    return response


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Each @app.route maps a URL pattern to a Python function.
# ══════════════════════════════════════════════════════════════════════════════

# ── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET  /login → show the login form (render the HTML template)
    POST /login → process the submitted username+password
    """
    if request.method == 'POST':
        # request.form is a dict of form fields from a POST body.
        # .get() returns None if the key doesn't exist (safe default).
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Query the DB: SELECT * FROM users WHERE username = ? LIMIT 1
        # .filter_by() generates a WHERE clause. .first() returns the first row or None.
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # session['user_id'] = ... sets an encrypted cookie on the browser.
            # On every subsequent request, Flask decrypts this cookie and
            # makes session['user_id'] available again.
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        error = 'Invalid credentials'
        return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear the session (log out) and redirect to login."""
    session.clear()
    return redirect(url_for('login'))


# ── PAGE ROUTES ───────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    """Main dashboard — shows summary metrics and system health."""
    # db.session.query(Model).count() → SELECT COUNT(*) FROM table
    total_assets = SoftwareAsset.query.count()
    open_vulns   = Vulnerability.query.filter_by(status='open').count()
    open_tickets = ChangeTicket.query.filter(
        ChangeTicket.status.in_(['submitted', 'approved', 'in_progress'])
    ).count()
    critical_vulns = Vulnerability.query.filter_by(
        status='open', severity='Critical'
    ).count()

    # Get system health from psutil
    sys_health = get_system_health()

    # Recent activity — last 5 change tickets, ordered by newest first
    recent_changes = ChangeTicket.query.order_by(
        ChangeTicket.created_at.desc()
    ).limit(5).all()

    return render_template('dashboard.html',
        user=g.user,
        total_assets=total_assets,
        open_vulns=open_vulns,
        open_tickets=open_tickets,
        critical_vulns=critical_vulns,
        sys_health=sys_health,
        recent_changes=recent_changes
    )


@app.route('/assets')
@login_required
def assets():
    """Software asset inventory page."""
    all_assets = SoftwareAsset.query.order_by(SoftwareAsset.name).all()
    return render_template('assets.html', user=g.user, assets=all_assets)


@app.route('/vulnerabilities')
@login_required
def vulnerabilities():
    """Vulnerability / POA&M tracking page."""
    all_vulns = Vulnerability.query.order_by(
        Vulnerability.cvss_score.desc()
    ).all()
    return render_template('vulns.html', user=g.user, vulns=all_vulns)


@app.route('/changes')
@login_required
def changes():
    """Change management ticket list."""
    all_changes = ChangeTicket.query.order_by(
        ChangeTicket.created_at.desc()
    ).all()
    return render_template('changes.html', user=g.user, changes=all_changes)


# ══════════════════════════════════════════════════════════════════════════════
# REST API ROUTES — return JSON, consumed by JavaScript fetch() calls
# REST = Representational State Transfer:
#   GET    = read
#   POST   = create
#   PUT    = full update
#   PATCH  = partial update
#   DELETE = delete
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/system/health')
@login_required
def api_system_health():
    """
    REST endpoint: GET /api/system/health
    Returns live CPU, memory, disk stats from psutil.
    This simulates a monitoring endpoint a SysAdmin would build.
    """
    return jsonify(get_system_health())


@app.route('/api/assets', methods=['GET'])
@login_required
def api_assets():
    """GET /api/assets — return all assets as JSON array."""
    assets = SoftwareAsset.query.all()
    # List comprehension: call .to_dict() on each asset object → list of dicts
    return jsonify([a.to_dict() for a in assets])


@app.route('/api/assets', methods=['POST'])
@role_required('admin', 'engineer')
def api_create_asset():
    """
    POST /api/assets — create a new software asset.
    Request body: JSON with asset fields.
    Only admin and engineer roles can create assets (RBAC).
    """
    # request.get_json() parses the request body as JSON → Python dict
    # force=True means parse even if Content-Type header isn't set
    data = request.get_json(force=True)

    if not data or not data.get('name'):
        # 400 Bad Request — client sent invalid data
        return jsonify({'error': 'name is required'}), 400

    asset = SoftwareAsset(
        name=data['name'],
        vendor=data.get('vendor', ''),
        version=data.get('version', ''),
        latest_version=data.get('latest_version', ''),
        category=data.get('category', 'Other'),
        environment=data.get('environment', 'production'),
        server_host=data.get('server_host', ''),
        patch_status=data.get('patch_status', 'current'),
        security_score=data.get('security_score', 100),
        install_date=datetime.utcnow(),
        last_patched=datetime.utcnow()
    )

    # db.session.add(object) → stages the INSERT for the next commit
    db.session.add(asset)
    # db.session.commit() → executes the SQL INSERT and persists to disk
    db.session.commit()

    # 201 Created — standard HTTP status for successful resource creation
    return jsonify(asset.to_dict()), 201


@app.route('/api/assets/<int:asset_id>', methods=['GET'])
@login_required
def api_get_asset(asset_id):
    """
    GET /api/assets/<id> — get one asset by ID.
    <int:asset_id> is a URL variable — Flask extracts it and passes it as argument.
    """
    # db.get_or_404 returns the object or raises 404 Not Found automatically
    asset = db.get_or_404(SoftwareAsset, asset_id)
    result = asset.to_dict()
    result['vulnerabilities'] = [v.to_dict() for v in asset.vulnerabilities]
    return jsonify(result)


@app.route('/api/assets/<int:asset_id>/patch', methods=['POST'])
@role_required('admin', 'engineer')
def api_patch_asset(asset_id):
    """
    POST /api/assets/<id>/patch — mark an asset as patched.
    Simulates the action of applying a software patch.
    Demonstrates: state transition, audit trail, security score recalculation.
    """
    asset = db.get_or_404(SoftwareAsset, asset_id)

    # Update the asset fields
    asset.last_patched = datetime.utcnow()
    asset.patch_status = 'current'
    asset.security_score = min(100, asset.security_score + 15)

    # If there's a newer version specified, update to it
    data = request.get_json(force=True) or {}
    if data.get('new_version'):
        asset.version = data['new_version']

    db.session.commit()
    return jsonify({'message': f'Asset {asset.name} patched successfully', 'asset': asset.to_dict()})


@app.route('/api/vulnerabilities', methods=['GET'])
@login_required
def api_vulnerabilities():
    """GET /api/vulnerabilities — list all vulnerabilities with optional filter."""
    # request.args is a dict of query parameters from the URL
    # e.g. /api/vulnerabilities?status=open&severity=Critical
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')

    query = Vulnerability.query

    # Dynamically add WHERE clauses based on query params
    if status_filter:
        query = query.filter_by(status=status_filter)
    if severity_filter:
        query = query.filter_by(severity=severity_filter)

    vulns = query.order_by(Vulnerability.cvss_score.desc()).all()
    return jsonify([v.to_dict() for v in vulns])


@app.route('/api/vulnerabilities', methods=['POST'])
@role_required('admin', 'engineer')
def api_create_vulnerability():
    """POST /api/vulnerabilities — log a new vulnerability finding."""
    data = request.get_json(force=True)
    if not data or not data.get('title'):
        return jsonify({'error': 'title is required'}), 400

    asset = db.get_or_404(SoftwareAsset, data.get('asset_id', 0))

    vuln = Vulnerability(
        asset_id=asset.id,
        cve_id=data.get('cve_id', ''),
        title=data['title'],
        description=data.get('description', ''),
        severity=data.get('severity', 'Medium'),
        cvss_score=float(data.get('cvss_score', 5.0)),
        status='open'
    )
    db.session.add(vuln)

    # Recalculate asset security score based on new vulnerability
    deduction = {'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 3}
    asset.security_score = max(0, asset.security_score - deduction.get(vuln.severity, 5))
    asset.patch_status = 'critical_update' if vuln.severity == 'Critical' else 'patch_available'

    db.session.commit()
    return jsonify(vuln.to_dict()), 201


@app.route('/api/vulnerabilities/<int:vuln_id>/resolve', methods=['POST'])
@role_required('admin', 'engineer')
def api_resolve_vulnerability(vuln_id):
    """POST /api/vulnerabilities/<id>/resolve — mark a vulnerability as resolved."""
    vuln = db.get_or_404(Vulnerability, vuln_id)
    data = request.get_json(force=True) or {}

    vuln.status = 'resolved'
    vuln.resolved_at = datetime.utcnow()
    vuln.remediation_notes = data.get('notes', 'Resolved')

    # Improve asset security score when vulnerability is resolved
    improvement = {'Critical': 20, 'High': 12, 'Medium': 6, 'Low': 2}
    asset = vuln.asset
    asset.security_score = min(100, asset.security_score + improvement.get(vuln.severity, 5))

    # Check if there are remaining open vulnerabilities
    remaining = Vulnerability.query.filter_by(asset_id=asset.id, status='open').count()
    if remaining == 0:
        asset.patch_status = 'current'

    db.session.commit()
    return jsonify({'message': 'Vulnerability resolved', 'vuln': vuln.to_dict()})


@app.route('/api/changes', methods=['GET'])
@login_required
def api_changes():
    """GET /api/changes — list all change tickets."""
    changes = ChangeTicket.query.order_by(ChangeTicket.created_at.desc()).all()
    return jsonify([c.to_dict() for c in changes])


@app.route('/api/changes', methods=['POST'])
@role_required('admin', 'engineer')
def api_create_change():
    """POST /api/changes — create a new ITIL change ticket."""
    data = request.get_json(force=True)
    if not data or not data.get('title'):
        return jsonify({'error': 'title is required'}), 400

    # Generate ticket number: CHG-0001, CHG-0002, etc.
    count = ChangeTicket.query.count()
    ticket_number = f"CHG-{str(count + 1).zfill(4)}"

    ticket = ChangeTicket(
        ticket_number=ticket_number,
        title=data['title'],
        description=data.get('description', ''),
        change_type=data.get('change_type', 'config'),
        priority=data.get('priority', 'normal'),
        status='draft',
        requester_id=g.user.id,
        asset_id=data.get('asset_id')
    )
    db.session.add(ticket)
    db.session.commit()
    return jsonify(ticket.to_dict()), 201


@app.route('/api/changes/<int:ticket_id>/advance', methods=['POST'])
@role_required('admin', 'engineer')
def api_advance_change(ticket_id):
    """
    POST /api/changes/<id>/advance — move a ticket to the next state.
    This is the ITIL change management state machine in action.
    Demonstrates: workflow state transitions, role-based approval.
    """
    ticket = db.get_or_404(ChangeTicket, ticket_id)

    # State machine: define valid transitions
    # Only admins can approve tickets (move from submitted → approved)
    transitions = {
        'draft':       ('submitted', None),         # anyone with engineer+ can submit
        'submitted':   ('approved', ['admin']),      # only admin can approve
        'approved':    ('in_progress', None),        # engineer can start work
        'in_progress': ('completed', None),          # engineer can complete
    }

    current = ticket.status
    if current not in transitions:
        return jsonify({'error': f'Cannot advance from status: {current}'}), 400

    next_status, required_roles = transitions[current]

    # Check role constraint for this specific transition
    if required_roles and g.user.role not in required_roles:
        return jsonify({'error': f'Only {required_roles} can perform this transition'}), 403

    ticket.status = next_status
    if next_status == 'completed':
        ticket.completed_at = datetime.utcnow()

    db.session.commit()
    return jsonify({'message': f'Ticket advanced to {next_status}', 'ticket': ticket.to_dict()})


@app.route('/api/dashboard/summary')
@login_required
def api_dashboard_summary():
    """GET /api/dashboard/summary — aggregated metrics for the dashboard."""
    assets_by_status = db.session.query(
        SoftwareAsset.patch_status,
        db.func.count(SoftwareAsset.id)
    ).group_by(SoftwareAsset.patch_status).all()

    vulns_by_severity = db.session.query(
        Vulnerability.severity,
        db.func.count(Vulnerability.id)
    ).filter_by(status='open').group_by(Vulnerability.severity).all()

    return jsonify({
        'totals': {
            'assets':        SoftwareAsset.query.count(),
            'open_vulns':    Vulnerability.query.filter_by(status='open').count(),
            'critical_vulns': Vulnerability.query.filter_by(status='open', severity='Critical').count(),
            'open_tickets':  ChangeTicket.query.filter(
                                 ChangeTicket.status.in_(['submitted','approved','in_progress'])
                             ).count()
        },
        'assets_by_patch_status': {row[0]: row[1] for row in assets_by_status},
        'vulns_by_severity':      {row[0]: row[1] for row in vulns_by_severity},
        'system': get_system_health()
    })


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_system_health():
    """
    Use psutil to read live system metrics.
    psutil — "process and system utilities" — reads from the OS kernel.
    Returns a dict of CPU, memory, disk, and process stats.
    """
    # psutil.cpu_percent(interval=0.1):
    #   Measures CPU usage over 0.1 seconds.
    #   Returns a float: 0.0 = idle, 100.0 = fully loaded.
    #   interval=None would return 0.0 the first call (needs two samples).
    cpu = psutil.cpu_percent(interval=0.1)

    # psutil.virtual_memory():
    #   Returns a named tuple with fields:
    #   .total = total RAM in bytes
    #   .available = free + reclaimable RAM in bytes
    #   .percent = used percentage (0-100)
    #   .used = bytes actively used
    mem = psutil.virtual_memory()

    # psutil.disk_usage(path):
    #   Returns disk stats for the partition that contains the given path.
    #   '/' = root filesystem on Linux/Mac.
    #   .total, .used, .free, .percent — same pattern as memory.
    disk = psutil.disk_usage('/')

    # psutil.process_iter(['pid','name','status']):
    #   Iterator over all running processes.
    #   We count only processes with status='running' (not sleeping/zombie).
    #   list(...) materializes the iterator so we can call len().
    running_procs = len([
        p for p in psutil.process_iter(['status'])
        if p.info['status'] == psutil.STATUS_RUNNING
    ])

    # Convert bytes to GB:  bytes / (1024^3)
    # round(x, 1) rounds to 1 decimal place
    return {
        'cpu_percent':    cpu,
        'memory_percent': mem.percent,
        'memory_total_gb': round(mem.total / (1024**3), 1),
        'memory_used_gb':  round(mem.used  / (1024**3), 1),
        'disk_percent':   disk.percent,
        'disk_total_gb':  round(disk.total / (1024**3), 1),
        'disk_used_gb':   round(disk.used  / (1024**3), 1),
        'running_processes': running_procs,
        'timestamp': datetime.utcnow().isoformat()
    }


def seed_database():
    """
    Populate the database with sample data for the demo.
    Called once at startup if the DB is empty.
    This is called 'seeding' — like planting seeds in a garden.
    """
    if User.query.count() > 0:
        return  # Already seeded, don't add duplicates

    print("Seeding database with demo data...")

    # Create users with different roles (RBAC demo)
    admin = User(username='admin', role='admin')
    admin.set_password('admin123')

    engineer = User(username='engineer', role='engineer')
    engineer.set_password('eng123')

    viewer = User(username='viewer', role='viewer')
    viewer.set_password('view123')

    db.session.add_all([admin, engineer, viewer])
    db.session.commit()

    # Create software assets representing a real CfA-style environment
    assets_data = [
        {
            'name': 'Oracle ERP Cloud 19c',
            'vendor': 'Oracle',
            'version': '19.3.0.0',
            'latest_version': '19.4.0.1',
            'category': 'ERP',
            'environment': 'production',
            'server_host': 'erp-prod-01.cfa.harvard.edu',
            'patch_status': 'critical_update',
            'security_score': 62,
        },
        {
            'name': 'Salesforce CRM',
            'vendor': 'Salesforce',
            'version': 'Winter 25',
            'latest_version': 'Spring 25',
            'category': 'CRM',
            'environment': 'production',
            'server_host': 'cloud-saas (vendor-managed)',
            'patch_status': 'patch_available',
            'security_score': 78,
        },
        {
            'name': 'Google Workspace',
            'vendor': 'Google',
            'version': 'Enterprise Plus',
            'latest_version': 'Enterprise Plus',
            'category': 'Collaboration',
            'environment': 'production',
            'server_host': 'cloud-saas (vendor-managed)',
            'patch_status': 'current',
            'security_score': 95,
        },
        {
            'name': 'Microsoft Teams',
            'vendor': 'Microsoft',
            'version': '1.6.00.30963',
            'latest_version': '1.7.00.21865',
            'category': 'Collaboration',
            'environment': 'production',
            'server_host': 'cloud-saas (vendor-managed)',
            'patch_status': 'patch_available',
            'security_score': 83,
        },
        {
            'name': 'Slack Enterprise Grid',
            'vendor': 'Salesforce',
            'version': '4.35.126',
            'latest_version': '4.35.126',
            'category': 'Collaboration',
            'environment': 'production',
            'server_host': 'cloud-saas (vendor-managed)',
            'patch_status': 'current',
            'security_score': 91,
        },
        {
            'name': 'Ubuntu Server 22.04 LTS',
            'vendor': 'Canonical',
            'version': '22.04.3',
            'latest_version': '22.04.4',
            'category': 'OS',
            'environment': 'production',
            'server_host': 'compute-01.cfa.harvard.edu',
            'patch_status': 'patch_available',
            'security_score': 87,
        },
    ]

    asset_objects = []
    for d in assets_data:
        a = SoftwareAsset(
            install_date=datetime.utcnow() - timedelta(days=180),
            last_patched=datetime.utcnow() - timedelta(days=90),
            **d
        )
        db.session.add(a)
        asset_objects.append(a)

    db.session.commit()

    # Create sample vulnerabilities
    vulns_data = [
        {
            'asset': asset_objects[0],  # Oracle ERP
            'cve_id': 'CVE-2024-20953',
            'title': 'Oracle ERP — Unauthenticated Remote Code Execution',
            'description': 'A vulnerability in the Oracle Applications Framework allows an unauthenticated attacker to execute arbitrary code via a crafted HTTP request.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'status': 'open'
        },
        {
            'asset': asset_objects[0],  # Oracle ERP
            'cve_id': 'CVE-2024-20918',
            'title': 'Oracle ERP — Privilege Escalation via XML Parser',
            'description': 'Improper input validation in the XML parser component allows authenticated users to escalate privileges.',
            'severity': 'High',
            'cvss_score': 8.1,
            'status': 'in_remediation'
        },
        {
            'asset': asset_objects[1],  # Salesforce CRM
            'cve_id': 'CVE-2024-41110',
            'title': 'Salesforce CRM — Cross-Site Scripting via Custom Fields',
            'description': 'Improper output encoding in custom field rendering allows stored XSS attacks.',
            'severity': 'Medium',
            'cvss_score': 6.5,
            'status': 'open'
        },
        {
            'asset': asset_objects[5],  # Ubuntu
            'cve_id': 'CVE-2024-32002',
            'title': 'OpenSSH — Remote Code Execution (regreSSHion)',
            'description': 'A race condition in OpenSSH sshd allows unauthenticated remote code execution as root on glibc-based Linux systems.',
            'severity': 'Critical',
            'cvss_score': 8.1,
            'status': 'resolved'
        },
    ]

    for d in vulns_data:
        asset_obj = d.pop('asset')
        v = Vulnerability(asset_id=asset_obj.id, **d)
        db.session.add(v)

    db.session.commit()

    # Create sample change tickets
    tickets_data = [
        {
            'ticket_number': 'CHG-0001',
            'title': 'Apply Oracle ERP Critical Security Patch (CVE-2024-20953)',
            'description': 'Emergency patch for critical RCE vulnerability. Requires 2-hour maintenance window.',
            'change_type': 'patch',
            'priority': 'critical',
            'status': 'approved',
            'requester_id': engineer.id,
            'asset_id': asset_objects[0].id,
            'scheduled_at': datetime.utcnow() + timedelta(days=1)
        },
        {
            'ticket_number': 'CHG-0002',
            'title': 'Upgrade Ubuntu Server 22.04.3 to 22.04.4',
            'description': 'Quarterly security update rollup. Includes kernel patches and OpenSSL updates.',
            'change_type': 'upgrade',
            'priority': 'normal',
            'status': 'submitted',
            'requester_id': engineer.id,
            'asset_id': asset_objects[5].id,
            'scheduled_at': datetime.utcnow() + timedelta(days=7)
        },
        {
            'ticket_number': 'CHG-0003',
            'title': 'Configure MFA for Oracle ERP Admin Accounts',
            'description': 'Enable TOTP-based multi-factor authentication for all administrator accounts per new security policy.',
            'change_type': 'config',
            'priority': 'high',
            'status': 'completed',
            'requester_id': admin.id,
            'asset_id': asset_objects[0].id,
            'completed_at': datetime.utcnow() - timedelta(days=5)
        },
    ]

    for d in tickets_data:
        t = ChangeTicket(**d)
        db.session.add(t)

    db.session.commit()
    print("Database seeded successfully!")


# ══════════════════════════════════════════════════════════════════════════════
# APP STARTUP
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # app.app_context() — Flask uses contexts to give code access to the app.
    # Database operations require the application context to be active.
    with app.app_context():
        # db.create_all() — inspects all db.Model subclasses and creates
        # the corresponding SQL tables if they don't exist yet.
        # It won't drop or modify existing tables (safe to call repeatedly).
        db.create_all()
        seed_database()

    # app.run() starts Flask's built-in development web server.
    # debug=True → auto-reload on code changes, show detailed error pages.
    # host='0.0.0.0' → listen on all network interfaces (not just localhost).
    # port=5000 → the port number to listen on.
    # In production you'd use gunicorn or uwsgi behind nginx instead.
    app.run(debug=True, host='0.0.0.0', port=5000)
