#!/usr/bin/env python3
"""
Python License Server for Instagram + Fb Auto (InstaTool)
Compatible with Render.com and Railway.app
Supports SHA256withRSA signature verification matching Android client.
"""

import os
import time
import json
import sqlite3
import base64
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "licenses.db")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public_key.pem")

app = Flask(__name__)

# ==============================================================================
# RSA Key Loading & Signature Helper
# ==============================================================================

def load_or_create_keys():
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        from generate_keys import generate_keypair
        private_key, public_key, _ = generate_keypair()
        return private_key, public_key

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

PRIVATE_KEY, PUBLIC_KEY = load_or_create_keys()

def sign_payload(payload_dict):
    """
    Serializes payload_dict to compact JSON, signs with SHA256withRSA,
    and returns (payload_b64, sig_b64).
    """
    raw_bytes = json.dumps(payload_dict, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64.b64encode(raw_bytes).decode('ascii')

    sig = PRIVATE_KEY.sign(
        raw_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(sig).decode('ascii')
    return payload_b64, sig_b64

# ==============================================================================
# Database Helper
# ==============================================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                days_valid INTEGER NOT NULL DEFAULT 30,
                device_limit INTEGER NOT NULL DEFAULT 1,
                bound_devices TEXT NOT NULL DEFAULT '[]',
                activated_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                notes TEXT
            )
        """)
        # Pre-seed default demo keys if empty
        cur = conn.execute("SELECT COUNT(*) as count FROM licenses")
        if cur.fetchone()["count"] == 0:
            now = int(time.time())
            conn.execute("""
                INSERT INTO licenses (key, label, status, days_valid, device_limit, created_at, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("DEMO-KEY-2026", "Demo VIP Account", "active", 365, 2, now, "Initial demo key valid 365 days"))
            conn.execute("""
                INSERT INTO licenses (key, label, status, days_valid, device_limit, created_at, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("VIP-LIFETIME-001", "Lifetime VIP Account", "active", 0, 5, now, "Lifetime key for 5 devices"))
            conn.commit()

init_db()

# ==============================================================================
# License Verification API (Matches Android Client)
# ==============================================================================

@app.route("/apis.php", methods=["POST", "GET"])
@app.route("/license", methods=["POST", "GET"])
def handle_license():
    # Support both GET for health check and POST for activation
    if request.method == "GET":
        return jsonify({
            "status": "online",
            "server": "InstaTool Python License Server",
            "time": int(time.time())
        })

    # Read form-data or JSON
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    
    key_str = data.get("key", "").strip()
    install = data.get("install", "").strip()
    nonce = data.get("nonce", "").strip()
    cert = data.get("cert", "").strip()
    activate = data.get("activate", "0") == "1"
    model = data.get("model", "")
    now = int(time.time())

    # Default payload template
    payload = {
        "key": key_str,
        "nonce": nonce,
        "install": install,
        "cert": cert,
        "status": "invalid",
        "label": "Unknown",
        "expires": 0,
        "serverTime": now,
        "minVersion": 1,
        "updateUrl": "",
        "updateMessage": ""
    }

    if not key_str:
        payload["status"] = "missing"
        p_b64, s_b64 = sign_payload(payload)
        return jsonify({"payload": p_b64, "sig": s_b64})

    with get_db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE key = ?", (key_str,)).fetchone()
        if not row:
            payload["status"] = "invalid"
            p_b64, s_b64 = sign_payload(payload)
            return jsonify({"payload": p_b64, "sig": s_b64})

        label = row["label"]
        db_status = row["status"]
        days_valid = row["days_valid"]
        device_limit = row["device_limit"]
        bound_devices = json.loads(row["bound_devices"])
        activated_at = row["activated_at"]
        expires_at = row["expires_at"]

        # Check explicit revocation
        if db_status == "revoked":
            payload["status"] = "revoked"
            payload["label"] = label
            p_b64, s_b64 = sign_payload(payload)
            return jsonify({"payload": p_b64, "sig": s_b64})

        # Check first-time activation
        if activated_at == 0 and activate:
            activated_at = now
            if days_valid > 0:
                expires_at = now + (days_valid * 86400)
            else:
                expires_at = 0  # 0 indicates never expires

        # Check expiration
        if expires_at > 0 and now > expires_at:
            payload["status"] = "expired"
            payload["label"] = label
            payload["expires"] = expires_at
            p_b64, s_b64 = sign_payload(payload)
            return jsonify({"payload": p_b64, "sig": s_b64})

        # Check device binding
        if install:
            if install not in bound_devices:
                if len(bound_devices) < device_limit:
                    if activate:
                        bound_devices.append(install)
                        conn.execute("""
                            UPDATE licenses 
                            SET bound_devices = ?, activated_at = ?, expires_at = ?
                            WHERE key = ?
                        """, (json.dumps(bound_devices), activated_at, expires_at, key_str))
                        conn.commit()
                else:
                    # Device limit exceeded
                    payload["status"] = "device_limit"
                    payload["label"] = label
                    payload["expires"] = expires_at
                    p_b64, s_b64 = sign_payload(payload)
                    return jsonify({"payload": p_b64, "sig": s_b64})
            else:
                # Already bound, ensure timestamps updated if needed
                if activated_at > 0:
                    conn.execute("""
                        UPDATE licenses 
                        SET activated_at = ?, expires_at = ?
                        WHERE key = ?
                    """, (activated_at, expires_at, key_str))
                    conn.commit()

        # License is ACTIVE
        payload["status"] = "active"
        payload["label"] = label
        payload["expires"] = expires_at

    p_b64, s_b64 = sign_payload(payload)
    return jsonify({"payload": p_b64, "sig": s_b64})

# ==============================================================================
# Admin Dashboard & Management UI
# ==============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InstaTool License Server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f6f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .card { border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); border: none; }
        .badge-active { background-color: #28a745; }
        .badge-expired { background-color: #dc3545; }
        .badge-revoked { background-color: #6c757d; }
    </style>
</head>
<body class="py-4">
    <div class="container">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="fw-bold mb-0">🔑 InstaTool License Server</h2>
                <p class="text-muted mb-0">Manage and distribute application licenses</p>
            </div>
            <div>
                <span class="badge bg-success p-2">Server Running</span>
            </div>
        </div>

        <div class="row g-4">
            <!-- Create Key Form -->
            <div class="col-lg-4">
                <div class="card p-4">
                    <h5 class="fw-bold mb-3">➕ Generate New Key</h5>
                    <form method="POST" action="/admin/create">
                        <div class="mb-3">
                            <label class="form-label">License Key</label>
                            <input type="text" name="key" class="form-control" placeholder="e.g. VIP-2026-USER1" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Client Name / Label</label>
                            <input type="text" name="label" class="form-control" placeholder="e.g. John Doe VIP" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Valid Days (0 for Lifetime)</label>
                            <input type="number" name="days" class="form-control" value="30" min="0" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Max Allowed Devices</label>
                            <input type="number" name="devices" class="form-control" value="1" min="1" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Notes</label>
                            <input type="text" name="notes" class="form-control" placeholder="Optional notes">
                        </div>
                        <button type="submit" class="btn btn-primary w-100 fw-bold">Generate Key</button>
                    </form>
                </div>
            </div>

            <!-- Keys Table -->
            <div class="col-lg-8">
                <div class="card p-4">
                    <h5 class="fw-bold mb-3">📋 Active Licenses</h5>
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th>License Key</th>
                                    <th>Label</th>
                                    <th>Status</th>
                                    <th>Devices</th>
                                    <th>Expires</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for item in licenses %}
                                <tr>
                                    <td><code>{{ item.key }}</code></td>
                                    <td>{{ item.label }}</td>
                                    <td>
                                        {% if item.status == 'active' %}
                                            <span class="badge badge-active">Active</span>
                                        {% elif item.status == 'expired' %}
                                            <span class="badge badge-expired">Expired</span>
                                        {% else %}
                                            <span class="badge badge-revoked">{{ item.status }}</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ item.bound_count }} / {{ item.device_limit }}</td>
                                    <td>
                                        {% if item.expires_at == 0 %}
                                            <span class="text-success fw-bold">Lifetime</span>
                                        {% else %}
                                            {{ item.expires_str }}
                                        {% endif %}
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <form method="POST" action="/admin/reset-devices" style="display:inline;">
                                                <input type="hidden" name="key" value="{{ item.key }}">
                                                <button type="submit" class="btn btn-outline-warning" title="Reset Devices">Reset</button>
                                            </form>
                                            {% if item.status == 'active' %}
                                            <form method="POST" action="/admin/revoke" style="display:inline;">
                                                <input type="hidden" name="key" value="{{ item.key }}">
                                                <button type="submit" class="btn btn-outline-danger" title="Revoke Key">Revoke</button>
                                            </form>
                                            {% else %}
                                            <form method="POST" action="/admin/activate" style="display:inline;">
                                                <input type="hidden" name="key" value="{{ item.key }}">
                                                <button type="submit" class="btn btn-outline-success" title="Activate Key">Activate</button>
                                            </form>
                                            {% endif %}
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def dashboard():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
        licenses = []
        for r in rows:
            bound = json.loads(r["bound_devices"])
            exp_str = time.strftime('%Y-%m-%d', time.localtime(r["expires_at"])) if r["expires_at"] > 0 else "Lifetime"
            licenses.append({
                "key": r["key"],
                "label": r["label"],
                "status": r["status"],
                "device_limit": r["device_limit"],
                "bound_count": len(bound),
                "expires_at": r["expires_at"],
                "expires_str": exp_str
            })
    return render_template_string(HTML_TEMPLATE, licenses=licenses)

@app.route("/admin/create", methods=["POST"])
def admin_create():
    key = request.form.get("key", "").strip()
    label = request.form.get("label", "").strip()
    days = int(request.form.get("days", 30))
    devices = int(request.form.get("devices", 1))
    notes = request.form.get("notes", "")

    if key and label:
        with get_db() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO licenses 
                (key, label, status, days_valid, device_limit, created_at, notes)
                VALUES (?, ?, 'active', ?, ?, ?, ?)
            """, (key, label, days, devices, int(time.time()), notes))
            conn.commit()
    return dashboard()

@app.route("/admin/reset-devices", methods=["POST"])
def admin_reset_devices():
    key = request.form.get("key", "").strip()
    if key:
        with get_db() as conn:
            conn.execute("UPDATE licenses SET bound_devices = '[]' WHERE key = ?", (key,))
            conn.commit()
    return dashboard()

@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    key = request.form.get("key", "").strip()
    if key:
        with get_db() as conn:
            conn.execute("UPDATE licenses SET status = 'revoked' WHERE key = ?", (key,))
            conn.commit()
    return dashboard()

@app.route("/admin/activate", methods=["POST"])
def admin_activate():
    key = request.form.get("key", "").strip()
    if key:
        with get_db() as conn:
            conn.execute("UPDATE licenses SET status = 'active' WHERE key = ?", (key,))
            conn.commit()
    return dashboard()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"[INFO] Starting License Server on port {port}...")
    app.run(host="0.0.0.0", port=port)
