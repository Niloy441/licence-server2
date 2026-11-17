#!/usr/bin/env python3
"""
Python Real-Time License Server for Android Client
Compatible with Render.com and Railway.app
Supports SHA256withRSA signature verification and Real-Time Dashboard.
"""

import os
import time
import json
import sqlite3
import base64
from flask import Flask, request, jsonify, render_template_string, redirect

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
            "server": "InstaTool Real-Time License Server",
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
                expires_at = 0

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
                    payload["status"] = "device_limit"
                    payload["label"] = label
                    payload["expires"] = expires_at
                    p_b64, s_b64 = sign_payload(payload)
                    return jsonify({"payload": p_b64, "sig": s_b64})
            else:
                if activated_at > 0:
                    conn.execute("""
                        UPDATE licenses 
                        SET activated_at = ?, expires_at = ?
                        WHERE key = ?
                    """, (activated_at, expires_at, key_str))
                    conn.commit()

        payload["status"] = "active"
        payload["label"] = label
        payload["expires"] = expires_at

    p_b64, s_b64 = sign_payload(payload)
    return jsonify({"payload": p_b64, "sig": s_b64})

# ==============================================================================
# Real-Time AJAX REST APIs
# ==============================================================================

@app.route("/api/licenses", methods=["GET"])
def api_get_licenses():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            bound = json.loads(r["bound_devices"])
            exp_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(r["expires_at"])) if r["expires_at"] > 0 else "Lifetime"
            result.append({
                "key": r["key"],
                "label": r["label"],
                "status": r["status"],
                "days_valid": r["days_valid"],
                "device_limit": r["device_limit"],
                "bound_devices": bound,
                "bound_count": len(bound),
                "expires_at": r["expires_at"],
                "expires_str": exp_str,
                "created_at": r["created_at"],
                "notes": r["notes"] or ""
            })
    return jsonify({"success": True, "licenses": result, "time": int(time.time())})

@app.route("/api/licenses/create", methods=["POST"])
def api_create_license():
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    key = data.get("key", "").strip()
    label = data.get("label", "").strip()
    days = int(data.get("days", 30))
    devices = int(data.get("devices", 1))
    notes = data.get("notes", "").strip()

    if not key or not label:
        return jsonify({"success": False, "error": "Key and Label are required"}), 400

    now = int(time.time())
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO licenses 
            (key, label, status, days_valid, device_limit, created_at, notes)
            VALUES (?, ?, 'active', ?, ?, ?, ?)
        """, (key, label, days, devices, now, notes))
        conn.commit()

    return jsonify({"success": True, "message": "License created successfully", "key": key})

@app.route("/api/licenses/action", methods=["POST"])
def api_license_action():
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    key = data.get("key", "").strip()
    action = data.get("action", "").strip()

    if not key:
        return jsonify({"success": False, "error": "Key is required"}), 400

    with get_db() as conn:
        if action == "reset":
            conn.execute("UPDATE licenses SET bound_devices = '[]' WHERE key = ?", (key,))
            msg = "Device bindings reset successfully"
        elif action == "revoke":
            conn.execute("UPDATE licenses SET status = 'revoked' WHERE key = ?", (key,))
            msg = "License revoked"
        elif action == "activate":
            conn.execute("UPDATE licenses SET status = 'active' WHERE key = ?", (key,))
            msg = "License activated"
        elif action == "delete":
            conn.execute("DELETE FROM licenses WHERE key = ?", (key,))
            msg = "License deleted"
        else:
            return jsonify({"success": False, "error": "Invalid action"}), 400
        conn.commit()

    return jsonify({"success": True, "message": msg, "key": key})

# ==============================================================================
# Backward Compatible Form Routes (PRG Pattern: Always Redirect to /)
# ==============================================================================

@app.route("/admin/create", methods=["GET", "POST"])
def admin_create():
    if request.method == "POST":
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
    # Always redirect to root (PRG pattern - avoids 405 and form resubmission)
    return redirect("/")

@app.route("/admin/reset-devices", methods=["GET", "POST"])
def admin_reset_devices():
    if request.method == "POST":
        key = request.form.get("key", "").strip()
        if key:
            with get_db() as conn:
                conn.execute("UPDATE licenses SET bound_devices = '[]' WHERE key = ?", (key,))
                conn.commit()
    return redirect("/")

@app.route("/admin/revoke", methods=["GET", "POST"])
def admin_revoke():
    if request.method == "POST":
        key = request.form.get("key", "").strip()
        if key:
            with get_db() as conn:
                conn.execute("UPDATE licenses SET status = 'revoked' WHERE key = ?", (key,))
                conn.commit()
    return redirect("/")

@app.route("/admin/activate", methods=["GET", "POST"])
def admin_activate():
    if request.method == "POST":
        key = request.form.get("key", "").strip()
        if key:
            with get_db() as conn:
                conn.execute("UPDATE licenses SET status = 'active' WHERE key = ?", (key,))
                conn.commit()
    return redirect("/")

# ==============================================================================
# Real-Time Sleek Web Dashboard
# ==============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ Real-Time License Control Center</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-primary: #3b82f6;
            --accent-success: #10b981;
            --accent-danger: #ef4444;
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
        }
        .navbar-brand { font-weight: 700; letter-spacing: 0.5px; }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 14px;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
        }
        .form-control, .form-select {
            background-color: #0f172a;
            border: 1px solid var(--card-border);
            color: #f8fafc;
            border-radius: 8px;
        }
        .form-control:focus, .form-select:focus {
            background-color: #0f172a;
            border-color: var(--accent-primary);
            color: #fff;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
        }
        .table {
            color: var(--text-primary);
            border-color: var(--card-border);
            vertical-align: middle;
        }
        .table thead th {
            background-color: #0f172a;
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            border-bottom: 2px solid var(--card-border);
        }
        .stat-card {
            padding: 1.25rem;
            border-radius: 12px;
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8), rgba(15, 23, 42, 0.9));
            border: 1px solid var(--card-border);
        }
        .badge-active { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-expired { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-revoked { background-color: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.4); }
        .pulse-dot {
            width: 10px; height: 10px; border-radius: 50%;
            background-color: var(--accent-success);
            display: inline-block;
            box-shadow: 0 0 10px var(--accent-success);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }
        .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 1050; }
    </style>
</head>
<body class="py-4">
    <div class="container-xl">
        <!-- Top Header -->
        <header class="d-flex flex-wrap justify-content-between align-items-center pb-4 mb-4 border-bottom border-secondary">
            <div>
                <h3 class="fw-bold mb-1"><i class="fa-solid fa-shield-halved text-primary me-2"></i>License Control Center</h3>
                <span class="text-secondary small">Real-Time Management & RSA Cryptographic Auth</span>
            </div>
            <div class="d-flex align-items-center gap-3">
                <span class="badge bg-dark border border-secondary px-3 py-2">
                    <span class="pulse-dot me-2"></span>Server Live
                </span>
                <button class="btn btn-outline-primary btn-sm" onclick="fetchLicenses()">
                    <i class="fa-solid fa-rotate me-1"></i> Refresh
                </button>
            </div>
        </header>

        <!-- Stats Overview Cards -->
        <div class="row g-3 mb-4">
            <div class="col-sm-6 col-md-3">
                <div class="stat-card">
                    <div class="text-secondary small fw-bold">TOTAL KEYS</div>
                    <div class="h3 fw-bold mb-0 text-white" id="stat-total">0</div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="stat-card">
                    <div class="text-secondary small fw-bold">ACTIVE LICENSES</div>
                    <div class="h3 fw-bold mb-0 text-success" id="stat-active">0</div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="stat-card">
                    <div class="text-secondary small fw-bold">BOUND DEVICES</div>
                    <div class="h3 fw-bold mb-0 text-info" id="stat-devices">0</div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="stat-card">
                    <div class="text-secondary small fw-bold">EXPIRED / REVOKED</div>
                    <div class="h3 fw-bold mb-0 text-danger" id="stat-inactive">0</div>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <!-- Left: Add New Key Form -->
            <div class="col-lg-4">
                <div class="card p-4">
                    <h5 class="fw-bold mb-3"><i class="fa-solid fa-key text-warning me-2"></i>Generate Key</h5>
                    <form id="createForm" onsubmit="handleCreateKey(event)">
                        <div class="mb-3">
                            <label class="form-label text-secondary small fw-bold">LICENSE KEY</label>
                            <div class="input-group">
                                <input type="text" id="in-key" class="form-control" placeholder="VIP-2026-ABCD" required>
                                <button type="button" class="btn btn-outline-secondary" onclick="generateRandomKey()" title="Random Key">
                                    <i class="fa-solid fa-wand-magic-sparkles"></i>
                                </button>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-secondary small fw-bold">USER / CLIENT LABEL</label>
                            <input type="text" id="in-label" class="form-control" placeholder="e.g. Rahim VIP" required>
                        </div>
                        <div class="row g-2 mb-3">
                            <div class="col-6">
                                <label class="form-label text-secondary small fw-bold">DAYS VALID</label>
                                <input type="number" id="in-days" class="form-control" value="30" min="0" required>
                                <div class="form-text text-secondary small">0 = Lifetime</div>
                            </div>
                            <div class="col-6">
                                <label class="form-label text-secondary small fw-bold">MAX DEVICES</label>
                                <input type="number" id="in-devices" class="form-control" value="1" min="1" required>
                            </div>
                        </div>
                        <div class="mb-4">
                            <label class="form-label text-secondary small fw-bold">NOTES</label>
                            <input type="text" id="in-notes" class="form-control" placeholder="Optional remark">
                        </div>
                        <button type="submit" class="btn btn-primary w-100 fw-bold py-2" id="btn-create">
                            <i class="fa-solid fa-plus me-1"></i> Create License Key
                        </button>
                    </form>
                </div>
            </div>

            <!-- Right: Real-time Keys List -->
            <div class="col-lg-8">
                <div class="card p-4">
                    <div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
                        <h5 class="fw-bold mb-0"><i class="fa-solid fa-list text-primary me-2"></i>Licenses Table</h5>
                        <div style="width: 240px;">
                            <input type="text" id="searchInput" class="form-control form-control-sm" placeholder="🔍 Search key or user..." onkeyup="filterTable()">
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table align-middle">
                            <thead>
                                <tr>
                                    <th>Key</th>
                                    <th>User Label</th>
                                    <th>Status</th>
                                    <th>Devices</th>
                                    <th>Expires</th>
                                    <th class="text-end">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="licensesTbody">
                                <tr><td colspan="6" class="text-center py-4 text-secondary">Loading licenses...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div class="toast-container">
        <div id="liveToast" class="toast align-items-center text-white bg-primary border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body" id="toastMessage">Success</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let allLicenses = [];

        function showToast(msg, bg = 'bg-primary') {
            const toastEl = document.getElementById('liveToast');
            toastEl.className = 'toast align-items-center text-white border-0 ' + bg;
            document.getElementById('toastMessage').innerText = msg;
            new bootstrap.Toast(toastEl, { delay: 3000 }).show();
        }

        function generateRandomKey() {
            const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
            let segment1 = '', segment2 = '', segment3 = '';
            for(let i=0; i<4; i++) segment1 += chars[Math.floor(Math.random() * chars.length)];
            for(let i=0; i<4; i++) segment2 += chars[Math.floor(Math.random() * chars.length)];
            for(let i=0; i<4; i++) segment3 += chars[Math.floor(Math.random() * chars.length)];
            document.getElementById('in-key').value = `VIP-${segment1}-${segment2}-${segment3}`;
        }

        async function fetchLicenses() {
            try {
                const res = await fetch('/api/licenses');
                const data = await res.json();
                if (data.success) {
                    allLicenses = data.licenses;
                    renderTable(allLicenses);
                    updateStats(allLicenses);
                }
            } catch (err) {
                console.error("Failed to load licenses", err);
            }
        }

        function updateStats(items) {
            document.getElementById('stat-total').innerText = items.length;
            const active = items.filter(x => x.status === 'active').length;
            document.getElementById('stat-active').innerText = active;
            document.getElementById('stat-inactive').innerText = items.length - active;
            const devices = items.reduce((acc, curr) => acc + curr.bound_count, 0);
            document.getElementById('stat-devices').innerText = devices;
        }

        function renderTable(items) {
            const tbody = document.getElementById('licensesTbody');
            if (items.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-secondary">No licenses found</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(item => {
                let badgeClass = 'badge-active';
                if (item.status === 'expired') badgeClass = 'badge-expired';
                if (item.status === 'revoked') badgeClass = 'badge-revoked';

                return `
                    <tr>
                        <td>
                            <code class="text-info fw-bold">${item.key}</code>
                            <button class="btn btn-link btn-sm text-secondary p-0 ms-1" onclick="copyToClipboard('${item.key}')" title="Copy Key">
                                <i class="fa-regular fa-copy"></i>
                            </button>
                        </td>
                        <td>${item.label}</td>
                        <td><span class="badge ${badgeClass} px-2 py-1">${item.status.toUpperCase()}</span></td>
                        <td>${item.bound_count} / ${item.device_limit}</td>
                        <td class="small">${item.expires_str}</td>
                        <td class="text-end">
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-warning" onclick="handleAction('${item.key}', 'reset')" title="Reset Device Bindings">
                                    <i class="fa-solid fa-arrows-rotate"></i> Reset
                                </button>
                                ${item.status === 'active' 
                                    ? `<button class="btn btn-outline-danger" onclick="handleAction('${item.key}', 'revoke')" title="Revoke">
                                        <i class="fa-solid fa-ban"></i>
                                       </button>`
                                    : `<button class="btn btn-outline-success" onclick="handleAction('${item.key}', 'activate')" title="Activate">
                                        <i class="fa-solid fa-check"></i>
                                       </button>`
                                }
                                <button class="btn btn-outline-secondary" onclick="handleAction('${item.key}', 'delete')" title="Delete">
                                    <i class="fa-solid fa-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function filterTable() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const filtered = allLicenses.filter(x => 
                x.key.toLowerCase().includes(query) || 
                x.label.toLowerCase().includes(query)
            );
            renderTable(filtered);
        }

        async function handleCreateKey(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-create');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Creating...';

            const payload = {
                key: document.getElementById('in-key').value.trim(),
                label: document.getElementById('in-label').value.trim(),
                days: document.getElementById('in-days').value,
                devices: document.getElementById('in-devices').value,
                notes: document.getElementById('in-notes').value.trim()
            };

            try {
                const res = await fetch('/api/licenses/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Key ${payload.key} created successfully!`, 'bg-success');
                    document.getElementById('createForm').reset();
                    generateRandomKey();
                    fetchLicenses();
                } else {
                    showToast(data.error || 'Failed to create key', 'bg-danger');
                }
            } catch (err) {
                showToast('Network error', 'bg-danger');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-plus me-1"></i> Create License Key';
            }
        }

        async function handleAction(key, action) {
            if (action === 'delete' && !confirm(`Are you sure you want to delete ${key}?`)) {
                return;
            }
            try {
                const res = await fetch('/api/licenses/action', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key, action })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'bg-info');
                    fetchLicenses();
                } else {
                    showToast(data.error || 'Action failed', 'bg-danger');
                }
            } catch (err) {
                showToast('Network error', 'bg-danger');
            }
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('Key copied to clipboard: ' + text, 'bg-dark');
            });
        }

        // Initialize on load
        generateRandomKey();
        fetchLicenses();
        // Polling every 10 seconds for real-time sync across sessions
        setInterval(fetchLicenses, 10000);
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def dashboard():
    return render_template_string(HTML_TEMPLATE)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"[INFO] Starting Real-Time License Server on port {port}...")
    app.run(host="0.0.0.0", port=port)
